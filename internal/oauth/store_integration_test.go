package oauth

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// This adapter exists only in tests: real Lua is executed by ephemeral loopback
// Redis behind a REST bridge. Production always uses dispatch.Redis.Command.
type redisRESTFixture struct {
	endpoint             string
	client               *http.Client
	unavailable          atomic.Bool
	loseResponse         atomic.Bool
	loseMutationResponse atomic.Bool
	requests             atomic.Int64
}

func (r *redisRESTFixture) Command(ctx context.Context, args ...any) (json.RawMessage, error) {
	raw, e := json.Marshal(args)
	if e != nil {
		return nil, e
	}
	req, e := http.NewRequestWithContext(ctx, "POST", r.endpoint, bytes.NewReader(raw))
	if e != nil {
		return nil, e
	}
	res, e := r.client.Do(req)
	if e != nil {
		return nil, e
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("fixture HTTP %d", res.StatusCode)
	}
	var out struct {
		Result json.RawMessage `json:"result"`
		Error  string          `json:"error"`
	}
	if e = json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&out); e != nil {
		return nil, e
	}
	if out.Error != "" {
		return nil, fmt.Errorf("fixture Redis: %s", out.Error)
	}
	return out.Result, nil
}
func oauthRedisFixture(t *testing.T) (*RedisStore, *RedisStore, *redisRESTFixture) {
	t.Helper()
	addr := os.Getenv("ANGELOS_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("ephemeral Redis fixture not configured")
	}
	if !strings.HasPrefix(addr, "127.0.0.1:") {
		t.Fatal("test Redis must be loopback")
	}
	bridge := &redisRESTFixture{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bridge.requests.Add(1)
		if bridge.unavailable.Load() {
			http.Error(w, "unavailable", 503)
			return
		}
		var cmd []any
		decoder := json.NewDecoder(io.LimitReader(r.Body, 256<<10))
		decoder.UseNumber()
		if decoder.Decode(&cmd) != nil {
			http.Error(w, "bad JSON", 400)
			return
		}
		c, e := net.DialTimeout("tcp", addr, 2*time.Second)
		if e != nil {
			http.Error(w, "unavailable", 503)
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		fmt.Fprintf(c, "*%d\r\n", len(cmd))
		for _, arg := range cmd {
			s := fmt.Sprint(arg)
			fmt.Fprintf(c, "$%d\r\n%s\r\n", len(s), s)
		}
		v, e := oauthReadRESP(bufio.NewReader(c))
		if bridge.loseResponse.CompareAndSwap(true, false) || (len(cmd) > 0 && cmd[0] != "GET" && bridge.loseMutationResponse.CompareAndSwap(true, false)) {
			http.Error(w, "lost after commit", 503)
			return
		}
		if e != nil {
			t.Logf("fixture command failed: %v", e)
			json.NewEncoder(w).Encode(map[string]any{"error": e.Error()})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"result": v})
	}))
	t.Cleanup(srv.Close)
	bridge.endpoint = srv.URL
	bridge.client = srv.Client()
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		t.Fatal(e)
	}
	owner := "fixture-owner-" + hex.EncodeToString(b[:])
	a := testStore(t, bridge, owner)
	bstore := testStore(t, bridge, owner)
	t.Cleanup(func() {
		ctx := context.Background()
		v, e := bridge.Command(ctx, "KEYS", a.prefix+"*")
		if e != nil {
			return
		}
		var keys []string
		if json.Unmarshal(v, &keys) != nil {
			return
		}
		for _, k := range keys {
			_, _ = bridge.Command(ctx, "DEL", k)
		}
	})
	return a, bstore, bridge
}
func oauthReadRESP(r *bufio.Reader) (any, error) {
	line, e := r.ReadString('\n')
	if e != nil {
		return nil, e
	}
	if len(line) < 3 {
		return nil, fmt.Errorf("bad RESP")
	}
	body := strings.TrimSuffix(line[1:], "\r\n")
	switch line[0] {
	case '+':
		return body, nil
	case '-':
		return nil, fmt.Errorf("Redis error: %s", body)
	case ':':
		return strconv.Atoi(body)
	case '$':
		n, e := strconv.Atoi(body)
		if e != nil || n > 1<<20 {
			return nil, fmt.Errorf("bad bulk")
		}
		if n < 0 {
			return nil, nil
		}
		b := make([]byte, n+2)
		_, e = io.ReadFull(r, b)
		return string(b[:n]), e
	case '*':
		n, e := strconv.Atoi(body)
		if e != nil || n > 4096 || n < 0 {
			return nil, fmt.Errorf("bad array")
		}
		v := make([]any, n)
		for i := range v {
			v[i], e = oauthReadRESP(r)
			if e != nil {
				return nil, e
			}
		}
		return v, nil
	}
	return nil, fmt.Errorf("unknown RESP")
}
func fixtureGrant(s *RedisStore) Grant {
	now := time.Now()
	return Grant{ID: "grant", Subject: s.owner, ClientID: "client", ClientName: "Example client", Resource: "https://api.example.test/mcp", Scopes: []string{"mail.read"}, CreatedUnix: now.Unix(), ExpiresUnix: now.Add(time.Hour).Unix()}
}
func fixtureRefresh(g Grant) Refresh {
	return Refresh{FamilyID: "family", GrantID: g.ID, Subject: g.Subject, ClientID: g.ClientID, Resource: g.Resource, Scopes: g.Scopes, ExpiresUnix: g.ExpiresUnix}
}
func assertRedisTTL(t *testing.T, r RedisCommander, key string, max int) {
	t.Helper()
	v, e := r.Command(context.Background(), "TTL", key)
	if e != nil {
		t.Fatal(e)
	}
	var n int
	if json.Unmarshal(v, &n) != nil || n <= 0 || n > max {
		t.Fatalf("unexpected TTL %s", v)
	}
}
func TestRedisOAuthSingleUseAcrossInstancesAndRestart(t *testing.T) {
	a, b, _ := oauthRedisFixture(t)
	ctx := context.Background()
	for _, bucket := range []string{"code", "challenge", "bootstrap"} {
		if e := a.Put(ctx, bucket, "opaque-secret", []byte(`{"purpose":"fixture"}`), time.Minute); e != nil {
			t.Fatal(e)
		}
		var won atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < 32; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				s := a
				if i%2 == 0 {
					s = b
				}
				raw, e := s.Consume(ctx, bucket, "opaque-secret")
				if e == nil {
					won.Add(1)
					if string(raw) != `{"purpose":"fixture"}` {
						t.Errorf("bad state %s", raw)
					}
				} else if e != ErrNotFound {
					t.Error(e)
				}
			}(i)
		}
		wg.Wait()
		if won.Load() != 1 {
			t.Fatalf("%s consumed %d times", bucket, won.Load())
		}
		restarted := testStore(t, a.redis, a.owner)
		if _, e := restarted.Consume(ctx, bucket, "opaque-secret"); e != ErrNotFound {
			t.Fatalf("restart restored spent %s: %v", bucket, e)
		}
	}
}
func TestRedisOAuthStateExpiresAndIsolatesOwners(t *testing.T) {
	a, b, r := oauthRedisFixture(t)
	ctx := context.Background()
	if e := a.Put(ctx, "session", "token", []byte(`{"expires":1}`), time.Second); e != nil {
		t.Fatal(e)
	}
	k, _ := a.stateKey("session", "token")
	assertRedisTTL(t, r, k, 1)
	other := testStore(t, r, "different-owner")
	if _, e := other.Get(ctx, "session", "token"); e != ErrNotFound {
		t.Fatal("foreign owner state exposed", e)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_, e := b.Get(ctx, "session", "token")
		if e == ErrNotFound {
			return
		}
		if e != nil {
			t.Fatal(e)
		}
		time.Sleep(30 * time.Millisecond)
	}
	t.Fatal("session survived TTL")
}
func TestRedisOAuthOwnerBindAndCASAtomic(t *testing.T) {
	a, b, r := oauthRedisFixture(t)
	ctx := context.Background()
	initial := []byte(`{"version":1,"credentials":["fixture"]}`)
	var bound atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, e := a.BootstrapOwner(ctx, initial)
			if e != nil {
				t.Error(e)
			}
			if ok {
				bound.Add(1)
			}
		}()
	}
	wg.Wait()
	if bound.Load() != 1 {
		t.Fatalf("bootstrap binds: %d", bound.Load())
	}
	loaded, e := b.LoadOwner(ctx)
	if e != nil || !bytes.Equal(loaded, initial) {
		t.Fatal("owner not durable", e)
	}
	ttl, e := r.Command(ctx, "TTL", a.prefix+"owner")
	if e != nil || string(ttl) != "-1" {
		t.Fatal("owner credential expires", e, string(ttl))
	}
	var swapped atomic.Int32
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, e := b.CASOwner(ctx, initial, []byte(`{"version":2}`))
			if e != nil {
				t.Error(e)
			}
			if ok {
				swapped.Add(1)
			}
		}()
	}
	wg.Wait()
	if swapped.Load() != 1 {
		t.Fatalf("CAS winners: %d", swapped.Load())
	}
	// Losing the credential record alone must not re-enable first enrollment.
	if _, e := r.Command(ctx, "DEL", a.prefix+"owner"); e != nil {
		t.Fatal(e)
	}
	if ok, e := a.BootstrapOwner(ctx, initial); e != nil || ok {
		t.Fatal("bootstrap reset after missing owner", ok, e)
	}
}
func TestRedisOAuthSessionCASAndBoundedRate(t *testing.T) {
	a, b, _ := oauthRedisFixture(t)
	ctx := context.Background()
	old := []byte(`{"last_seen":1}`)
	if e := a.Put(ctx, "session", "session-token", old, time.Minute); e != nil {
		t.Fatal(e)
	}
	var updates, allowed atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, e := b.CompareAndSwap(ctx, "session", "session-token", old, []byte(`{"last_seen":2}`), time.Minute)
			if e != nil {
				t.Error(e)
			}
			if ok {
				updates.Add(1)
			}
			ok, e = a.Allow(ctx, "owner-login", 5, time.Minute)
			if e != nil {
				t.Error(e)
			}
			if ok {
				allowed.Add(1)
			}
		}()
	}
	wg.Wait()
	if updates.Load() != 1 || allowed.Load() != 5 {
		t.Fatal(updates.Load(), allowed.Load())
	}
	if e := a.Delete(ctx, "session", "session-token"); e != nil {
		t.Fatal(e)
	}
	if _, e := b.Get(ctx, "session", "session-token"); e != ErrNotFound {
		t.Fatal("logout not visible", e)
	}
}
func TestRedisOAuthRefreshRotatesAndReplayRevokesGrant(t *testing.T) {
	a, b, r := oauthRedisFixture(t)
	ctx := context.Background()
	g := fixtureGrant(a)
	if e := a.CreateGrant(ctx, g); e != nil {
		t.Fatal(e)
	}
	refresh := fixtureRefresh(g)
	if e := a.CreateRefresh(ctx, "refresh-original", refresh); e != nil {
		t.Fatal(e)
	}
	if _, e := b.RotateRefresh(ctx, "refresh-original", "unused", "different-client", g.Resource, time.Now()); e != ErrNotFound {
		t.Fatal("wrong client accepted", e)
	}
	if _, e := b.RotateRefresh(ctx, "refresh-original", "unused", g.ClientID, "https://wrong.test/mcp", time.Now()); e != ErrNotFound {
		t.Fatal("wrong resource accepted", e)
	}
	rotated, e := b.RotateRefresh(ctx, "refresh-original", "refresh-next", g.ClientID, g.Resource, time.Now())
	if e != nil || rotated.ExpiresUnix != g.ExpiresUnix {
		t.Fatal("rotation failed or extended expiry", e)
	}
	raw, e := r.Command(ctx, "GET", a.prefix+"refresh:"+stateHash("refresh-original"))
	if e != nil || !strings.Contains(string(raw), "spent") {
		t.Fatal("spent tombstone missing", string(raw), e)
	}
	assertRedisTTL(t, r, a.prefix+"refresh:"+stateHash("refresh-original"), 3600)
	restarted := testStore(t, r, a.owner)
	if _, e := restarted.RotateRefresh(ctx, "refresh-original", "refresh-attacker", g.ClientID, g.Resource, time.Now()); e != ErrReplay {
		t.Fatal("replay not detected after restart", e)
	}
	if _, e := b.GetGrant(ctx, g.ID); e != ErrNotFound {
		t.Fatal("replay did not revoke grant immediately", e)
	}
	if _, e := b.RotateRefresh(ctx, "refresh-next", "refresh-third", g.ClientID, g.Resource, time.Now()); e != ErrNotFound {
		t.Fatal("family survived replay", e)
	}
}
func TestRedisOAuthConcurrentRefreshHasOneWinnerThenRevokes(t *testing.T) {
	a, b, _ := oauthRedisFixture(t)
	ctx := context.Background()
	g := fixtureGrant(a)
	if e := a.CreateGrant(ctx, g); e != nil {
		t.Fatal(e)
	}
	if e := a.CreateRefresh(ctx, "original", fixtureRefresh(g)); e != nil {
		t.Fatal(e)
	}
	var winners atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s := a
			if i%2 == 0 {
				s = b
			}
			_, e := s.RotateRefresh(ctx, "original", fmt.Sprintf("next-%d", i), g.ClientID, g.Resource, time.Now())
			if e == nil {
				winners.Add(1)
			} else if e != ErrReplay && e != ErrNotFound {
				t.Error(e)
			}
		}(i)
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatalf("rotation winners: %d", winners.Load())
	}
	if _, e := a.GetGrant(ctx, g.ID); e != ErrNotFound {
		t.Fatal("concurrent replay failed to revoke", e)
	}
}
func TestRedisOAuthGrantBindingsRevocationAndLimits(t *testing.T) {
	a, b, r := oauthRedisFixture(t)
	ctx := context.Background()
	g := fixtureGrant(a)
	if e := a.CreateGrant(ctx, g); e != nil {
		t.Fatal(e)
	}
	bad := fixtureRefresh(g)
	bad.Scopes = []string{"mail.read", "mail.send"}
	if e := a.CreateRefresh(ctx, "bad", bad); e != ErrNotFound {
		t.Fatal("expanded refresh scopes accepted", e)
	}
	all, e := b.ListGrants(ctx)
	if e != nil || len(all) != 1 {
		t.Fatal(len(all), e)
	}
	if e := b.RevokeGrant(ctx, g.ID); e != nil {
		t.Fatal(e)
	}
	if e := a.CreateRefresh(ctx, "revoked", fixtureRefresh(g)); e != ErrNotFound {
		t.Fatal("refresh created for revoked grant", e)
	}
	for i := 0; i < maxGrants; i++ {
		g.ID = fmt.Sprintf("grant-%d", i)
		if e := a.CreateGrant(ctx, g); e != nil {
			t.Fatalf("grant %d: %v", i, e)
		}
	}
	g.ID = "too-many"
	if e := a.CreateGrant(ctx, g); e != ErrConflict {
		t.Fatal("grant cap absent", e)
	}
	assertRedisTTL(t, r, a.prefix+"grants", int(maxStateTTL/time.Second))
}
func TestRedisOAuthFailureAndAmbiguousConsumeNeverRetries(t *testing.T) {
	a, b, r := oauthRedisFixture(t)
	ctx := context.Background()
	if e := a.Put(ctx, "code", "code", []byte(`{}`), time.Minute); e != nil {
		t.Fatal(e)
	}
	before := r.requests.Load()
	r.loseResponse.Store(true)
	if _, e := a.Consume(ctx, "code", "code"); e != ErrUnavailable {
		t.Fatal("lost response did not fail closed", e)
	}
	if r.requests.Load() != before+1 {
		t.Fatal("ambiguous consumption retried")
	}
	if _, e := b.Consume(ctx, "code", "code"); e != ErrNotFound {
		t.Fatal("ambiguous code reusable", e)
	}
	r.unavailable.Store(true)
	if _, e := a.LoadOwner(ctx); e != ErrUnavailable {
		t.Fatal(e)
	}
	if _, e := a.GetGrant(ctx, "grant"); e != ErrUnavailable {
		t.Fatal(e)
	}
	if _, e := a.Allow(ctx, "login", 1, time.Minute); e != ErrUnavailable {
		t.Fatal(e)
	}
	r.unavailable.Store(false)
}
func TestRedisOAuthRefreshTTLAbsoluteAndUnknownFails(t *testing.T) {
	a, b, r := oauthRedisFixture(t)
	ctx := context.Background()
	g := fixtureGrant(a)
	g.ExpiresUnix = time.Now().Add(2 * time.Second).Unix()
	if e := a.CreateGrant(ctx, g); e != nil {
		t.Fatal(e)
	}
	if e := a.CreateRefresh(ctx, "old", fixtureRefresh(g)); e != nil {
		t.Fatal(e)
	}
	if _, e := b.RotateRefresh(ctx, "old", "new", g.ClientID, g.Resource, time.Now()); e != nil {
		t.Fatal(e)
	}
	assertRedisTTL(t, r, a.prefix+"refresh:"+stateHash("old"), 2)
	assertRedisTTL(t, r, a.prefix+"refresh:"+stateHash("new"), 2)
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		_, e := a.GetGrant(ctx, g.ID)
		if e == ErrNotFound {
			if _, e := b.RotateRefresh(ctx, "new", "later", g.ClientID, g.Resource, time.Now()); e != ErrNotFound {
				t.Fatal("expired family renewed", e)
			}
			return
		}
		if e != nil {
			t.Fatal(e)
		}
		time.Sleep(30 * time.Millisecond)
	}
	t.Fatal("grant did not expire")
}

func TestRedisOAuthAmbiguousRefreshAndBootstrapNeverRetry(t *testing.T) {
	a, b, r := oauthRedisFixture(t)
	ctx := context.Background()
	owner := []byte(`{"credential":"first"}`)
	r.loseMutationResponse.Store(true)
	before := r.requests.Load()
	if _, e := a.BootstrapOwner(ctx, owner); e != ErrUnavailable {
		t.Fatal("bootstrap uncertainty accepted", e)
	}
	if r.requests.Load() != before+1 {
		t.Fatal("bootstrap retried")
	}
	if ok, e := b.BootstrapOwner(ctx, []byte(`{"credential":"other"}`)); e != nil || ok {
		t.Fatal("ambiguous bind overwritten", ok, e)
	}
	loaded, e := b.LoadOwner(ctx)
	if e != nil || !bytes.Equal(loaded, owner) {
		t.Fatal("first owner lost", e)
	}
	g := fixtureGrant(a)
	if e := a.CreateGrant(ctx, g); e != nil {
		t.Fatal(e)
	}
	if e := a.CreateRefresh(ctx, "original", fixtureRefresh(g)); e != nil {
		t.Fatal(e)
	}
	before = r.requests.Load()
	r.loseMutationResponse.Store(true)
	if _, e := a.RotateRefresh(ctx, "original", "response-lost-new", g.ClientID, g.Resource, time.Now()); e != ErrUnavailable {
		t.Fatal("lost rotation did not fail closed", e)
	}
	if r.requests.Load() != before+2 {
		t.Fatal("rotation retried beyond GET plus EVAL")
	}
	if _, e := b.RotateRefresh(ctx, "original", "retry-new", g.ClientID, g.Resource, time.Now()); e != ErrReplay {
		t.Fatal("lost-response token reused", e)
	}
	if _, e := b.GetGrant(ctx, g.ID); e != ErrNotFound {
		t.Fatal("uncertain rotation replay did not revoke", e)
	}
}
func TestRedisOAuthSingleFamilyPerGrantAndRotationBound(t *testing.T) {
	a, b, r := oauthRedisFixture(t)
	ctx := context.Background()
	g := fixtureGrant(a)
	if e := a.CreateGrant(ctx, g); e != nil {
		t.Fatal(e)
	}
	ref := fixtureRefresh(g)
	if e := a.CreateRefresh(ctx, "initial", ref); e != nil {
		t.Fatal(e)
	}
	second := ref
	second.FamilyID = "other-family"
	if e := b.CreateRefresh(ctx, "second-family", second); e != ErrConflict {
		t.Fatal("second family for grant accepted", e)
	}
	// Move only the local test fixture to the documented rotation cap.
	familyKey := a.prefix + "family:" + stateHash(ref.FamilyID)
	raw, e := r.Command(ctx, "GET", familyKey)
	if e != nil {
		t.Fatal(e)
	}
	bytes, e := decodeString(raw)
	if e != nil {
		t.Fatal(e)
	}
	var state refreshState
	if e = json.Unmarshal(bytes, &state); e != nil {
		t.Fatal(e)
	}
	state.Rotations = maxFamilyRotations
	encoded, _ := json.Marshal(state)
	if _, e := r.Command(ctx, "SET", familyKey, string(encoded), "EX", 3600); e != nil {
		t.Fatal(e)
	}
	if _, e := b.RotateRefresh(ctx, "initial", "over-limit", g.ClientID, g.Resource, time.Now()); e != ErrNotFound {
		t.Fatal("unbounded token chain", e)
	}
	if _, e := a.GetGrant(ctx, g.ID); e != ErrNotFound {
		t.Fatal("rotation bound did not revoke", e)
	}
}

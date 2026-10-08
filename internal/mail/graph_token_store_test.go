package mail

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type microsoftMemoryTokenStore struct {
	mu                sync.Mutex
	records           map[string]string
	commands          [][]any
	failRead          bool
	failWrite         bool
	loseWriteResponse bool
}

func newMicrosoftMemoryTokenStore() *microsoftMemoryTokenStore {
	return &microsoftMemoryTokenStore{records: make(map[string]string)}
}

func (s *microsoftMemoryTokenStore) Command(ctx context.Context, args ...any) (json.RawMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.commands = append(s.commands, append([]any(nil), args...))
	if len(args) == 6 && args[0] == "EVAL" && args[1] == microsoftRefreshLoadScript && args[2] == 2 {
		if s.failRead {
			return nil, errors.New("synthetic-secret store failure")
		}
		value, exists := s.records[args[3].(string)]
		marker, initialized := s.records[args[4].(string)]
		if !exists {
			if initialized {
				return json.Marshal([]any{2, ""})
			}
			return json.Marshal([]any{0, ""})
		}
		if marker != "v1" || len(value) > maxMicrosoftStoredToken {
			return json.Marshal([]any{2, ""})
		}
		return json.Marshal([]any{1, value})
	}
	if len(args) == 7 && args[0] == "EVAL" && args[1] == microsoftRefreshCASScript && args[2] == 2 {
		if s.failWrite {
			return nil, errors.New("synthetic-secret store failure")
		}
		key, markerKey, old, next := args[3].(string), args[4].(string), args[5].(string), args[6].(string)
		current, found := s.records[key]
		marker, initialized := s.records[markerKey]
		if old == "" && (found || initialized) || old != "" && (!found || current != old || marker != "v1") {
			return json.RawMessage("0"), nil
		}
		s.records[key] = next
		s.records[markerKey] = "v1"
		if s.loseWriteResponse {
			s.loseWriteResponse = false
			return nil, errors.New("synthetic-secret response lost after commit")
		}
		return json.RawMessage("1"), nil
	}
	return nil, errors.New("unexpected synthetic store command")
}

type microsoftCommandsFunc func(context.Context, ...any) (json.RawMessage, error)

func (f microsoftCommandsFunc) Command(ctx context.Context, args ...any) (json.RawMessage, error) {
	return f(ctx, args...)
}

func TestMicrosoftTokenStoreEncryptedColdStartRotation(t *testing.T) {
	store := newMicrosoftMemoryTokenStore()
	var calls atomic.Int32
	handler := func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		want := "synthetic-refresh-token"
		if n > 1 {
			want = fmt.Sprintf("rotated-%d", n-1)
		}
		if r.PostForm.Get("refresh_token") != want {
			t.Error("cold start did not use durable rotation")
		}
		fmt.Fprintf(w, `{"access_token":"opaque-access-%d","refresh_token":"rotated-%d","token_type":"Bearer","expires_in":120,"scope":"User.Read Mail.ReadWrite Mail.Send"}`, n, n)
	}
	first := microsoftRefreshBackend(t, handler)
	first.tokenStore.client = store
	if _, err := first.graphToken(context.Background()); err != nil {
		t.Fatal(err)
	}
	second := microsoftRefreshBackend(t, handler) // A separate function's empty memory.
	second.tokenStore.client = store
	if _, err := second.graphToken(context.Background()); err != nil {
		t.Fatal(err)
	}
	third := microsoftRefreshBackend(t, handler)
	third.tokenStore.client = store
	if _, err := third.graphToken(context.Background()); err != nil || calls.Load() != 3 {
		t.Fatalf("third cold start failed: %v", err)
	}
	if first.config.MicrosoftRefreshToken != "synthetic-refresh-token" {
		t.Fatal("configuration was changed by refresh")
	}
	if len(store.records) != 2 {
		t.Fatal("rotation did not use one owner record")
	}
	for key, encoded := range store.records {
		for _, secret := range []string{"person@example.com", "synthetic-client-id", "synthetic-account", "synthetic-refresh-token", "rotated-", "opaque-access"} {
			if strings.Contains(key, secret) || strings.Contains(encoded, secret) {
				t.Fatal("owner or token plaintext reached Redis")
			}
		}
		if !strings.HasSuffix(key, ":initialized") && !strings.HasPrefix(encoded, "v1.") {
			t.Fatal("missing authenticated record version")
		}
	}
	for _, cmd := range store.commands {
		raw, _ := json.Marshal(cmd)
		if strings.Contains(string(raw), "synthetic-refresh-token") || strings.Contains(string(raw), "rotated-") || strings.Contains(string(raw), "opaque-access") {
			t.Fatal("plaintext sent to Redis command transport")
		}
	}
}

func TestMicrosoftTokenStoreConcurrentFunctionsKeepCASWinner(t *testing.T) {
	store := newMicrosoftMemoryTokenStore()
	entered := make(chan struct{}, 2)
	releaseFirst, releaseSecond := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	backend := func(rotated string, release <-chan struct{}) *GraphBackend {
		b := microsoftRefreshBackend(t, func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			if r.PostForm.Get("refresh_token") != "synthetic-refresh-token" {
				t.Error("concurrent functions did not start from the same seed")
			}
			entered <- struct{}{}
			select {
			case <-release:
				fmt.Fprintf(w, `{"access_token":"access-%s","refresh_token":"%s","token_type":"Bearer","expires_in":120,"scope":"User.Read Mail.ReadWrite Mail.Send"}`, rotated, rotated)
			case <-r.Context().Done():
			}
		})
		b.tokenStore.client = store
		return b
	}
	a, b := backend("winner-rotation", releaseFirst), backend("stale-rotation", releaseSecond)
	resultA, resultB := make(chan error, 1), make(chan error, 1)
	go func() { _, err := a.graphToken(context.Background()); resultA <- err }()
	go func() { _, err := b.graphToken(context.Background()); resultB <- err }()
	for range 2 {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("both concurrent functions did not reach OAuth")
		}
	}
	close(releaseFirst)
	if err := <-resultA; err != nil {
		t.Fatal(err)
	}
	winningRecord := store.records[a.tokenStore.key]
	close(releaseSecond)
	if err := <-resultB; err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 || store.records[a.tokenStore.key] != winningRecord || b.tokens.refreshToken != "winner-rotation" {
		t.Fatal("stale function overwrote or discarded persisted winner")
	}
	if b.tokens.token.value != "access-stale-rotation" {
		t.Fatal("losing CAS unnecessarily discarded its valid access token")
	}
	cold := microsoftRefreshBackend(t, func(w http.ResponseWriter, r *http.Request) {
		if r.PostForm.Get("refresh_token") != "winner-rotation" {
			t.Error("cold start did not select CAS winner")
		}
		fmt.Fprint(w, fakeMicrosoftTokenResponse)
	})
	cold.tokenStore.client = store
	if _, err := cold.graphToken(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestMicrosoftTokenStoreTamperKeyMismatchAndBinding(t *testing.T) {
	b := microsoftRefreshBackend(t, func(w http.ResponseWriter, r *http.Request) { t.Error("tamper reached OAuth") })
	store := b.tokenStore
	encoded, err := store.seal("secret-rotation")
	if err != nil {
		t.Fatal(err)
	}
	encoded2, err := store.seal("secret-rotation")
	if err != nil || encoded == encoded2 {
		t.Fatal("AES-GCM nonce was not randomized")
	}
	if plain, err := store.open(encoded); err != nil || plain != "secret-rotation" {
		t.Fatal("valid encrypted record did not round-trip")
	}
	for _, bad := range []string{"", "secret-rotation", "v0." + encoded[3:], "v1.invalid", encoded[:len(encoded)-1], encoded + "=", strings.Repeat("a", maxMicrosoftStoredToken+1)} {
		if _, err := store.open(bad); err != ErrUnavailable {
			t.Fatal("malformed encrypted record accepted")
		}
	}
	// Changing any bound owner field or initial grant changes the namespace,
	// and copying an old record into that namespace fails AEAD authentication.
	changes := []func(){
		func() { b.config.MicrosoftTenantID = "12345678-1234-1234-1234-123456789abc" },
		func() { b.config.MicrosoftClientID = "changed-client" },
		func() { b.config.MicrosoftAccountID = "changed-account" },
		func() { b.config.From = "other@example.com" },
		func() { b.config.MicrosoftRefreshToken = "explicit-reauthorization" },
	}
	previousKey := store.key
	for _, change := range changes {
		change()
		nextKey := microsoftStoreNamespace(b.config)
		if nextKey == previousKey {
			t.Fatal("namespace did not bind owner or reauthorization")
		}
		copyStore := *store
		copyStore.key = nextKey
		if _, err := copyStore.open(encoded); err != ErrUnavailable {
			t.Fatal("record copied across owner accepted")
		}
		previousKey = nextKey
	}
	other := microsoftRefreshBackend(t, func(w http.ResponseWriter, r *http.Request) { t.Error("wrong key reached OAuth") })
	oldNamespace := other.tokenStore.key
	other.config.MicrosoftTokenEncryptionKey = strings.Repeat("34", 32)
	other.tokenStore = nil
	memory := newMicrosoftMemoryTokenStore()
	memory.records[oldNamespace] = encoded
	memory.records[oldNamespace+":initialized"] = "v1"
	if err := other.ConfigureTokenStore(memory); err != nil {
		t.Fatal(err)
	}
	if other.tokenStore.key != oldNamespace {
		t.Fatal("key replacement incorrectly bypassed the existing record")
	}
	if _, err := other.graphToken(context.Background()); err != ErrUnavailable {
		t.Fatal("key mismatch did not fail closed")
	}
}

func TestMicrosoftTokenStoreFailuresNeverReturnAccessOrRetryOAuth(t *testing.T) {
	for _, failure := range []string{"read", "write", "lost-write", "tamper"} {
		t.Run(failure, func(t *testing.T) {
			var calls atomic.Int32
			b := microsoftRefreshBackend(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				fmt.Fprint(w, strings.TrimSuffix(fakeMicrosoftTokenResponse, "}")+`,"refresh_token":"rotated-after-error"}`)
			})
			memory := b.tokenStore.client.(*microsoftMemoryTokenStore)
			memory.failRead = failure == "read"
			memory.failWrite = failure == "write"
			memory.loseWriteResponse = failure == "lost-write"
			if failure == "tamper" {
				memory.records[b.tokenStore.key] = "v1.tampered"
			}
			if token, err := b.graphToken(context.Background()); err != ErrUnavailable || token != "" {
				t.Fatalf("store failure did not fail statically: %v", err)
			}
			wantCalls := int32(1)
			if failure == "read" || failure == "tamper" {
				wantCalls = 0
			}
			if calls.Load() != wantCalls || b.tokens.token.value != "" || b.tokens.refreshToken != "" {
				t.Fatal("failed persistence cached token or retried OAuth")
			}
			if failure == "lost-write" {
				winner, err := b.tokenStore.load(context.Background(), "")
				if err != nil || winner.token != "rotated-after-error" {
					t.Fatal("uncertain persisted rotation could not survive a cold start")
				}
			}
		})
	}
}

func TestMicrosoftTokenStoreConfigurationAndMalformedReplies(t *testing.T) {
	b := microsoftRefreshBackend(t, func(w http.ResponseWriter, r *http.Request) { t.Error("invalid store reached OAuth") })
	b.tokenStore = nil
	if _, err := b.graphToken(context.Background()); err != ErrUnavailable {
		t.Fatal("unconfigured durable store accepted")
	}
	if err := b.ConfigureTokenStore(nil); err != ErrInvalidInput {
		t.Fatal("nil store accepted")
	}
	var typedNil *microsoftMemoryTokenStore
	if err := b.ConfigureTokenStore(typedNil); err != ErrInvalidInput {
		t.Fatal("typed nil store accepted")
	}
	var nilFunc microsoftCommandsFunc
	if err := b.ConfigureTokenStore(nilFunc); err != ErrInvalidInput {
		t.Fatal("nil function store accepted")
	}
	for _, key := range []string{"", "not-hex", strings.Repeat("12", 16), strings.Repeat("12", 31), strings.Repeat("12", 33)} {
		b.config.MicrosoftTokenEncryptionKey = key
		if err := b.ConfigureTokenStore(newMicrosoftMemoryTokenStore()); err != ErrInvalidInput {
			t.Fatal("invalid encryption key accepted")
		}
	}
	b.config.MicrosoftTokenEncryptionKey = strings.Repeat("12", 32)
	if err := b.ConfigureTokenStore(newMicrosoftMemoryTokenStore()); err != nil {
		t.Fatal(err)
	}
	if err := b.ConfigureTokenStore(newMicrosoftMemoryTokenStore()); err != ErrInvalidInput {
		t.Fatal("store reconfigured after setup")
	}
	for _, raw := range []string{"", "{}", "[]", "true", "123", `[0,null]`, `[null,""]`, `[0,"extra"]`, `[2,""]`, `[1,""]`, `""`, `"plaintext"`, `"v1.invalid"`, `"` + strings.Repeat("a", maxMicrosoftStoredToken+1) + `"`} {
		b.tokenStore.client = microsoftCommandsFunc(func(context.Context, ...any) (json.RawMessage, error) { return json.RawMessage(raw), nil })
		if _, err := b.tokenStore.load(context.Background(), "synthetic-refresh-token"); err != ErrUnavailable {
			t.Fatal("malformed store record accepted")
		}
	}
	for _, raw := range []string{"", "null", "{}", "[]", "true", "2", "-1", `"1"`} {
		b.tokenStore.client = microsoftCommandsFunc(func(context.Context, ...any) (json.RawMessage, error) { return json.RawMessage(raw), nil })
		if _, err := b.tokenStore.advance(context.Background(), microsoftStoredRefresh{}, "rotation"); err != ErrUnavailable {
			t.Fatal("malformed CAS reply accepted")
		}
	}
	// A CAS loss followed by a missing record must never bootstrap the seed.
	b.tokenStore.client = microsoftCommandsFunc(func(_ context.Context, args ...any) (json.RawMessage, error) {
		if args[1] == microsoftRefreshCASScript {
			return json.RawMessage("0"), nil
		}
		return json.RawMessage(`[0,""]`), nil
	})
	if _, err := b.tokenStore.advance(context.Background(), microsoftStoredRefresh{}, "rotation"); err != ErrUnavailable {
		t.Fatal("CAS loss silently bootstrapped missing winner")
	}
}

func TestMicrosoftTokenStoreDeadlineCoversReadAndCommit(t *testing.T) {
	for _, stall := range []string{microsoftRefreshLoadScript, microsoftRefreshCASScript} {
		t.Run(stall, func(t *testing.T) {
			var calls atomic.Int32
			b := microsoftRefreshBackend(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1); fmt.Fprint(w, fakeMicrosoftTokenResponse) })
			b.config.Timeout = 40 * time.Millisecond
			memory := newMicrosoftMemoryTokenStore()
			b.tokenStore.client = microsoftCommandsFunc(func(ctx context.Context, args ...any) (json.RawMessage, error) {
				if args[1] == stall {
					<-ctx.Done()
					return nil, errors.New("synthetic-secret timeout")
				}
				return memory.Command(ctx, args...)
			})
			started := time.Now()
			if token, err := b.graphToken(context.Background()); !errors.Is(err, context.DeadlineExceeded) || token != "" {
				t.Fatalf("store deadline not enforced: %v", err)
			}
			if time.Since(started) > time.Second || calls.Load() > 1 {
				t.Fatal("unbounded store wait or OAuth retry")
			}
		})
	}
}

// The real Redis fixture is ephemeral and loopback-only. This small RESP
// adapter tests the exact production Lua; production uses dispatch.Redis.Command.
type microsoftRESPFixture struct{ addr string }

func (r *microsoftRESPFixture) Command(ctx context.Context, args ...any) (json.RawMessage, error) {
	conn, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp", r.addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	deadline := time.Now().Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	conn.SetDeadline(deadline)
	fmt.Fprintf(conn, "*%d\r\n", len(args))
	for _, arg := range args {
		value := fmt.Sprint(arg)
		fmt.Fprintf(conn, "$%d\r\n%s\r\n", len(value), value)
	}
	value, err := microsoftReadRESP(bufio.NewReader(conn))
	if err != nil {
		return nil, err
	}
	return json.Marshal(value)
}

func microsoftReadRESP(r *bufio.Reader) (any, error) {
	line, err := r.ReadString('\n')
	if err != nil || len(line) < 3 {
		return nil, errors.New("invalid test Redis response")
	}
	body := strings.TrimSuffix(line[1:], "\r\n")
	switch line[0] {
	case '+':
		return body, nil
	case ':':
		return strconv.Atoi(body)
	case '*':
		n, err := strconv.Atoi(body)
		if err != nil || n < 0 || n > 3 {
			return nil, errors.New("invalid test Redis array")
		}
		out := make([]any, n)
		for i := range out {
			out[i], err = microsoftReadRESP(r)
			if err != nil {
				return nil, err
			}
		}
		return out, nil
	case '$':
		n, err := strconv.Atoi(body)
		if err != nil || n > maxMicrosoftStoredToken {
			return nil, errors.New("invalid test Redis size")
		}
		if n < 0 {
			return nil, nil
		}
		value := make([]byte, n+2)
		_, err = io.ReadFull(r, value)
		return string(value[:n]), err
	default:
		return nil, errors.New("test Redis rejected command")
	}
}

func TestMicrosoftTokenStoreRealRedisCASAndNoTTL(t *testing.T) {
	addr := os.Getenv("ANGELOS_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("ephemeral Redis fixture not configured")
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host != "127.0.0.1" {
		t.Fatal("Redis fixture must be loopback")
	}
	fixture := &microsoftRESPFixture{addr: addr}
	b := microsoftRefreshBackend(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, fakeMicrosoftTokenResponse) })
	var entropy [16]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		t.Fatal(err)
	}
	b.config.MicrosoftRefreshToken = "synthetic-redis-seed-" + hex.EncodeToString(entropy[:])
	b.tokenStore = nil
	if err := b.ConfigureTokenStore(fixture); err != nil {
		t.Fatal(err)
	}
	store := b.tokenStore
	t.Cleanup(func() { _, _ = fixture.Command(context.Background(), "DEL", store.key, store.markerKey()) })
	ctx := context.Background()
	previous, err := store.load(ctx, b.config.MicrosoftRefreshToken)
	if err != nil || previous.encoded != "" || previous.token != b.config.MicrosoftRefreshToken {
		t.Fatal("Redis bootstrap failed")
	}
	var wg sync.WaitGroup
	out := make(chan string, 16)
	for i := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			token, err := store.advance(ctx, previous, fmt.Sprintf("synthetic-winner-%d", i))
			if err != nil {
				t.Errorf("Redis CAS failed: %v", err)
			}
			out <- token
		}()
	}
	wg.Wait()
	close(out)
	winner, err := store.load(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	for got := range out {
		if got != winner.token {
			t.Fatal("concurrent Redis writer did not preserve CAS winner")
		}
	}
	ttl, err := fixture.Command(ctx, "TTL", store.key)
	if err != nil || string(ttl) != "-1" {
		t.Fatal("durable token unexpectedly expires")
	}
	newest, err := store.advance(ctx, winner, "newest-rotation")
	if err != nil || newest != "newest-rotation" {
		t.Fatal("Redis winner could not advance")
	}
	if got, err := store.advance(ctx, previous, "late-stale-rotation"); err != nil || got != "newest-rotation" {
		t.Fatal("stale Redis function overwrote newer generation")
	}
	if ttl, err := fixture.Command(ctx, "TTL", store.markerKey()); err != nil || string(ttl) != "-1" {
		t.Fatal("initialization marker unexpectedly expires")
	}
	if _, err := fixture.Command(ctx, "DEL", store.key); err != nil {
		t.Fatal(err)
	}
	if _, err := store.load(ctx, b.config.MicrosoftRefreshToken); err != ErrUnavailable {
		t.Fatal("real Redis record loss silently reused configured seed")
	}
	if _, err := store.advance(ctx, microsoftStoredRefresh{}, "resurrection"); err != ErrUnavailable {
		t.Fatal("real Redis CAS resurrected partially lost record")
	}
}

func TestMicrosoftTokenStoreInitializedRecordLossFailsClosed(t *testing.T) {
	for _, missing := range []string{"token", "marker", "invalid-marker"} {
		t.Run(missing, func(t *testing.T) {
			var calls atomic.Int32
			handler := func(w http.ResponseWriter, r *http.Request) { calls.Add(1); fmt.Fprint(w, fakeMicrosoftTokenResponse) }
			first := microsoftRefreshBackend(t, handler)
			memory := first.tokenStore.client.(*microsoftMemoryTokenStore)
			if _, err := first.graphToken(context.Background()); err != nil {
				t.Fatal(err)
			}
			memory.mu.Lock()
			switch missing {
			case "token":
				delete(memory.records, first.tokenStore.key)
			case "marker":
				delete(memory.records, first.tokenStore.markerKey())
			case "invalid-marker":
				memory.records[first.tokenStore.markerKey()] = "tampered"
			}
			memory.mu.Unlock()
			cold := microsoftRefreshBackend(t, handler)
			cold.tokenStore.client = memory
			if token, err := cold.graphToken(context.Background()); err != ErrUnavailable || token != "" || calls.Load() != 1 {
				t.Fatal("partially lost initialized store retried seed or returned access")
			}
		})
	}
}

func TestMicrosoftTokenStoreLatePersistenceDoesNotReturnExpiredAccess(t *testing.T) {
	b := microsoftRefreshBackend(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, strings.Replace(fakeMicrosoftTokenResponse, `"expires_in":120`, `"expires_in":1`, 1))
	})
	memory := newMicrosoftMemoryTokenStore()
	b.tokenStore.client = microsoftCommandsFunc(func(ctx context.Context, args ...any) (json.RawMessage, error) {
		if args[1] == microsoftRefreshCASScript {
			select {
			case <-time.After(time.Second):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return memory.Command(ctx, args...)
	})
	if token, err := b.graphToken(context.Background()); err != ErrUnavailable || token != "" || b.tokens.token.value != "" {
		t.Fatal("durable persistence returned an expired access token")
	}
	if _, err := b.tokenStore.load(context.Background(), ""); err != nil {
		t.Fatal("expired access token discarded the durable refresh credential")
	}
}

package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

type fakeCommander struct {
	calls  int
	result json.RawMessage
	err    error
	args   []any
}

func (f *fakeCommander) Command(_ context.Context, args ...any) (json.RawMessage, error) {
	f.calls++
	f.args = args
	return f.result, f.err
}
func testStore(t *testing.T, f RedisCommander, owner string) *RedisStore {
	t.Helper()
	s, e := NewRedisStore(f, owner)
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func TestStateKeysAreOwnerScopedHashedAndVersioned(t *testing.T) {
	f := &fakeCommander{result: json.RawMessage(`"OK"`)}
	s := testStore(t, f, "subject-A")
	ctx := context.Background()
	token := "SECRET_TOKEN_never_in_keys"
	if e := s.Put(ctx, "code", token, []byte(`{"value":true}`), time.Minute); e != nil {
		t.Fatal(e)
	}
	key := f.args[1].(string)
	want := "angelos:oauth:{" + stateHash("subject-A") + "}:v1:code:" + stateHash(token)
	if key != want || strings.Contains(key, token) || strings.Contains(key, "subject-A") || strings.HasPrefix(key, "angelos:send:") {
		t.Fatal(key)
	}
	other := testStore(t, f, "subject-B")
	otherKey, _ := other.stateKey("code", token)
	if key == otherKey {
		t.Fatal("owner namespaces collide")
	}
	if f.args[3] != "NX" || f.args[4] != "EX" {
		t.Fatal("new records not NX/EX")
	}
}
func TestStateRejectsInvalidInputBeforeRedis(t *testing.T) {
	f := &fakeCommander{result: json.RawMessage(`"OK"`)}
	s := testStore(t, f, "owner")
	ctx := context.Background()
	tests := []struct {
		bucket, id string
		data       []byte
		ttl        time.Duration
	}{
		{"../send", "id", []byte(`{}`), time.Minute}, {"code", "", []byte(`{}`), time.Minute}, {"code", strings.Repeat("x", 4097), []byte(`{}`), time.Minute},
		{"code", "id", []byte(`{}`), 6 * time.Minute}, {"challenge", "id", []byte(`{}`), 11 * time.Minute}, {"session", "id", []byte(`{}`), 25 * time.Hour},
		{"code", "id", []byte(`{}`), time.Millisecond}, {"code", "id", []byte(`{}`), time.Second + time.Nanosecond}, {"code", "id", []byte(`invalid`), time.Minute},
		{"code", "id", []byte(`"` + strings.Repeat("x", maxStateBytes) + `"`), time.Minute}, {"credential", "id", []byte(`{}`), time.Minute},
	}
	for _, tt := range tests {
		if e := s.Put(ctx, tt.bucket, tt.id, tt.data, tt.ttl); e == nil {
			t.Errorf("accepted %+v", tt)
		}
	}
	if f.calls != 0 {
		t.Fatalf("invalid writes reached Redis: %d", f.calls)
	}
	if _, e := NewRedisStore(nil, "owner"); e == nil {
		t.Fatal("nil Redis accepted")
	}
	if _, e := NewRedisStore(f, ""); e == nil {
		t.Fatal("missing owner accepted")
	}
}
func TestStateFailsClosedWithoutRetry(t *testing.T) {
	for _, raw := range []string{"", `{}`, `[]`, `true`, `"unexpected"`, `null`} {
		f := &fakeCommander{result: json.RawMessage(raw)}
		s := testStore(t, f, "owner")
		if e := s.Put(context.Background(), "code", "token", []byte(`{}`), time.Minute); e == nil {
			t.Fatalf("accepted %q", raw)
		}
		if f.calls != 1 {
			t.Fatal("operation retried")
		}
	}
	f := &fakeCommander{err: errors.New("connection interrupted after execution")}
	s := testStore(t, f, "owner")
	if _, e := s.Consume(context.Background(), "code", "secret"); !errors.Is(e, ErrUnavailable) {
		t.Fatal(e)
	}
	if f.calls != 1 {
		t.Fatal("ambiguous consumption retried")
	}
	f.err = nil
	f.result = json.RawMessage(`null`)
	if _, e := s.Get(context.Background(), "code", "secret"); !errors.Is(e, ErrNotFound) {
		t.Fatal(e)
	}
}
func TestOwnerAndStateResponseBounds(t *testing.T) {
	f := &fakeCommander{result: json.RawMessage(`1`)}
	s := testStore(t, f, "owner")
	ctx := context.Background()
	if _, e := s.BootstrapOwner(ctx, []byte(`"`+strings.Repeat("x", maxOwnerBytes)+`"`)); e == nil {
		t.Fatal("oversized owner accepted")
	}
	if _, e := s.CASOwner(ctx, []byte(`{}`), []byte(`invalid`)); e == nil {
		t.Fatal("invalid owner accepted")
	}
	if _, e := s.Allow(ctx, "rate", 0, time.Minute); e == nil {
		t.Fatal("zero limit accepted")
	}
	if _, e := s.Allow(ctx, "rate", 1, 2*time.Hour); e == nil {
		t.Fatal("unbounded window accepted")
	}
	if f.calls != 0 {
		t.Fatal("bad request reached Redis")
	}
}
func TestTypedStateOwnerScopesAndBounds(t *testing.T) {
	f := &fakeCommander{result: json.RawMessage(`1`)}
	s := testStore(t, f, "owner")
	ctx := context.Background()
	now := time.Now()
	g := Grant{ID: "g", Subject: "owner", ClientID: "client", ClientName: "test", Resource: "https://resource/mcp", Scopes: []string{"mail.read"}, CreatedUnix: now.Unix(), ExpiresUnix: now.Add(time.Hour).Unix()}
	for _, edit := range []func(*Grant){func(g *Grant) { g.Subject = "foreign" }, func(g *Grant) { g.ExpiresUnix = now.Add(31 * 24 * time.Hour).Unix() }, func(g *Grant) { g.Scopes = []string{"mail.admin"} }, func(g *Grant) { g.Scopes = []string{"mail.read", "mail.read"} }, func(g *Grant) { g.ID = "" }} {
		bad := g
		edit(&bad)
		if s.CreateGrant(ctx, bad) == nil {
			t.Fatal("invalid grant accepted")
		}
	}
	if f.calls != 0 {
		t.Fatal("bad grant reached Redis")
	}
	if e := s.CreateGrant(ctx, g); e != nil {
		t.Fatal(e)
	}
	if _, e := s.RotateRefresh(ctx, "same", "same", "client", g.Resource, now); e == nil {
		t.Fatal("nonrotating token accepted")
	}
}

func TestGrantExpiryDuringStoreRead(t *testing.T) {
	now := time.Now()
	g := Grant{ID: "grant", Subject: "owner", ClientID: "client", ClientName: "client", Resource: "https://example.test/mcp", Scopes: []string{"mail.read"}, CreatedUnix: now.Add(-time.Hour).Unix(), ExpiresUnix: now.Unix()}
	// Model Redis returning a grant just before its expiry while the REST result
	// reaches the caller just after it. Neither operation may admit expired state.
	raw, _ := json.Marshal(g)
	encoded, _ := json.Marshal(string(raw))
	f := &fakeCommander{result: encoded}
	s := testStore(t, f, "owner")
	if _, e := s.GetGrant(context.Background(), g.ID); !errors.Is(e, ErrNotFound) {
		t.Fatalf("expiry reported as %v", e)
	}
	list, _ := json.Marshal([]string{string(raw)})
	f.result = list
	grants, e := s.ListGrants(context.Background())
	if e != nil || len(grants) != 0 {
		t.Fatalf("in-flight expiry not excluded: %v %+v", e, grants)
	}
}

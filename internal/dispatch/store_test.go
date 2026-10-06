package dispatch

import (
	"context"
	"encoding/json"
	"github.com/amxv/angelos/internal/compose"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRedisRejectsUnsafeConfig(t *testing.T) {
	for _, u := range []string{"http://example.com", "https://user@example.com", "https://example.com/?token=x", "https://example.com/path"} {
		if _, e := NewRedis(u, "test-test"); e == nil {
			t.Fatal(u)
		}
	}
}
func TestClaimContract(t *testing.T) {
	p := compose.Prepared{ID: strings.Repeat("a", 32), Digest: strings.Repeat("b", 64)}
	record, _ := json.Marshal(Record{Message: p, Status: "prepared", ExpiresUnix: time.Now().Add(time.Minute).Unix()})
	seen := false
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fixture-token" {
			t.Error("missing auth")
		}
		var cmd []any
		json.NewDecoder(r.Body).Decode(&cmd)
		if cmd[0] != "EVAL" || cmd[1] != claimScript {
			t.Error("unexpected command")
		}
		kind := "claimed"
		if seen {
			kind = "existing"
		}
		seen = true
		json.NewEncoder(w).Encode(map[string]any{"result": []string{kind, string(record)}})
	}))
	defer s.Close()
	redis := &Redis{endpoint: s.URL, token: "fixture-token", client: s.Client()}
	_, claimed, e := redis.Claim(context.Background(), p.ID, p.Digest, time.Now())
	if e != nil || !claimed {
		t.Fatal(e)
	}
	_, claimed, e = redis.Claim(context.Background(), p.ID, p.Digest, time.Now())
	if e != nil || claimed {
		t.Fatal("duplicate claim allowed")
	}
}
func TestInvalidIDNeverCallsStore(t *testing.T) {
	r := &Redis{}
	if _, _, e := r.Claim(context.Background(), "../bad", strings.Repeat("a", 64), time.Now()); e == nil {
		t.Fatal("invalid id")
	}
}

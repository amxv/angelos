package dispatch

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func TestRedisSharedTransportRejectsUnsafeDestinations(t *testing.T) {
	for _, endpoint := range []string{"https://redis.example:8443", "https://redis.example?", "https://redis.example/%2f", "https://[fe80::1%25eth0]", "https://redis.example/path", "https://user:password@redis.example"} {
		if _, e := NewRedis(endpoint, "fixture-only"); e == nil {
			t.Errorf("accepted %q", endpoint)
		}
	}
	for _, addr := range []string{"0.0.0.1", "127.0.0.1", "10.0.0.1", "192.88.99.1", "100.64.0.1", "169.254.169.254", "2001:db8::1", "2001::1", "2002:7f00:1::", "64:ff9b::7f00:1", "::ffff:127.0.0.1", "fe80::1%eth0"} {
		if public(netip.MustParseAddr(addr)) {
			t.Errorf("accepted nonpublic %s", addr)
		}
	}
	for _, addr := range []string{"8.8.8.8", "2606:4700:4700::1111"} {
		if !public(netip.MustParseAddr(addr)) {
			t.Errorf("rejected public %s", addr)
		}
	}
	if public(netip.Addr{}) {
		t.Fatal("accepted invalid IP")
	}
}
func TestOAuthCommandSharesBearerAndDoesNotRetry(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "Bearer fixture-only" {
			t.Error("missing shared bearer")
		}
		http.Error(w, "ambiguous failure", 503)
	}))
	defer srv.Close()
	r := &Redis{endpoint: srv.URL, token: "fixture-only", client: srv.Client()}
	if _, e := r.Command(context.Background(), "EVAL", "script", 1, "angelos:oauth:fixture"); e == nil {
		t.Fatal("operation failure accepted")
	}
	if calls != 1 {
		t.Fatal("operation retried", calls)
	}
	if _, e := r.Command(context.Background(), "SET", "key", strings.Repeat("x", 256<<10)); e == nil {
		t.Fatal("oversized request sent")
	}
	if calls != 1 {
		t.Fatal("oversized request reached transport")
	}
	var nilRedis *Redis
	if _, e := nilRedis.Command(context.Background(), "GET", "key"); e == nil {
		t.Fatal("nil store accepted")
	}
}
func TestOAuthCommandResponseLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"result": strings.Repeat("x", 1<<20)})
	}))
	defer srv.Close()
	r := &Redis{endpoint: srv.URL, token: "fixture-only", client: srv.Client()}
	if _, e := r.Command(context.Background(), "GET", "key"); e == nil {
		t.Fatal("oversized response accepted")
	}
}

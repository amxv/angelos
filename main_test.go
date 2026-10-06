package main

import (
	"github.com/amxv/angelos/internal/app"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMissingConfigFailsClosed(t *testing.T) {
	for _, v := range []string{"MAIL_USERNAME", "MAIL_PASSWORD", "MCP_RESOURCE_URL", "MCP_OAUTH_ISSUER", "MCP_OAUTH_JWKS_URL", "MCP_ALLOWED_SUBJECTS"} {
		t.Setenv(v, "")
	}
	h := newHandler()
	r := httptest.NewRecorder()
	h.ServeHTTP(r, httptest.NewRequest("POST", "https://example.com/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)))
	if r.Code != http.StatusServiceUnavailable {
		t.Fatal(r.Code)
	}
	r = httptest.NewRecorder()
	h.ServeHTTP(r, httptest.NewRequest("GET", "https://example.com/healthz", nil))
	if r.Code != 200 || (!strings.Contains(r.Body.String(), `"configured":false`) || !strings.Contains(r.Body.String(), `"version":"`+app.Version+`"`)) {
		t.Fatal(r.Body.String())
	}
}
func TestEnableFlagsExact(t *testing.T) {
	for _, v := range []string{"", "true", "yes", "0"} {
		t.Setenv("MAIL_ENABLE_SEND", v)
		if enabled("MAIL_ENABLE_SEND") {
			t.Fatal(v)
		}
	}
	t.Setenv("MAIL_ENABLE_SEND", "1")
	if !enabled("MAIL_ENABLE_SEND") {
		t.Fatal("1 should enable")
	}
}

func TestConfigureStoreIndependentOfSendEnablement(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, valid := range []bool{false, true} {
			t.Setenv("ANGELOS_REDIS_REST_URL", "")
			t.Setenv("ANGELOS_REDIS_REST_TOKEN", "")
			if valid {
				t.Setenv("ANGELOS_REDIS_REST_URL", "https://redis.example.com")
				t.Setenv("ANGELOS_REDIS_REST_TOKEN", "fixture-token")
			}
			a := &app.App{EnableSend: enabled}
			configureStore(a)
			if (a.Store != nil) != valid || a.EnableSend != (enabled && valid) {
				t.Fatalf("enabled=%t valid=%t: store=%t send=%t", enabled, valid, a.Store != nil, a.EnableSend)
			}
		}
	}
}

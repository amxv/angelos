package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"github.com/amxv/angelos/internal/app"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFirstPartyMountsDiscoveryAndProtectsMCP(t *testing.T) {
	// Disposable generated key is a local test fixture, never runtime behavior.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]string{
		"MAIL_PROVIDER": "spacemail", "MAIL_USERNAME": "fixture@example.com", "MAIL_FROM": "fixture@example.com", "MAIL_PASSWORD": "fixture-not-live",
		"MCP_RESOURCE_URL": "https://api.angelos.ashray.xyz/mcp", "MCP_OAUTH_ISSUER": "https://api.angelos.ashray.xyz", "MCP_OAUTH_JWKS_URL": "https://api.angelos.ashray.xyz/oauth/jwks.json", "MCP_ALLOWED_SUBJECTS": "fixture-owner",
		"ANGELOS_OAUTH_ENABLED": "1", "ANGELOS_OAUTH_SIGNING_KEY_ID": "fixture-1", "ANGELOS_OAUTH_SIGNING_KEY_PEM": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		"ANGELOS_OAUTH_CLIENTS_JSON":           `[{"client_id":"fixture-client","client_name":"Fixture","redirect_uris":["https://client.example.com/callback"]}]`,
		"ANGELOS_OAUTH_VERIFICATION_KEYS_JSON": "", "ANGELOS_OAUTH_BOOTSTRAP_TOKEN_HASH": "", "ANGELOS_OAUTH_CHATGPT_CIMD_ENABLED": "0",
		"ANGELOS_REDIS_REST_URL": "https://redis.example.com", "ANGELOS_REDIS_REST_TOKEN": "fixture-not-live",
		"MAIL_ENABLE_WRITES": "0", "MAIL_ENABLE_SEND": "0", "MAIL_ENABLE_DELETE": "0",
	}
	for name, value := range values {
		t.Setenv(name, value)
	}
	h := newHandler()
	for path, marker := range map[string]string{
		"/.well-known/oauth-authorization-server":   `"code_challenge_methods_supported":["S256"]`,
		"/.well-known/oauth-protected-resource":     `"authorization_servers":["https://api.angelos.ashray.xyz"]`,
		"/.well-known/oauth-protected-resource/mcp": `"resource":"https://api.angelos.ashray.xyz/mcp"`,
		"/oauth/jwks.json":                          `"kid":"fixture-1"`,
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", "https://api.angelos.ashray.xyz"+path, nil))
		if w.Code != 200 || !strings.Contains(w.Body.String(), marker) || strings.Contains(w.Body.String(), "PRIVATE KEY") {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "https://api.angelos.ashray.xyz/mcp", nil))
	if w.Code != 401 || !strings.Contains(w.Header().Get("WWW-Authenticate"), `resource_metadata="https://api.angelos.ashray.xyz/.well-known/oauth-protected-resource"`) {
		t.Fatal(w.Code, w.Header())
	}
	// A valid stable key alone cannot substitute for the durable state config.
	t.Setenv("ANGELOS_REDIS_REST_TOKEN", "")
	w = httptest.NewRecorder()
	newHandler().ServeHTTP(w, httptest.NewRequest("POST", "https://api.angelos.ashray.xyz/mcp", nil))
	if w.Code != 503 {
		t.Fatal("missing Redis config enabled MCP", w.Code)
	}
}

func TestMissingConfigFailsClosed(t *testing.T) {
	for _, v := range []string{"MAIL_USERNAME", "MAIL_PASSWORD", "MCP_RESOURCE_URL", "MCP_OAUTH_ISSUER", "MCP_OAUTH_JWKS_URL", "MCP_ALLOWED_SUBJECTS"} {
		t.Setenv(v, "")
	}
	t.Setenv("ANGELOS_OAUTH_ENABLED", "")
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

func TestConfiguredMailboxCannotUnlockIncompleteFirstParty(t *testing.T) {
	for _, enabled := range []string{"", "0", "true", "1"} {
		t.Run("enabled="+enabled, func(t *testing.T) {
			t.Setenv("MAIL_PROVIDER", "spacemail")
			t.Setenv("MAIL_USERNAME", "fixture@example.com")
			t.Setenv("MAIL_FROM", "fixture@example.com")
			t.Setenv("MAIL_PASSWORD", "fixture-not-a-live-password")
			t.Setenv("MCP_RESOURCE_URL", "https://api.angelos.ashray.xyz/mcp")
			t.Setenv("MCP_OAUTH_ISSUER", "https://api.angelos.ashray.xyz")
			t.Setenv("MCP_OAUTH_JWKS_URL", "https://api.angelos.ashray.xyz/oauth/jwks.json")
			t.Setenv("MCP_ALLOWED_SUBJECTS", "fixture-owner")
			t.Setenv("ANGELOS_OAUTH_ENABLED", enabled)
			t.Setenv("ANGELOS_OAUTH_SIGNING_KEY_PEM", "")
			t.Setenv("ANGELOS_REDIS_REST_URL", "")
			t.Setenv("ANGELOS_REDIS_REST_TOKEN", "")
			h := newHandler()
			for _, method := range []string{"GET", "POST", "DELETE"} {
				w := httptest.NewRecorder()
				h.ServeHTTP(w, httptest.NewRequest(method, "https://api.angelos.ashray.xyz/mcp", nil))
				if w.Code != http.StatusServiceUnavailable {
					t.Fatalf("%s mailbox-only unlocked: %d", method, w.Code)
				}
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest("GET", "https://api.angelos.ashray.xyz/healthz", nil))
			if !strings.Contains(w.Body.String(), `"configured":false`) {
				t.Fatal(w.Body.String())
			}
		})
	}
}

func TestCanonicalHostIgnoresNoUntrustedOrigin(t *testing.T) {
	h := canonicalHost(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	for _, test := range []struct {
		host, header, value string
		status              int
	}{
		{"api.angelos.ashray.xyz", "", "", 204},
		{"attacker.example", "", "", 400},
		{"api.angelos.ashray.xyz:443", "", "", 400},
		{"api.angelos.ashray.xyz", "X-Forwarded-Host", "attacker.example", 400},
		{"api.angelos.ashray.xyz", "X-Forwarded-Proto", "http", 400},
		{"api.angelos.ashray.xyz", "Forwarded", "host=attacker.example;proto=https", 400},
		{"api.angelos.ashray.xyz", "X-Forwarded-Proto", "https", 204},
	} {
		r := httptest.NewRequest("GET", "http://"+test.host+"/mcp", nil)
		if test.header != "" {
			r.Header.Set(test.header, test.value)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != test.status {
			t.Fatalf("%+v status=%d", test, w.Code)
		}
	}
	for _, header := range []string{"X-Forwarded-Host", "X-Forwarded-Proto", "Forwarded"} {
		r := httptest.NewRequest("GET", "https://api.angelos.ashray.xyz/mcp", nil)
		switch header {
		case "X-Forwarded-Host":
			r.Header[header] = []string{"api.angelos.ashray.xyz", "attacker.example"}
		case "X-Forwarded-Proto":
			r.Header[header] = []string{"https", "http"}
		default:
			r.Header[header] = []string{""}
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusBadRequest {
			t.Fatal("ambiguous proxy header accepted", header)
		}
	}
}

func TestExternalIssuerRemainsAvailableWithoutFirstPartySecrets(t *testing.T) {
	t.Setenv("MAIL_PROVIDER", "spacemail")
	t.Setenv("MAIL_USERNAME", "fixture@example.com")
	t.Setenv("MAIL_FROM", "fixture@example.com")
	t.Setenv("MAIL_PASSWORD", "fixture-not-a-live-password")
	t.Setenv("MCP_RESOURCE_URL", "https://mail.example.com/mcp")
	t.Setenv("MCP_OAUTH_ISSUER", "https://login.example.com/")
	t.Setenv("MCP_OAUTH_JWKS_URL", "https://login.example.com/jwks.json")
	t.Setenv("MCP_ALLOWED_SUBJECTS", "fixture-owner")
	t.Setenv("ANGELOS_OAUTH_ENABLED", "0")
	t.Setenv("ANGELOS_OAUTH_SIGNING_KEY_PEM", "")
	t.Setenv("ANGELOS_REDIS_REST_URL", "")
	t.Setenv("ANGELOS_REDIS_REST_TOKEN", "")
	h := newHandler()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "https://mail.example.com/mcp", nil))
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Header().Get("WWW-Authenticate"), "resource_metadata=") {
		t.Fatal(w.Code, w.Header())
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "https://mail.example.com/.well-known/oauth-protected-resource/mcp", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "https://login.example.com/") {
		t.Fatal(w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "https://mail.example.com/oauth/login", nil))
	if w.Code != http.StatusNotFound {
		t.Fatal("local login exposed in external mode", w.Code)
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

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"github.com/amxv/angelos/internal/app"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Vercel routes the public HTTPS hostname into a loopback Go function. The
// default SDK handler correctly protects localhost, while our first-party
// transport can accept that hop only behind strict canonical-host validation.
// This exercises the real six-tool discovery wire response, not mail actions.
func TestFirstPartyCanonicalHostAllowsLoopbackMCPDiscovery(t *testing.T) {
	for _, issuer := range []string{"https://api.angelos.ashray.xyz", "https://owner-mail.vercel.app", "https://mail.owner.example.com"} {
		t.Run(issuer, func(t *testing.T) { testFirstPartyLoopbackMCPDiscovery(t, issuer) })
	}
}
func testFirstPartyLoopbackMCPDiscovery(t *testing.T, issuer string) {
	host := strings.TrimPrefix(issuer, "https://")
	h := canonicalHost((&app.App{}).HandlerBehindCanonicalHostGate(), issuer)
	request := func(host, forwardedHost, forwardedProto string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, issuer+"/mcp", bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
		r.Host = host
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json, text/event-stream")
		r.Header.Set("MCP-Protocol-Version", "2025-11-25")
		r.Header.Set("X-Forwarded-Host", forwardedHost)
		r.Header.Set("X-Forwarded-Proto", forwardedProto)
		r.Header.Set("Forwarded", `for=127.0.0.1;host=attacker.example;proto=http`)
		return r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}))
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request(host, host, "https"))
	if w.Code != http.StatusOK {
		t.Fatalf("legitimate Vercel loopback transport rejected: HTTP %d %s", w.Code, w.Body.String())
	}
	var response struct {
		Result struct {
			Tools []struct {
				Name            string          `json:"name"`
				SecuritySchemes json.RawMessage `json:"securitySchemes"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || len(response.Result.Tools) != 6 {
		t.Fatalf("missing six-tool discovery: %v %s", err, w.Body.String())
	}
	for _, tool := range response.Result.Tools {
		if len(tool.SecuritySchemes) == 0 {
			t.Fatalf("%s lost OAuth discovery metadata", tool.Name)
		}
	}
	for _, bad := range []struct{ host, forwardedHost, forwardedProto string }{
		{"attacker.example", "attacker.example", "https"},
		{host + ":443", host, "https"},
		{host, "attacker.example", "https"},
		{host, host, "http"},
	} {
		w = httptest.NewRecorder()
		h.ServeHTTP(w, request(bad.host, bad.forwardedHost, bad.forwardedProto))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("untrusted public host/forwarding passed gate: %q %q %q HTTP %d", bad.host, bad.forwardedHost, bad.forwardedProto, w.Code)
		}
	}
}

func TestFirstPartyMountsDiscoveryAndProtectsMCP(t *testing.T) {
	for _, issuer := range []string{"https://api.angelos.ashray.xyz", "https://owner-mail.vercel.app", "https://mail.owner.example.com"} {
		t.Run(issuer, func(t *testing.T) { testFirstPartyMountsDiscoveryAtIssuer(t, issuer) })
	}
}
func testFirstPartyMountsDiscoveryAtIssuer(t *testing.T, issuer string) {
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
		"MCP_RESOURCE_URL": issuer + "/mcp", "MCP_OAUTH_ISSUER": issuer, "MCP_OAUTH_JWKS_URL": issuer + "/oauth/jwks.json", "MCP_ALLOWED_SUBJECTS": "fixture-owner",
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
		"/.well-known/oauth-protected-resource":     `"authorization_servers":["` + issuer + `"]`,
		"/.well-known/oauth-protected-resource/mcp": `"resource":"` + issuer + `/mcp"`,
		"/oauth/jwks.json":                          `"kid":"fixture-1"`,
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", issuer+path, nil))
		if w.Code != 200 || !strings.Contains(w.Body.String(), marker) || strings.Contains(w.Body.String(), "PRIVATE KEY") {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", issuer+"/mcp", nil))
	if w.Code != 401 || !strings.Contains(w.Header().Get("WWW-Authenticate"), `resource_metadata="`+issuer+`/.well-known/oauth-protected-resource"`) {
		t.Fatal(w.Code, w.Header())
	}
	// A valid stable key alone cannot substitute for the durable state config.
	t.Setenv("ANGELOS_REDIS_REST_TOKEN", "")
	w = httptest.NewRecorder()
	newHandler().ServeHTTP(w, httptest.NewRequest("POST", issuer+"/mcp", nil))
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
	for _, issuer := range []string{"https://api.angelos.ashray.xyz", "https://owner-mail.vercel.app", "https://mail.owner.example.com"} {
		t.Run(issuer, func(t *testing.T) { testConfiguredMailboxCannotUnlockFirstParty(t, issuer) })
	}
}
func testConfiguredMailboxCannotUnlockFirstParty(t *testing.T, issuer string) {
	for _, enabled := range []string{"", "0", "true", "1"} {
		t.Run("enabled="+enabled, func(t *testing.T) {
			t.Setenv("MAIL_PROVIDER", "spacemail")
			t.Setenv("MAIL_USERNAME", "fixture@example.com")
			t.Setenv("MAIL_FROM", "fixture@example.com")
			t.Setenv("MAIL_PASSWORD", "fixture-not-a-live-password")
			t.Setenv("MCP_RESOURCE_URL", issuer+"/mcp")
			t.Setenv("MCP_OAUTH_ISSUER", issuer)
			t.Setenv("MCP_OAUTH_JWKS_URL", issuer+"/oauth/jwks.json")
			t.Setenv("MCP_ALLOWED_SUBJECTS", "fixture-owner")
			t.Setenv("ANGELOS_OAUTH_ENABLED", enabled)
			t.Setenv("ANGELOS_OAUTH_SIGNING_KEY_PEM", "")
			t.Setenv("ANGELOS_REDIS_REST_URL", "")
			t.Setenv("ANGELOS_REDIS_REST_TOKEN", "")
			h := newHandler()
			for _, method := range []string{"GET", "POST", "DELETE"} {
				w := httptest.NewRecorder()
				h.ServeHTTP(w, httptest.NewRequest(method, issuer+"/mcp", nil))
				if w.Code != http.StatusServiceUnavailable {
					t.Fatalf("%s mailbox-only unlocked: %d", method, w.Code)
				}
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest("GET", issuer+"/healthz", nil))
			if !strings.Contains(w.Body.String(), `"configured":false`) {
				t.Fatal(w.Body.String())
			}
		})
	}
}

func TestCanonicalHostIgnoresNoUntrustedOrigin(t *testing.T) {
	h := canonicalHost(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }), "https://api.angelos.ashray.xyz")
	for _, test := range []struct {
		host, header, value string
		status              int
	}{
		{"api.angelos.ashray.xyz", "", "", 204},
		{"attacker.example", "", "", 400},
		{"api.angelos.ashray.xyz:443", "", "", 400},
		{"api.angelos.ashray.xyz", "X-Forwarded-Host", "attacker.example", 400},
		{"api.angelos.ashray.xyz", "X-Forwarded-Proto", "http", 400},
		// RFC 7239 Forwarded is ignored, not trusted for canonical origin decisions.
		{"api.angelos.ashray.xyz", "Forwarded", "host=attacker.example;proto=http", 204},
		{"api.angelos.ashray.xyz", "X-Forwarded-Proto", "https", 204},
	} {
		r := httptest.NewRequest("GET", "https://"+test.host+"/mcp", nil)
		if test.header != "" {
			r.Header.Set(test.header, test.value)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != test.status {
			t.Fatalf("%+v status=%d", test, w.Code)
		}
	}
	for _, header := range []string{"X-Forwarded-Host", "X-Forwarded-Proto"} {
		r := httptest.NewRequest("GET", "https://api.angelos.ashray.xyz/mcp", nil)
		switch header {
		case "X-Forwarded-Host":
			r.Header[header] = []string{"api.angelos.ashray.xyz", "attacker.example"}
		case "X-Forwarded-Proto":
			r.Header[header] = []string{"https", "http"}
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusBadRequest {
			t.Fatal("ambiguous proxy header accepted", header)
		}
	}
}

func TestExternalIssuerRemainsAvailableWithoutFirstPartySecrets(t *testing.T) {
	for _, issuer := range []string{"https://login.example.com/", "https://mail.example.com/realms/owner"} {
		t.Run(issuer, func(t *testing.T) { testExternalIssuerWithoutFirstPartySecrets(t, issuer) })
	}
}
func testExternalIssuerWithoutFirstPartySecrets(t *testing.T, issuer string) {
	t.Setenv("MAIL_PROVIDER", "spacemail")
	t.Setenv("MAIL_USERNAME", "fixture@example.com")
	t.Setenv("MAIL_FROM", "fixture@example.com")
	t.Setenv("MAIL_PASSWORD", "fixture-not-a-live-password")
	t.Setenv("MCP_RESOURCE_URL", "https://mail.example.com/mcp")
	t.Setenv("MCP_OAUTH_ISSUER", issuer)
	t.Setenv("MCP_OAUTH_JWKS_URL", strings.TrimSuffix(issuer, "/")+"/jwks.json")
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
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), issuer) {
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

func TestDisabledSelfHostedIssuerCannotBecomeExternalVerifier(t *testing.T) {
	for _, issuer := range []string{"https://owner-mail.vercel.app", "https://owner-mail.vercel.app/", "https://owner-mail.vercel.app:443", "https://OWNER-MAIL.vercel.app"} {
		t.Run(issuer, func(t *testing.T) {
			for name, value := range map[string]string{
				"MAIL_PROVIDER": "spacemail", "MAIL_USERNAME": "fixture@example.com", "MAIL_FROM": "fixture@example.com", "MAIL_PASSWORD": "fixture-not-live",
				"MCP_RESOURCE_URL": "https://owner-mail.vercel.app/mcp", "MCP_OAUTH_ISSUER": issuer, "MCP_OAUTH_JWKS_URL": "https://owner-mail.vercel.app/oauth/jwks.json", "MCP_ALLOWED_SUBJECTS": "fixture-owner", "ANGELOS_OAUTH_ENABLED": "0",
			} {
				t.Setenv(name, value)
			}
			w := httptest.NewRecorder()
			newHandler().ServeHTTP(w, httptest.NewRequest("POST", "https://owner-mail.vercel.app/mcp", nil))
			if w.Code != http.StatusServiceUnavailable {
				t.Fatalf("co-hosted issuer fell back to external verifier: %d", w.Code)
			}
		})
	}
}

func TestDeploymentHostGuardProtectsMCPAndDiscovery(t *testing.T) {
	const issuer = "https://owner-mail.vercel.app"
	h := canonicalHost(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }), issuer)
	for _, path := range []string{"/mcp", "/oauth/login", "/oauth/jwks.json", "/.well-known/oauth-authorization-server", "/.well-known/oauth-protected-resource", "/healthz"} {
		for _, origin := range []string{issuer, "https://api.angelos.ashray.xyz", "https://other.vercel.app", issuer + ":443", "http://owner-mail.vercel.app"} {
			r := httptest.NewRequest("GET", origin+path, nil)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			want := http.StatusBadRequest
			if origin == issuer {
				want = http.StatusNoContent
			}
			if w.Code != want {
				t.Fatalf("%s%s: %d, want %d", origin, path, w.Code, want)
			}
		}
	}
	for _, bad := range []string{"", "http://owner-mail.vercel.app", issuer + "/"} {
		w := httptest.NewRecorder()
		canonicalHost(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }), bad).ServeHTTP(w, httptest.NewRequest("GET", issuer+"/mcp", nil))
		if w.Code != http.StatusBadRequest {
			t.Fatal("invalid origin configuration passed host gate")
		}
	}
}

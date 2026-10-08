package auth

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestInitialScopesAreExplicitAndGateAware(t *testing.T) {
	for name, value := range map[string]string{
		"MCP_RESOURCE_URL": "https://mail.example.com/mcp", "MCP_OAUTH_ISSUER": "https://login.example.com",
		"MCP_OAUTH_JWKS_URL": "https://login.example.com/jwks", "MCP_ALLOWED_SUBJECTS": "owner",
	} {
		t.Setenv(name, value)
	}
	for _, tc := range []struct {
		name, requested, writes, send, want string
	}{
		{"legacy remains read only", "", "1", "1", ScopeRead},
		{"explicit full setup", "mail.read mail.write mail.send", "1", "1", "mail.read mail.write mail.send"},
		{"canonical order", "mail.send mail.read mail.write", "1", "1", "mail.read mail.write mail.send"},
		{"writes disabled", "mail.read mail.write mail.send", "0", "1", "mail.read mail.send"},
		{"send disabled", "mail.read mail.write mail.send", "1", "0", "mail.read mail.write"},
		{"all gates disabled", "mail.read mail.write mail.send", "0", "0", ScopeRead},
		{"only explicit gate values", "mail.read mail.write mail.send", "true", "yes", ScopeRead},
		{"read only requested", ScopeRead, "1", "1", ScopeRead},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("MCP_OAUTH_INITIAL_SCOPES", tc.requested)
			t.Setenv("MAIL_ENABLE_WRITES", tc.writes)
			t.Setenv("MAIL_ENABLE_SEND", tc.send)
			c, err := ConfigFromEnv()
			if err != nil {
				t.Fatal(err)
			}
			a, err := New(c)
			if err != nil {
				t.Fatal(err)
			}
			w := call(a, "")
			if w.Code != http.StatusUnauthorized || !strings.Contains(w.Header().Get("WWW-Authenticate"), `scope="`+tc.want+`"`) {
				t.Fatalf("initial authorization challenge: %d %s", w.Code, w.Header().Get("WWW-Authenticate"))
			}
		})
	}
	for _, bad := range []string{"mail.write", "mail.send", "mail.read mail.read", "mail.read openid", " mail.read", "mail.read ", "mail.read  mail.send", "mail.read\tmail.send", "mail.read\r\nX-Injected: true"} {
		t.Setenv("MCP_OAUTH_INITIAL_SCOPES", bad)
		if _, err := ConfigFromEnv(); err == nil {
			t.Errorf("unsafe initial scope accepted: %q", bad)
		}
	}
}

func TestInitialScopesDoNotElevateTokensOrStepUpChallenges(t *testing.T) {
	c := testConfig()
	c.InitialScopes = []string{ScopeSend, ScopeRead, ScopeWrite}
	f := newFixtureWithConfig(t, c)
	c.InitialScopes[0] = "forged"
	if !reflect.DeepEqual(f.a.config.InitialScopes, []string{ScopeRead, ScopeWrite, ScopeSend}) {
		t.Fatal("initial scopes retain mutable caller state")
	}
	for scope, want := range map[string]string{
		ScopeRead:                    ScopeRead,
		ScopeWrite:                   "mail.read mail.write",
		ScopeSend:                    "mail.read mail.send",
		ScopeWrite + " " + ScopeSend: "mail.read mail.write mail.send",
		"untrusted\r\nheader":        ScopeRead,
	} {
		if got := f.a.Challenge(scope); !strings.Contains(got, `scope="`+want+`"`) {
			t.Fatalf("operation-specific challenge broadened: %q => %q", scope, got)
		}
	}
	claims := f.claims()
	claims["scope"] = ScopeRead
	token := rsaToken(t, f.key, tokenHeader(), claims)
	called := false
	handler := f.a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if !HasScope(r.Context(), ScopeRead) || HasScope(r.Context(), ScopeWrite) || HasScope(r.Context(), ScopeSend) {
			t.Fatal("initial full request elevated an existing read-only token")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	r := httptest.NewRequest(http.MethodPost, c.ResourceURL, nil)
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if !called || w.Code != http.StatusNoContent {
		t.Fatal("valid read-only token no longer works", w.Code)
	}
	// An authenticated token lacking the mandatory read scope requests only
	// that missing baseline scope; initial setup preferences do not alter 403s.
	claims["scope"] = ScopeSend
	w = call(f.a, rsaToken(t, f.key, tokenHeader(), claims))
	if w.Code != http.StatusForbidden || !strings.Contains(w.Header().Get("WWW-Authenticate"), `scope="mail.read"`) {
		t.Fatal("authenticated denial broadened", w.Code, w.Header())
	}
}

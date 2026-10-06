package auth

import (
	"context"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Obtain the context through the real authentication boundary. Tests must not
// establish ownership by inserting synthetic principals into a context.
func verifiedContext(t *testing.T, f *fixture, token string) context.Context {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/mcp", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	var ctx context.Context
	f.a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx = r.Context()
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(w, r)
	if w.Code != http.StatusNoContent || ctx == nil {
		t.Fatalf("authentication failed: status %d", w.Code)
	}
	return ctx
}

func TestPrincipalBindingStableAcrossTokens(t *testing.T) {
	f := newFixture(t)
	token := rsaToken(t, f.key, tokenHeader(), f.claims())
	ctx := verifiedContext(t, f, token)
	binding := PrincipalBinding(ctx)
	// Pin the versioned encoding independently of the implementation.
	const expected = "43c6f0f43e1c997e688801bd8e239705a3b4af92979eadd0155fd5038d753efd"
	if binding != expected {
		t.Fatalf("binding %q; want %q", binding, expected)
	}
	decoded, err := hex.DecodeString(binding)
	if err != nil || len(decoded) != 32 || binding != strings.ToLower(binding) {
		t.Fatalf("binding is not a lowercase SHA-256 digest: %q", binding)
	}
	if got := PrincipalBinding(ctx); got != binding {
		t.Fatalf("binding changed on repeated lookup: %q", got)
	}
	for _, test := range []struct {
		name   string
		change func(map[string]any)
	}{
		{"read only", func(c map[string]any) { c["scope"] = ScopeRead }},
		{"scope order", func(c map[string]any) { c["scope"] = ScopeSend + " " + ScopeWrite + " " + ScopeRead }},
		{"extra scope", func(c map[string]any) { c["scope"] = ScopeRead + " other.scope" }},
		{"renewed lifetime", func(c map[string]any) {
			c["iat"] = f.now.Unix()
			c["nbf"] = f.now.Add(-time.Minute).Unix()
			c["exp"] = f.now.Add(2 * time.Hour).Unix()
			c["jti"] = "replacement-access-token"
		}},
		{"optional timestamps absent", func(c map[string]any) { delete(c, "iat"); delete(c, "nbf") }},
		{"multiple audiences", func(c map[string]any) {
			c["aud"] = []string{"https://other.example.com/mcp", f.a.config.ResourceURL}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			claims := f.claims()
			test.change(claims)
			token := rsaToken(t, f.key, tokenHeader(), claims)
			ctx := verifiedContext(t, f, token)
			if got := PrincipalBinding(ctx); got != binding {
				t.Fatalf("same verified owner changed binding: %q", got)
			}
		})
	}
}

func TestPrincipalBindingSeparatesNamespaces(t *testing.T) {
	seen := make(map[string]string)
	for _, test := range []struct {
		name   string
		change func(*Config)
	}{
		{"base", func(*Config) {}},
		{"issuer", func(c *Config) { c.Issuer += "other" }},
		{"issuer exact spelling", func(c *Config) { c.Issuer = strings.TrimSuffix(c.Issuer, "/") }},
		{"resource", func(c *Config) { c.ResourceURL += "/other" }},
		{"subject", func(c *Config) { c.AllowedSubjects = []string{"other-owner"} }},
		{"subject exact spelling", func(c *Config) { c.AllowedSubjects = []string{"OWNER-123"} }},
		{"ambiguous unprefixed tuple", func(c *Config) {
			// Concatenating the resource and subject would match the base tuple.
			c.ResourceURL = strings.TrimSuffix(c.ResourceURL, "p")
			c.AllowedSubjects = []string{"powner-123"}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := testConfig()
			test.change(&c)
			f := newFixtureWithConfig(t, c)
			claims := f.claims()
			claims["sub"] = c.AllowedSubjects[0]
			ctx := verifiedContext(t, f, rsaToken(t, f.key, tokenHeader(), claims))
			p, ok := PrincipalFromContext(ctx)
			if !ok || p.Issuer != c.Issuer || p.Resource != c.ResourceURL || p.Subject != c.AllowedSubjects[0] {
				t.Fatalf("wrong verified namespace: %#v", p)
			}
			binding := PrincipalBinding(ctx)
			if binding == "" {
				t.Fatal("verified owner has no binding")
			}
			if previous, exists := seen[binding]; exists {
				t.Fatalf("distinct namespace shares binding with %s", previous)
			}
			seen[binding] = test.name
		})
	}
}

func TestPrincipalBindingUnaffectedByPrincipalCopy(t *testing.T) {
	f := newFixture(t)
	ctx := verifiedContext(t, f, rsaToken(t, f.key, tokenHeader(), f.claims()))
	binding := PrincipalBinding(ctx)
	p, ok := PrincipalFromContext(ctx)
	if !ok {
		t.Fatal("verified context has no principal")
	}
	p.Issuer = "https://attacker.example.com/"
	p.Resource = "https://attacker.example.com/mcp"
	p.Subject = "attacker"
	p.Scopes[0] = "attacker.scope"
	stored, ok := PrincipalFromContext(ctx)
	if !ok || stored.Issuer != f.a.config.Issuer || stored.Resource != f.a.config.ResourceURL || stored.Subject != "owner-123" || !HasScope(ctx, ScopeRead) {
		t.Fatalf("principal copy changed verified identity: %#v", stored)
	}
	if got := PrincipalBinding(ctx); got != binding {
		t.Fatalf("principal copy changed binding: %q", got)
	}
}

func TestPrincipalBindingRequiresVerifiedPrincipal(t *testing.T) {
	if got := PrincipalBinding(context.Background()); got != "" {
		t.Fatalf("anonymous context has binding: %q", got)
	}
	for _, test := range []struct {
		name   string
		change func(map[string]any)
	}{
		{"wrong issuer", func(c map[string]any) { c["iss"] = "https://other.example.com/" }},
		{"wrong resource", func(c map[string]any) { c["aud"] = "https://other.example.com/mcp" }},
		{"wrong subject", func(c map[string]any) { c["sub"] = "other-owner" }},
		{"expired token", func(c map[string]any) { c["exp"] = int64(1) }},
		{"insufficient scope", func(c map[string]any) { c["scope"] = ScopeSend }},
		{"bad signature", func(map[string]any) {}},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newFixture(t)
			claims := f.claims()
			test.change(claims)
			token := rsaToken(t, f.key, tokenHeader(), claims)
			if test.name == "bad signature" {
				parts := strings.Split(token, ".")
				signature, err := rawBase64.DecodeString(parts[2])
				if err != nil {
					t.Fatal(err)
				}
				signature[0] ^= 1
				parts[2] = rawBase64.EncodeToString(signature)
				token = strings.Join(parts, ".")
			}
			p, err := f.a.verify(t.Context(), token)
			if err == nil || p.Issuer != "" || p.Resource != "" || p.Subject != "" || len(p.Scopes) != 0 {
				t.Fatalf("failed verification exposed principal: %#v, %v", p, err)
			}
			r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/mcp", nil)
			r.Header.Set("Authorization", "Bearer "+token)
			w := httptest.NewRecorder()
			f.a.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Fatal("unverified token reached authenticated handler")
			})).ServeHTTP(w, r)
			if w.Code != http.StatusUnauthorized && w.Code != http.StatusForbidden {
				t.Fatalf("failed token was not rejected: %d", w.Code)
			}
			if got := PrincipalBinding(r.Context()); got != "" {
				t.Fatalf("unverified request has binding: %q", got)
			}
		})
	}
}

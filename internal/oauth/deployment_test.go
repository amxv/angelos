package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/amxv/angelos/internal/auth"
)

func TestDeploymentOriginConfiguration(t *testing.T) {
	base := coreTestConfig(t)
	for _, issuer := range deploymentIssuers {
		t.Run(issuer, func(t *testing.T) {
			c := base
			c.Issuer, c.Resource = issuer, issuer+"/mcp"
			if _, err := New(c, newCoreMemoryStore()); err != nil {
				t.Fatal(err)
			}
			for name, value := range map[string]string{
				"ANGELOS_OAUTH_ENABLED": "1", "MCP_OAUTH_ISSUER": issuer, "MCP_RESOURCE_URL": c.Resource, "MCP_OAUTH_JWKS_URL": issuer + JWKSPath,
				"MCP_ALLOWED_SUBJECTS": c.OwnerSubject, "MAIL_FROM": c.OwnerMailbox, "ANGELOS_OAUTH_SIGNING_KEY_PEM": c.SigningKeyPEM, "ANGELOS_OAUTH_SIGNING_KEY_ID": c.SigningKeyID,
				"ANGELOS_OAUTH_CLIENTS_JSON": "", "ANGELOS_OAUTH_VERIFICATION_KEYS_JSON": "", "ANGELOS_OAUTH_BOOTSTRAP_TOKEN_HASH": "", "ANGELOS_OAUTH_CHATGPT_CIMD_ENABLED": "1",
				"VERCEL_URL": "untrusted-preview.vercel.app", "VERCEL_PROJECT_PRODUCTION_URL": "another-project.vercel.app",
			} {
				t.Setenv(name, value)
			}
			got, err := ConfigFromEnv()
			if err != nil || got.Issuer != issuer || got.Resource != c.Resource || got.passkeyRPID() != strings.TrimPrefix(issuer, "https://") {
				t.Fatalf("explicit deployment configuration changed: %+v %v", got, err)
			}
			for _, jwks := range []string{issuer + JWKSPath + "/", issuer + "/other.json", "https://other.example.com" + JWKSPath, issuer + ":443" + JWKSPath} {
				t.Setenv("MCP_OAUTH_JWKS_URL", jwks)
				if _, err := ConfigFromEnv(); err == nil {
					t.Errorf("non-exact JWKS URL accepted: %s", jwks)
				}
			}
			t.Setenv("MCP_OAUTH_JWKS_URL", issuer+JWKSPath)
			t.Setenv("MCP_OAUTH_ISSUER", "")
			if _, err := ConfigFromEnv(); err == nil {
				t.Fatal("issuer inferred from deployment environment")
			}
		})
	}
	for _, issuer := range []string{
		"", "http://owner.example.com", "https://owner.example.com/", "https://owner.example.com/oauth", "https://owner.example.com:443", "https://owner.example.com:444",
		"https://OWNER.example.com", "HTTPS://owner.example.com", "https://owner.example.com.", "https://owner.example.com:", "https://user@owner.example.com", "https://owner.example.com?x=1", "https://owner.example.com?", "https://owner.example.com#", "https://owner.example.com#fragment",
		"https://localhost", "https://127.0.0.1", "https://[::1]", "https://service.localhost", "https://service.local", "https://service.internal", "https://service.test", "https://service.invalid", "https://service.onion",
		"https://*.example.com", "https://a..example.com", "https://owner.example.com/%2f", "https://owner.example.com\\@evil.com", " https://owner.example.com", "https://owner.example.com\n",
	} {
		t.Run("reject_"+issuer, func(t *testing.T) {
			c := base
			c.Issuer, c.Resource = issuer, issuer+"/mcp"
			if _, err := New(c, newCoreMemoryStore()); err == nil {
				t.Errorf("unsafe origin accepted: %q", issuer)
			}
			if c.MatchRequest(httptest.NewRequest("GET", Issuer+MetadataPath, nil)) {
				t.Error("invalid configuration matched request")
			}
		})
	}
	for _, resource := range []string{Resource, "https://owner-mail.vercel.app/mcp/", "https://owner-mail.vercel.app:443/mcp", "https://owner-mail.vercel.app/MCP", "https://other.vercel.app/mcp"} {
		c := base
		c.Issuer, c.Resource = "https://owner-mail.vercel.app", resource
		if _, err := New(c, newCoreMemoryStore()); err == nil {
			t.Errorf("non-exact resource accepted: %s", resource)
		}
	}
}

func TestDeploymentRequestOriginIsNeverInferred(t *testing.T) {
	for _, issuer := range deploymentIssuers {
		t.Run(issuer, func(t *testing.T) {
			c := coreTestConfig(t)
			c.Issuer, c.Resource = issuer, issuer+"/mcp"
			s, err := New(c, newCoreMemoryStore())
			if err != nil {
				t.Fatal(err)
			}
			host := c.passkeyRPID()
			for name, mutate := range map[string]func(*http.Request){
				"other host":          func(r *http.Request) { r.Host = "other.vercel.app" },
				"explicit port":       func(r *http.Request) { r.Host += ":443" },
				"absolute other host": func(r *http.Request) { r.URL.Host = "other.vercel.app" },
				"absolute http":       func(r *http.Request) { r.URL.Scheme = "http" },
				"forwarded host":      func(r *http.Request) { r.Header.Set("X-Forwarded-Host", "other.vercel.app") },
				"forwarded proto":     func(r *http.Request) { r.Header.Set("X-Forwarded-Proto", "http") },
				"multiple hosts":      func(r *http.Request) { r.Header["X-Forwarded-Host"] = []string{host, host} },
				"multiple protos":     func(r *http.Request) { r.Header["X-Forwarded-Proto"] = []string{"https", "https"} },
			} {
				t.Run(name, func(t *testing.T) {
					r := httptest.NewRequest("GET", issuer+MetadataPath, nil)
					mutate(r)
					w := httptest.NewRecorder()
					s.Handler().ServeHTTP(w, r)
					if w.Code != http.StatusBadRequest {
						t.Fatalf("unsafe request accepted: %d", w.Code)
					}
				})
			}
			// Real reverse proxies use origin-form URLs over the internal hop.
			r := httptest.NewRequest("GET", MetadataPath, nil)
			r.Host = host
			r.Header.Set("X-Forwarded-Host", host)
			r.Header.Set("X-Forwarded-Proto", "https")
			r.Header.Set("Forwarded", "host=attacker.example;proto=http")
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			var metadata map[string]any
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &metadata) != nil {
				t.Fatal(w.Code, w.Body.String())
			}
			for name, want := range map[string]string{"issuer": issuer, "authorization_endpoint": issuer + "/oauth/authorize", "token_endpoint": issuer + "/oauth/token", "jwks_uri": issuer + JWKSPath} {
				if metadata[name] != want {
					t.Errorf("%s=%v; want %s", name, metadata[name], want)
				}
			}
		})
	}
}

func TestDeploymentPasskeysAndBrowserRejectOtherOrigins(t *testing.T) {
	for _, issuer := range deploymentIssuers[1:] {
		t.Run(issuer, func(t *testing.T) {
			c := coreTestConfig(t)
			c.Issuer, c.Resource = issuer, issuer+"/mcp"
			h := newBrowserHarnessWithConfig(t, c)
			for _, origin := range []string{Issuer, issuer + "/", issuer + ":443", "https://other.vercel.app", "null", ""} {
				if w := h.request("POST", "/oauth/passkeys/register/begin", `{}`, "application/json", origin); w.Code != 403 {
					t.Errorf("cross-origin POST %q: %d", origin, w.Code)
				}
			}
			for _, fault := range []string{"old origin", "old RP ID"} {
				id, challenge := h.begin(true)
				a := newVirtualAuthenticator(t)
				origin, rp := issuer, c.passkeyRPID()
				if fault == "old origin" {
					origin = Issuer
				} else {
					rp = passkeyRPID
				}
				w := h.post("/oauth/passkeys/register/finish", map[string]any{"ceremony": id, "credential": a.registration(t, challenge, origin, rp, 0x45)})
				if w.Code != 400 {
					t.Fatalf("foreign registration %s: %d %s", fault, w.Code, w.Body)
				}
			}
			a := h.enroll()
			if h.cookie.Domain != "" || !h.cookie.Secure || !h.cookie.HttpOnly || h.cookie.Path != "/" || h.cookie.SameSite != http.SameSiteLaxMode {
				t.Fatal("cookie scope weakened")
			}
			h.logout()
			for _, fault := range []string{"old origin", "old RP ID"} {
				id, challenge := h.begin(false)
				origin, rp := issuer, c.passkeyRPID()
				if fault == "old origin" {
					origin = Issuer
				} else {
					rp = passkeyRPID
				}
				w := h.post("/oauth/passkeys/login/finish", map[string]any{"ceremony": id, "credential": a.assertion(t, challenge, origin, rp, 0x05)})
				if w.Code != 400 {
					t.Fatalf("foreign login %s: %d %s", fault, w.Code, w.Body)
				}
			}
			id, challenge := h.begin(false)
			w := h.post("/oauth/passkeys/login/finish", map[string]any{"ceremony": id, "credential": a.assertion(t, challenge, issuer, c.passkeyRPID(), 0x05)})
			if w.Code != 200 {
				t.Fatal(w.Code, w.Body.String())
			}
		})
	}
}

func TestDeploymentTokensAndRefreshStayExactlyBound(t *testing.T) {
	for _, issuer := range deploymentIssuers[1:] {
		t.Run(issuer, func(t *testing.T) {
			c := coreTestConfig(t)
			c.Issuer, c.Resource = issuer, issuer+"/mcp"
			s, err := New(c, newCoreMemoryStore())
			if err != nil {
				t.Fatal(err)
			}
			a, _ := coreAuthorization(s)
			wrong := a
			wrong.Resource = Resource
			if _, err := s.ApproveAuthorization(context.Background(), wrong, c.OwnerSubject, wrong.Scopes); err == nil {
				t.Fatal("foreign consent resource accepted")
			}
			wrong = a
			wrong.RedirectURI += "/"
			if _, err := s.ApproveAuthorization(context.Background(), wrong, c.OwnerSubject, wrong.Scopes); err == nil {
				t.Fatal("non-exact redirect accepted")
			}
			denied, _ := url.Parse(s.DenyAuthorization(a))
			if denied.Query().Get("iss") != issuer {
				t.Fatal("denial uses foreign issuer")
			}
			p, _ := coreCode(t, s)
			for _, resource := range []string{Resource, c.Resource + "/", issuer + ":443/mcp"} {
				p.Set("resource", resource)
				if w := coreToken(s, p); w.Code != 400 {
					t.Fatal("foreign token resource accepted", resource, w.Code)
				}
			}
			p.Set("resource", c.Resource)
			w := coreToken(s, p)
			if w.Code != 200 {
				t.Fatal(w.Code, w.Body.String())
			}
			out := coreTokenValues(t, w)
			access := out["access_token"].(string)
			claims := coreClaims(t, access)
			if claims.Issuer != issuer || claims.Audience != c.Resource {
				t.Fatal("incorrect deployment token claims")
			}
			for _, target := range []struct {
				issuer, resource string
				status           int
			}{
				{issuer, c.Resource, 204}, {Issuer, c.Resource, 401}, {issuer, Resource, 401}, {issuer + "/", c.Resource, 401}, {issuer, c.Resource + "/", 401},
			} {
				gate, err := auth.New(auth.Config{Issuer: target.issuer, ResourceURL: target.resource, JWKSURL: strings.TrimSuffix(target.issuer, "/") + JWKSPath, AllowedSubjects: []string{c.OwnerSubject}, LocalJWKS: s.JWKS(), CheckGrant: s.GrantActive})
				if err != nil {
					t.Fatal(err)
				}
				r := httptest.NewRequest("POST", target.resource, nil)
				r.Header.Set("Authorization", "Bearer "+access)
				w := httptest.NewRecorder()
				gate.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })).ServeHTTP(w, r)
				if w.Code != target.status {
					t.Fatalf("issuer/audience verification %+v: %d", target, w.Code)
				}
			}
			refresh := url.Values{"grant_type": {"refresh_token"}, "client_id": {a.ClientID}, "resource": {Resource}, "refresh_token": {out["refresh_token"].(string)}}
			if w := coreToken(s, refresh); w.Code != 400 {
				t.Fatal("foreign refresh resource accepted", w.Code)
			}
			refresh.Set("resource", c.Resource)
			w = coreToken(s, refresh)
			if w.Code != 200 {
				t.Fatal(w.Code, w.Body.String())
			}
			refreshed := coreClaims(t, coreTokenValues(t, w)["access_token"].(string))
			if refreshed.Issuer != issuer || refreshed.Audience != c.Resource {
				t.Fatal("refresh lost deployment binding")
			}
		})
	}
}

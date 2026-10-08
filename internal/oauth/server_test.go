package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/amxv/angelos/internal/app"
	"github.com/amxv/angelos/internal/auth"
)

// Core HTTP tests use isolated atomic state. Real Lua/TTL and cross-instance
// behavior is independently covered by the Redis integration suite.
type coreMemoryStore struct {
	Store
	mu      sync.Mutex
	state   map[string][]byte
	grants  map[string]Grant
	refresh map[string]Refresh
	spent   map[string]bool
	fail    bool
}

func newCoreMemoryStore() *coreMemoryStore {
	return &coreMemoryStore{state: map[string][]byte{}, grants: map[string]Grant{}, refresh: map[string]Refresh{}, spent: map[string]bool{}}
}
func (m *coreMemoryStore) Put(_ context.Context, bucket, id string, value []byte, _ time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return ErrUnavailable
	}
	key := bucket + id
	if _, ok := m.state[key]; ok {
		return ErrConflict
	}
	m.state[key] = append([]byte(nil), value...)
	return nil
}
func (m *coreMemoryStore) Get(_ context.Context, bucket, id string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return nil, ErrUnavailable
	}
	v, ok := m.state[bucket+id]
	if !ok {
		return nil, ErrNotFound
	}
	return append([]byte(nil), v...), nil
}
func (m *coreMemoryStore) Consume(_ context.Context, bucket, id string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return nil, ErrUnavailable
	}
	key := bucket + id
	v, ok := m.state[key]
	if !ok {
		return nil, ErrNotFound
	}
	delete(m.state, key)
	return append([]byte(nil), v...), nil
}
func (m *coreMemoryStore) Delete(_ context.Context, bucket, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return ErrUnavailable
	}
	delete(m.state, bucket+id)
	return nil
}
func (m *coreMemoryStore) Allow(context.Context, string, int, time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return false, ErrUnavailable
	}
	return true, nil
}
func (m *coreMemoryStore) CreateGrant(_ context.Context, g Grant) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return ErrUnavailable
	}
	if _, ok := m.grants[g.ID]; ok {
		return ErrConflict
	}
	m.grants[g.ID] = g
	return nil
}
func (m *coreMemoryStore) GetGrant(_ context.Context, id string) (Grant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return Grant{}, ErrUnavailable
	}
	g, ok := m.grants[id]
	if !ok || g.ExpiresUnix <= time.Now().Unix() {
		return Grant{}, ErrNotFound
	}
	return g, nil
}
func (m *coreMemoryStore) ListGrants(context.Context) ([]Grant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return nil, ErrUnavailable
	}
	out := []Grant{}
	for _, g := range m.grants {
		out = append(out, g)
	}
	return out, nil
}
func (m *coreMemoryStore) RevokeGrant(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return ErrUnavailable
	}
	delete(m.grants, id)
	return nil
}
func (m *coreMemoryStore) CreateRefresh(_ context.Context, token string, r Refresh) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return ErrUnavailable
	}
	if _, ok := m.grants[r.GrantID]; !ok {
		return ErrNotFound
	}
	if _, ok := m.refresh[token]; ok {
		return ErrConflict
	}
	m.refresh[token] = r
	return nil
}
func (m *coreMemoryStore) RotateRefresh(_ context.Context, old, next, client, resource string, now time.Time) (Refresh, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return Refresh{}, ErrUnavailable
	}
	r, ok := m.refresh[old]
	if !ok || r.ClientID != client || r.Resource != resource || r.ExpiresUnix <= now.Unix() {
		return Refresh{}, ErrNotFound
	}
	if m.spent[old] {
		delete(m.grants, r.GrantID)
		return Refresh{}, ErrReplay
	}
	if _, ok := m.grants[r.GrantID]; !ok {
		return Refresh{}, ErrNotFound
	}
	m.spent[old] = true
	m.refresh[next] = r
	return r, nil
}

func coreServer(t *testing.T) (*Server, *coreMemoryStore) {
	t.Helper()
	m := newCoreMemoryStore()
	s, e := New(coreTestConfig(t), m)
	if e != nil {
		t.Fatal(e)
	}
	return s, m
}

func coreAuthorization(s *Server) (AuthorizationRequest, string) {
	verifier := strings.Repeat("v", 64)
	digest := sha256.Sum256([]byte(verifier))
	c := s.config.Clients[0]
	return AuthorizationRequest{ClientID: c.ID, ClientName: c.Name, RedirectURI: c.RedirectURIs[0], Resource: s.config.Resource, State: "state-for-this-request", Challenge: base64.RawURLEncoding.EncodeToString(digest[:]), Scopes: []string{ScopeRead, ScopeSend}}, verifier
}
func coreCode(t *testing.T, s *Server) (url.Values, string) {
	t.Helper()
	a, v := coreAuthorization(s)
	redirect, e := s.ApproveAuthorization(context.Background(), a, s.config.OwnerSubject, a.Scopes)
	if e != nil {
		t.Fatal(e)
	}
	u, e := url.Parse(redirect)
	if e != nil {
		t.Fatal(e)
	}
	if u.Query().Get("iss") != s.config.Issuer || u.Query().Get("state") != a.State {
		t.Fatal("issuer/state missing", redirect)
	}
	return url.Values{"grant_type": {"authorization_code"}, "code": {u.Query().Get("code")}, "client_id": {a.ClientID}, "redirect_uri": {a.RedirectURI}, "resource": {s.config.Resource}, "code_verifier": {v}}, u.Query().Get("code")
}
func coreToken(s *Server, values url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, s.config.Issuer+"/oauth/token", strings.NewReader(values.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}
func coreTokenValues(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if e := json.Unmarshal(w.Body.Bytes(), &out); e != nil {
		t.Fatal(e, w.Body.String())
	}
	return out
}
func coreClaims(t *testing.T, token string) accessClaims {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatal("invalid JWT shape")
	}
	raw, e := base64.RawURLEncoding.DecodeString(parts[1])
	if e != nil {
		t.Fatal(e)
	}
	var out accessClaims
	if e := json.Unmarshal(raw, &out); e != nil {
		t.Fatal(e)
	}
	return out
}

func TestCoreDiscoveryAndIssuerResponses(t *testing.T) {
	s, _ := coreServer(t)
	for _, path := range []string{MetadataPath, JWKSPath} {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest("GET", Issuer+path, nil))
		if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal(path, w.Code, w.Body.String())
		}
		var doc map[string]any
		if json.Unmarshal(w.Body.Bytes(), &doc) != nil {
			t.Fatal("invalid metadata")
		}
		if path == MetadataPath {
			if doc["issuer"] != Issuer || doc["authorization_response_iss_parameter_supported"] != true || doc["registration_endpoint"] != nil || doc["client_id_metadata_document_supported"] != false {
				t.Fatal(doc)
			}
			if got := doc["token_endpoint_auth_methods_supported"].([]any); len(got) != 1 || got[0] != "none" {
				t.Fatal(doc)
			}
		} else if strings.Contains(w.Body.String(), `"d"`) {
			t.Fatal("private material in JWKS")
		}
	}
	a, _ := coreAuthorization(s)
	u, e := url.Parse(s.DenyAuthorization(a))
	if e != nil || u.Query().Get("error") != "access_denied" || u.Query().Get("iss") != Issuer || u.Query().Get("state") != a.State {
		t.Fatal("bad denied response", u, e)
	}
	for _, method := range []string{"POST", "PUT", "DELETE"} {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest(method, Issuer+MetadataPath, nil))
		if w.Code != 405 {
			t.Fatal(method, w.Code)
		}
	}
}

func TestCoreAuthorizationRejectsBeforeLoginAndSafeErrors(t *testing.T) {
	s, _ := coreServer(t)
	a, _ := coreAuthorization(s)
	base := url.Values{"response_type": {"code"}, "client_id": {a.ClientID}, "redirect_uri": {a.RedirectURI}, "state": {a.State}, "resource": {Resource}, "scope": {"mail.read mail.send"}, "code_challenge": {a.Challenge}, "code_challenge_method": {"S256"}}
	for _, tc := range []struct {
		name, key, value, err string
		local                 bool
	}{
		{"unknown client", "client_id", "evil", "invalid_client", true}, {"redirect prefix", "redirect_uri", a.RedirectURI + ".evil", "invalid_client", true}, {"wrong resource", "resource", Issuer, "invalid_target", false}, {"absent state", "state", "", "invalid_request", false}, {"unknown scope", "scope", "mail.read openid", "invalid_scope", false}, {"implicit grant", "response_type", "token", "unsupported_response_type", false}, {"PKCE plain", "code_challenge_method", "plain", "invalid_request", false}, {"bad challenge", "code_challenge", "short", "invalid_request", false}, {"form response", "response_mode", "form_post", "invalid_request", false}, {"request URI", "request_uri", "https://evil.example.com/request", "invalid_request", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := url.Values{}
			for k, v := range base {
				p[k] = append([]string(nil), v...)
			}
			p.Set(tc.key, tc.value)
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, httptest.NewRequest("GET", Issuer+"/oauth/authorize?"+p.Encode(), nil))
			if tc.local {
				if w.Code != 400 || w.Header().Get("Location") != "" {
					t.Fatal(w.Code, w.Header(), w.Body.String())
				}
			} else {
				u, e := url.Parse(w.Header().Get("Location"))
				if e != nil || w.Code != 303 || u.Query().Get("iss") != Issuer || u.Query().Get("error") != tc.err {
					t.Fatal(w.Code, w.Header(), w.Body.String())
				}
			}
		})
	}
	for _, key := range []string{"resource", "client_id", "redirect_uri", "state", "scope", "code_challenge", "code_challenge_method"} {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest("GET", Issuer+"/oauth/authorize?"+base.Encode()+"&"+key+"=duplicate", nil))
		if w.Code != 400 || w.Header().Get("Location") != "" {
			t.Fatal("duplicate accepted", key, w.Code)
		}
	}
}

func TestCoreCodeExchangeAndSingleUseConcurrent(t *testing.T) {
	s, _ := coreServer(t)
	params, _ := coreCode(t, s)
	var success atomic.Int32
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := coreToken(s, params)
			if w.Code == 200 {
				success.Add(1)
			} else if w.Code != 400 {
				t.Errorf("unexpected status %d", w.Code)
			}
		}()
	}
	wg.Wait()
	if success.Load() != 1 {
		t.Fatalf("code successes=%d", success.Load())
	}
}

func TestCoreCodeBindingsExpiryAndPKCE(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(url.Values, *Server, *coreMemoryStore, string)
	}{
		{"verifier", func(p url.Values, _ *Server, _ *coreMemoryStore, _ string) {
			p.Set("code_verifier", strings.Repeat("x", 64))
		}},
		{"redirect", func(p url.Values, _ *Server, _ *coreMemoryStore, _ string) {
			p.Set("redirect_uri", "https://evil.example.com/cb")
		}},
		{"resource", func(p url.Values, _ *Server, _ *coreMemoryStore, _ string) { p.Set("resource", Issuer) }},
		{"client", func(p url.Values, s *Server, _ *coreMemoryStore, _ string) {
			s.config.Clients = append(s.config.Clients, Client{ID: "another", Name: "Another", RedirectURIs: []string{s.config.Clients[0].RedirectURIs[0]}})
			p.Set("client_id", "another")
		}},
		{"expiry", func(_ url.Values, _ *Server, m *coreMemoryStore, code string) {
			var a AuthorizationCode
			_ = json.Unmarshal(m.state["code"+code], &a)
			a.ExpiresUnix = time.Now().Add(-time.Second).Unix()
			m.state["code"+code], _ = json.Marshal(a)
		}},
		{"subject", func(_ url.Values, _ *Server, m *coreMemoryStore, code string) {
			var a AuthorizationCode
			_ = json.Unmarshal(m.state["code"+code], &a)
			a.Subject = "attacker"
			m.state["code"+code], _ = json.Marshal(a)
		}},
		{"revoked grant", func(_ url.Values, _ *Server, m *coreMemoryStore, _ string) { m.grants = map[string]Grant{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, m := coreServer(t)
			p, code := coreCode(t, s)
			tc.change(p, s, m, code)
			w := coreToken(s, p)
			if w.Code != 400 {
				t.Fatal(w.Code, w.Body.String())
			}
			if coreTokenValues(t, w)["access_token"] != nil {
				t.Fatal("invalid request issued token")
			}
		})
	}
}

func TestCoreTokenRejectsParameterConfusion(t *testing.T) {
	s, _ := coreServer(t)
	p, _ := coreCode(t, s)
	for _, tc := range []struct{ name, query, extra, auth, content string }{
		{"query token", "?resource=" + url.QueryEscape(Resource), "", "", "application/x-www-form-urlencoded"},
		{"duplicate client", "", "&client_id=test-client", "", "application/x-www-form-urlencoded"},
		{"duplicate resource", "", "&resource=" + url.QueryEscape(Resource), "", "application/x-www-form-urlencoded"},
		{"secret auth", "", "&client_secret=", "", "application/x-www-form-urlencoded"},
		{"JWT auth", "", "&client_assertion=anything", "", "application/x-www-form-urlencoded"},
		{"basic auth", "", "", "Basic dGVzdDp0ZXN0", "application/x-www-form-urlencoded"},
		{"JSON body", "", "", "", "application/json"},
		{"large body", "", "&ignored=" + strings.Repeat("x", 17000), "", "application/x-www-form-urlencoded"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", Issuer+"/oauth/token"+tc.query, strings.NewReader(p.Encode()+tc.extra))
			r.Header.Set("Content-Type", tc.content)
			if tc.auth != "" {
				r.Header.Set("Authorization", tc.auth)
			}
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			if w.Code != 400 {
				t.Fatal(w.Code, w.Body.String())
			}
		})
	}
	if w := coreToken(s, p); w.Code != 200 {
		t.Fatal("malformed requests consumed original code", w.Code, w.Body.String())
	}
}

func TestCoreRefreshRotationReplayRevocationAndScope(t *testing.T) {
	s, m := coreServer(t)
	p, _ := coreCode(t, s)
	w := coreToken(s, p)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	out := coreTokenValues(t, w)
	claims := coreClaims(t, out["access_token"].(string))
	refresh := url.Values{"grant_type": {"refresh_token"}, "client_id": {p.Get("client_id")}, "resource": {Resource}, "refresh_token": {out["refresh_token"].(string)}, "scope": {ScopeRead}}
	w = coreToken(s, refresh)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	next := coreTokenValues(t, w)
	if next["refresh_token"] == out["refresh_token"] || next["scope"] != ScopeRead {
		t.Fatal("refresh not rotated/narrowed", next)
	}
	if err := s.GrantActive(context.Background(), claims.GrantID, claims.ClientID, claims.Subject, []string{ScopeRead, ScopeSend}); err != nil {
		t.Fatal(err)
	}
	if w = coreToken(s, refresh); w.Code != 400 {
		t.Fatal("replay accepted", w.Code)
	}
	if err := s.GrantActive(context.Background(), claims.GrantID, claims.ClientID, claims.Subject, []string{ScopeRead}); !errors.Is(err, ErrNotFound) {
		t.Fatal("replay did not revoke JWT", err)
	}
	refresh.Set("refresh_token", next["refresh_token"].(string))
	if w = coreToken(s, refresh); w.Code != 400 {
		t.Fatal("family survived replay", w.Code)
	}
	if len(m.grants) != 0 {
		t.Fatal("replayed grant remains")
	}
}

func TestCoreRefreshScopeExpansionRevokesAfterRotation(t *testing.T) {
	s, _ := coreServer(t)
	p, _ := coreCode(t, s)
	w := coreToken(s, p)
	out := coreTokenValues(t, w)
	claims := coreClaims(t, out["access_token"].(string))
	p = url.Values{"grant_type": {"refresh_token"}, "client_id": {claims.ClientID}, "resource": {Resource}, "refresh_token": {out["refresh_token"].(string)}, "scope": {"mail.read mail.write"}}
	w = coreToken(s, p)
	if w.Code != 400 || coreTokenValues(t, w)["error"] != "invalid_scope" {
		t.Fatal(w.Code, w.Body.String())
	}
	if err := s.GrantActive(context.Background(), claims.GrantID, claims.ClientID, claims.Subject, []string{ScopeRead}); err == nil {
		t.Fatal("scope expansion left live grant")
	}
}

func TestCoreFailClosedAndCanonicalRequest(t *testing.T) {
	s, m := coreServer(t)
	p, _ := coreCode(t, s)
	m.fail = true
	if w := coreToken(s, p); w.Code != 503 {
		t.Fatal(w.Code, w.Body.String())
	}
	m.fail = false
	for _, tc := range []struct{ host, header, value string }{{"evil.example.com", "", ""}, {"api.angelos.ashray.xyz:443", "", ""}, {"api.angelos.ashray.xyz", "X-Forwarded-Host", "evil.example.com"}, {"api.angelos.ashray.xyz", "X-Forwarded-Proto", "http"}, {"api.angelos.ashray.xyz", "X-Forwarded-Host", "api.angelos.ashray.xyz,evil.example.com"}} {
		r := httptest.NewRequest("GET", Issuer+MetadataPath, nil)
		r.Host = tc.host
		if tc.header != "" {
			r.Header.Set(tc.header, tc.value)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != 400 {
			t.Fatal("forged proxy/host accepted", tc, w.Code)
		}
	}

	// Vercel adds Forwarded even for legitimate canonical requests. Values from
	// this untrusted header must not change the fixed issuer in OAuth metadata.
	r := httptest.NewRequest("GET", Issuer+MetadataPath, nil)
	r.Header.Set("Forwarded", "for=192.0.2.1;host=evil.example.com;proto=http")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), Issuer) {
		t.Fatal("Forwarded header affected fixed issuer", w.Code, w.Body.String())
	}
}

func TestCoreIssuedAccessInitializesMCPAndListsSixTools(t *testing.T) {
	for _, issuer := range deploymentIssuers {
		t.Run(issuer, func(t *testing.T) { testCoreIssuedAccessAtIssuer(t, issuer) })
	}
}
func testCoreIssuedAccessAtIssuer(t *testing.T, issuer string) {
	config := coreTestConfig(t)
	config.Issuer, config.Resource = issuer, issuer+"/mcp"
	m := newCoreMemoryStore()
	s, err := New(config, m)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := coreCode(t, s)
	w := coreToken(s, p)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	out := coreTokenValues(t, w)
	access := out["access_token"].(string)
	claims := coreClaims(t, access)
	verifier, e := auth.New(auth.Config{Issuer: issuer, ResourceURL: config.Resource, JWKSURL: issuer + JWKSPath, AllowedSubjects: []string{s.config.OwnerSubject}, LocalJWKS: s.JWKS(), CheckGrant: s.GrantActive})
	if e != nil {
		t.Fatal(e)
	}
	application := &app.App{AuthChallenge: verifier.Challenge}
	handler := verifier.Middleware(application.Handler())
	call := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", config.Resource, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+access)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json, text/event-stream")
		r.Header.Set("MCP-Protocol-Version", "2025-11-25")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	if w = call(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"oauth-integration-test","version":"1"}}}`); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	w = call(`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	result := coreTokenValues(t, w)
	if len(result["result"].(map[string]any)["tools"].([]any)) != 6 {
		t.Fatal("MCP tool boundary changed")
	}
	m.fail = true
	w = call(`{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}}`)
	if w.Code != 401 || !strings.Contains(w.Header().Get("WWW-Authenticate"), `resource_metadata="`+issuer+auth.MetadataPath+`"`) {
		t.Fatal("Redis outage did not fail closed", w.Code, w.Header())
	}
	m.fail = false
	if e := m.RevokeGrant(context.Background(), claims.GrantID); e != nil {
		t.Fatal(e)
	}
	if w = call(`{"jsonrpc":"2.0","id":4,"method":"tools/list","params":{}}`); w.Code != 401 {
		t.Fatal("revoked access accepted", w.Code)
	}
}

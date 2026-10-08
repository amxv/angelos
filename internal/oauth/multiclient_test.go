package oauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/amxv/angelos/internal/app"
	"github.com/amxv/angelos/internal/auth"
)

// Claude's hosted callback is documented by Anthropic. This test deliberately
// uses an operator-predefined public client, without DCR or unverified CIMD URLs.
// https://claude.com/docs/connectors/building/authentication#callback-urls
const hostedClaudeCallback = "https://claude.ai/api/mcp/auth_callback"

func multiClientConfig(t *testing.T) Config {
	t.Helper()
	c := coreTestConfig(t)
	c.EnableChatGPTCIMD = true
	c.Clients = []Client{
		{ID: "owner-claude", Name: "Claude", RedirectURIs: []string{hostedClaudeCallback}},
		{ID: "owner-other-assistant", Name: "Other Assistant", RedirectURIs: []string{"https://assistant.example.com/oauth/callback"}},
	}
	c.HTTPClient = &http.Client{Transport: coreRoundTripper(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != ChatGPTClientID {
			t.Fatalf("unexpected metadata network request: %s", r.URL)
		}
		return coreMetadataResponse(coreCIMD), nil
	})}
	return c
}

func multiClientCode(t *testing.T, s *Server, clientID string, scopes []string) url.Values {
	t.Helper()
	client, err := s.resolveClient(context.Background(), clientID)
	if err != nil {
		t.Fatal(err)
	}
	verifier := strings.Repeat("p", 64)
	digest := sha256.Sum256([]byte(verifier))
	a := AuthorizationRequest{ClientID: clientID, ClientName: client.Name, RedirectURI: client.RedirectURIs[0],
		Resource: s.config.Resource, State: "multi-client-state", Challenge: base64.RawURLEncoding.EncodeToString(digest[:]), Scopes: scopes}
	p := url.Values{"client_id": {client.ID}, "redirect_uri": {a.RedirectURI}, "resource": {a.Resource}, "state": {a.State},
		"response_type": {"code"}, "code_challenge": {a.Challenge}, "code_challenge_method": {"S256"}, "scope": {strings.Join(scopes, " ")}}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest("GET", s.config.Issuer+"/oauth/authorize?"+p.Encode(), nil))
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/oauth/login" {
		t.Fatal("public-client authorization did not require owner sign-in", w.Code, w.Header(), w.Body.String())
	}
	// Simulate owner consent through the same trusted boundary exercised by
	// the WebAuthn/browser suite; this is not a live authorization grant.
	redirect, err := s.ApproveAuthorization(context.Background(), a, s.config.OwnerSubject, scopes)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(redirect)
	if err != nil || u.Query().Get("state") != a.State || u.Query().Get("iss") != s.config.Issuer || !strings.HasPrefix(redirect, a.RedirectURI+"?") {
		t.Fatal("invalid consent callback", redirect, err)
	}
	return url.Values{"grant_type": {"authorization_code"}, "client_id": {clientID}, "redirect_uri": {a.RedirectURI}, "resource": {a.Resource}, "code_verifier": {verifier}, "code": {u.Query().Get("code")}}
}

func multiClientTokens(t *testing.T, s *Server, clientID string, scopes []string) map[string]any {
	t.Helper()
	w := coreToken(s, multiClientCode(t, s, clientID, scopes))
	if w.Code != http.StatusOK {
		t.Fatal("public code exchange failed", w.Code, w.Body.String())
	}
	out := coreTokenValues(t, w)
	if out["token_type"] != "Bearer" || out["scope"] != strings.Join(scopes, " ") || out["expires_in"].(float64) <= 0 || out["refresh_token"] == "" {
		t.Fatal("incomplete token response", out)
	}
	return out
}

func multiClientMCP(t *testing.T, s *Server) func(string, string) *httptest.ResponseRecorder {
	t.Helper()
	gate, err := auth.New(auth.Config{Issuer: s.config.Issuer, ResourceURL: s.config.Resource, JWKSURL: s.config.Issuer + JWKSPath,
		AllowedSubjects: []string{s.config.OwnerSubject}, LocalJWKS: s.JWKS(), CheckGrant: s.GrantActive,
		InitialScopes: []string{ScopeRead, ScopeWrite, ScopeSend}})
	if err != nil {
		t.Fatal(err)
	}
	a := &app.App{AuthChallenge: gate.Challenge}
	handler := gate.Middleware(a.Handler())
	return func(access, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, s.config.Resource, strings.NewReader(body))
		if access != "" {
			r.Header.Set("Authorization", "Bearer "+access)
		}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json, text/event-stream")
		r.Header.Set("MCP-Protocol-Version", "2025-11-25")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
}

// Include the browser session CAS operation needed by authorize, alongside the
// core token/grant fixture. No production store is replaced by this test double.
type multiClientMemoryStore struct{ *coreMemoryStore }

func (m *multiClientMemoryStore) CompareAndSwap(_ context.Context, bucket, id string, old, next []byte, _ time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return false, ErrUnavailable
	}
	current, ok := m.state[bucket+id]
	if !ok || !bytes.Equal(current, old) {
		return false, nil
	}
	m.state[bucket+id] = bytes.Clone(next)
	return true, nil
}

func TestMultiplePublicClientsHaveIndependentGrants(t *testing.T) {
	t.Run("memory", func(t *testing.T) { testMultiplePublicClients(t, &multiClientMemoryStore{newCoreMemoryStore()}) })
	t.Run("redis", func(t *testing.T) {
		store, _, _ := oauthRedisFixture(t)
		testMultiplePublicClients(t, store)
	})
}

func testMultiplePublicClients(t *testing.T, store Store) {
	c := multiClientConfig(t)
	if redis, ok := store.(*RedisStore); ok {
		c.OwnerSubject = redis.owner
	}
	s, err := New(c, store)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	full := []string{ScopeRead, ScopeWrite, ScopeSend}
	ids := []string{ChatGPTClientID, c.Clients[0].ID, c.Clients[1].ID}
	tokens := make(map[string]map[string]any)
	for _, id := range ids {
		scopes := full
		if id == ChatGPTClientID {
			scopes = []string{ScopeRead} // Preserve an existing narrower connection.
		}
		tokens[id] = multiClientTokens(t, s, id, scopes)
	}
	grants, err := store.ListGrants(ctx)
	if err != nil || len(grants) != 3 {
		t.Fatal("one client replaced another", len(grants), err)
	}
	call := multiClientMCP(t, s)
	list := `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`
	if w := call("", list); w.Code != 401 || !strings.Contains(w.Header().Get("WWW-Authenticate"), `scope="mail.read mail.write mail.send"`) {
		t.Fatal("full initial consent challenge missing", w.Code, w.Header())
	}
	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Go(func() {
			access := tokens[id]["access_token"].(string)
			if w := call(access, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"multi-client-test","version":"1"}}}`); w.Code != 200 {
				t.Error("initialize failed", id, w.Code)
			}
			w := call(access, list)
			var out struct {
				Result struct {
					Tools []json.RawMessage `json:"tools"`
				} `json:"result"`
			}
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || len(out.Result.Tools) != 6 {
				t.Error("concurrent tools/list failed", id, w.Code, w.Body.String())
			}
		})
	}
	wg.Wait()
	chatClaims := coreClaims(t, tokens[ChatGPTClientID]["access_token"].(string))
	if chatClaims.Scope != ScopeRead || s.GrantActive(ctx, chatClaims.GrantID, chatClaims.ClientID, chatClaims.Subject, full) == nil {
		t.Fatal("connecting a full-permission client elevated an existing read-only grant")
	}
	chatRefresh := url.Values{"grant_type": {"refresh_token"}, "client_id": {ChatGPTClientID}, "resource": {c.Resource}, "refresh_token": {tokens[ChatGPTClientID]["refresh_token"].(string)}}
	if w := coreToken(s, chatRefresh); w.Code != 200 || coreTokenValues(t, w)["scope"] != ScopeRead {
		t.Fatal("refresh changed the existing ChatGPT connection's scopes", w.Code, w.Body.String())
	}
	claude := tokens[c.Clients[0].ID]
	claudeClaims := coreClaims(t, claude["access_token"].(string))
	refresh := url.Values{"grant_type": {"refresh_token"}, "client_id": {ChatGPTClientID}, "resource": {c.Resource}, "refresh_token": {claude["refresh_token"].(string)}}
	if w := coreToken(s, refresh); w.Code != 400 || coreTokenValues(t, w)["error"] != "invalid_grant" {
		t.Fatal("cross-client refresh accepted", w.Code, w.Body.String())
	}
	if err := s.GrantActive(ctx, claudeClaims.GrantID, claudeClaims.ClientID, claudeClaims.Subject, full); err != nil {
		t.Fatal("wrong-client refresh revoked the other client's grant", err)
	}
	refresh.Set("client_id", c.Clients[0].ID)
	w := coreToken(s, refresh)
	if w.Code != 200 {
		t.Fatal("wrong-client refresh consumed legitimate refresh token", w.Code, w.Body.String())
	}
	rotated := coreTokenValues(t, w)
	// Replaying only Claude's spent token revokes that grant, not any other
	// client or another independently approved connection belonging to Claude.
	secondClaude := multiClientTokens(t, s, c.Clients[0].ID, full)
	if w = coreToken(s, refresh); w.Code != 400 {
		t.Fatal("spent refresh accepted", w.Code)
	}
	if w = call(rotated["access_token"].(string), list); w.Code != 401 {
		t.Fatal("replayed grant still authenticates", w.Code)
	}
	for _, token := range []string{tokens[ChatGPTClientID]["access_token"].(string), tokens[c.Clients[1].ID]["access_token"].(string), secondClaude["access_token"].(string)} {
		if w = call(token, list); w.Code != 200 {
			t.Fatal("unrelated grant was revoked", w.Code)
		}
	}
	// Explicit revocation is grant-specific, and a new server sharing the same
	// durable state sees it without changing the issuer, signing key, or owner.
	s, err = New(c, store)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeGrant(ctx, chatClaims.GrantID); err != nil {
		t.Fatal(err)
	}
	call = multiClientMCP(t, s)
	if w = call(tokens[ChatGPTClientID]["access_token"].(string), list); w.Code != 401 {
		t.Fatal("explicitly revoked client still authenticates", w.Code)
	}
	if w = call(secondClaude["access_token"].(string), list); w.Code != 200 {
		t.Fatal("ChatGPT revocation affected Claude", w.Code)
	}
}

func TestPredefinedClaudeClientRejectsCallbackSubstitution(t *testing.T) {
	c := multiClientConfig(t)
	s, err := New(c, newCoreMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	for _, callback := range []string{ChatGPTRedirectURI, hostedClaudeCallback + "/", hostedClaudeCallback + "?extra=1", "https://claude.ai.evil.example/api/mcp/auth_callback", "http://localhost:1234/callback"} {
		p := url.Values{"client_id": {c.Clients[0].ID}, "redirect_uri": {callback}}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest("GET", c.Issuer+"/oauth/authorize?"+p.Encode(), nil))
		if w.Code != 400 || w.Header().Get("Location") != "" {
			t.Fatal("unapproved callback reached browser/redirect", callback, w.Code, w.Header())
		}
	}
	// Each public client keeps the exact redirect configured for it. Adding
	// one must not change ChatGPT's pinned CIMD registration.
	chat, err := s.resolveClient(context.Background(), ChatGPTClientID)
	if err != nil || !reflect.DeepEqual(chat.RedirectURIs, []string{ChatGPTRedirectURI}) {
		t.Fatal("ChatGPT callback changed", chat, err)
	}
}

func TestAuthorizationCodesCannotCrossClients(t *testing.T) {
	for _, id := range []string{ChatGPTClientID, "owner-claude", "owner-other-assistant"} {
		t.Run(id, func(t *testing.T) {
			c := multiClientConfig(t)
			s, err := New(c, &multiClientMemoryStore{newCoreMemoryStore()})
			if err != nil {
				t.Fatal(err)
			}
			p := multiClientCode(t, s, id, []string{ScopeRead})
			other := c.Clients[0]
			if id == other.ID {
				other = c.Clients[1]
			}
			p.Set("client_id", other.ID)
			p.Set("redirect_uri", other.RedirectURIs[0])
			w := coreToken(s, p)
			out := coreTokenValues(t, w)
			if w.Code != 400 || out["error"] != "invalid_grant" || out["access_token"] != nil || out["refresh_token"] != nil {
				t.Fatal("authorization code exchanged by another client", w.Code, out)
			}
		})
	}
}

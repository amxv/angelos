package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// Published document, retrieved from the pinned URL on 2026-11-19. Claude on
// the web, Desktop, mobile, and Cowork share it; it lists a JWT-bearer grant
// Angelos does not offer and a client_uri Angelos never fetches.
const claudeAICIMD = `{"client_id":"https://claude.ai/oauth/mcp-oauth-client-metadata","client_name":"Claude","client_uri":"https://claude.ai","redirect_uris":["https://claude.ai/api/mcp/auth_callback"],"grant_types":["authorization_code","refresh_token","urn:ietf:params:oauth:grant-type:jwt-bearer"],"response_types":["code"],"token_endpoint_auth_method":"none"}`

func claudeAIConfig(t *testing.T, fetched *[]string) Config {
	t.Helper()
	c := coreTestConfig(t)
	c.Clients = nil
	c.EnableClaudeAICIMD = true
	c.HTTPClient = &http.Client{Transport: coreRoundTripper(func(r *http.Request) (*http.Response, error) {
		if fetched != nil {
			*fetched = append(*fetched, r.URL.String())
		}
		if r.URL.String() == ClaudeAIClientID {
			return coreMetadataResponse(claudeAICIMD), nil
		}
		t.Errorf("unpinned metadata request: %s", r.URL)
		return nil, errors.New("unpinned metadata request")
	})}
	return c
}

// claudeAIAuthorize mirrors the authorization request a Claude.ai custom
// connector sends with default settings (no client ID entered).
func claudeAIAuthorize(c Config, challenge string) url.Values {
	return url.Values{"response_type": {"code"}, "client_id": {ClaudeAIClientID}, "redirect_uri": {ClaudeAIRedirectURI}, "code_challenge": {challenge},
		"code_challenge_method": {"S256"}, "state": {"claude-ai-state"}, "scope": {"mail.read mail.write mail.send"}, "resource": {c.Resource}}
}

func TestClaudeAIConnectorCompletesAuthorization(t *testing.T) {
	var fetched []string
	config := claudeAIConfig(t, &fetched)
	h := newBrowserHarnessWithConfig(t, config)
	verifier, _ := browserRandom()
	digest := sha256.Sum256([]byte(verifier))
	response := h.get("/oauth/authorize?" + claudeAIAuthorize(config, b64(digest[:])).Encode())
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Owner sign-in") {
		t.Fatal("Claude.ai authorization did not reach owner sign-in", response.Code, response.Body.String())
	}
	raw, err := h.store.Get(context.Background(), "session", h.cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	var session browserSession
	_ = json.Unmarshal(raw, &session)
	h.enroll()
	response = h.get("/oauth/consent?request=" + session.PendingID)
	for _, text := range []string{ClaudeAIClientID, ClaudeAIRedirectURI} {
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), text) {
			t.Fatalf("consent omitted %q: %d", text, response.Code)
		}
	}
	if strings.Contains(response.Body.String(), "(an app on this device)") {
		t.Fatal("hosted callback labeled as a loopback app")
	}
	if csp := response.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "form-action 'self' https://claude.ai;") {
		t.Fatal("Claude.ai callback origin missing from consent CSP", csp)
	}
	response = h.form("/oauth/consent", url.Values{"request": {session.PendingID}, "decision": {"approve"}, "scope": {"mail.read", "mail.write", "mail.send"}})
	location := response.Header().Get("Location")
	callback, err := url.Parse(location)
	if response.Code != http.StatusSeeOther || err != nil || !strings.HasPrefix(location, ClaudeAIRedirectURI+"?") || callback.Query().Get("iss") != config.Issuer ||
		callback.Query().Get("state") != "claude-ai-state" || callback.Query().Get("code") == "" {
		t.Fatal("authorization did not return to Claude.ai", response.Code, location)
	}
	token := url.Values{"grant_type": {"authorization_code"}, "client_id": {ClaudeAIClientID}, "redirect_uri": {ClaudeAIRedirectURI}, "resource": {config.Resource},
		"code": {callback.Query().Get("code")}, "code_verifier": {verifier}}
	response = h.request("POST", "/oauth/token", token.Encode(), "application/x-www-form-urlencoded", "")
	if response.Code != http.StatusOK || coreTokenValues(t, response)["scope"] != "mail.read mail.write mail.send" {
		t.Fatal("Claude.ai code exchange failed", response.Code, response.Body.String())
	}
	if len(fetched) != 1 || fetched[0] != ClaudeAIClientID {
		t.Fatal("metadata was not fetched exactly once from its pinned URL", fetched)
	}
}

func TestClaudeAITokenLifecycleMatchesConnectorRequests(t *testing.T) {
	s, err := New(claudeAIConfig(t, nil), newCoreMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	scopes := []string{ScopeRead, ScopeWrite, ScopeSend}
	verifier := strings.Repeat("c", 64)
	digest := sha256.Sum256([]byte(verifier))
	a := AuthorizationRequest{ClientID: ClaudeAIClientID, ClientName: "Claude", RedirectURI: ClaudeAIRedirectURI, Resource: s.config.Resource, State: "claude-ai-state", Challenge: b64(digest[:]), Scopes: scopes}
	redirect, err := s.ApproveAuthorization(context.Background(), a, s.config.OwnerSubject, scopes)
	if err != nil || !strings.HasPrefix(redirect, ClaudeAIRedirectURI+"?") {
		t.Fatal("hosted approval failed", redirect, err)
	}
	u, _ := url.Parse(redirect)
	p := url.Values{"grant_type": {"authorization_code"}, "client_id": {ClaudeAIClientID}, "resource": {s.config.Resource}, "code": {u.Query().Get("code")}, "code_verifier": {verifier}}
	for _, wrong := range []string{ClaudeAIRedirectURI + "/", ChatGPTRedirectURI, "http://localhost:6000/callback"} {
		p.Set("redirect_uri", wrong)
		if w := coreToken(s, p); w.Code != http.StatusBadRequest {
			t.Fatal("code redeemed at another callback", wrong, w.Code)
		}
	}
	p.Set("redirect_uri", ClaudeAIRedirectURI)
	w := coreToken(s, p)
	if w.Code != http.StatusOK {
		t.Fatal("code exchange failed", w.Code, w.Body.String())
	}
	refresh := url.Values{"grant_type": {"refresh_token"}, "client_id": {ClaudeAIClientID}, "resource": {s.config.Resource}, "refresh_token": {coreTokenValues(t, w)["refresh_token"].(string)}}
	if w = coreToken(s, refresh); w.Code != http.StatusOK || coreTokenValues(t, w)["scope"] != "mail.read mail.write mail.send" {
		t.Fatal("Claude.ai refresh failed", w.Code, w.Body.String())
	}
	access := coreTokenValues(t, w)["access_token"].(string)
	call := multiClientMCP(t, s)
	list := `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`
	if w := call(access, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"claude-ai","version":"1"}}}`); w.Code != http.StatusOK {
		t.Fatal("Claude.ai initialize failed", w.Code, w.Body.String())
	}
	if w := call(access, list); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"mail_query"`) {
		t.Fatal("Claude.ai tools/list failed", w.Code, w.Body.String())
	}
	refresh.Set("refresh_token", coreTokenValues(t, w)["refresh_token"].(string))
	s.config.EnableClaudeAICIMD = false
	if w = coreToken(s, refresh); w.Code != http.StatusBadRequest {
		t.Fatal("disabled Claude.ai identity refreshed", w.Code)
	}
	if w := call(access, list); w.Code != http.StatusUnauthorized {
		t.Fatal("disabled Claude.ai identity kept MCP access", w.Code)
	}
}

func TestClaudeAIConnectorRejectsSubstitutionAndDisabledSwitch(t *testing.T) {
	var fetched []string
	config := claudeAIConfig(t, &fetched)
	s, err := New(config, newCoreMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(strings.Repeat("v", 64)))
	authorize := func(s *Server, change func(url.Values)) int {
		p := claudeAIAuthorize(config, b64(digest[:]))
		change(p)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest("GET", config.Issuer+"/oauth/authorize?"+p.Encode(), nil))
		if w.Code == http.StatusBadRequest && w.Header().Get("Location") != "" {
			t.Fatal("rejected client redirected", w.Header())
		}
		return w.Code
	}
	for _, redirect := range []string{ClaudeAIRedirectURI + "/", ClaudeAIRedirectURI + "?x=1", "https://claude.ai.evil.example/api/mcp/auth_callback", "http://claude.ai/api/mcp/auth_callback",
		"https://claude.ai/api/mcp/auth_callback2", ChatGPTRedirectURI, "http://localhost:1234/callback", "https://www.claude.ai/api/mcp/auth_callback"} {
		if code := authorize(s, func(p url.Values) { p.Set("redirect_uri", redirect) }); code != http.StatusBadRequest {
			t.Fatal("unpinned Claude.ai callback accepted", redirect, code)
		}
	}
	// Claude Code's loopback identity does not gain the hosted callback, and the
	// hosted identity does not gain loopback callbacks.
	cross := claudeAIConfig(t, nil)
	cross.EnableClaudeCodeCIMD = true
	cross.HTTPClient = &http.Client{Transport: coreRoundTripper(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() == ClaudeCodeClientID {
			return coreMetadataResponse(claudeCodeCIMD), nil
		}
		return coreMetadataResponse(claudeAICIMD), nil
	})}
	both, err := New(cross, &multiClientMemoryStore{newCoreMemoryStore()})
	if err != nil {
		t.Fatal(err)
	}
	if code := authorize(both, func(p url.Values) { p.Set("client_id", ClaudeCodeClientID) }); code != http.StatusBadRequest {
		t.Fatal("Claude Code identity accepted the hosted callback", code)
	}
	if code := authorize(both, func(p url.Values) { p.Set("redirect_uri", "http://localhost:6000/callback") }); code != http.StatusBadRequest {
		t.Fatal("Claude.ai identity accepted a loopback callback", code)
	}
	if code := authorize(both, func(url.Values) {}); code != http.StatusOK {
		t.Fatal("Claude.ai identity rejected alongside Claude Code", code)
	}
	fetched = nil
	off := claudeAIConfig(t, &fetched)
	off.EnableClaudeAICIMD, off.EnableChatGPTCIMD = false, true
	disabled, err := New(off, newCoreMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	if code := authorize(disabled, func(url.Values) {}); code != http.StatusBadRequest || len(fetched) != 0 {
		t.Fatal("disabled Claude.ai identity accepted or fetched", code, fetched)
	}
	predefined := coreTestConfig(t)
	predefined.Clients = []Client{{ID: ClaudeAIClientID, Name: "Claude", RedirectURIs: []string{ClaudeAIRedirectURI}}}
	if _, err := New(predefined, newCoreMemoryStore()); err == nil {
		t.Fatal("pinned Claude.ai ID configured as a predefined client")
	}
}

func TestClaudeAIPinnedDocumentCannotWidenRegistration(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"extra callback", strings.Replace(claudeAICIMD, `"redirect_uris":[`, `"redirect_uris":["https://evil.example.com/callback",`, 1)},
		{"loopback callback", strings.Replace(claudeAICIMD, ClaudeAIRedirectURI, "http://localhost/callback", 1)},
		{"renamed", strings.Replace(claudeAICIMD, `"client_name":"Claude"`, `"client_name":"Claude Code"`, 1)},
		{"other ID", strings.Replace(claudeAICIMD, ClaudeAIClientID, ClaudeCodeClientID, 1)},
		{"confidential", strings.Replace(claudeAICIMD, `"token_endpoint_auth_method":"none"`, `"token_endpoint_auth_method":"private_key_jwt"`, 1)},
		{"missing refresh", strings.Replace(claudeAICIMD, `"refresh_token",`, "", 1)},
		{"Claude Code document", claudeCodeCIMD},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := claudeAIConfig(t, nil)
			c.HTTPClient = &http.Client{Transport: coreRoundTripper(func(*http.Request) (*http.Response, error) { return coreMetadataResponse(tc.body), nil })}
			s, err := New(c, newCoreMemoryStore())
			if err != nil {
				t.Fatal(err)
			}
			if client, err := s.resolveClient(context.Background(), ClaudeAIClientID); err == nil {
				t.Fatal("unsafe metadata accepted", client)
			}
		})
	}
}

func TestClaudeAIConfigurationAndDiscovery(t *testing.T) {
	c := claudeAIConfig(t, nil)
	s, err := New(c, newCoreMemoryStore())
	if err != nil {
		t.Fatal("Claude.ai-only configuration rejected", err)
	}
	if !s.config.metadataClientsEnabled() {
		t.Fatal("Claude.ai switch does not advertise CIMD")
	}
	base := coreTestConfig(t)
	for name, value := range map[string]string{
		"ANGELOS_OAUTH_ENABLED": "1", "MCP_OAUTH_ISSUER": Issuer, "MCP_RESOURCE_URL": Resource, "MCP_OAUTH_JWKS_URL": Issuer + JWKSPath,
		"MCP_ALLOWED_SUBJECTS": base.OwnerSubject, "MAIL_FROM": base.OwnerMailbox, "ANGELOS_OAUTH_SIGNING_KEY_PEM": base.SigningKeyPEM, "ANGELOS_OAUTH_SIGNING_KEY_ID": base.SigningKeyID,
		"ANGELOS_OAUTH_CLIENTS_JSON": "", "ANGELOS_OAUTH_VERIFICATION_KEYS_JSON": "", "ANGELOS_OAUTH_BOOTSTRAP_TOKEN_HASH": "", "ANGELOS_OAUTH_CHATGPT_CIMD_ENABLED": "0",
		"ANGELOS_OAUTH_CLAUDE_CODE_CIMD_ENABLED": "0", "ANGELOS_OAUTH_CODEX_CIMD_ENABLED": "0", "ANGELOS_OAUTH_CLAUDE_AI_CIMD_ENABLED": "1",
	} {
		t.Setenv(name, value)
	}
	got, err := ConfigFromEnv()
	if err != nil || !got.EnableClaudeAICIMD || got.EnableClaudeCodeCIMD || got.EnableChatGPTCIMD || got.EnableCodexCIMD {
		t.Fatal("Claude.ai metadata switch not loaded alone", got.EnableClaudeAICIMD, err)
	}
	t.Setenv("ANGELOS_OAUTH_CLAUDE_AI_CIMD_ENABLED", "true")
	if _, err := ConfigFromEnv(); err == nil {
		t.Fatal("non-1 switch value enabled the Claude.ai identity")
	}
}

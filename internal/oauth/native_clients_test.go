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
	"testing"
)

// Published metadata documents, retrieved from the pinned URLs on 2026-11-15.
const claudeCodeCIMD = `{"client_id":"https://claude.ai/oauth/claude-code-client-metadata","client_name":"Claude Code","client_uri":"https://claude.ai","redirect_uris":["http://localhost/callback","http://127.0.0.1/callback"],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"token_endpoint_auth_method":"none"}`
const codexCIMD = `{"client_id":"https://chatgpt.com/oauth/codex/client.json","client_uri":"https://chatgpt.com/codex","application_type":"native","redirect_uris":["http://127.0.0.1/callback","http://localhost/callback"],"token_endpoint_auth_method":"none","token_endpoint_auth_methods_supported":["none"],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"client_name":"Codex","logo_uri":"https://persistent.oaistatic.com/sonic/misc/openai-logo.png"}`

// These callbacks and parameters mirror the authorization URLs printed by
// Claude Code 2.1.325 and Codex CLI 0.169.0 for a production Angelos server.
var nativeCLICases = []struct {
	name, clientID, redirect, origin string
	wrongRedirects                   []string
	refreshScope                     bool
	disable                          func(*Config)
}{
	{"Claude Code", ClaudeCodeClientID, "http://localhost:60007/callback", "http://localhost:60007",
		[]string{"http://localhost:60008/callback", "http://127.0.0.1:60007/callback", "http://localhost:60007/callback/"}, false,
		func(c *Config) { c.EnableClaudeCodeCIMD = false }},
	{"Codex", CodexClientID, "http://127.0.0.1:57879/callback", "http://127.0.0.1:57879",
		[]string{"http://127.0.0.1:57880/callback", "http://localhost:57879/callback", "http://127.0.0.1:57879/callback?x=1"}, true,
		func(c *Config) { c.EnableCodexCIMD = false }},
}

func nativeCIMDConfig(t *testing.T, fetched *[]string) Config {
	t.Helper()
	c := coreTestConfig(t)
	c.Clients = nil
	c.EnableClaudeCodeCIMD, c.EnableCodexCIMD = true, true
	c.HTTPClient = &http.Client{Transport: coreRoundTripper(func(r *http.Request) (*http.Response, error) {
		if fetched != nil {
			*fetched = append(*fetched, r.URL.String())
		}
		switch r.URL.String() {
		case ClaudeCodeClientID:
			return coreMetadataResponse(claudeCodeCIMD), nil
		case CodexClientID:
			return coreMetadataResponse(codexCIMD), nil
		}
		t.Errorf("unpinned metadata request: %s", r.URL)
		return nil, errors.New("unpinned metadata request")
	})}
	return c
}

func TestLoopbackRedirectMatching(t *testing.T) {
	for _, tc := range []struct{ registered, requested string }{
		{"http://localhost/callback", "http://localhost:60007/callback"},
		{"http://127.0.0.1/callback", "http://127.0.0.1:57879/callback"},
		{"http://127.0.0.1/callback", "http://127.0.0.1/callback"},
		{"http://localhost/callback", "http://localhost:1/callback"},
		{"http://localhost/callback", "http://localhost:65535/callback"},
		{"http://127.0.0.1/oauth/done?fixed=1", "http://127.0.0.1:4321/oauth/done?fixed=1"},
	} {
		if !validLoopbackRedirect(tc.registered) || !loopbackRedirectMatches(tc.registered, tc.requested) || !validCallback(tc.requested) {
			t.Errorf("loopback callback rejected: %s for %s", tc.requested, tc.registered)
		}
	}
	for _, requested := range []string{
		"http://127.0.0.1:8080/callback", "http://localhost:0/callback", "http://localhost:65536/callback", "http://localhost:08080/callback",
		"http://localhost:/callback", "http://localhost:123456/callback", "http://localhost:+80/callback", "http://localhost:8080@evil.example.com/callback",
		"http://localhost.evil.example.com/callback", "http://localhost:8080/callback/", "http://localhost:8080/Callback", "http://localhost:8080/callback?x=1",
		"http://localhost:8080/callback#fragment", "https://localhost:8080/callback", "HTTP://localhost:8080/callback", "http://LOCALHOST:8080/callback",
		"http://localhost:8080/a/../callback", "http://localhost:8080/%63allback", "http://localhost:8080/callback?code=old", "http://user@localhost:8080/callback",
		"http://127.0.0.2:8080/callback", "http://localhost:8080\\@evil.example.com/callback", "http://localhost:8080/call back", "http://evil.example.com/callback", "http://[::1]:8080/callback",
	} {
		if loopbackRedirectMatches("http://localhost/callback", requested) {
			t.Errorf("unsafe loopback callback accepted: %s", requested)
		}
	}
	for _, registered := range []string{"http://localhost:8080/callback", "http://localhost", "http://localhost/callback#x", "http://localhost/callback?state=x", "http://example.com/callback", "http://localhost/../callback", "http://127.1/callback", "http://[::1]/callback", "http://[0:0:0:0:0:0:0:1]/callback", "http://LOCALHOST/callback"} {
		if validLoopbackRedirect(registered) {
			t.Errorf("unsafe registered loopback callback accepted: %s", registered)
		}
	}
}

func TestPredefinedLoopbackClientSupportsFixedCallbackPorts(t *testing.T) {
	c := coreTestConfig(t)
	c.Clients = []Client{{ID: "angelos-claude-code", Name: "Claude Code", RedirectURIs: []string{"http://localhost/callback"}}}
	s, err := New(c, &multiClientMemoryStore{newCoreMemoryStore()})
	if err != nil {
		t.Fatal(err)
	}
	authorize := func(redirect string) *httptest.ResponseRecorder {
		digest := sha256.Sum256([]byte(strings.Repeat("v", 64)))
		p := url.Values{"response_type": {"code"}, "client_id": {"angelos-claude-code"}, "redirect_uri": {redirect}, "state": {"cli-state"}, "scope": {"mail.read"},
			"resource": {c.Resource}, "code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])}, "code_challenge_method": {"S256"}}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest("GET", c.Issuer+"/oauth/authorize?"+p.Encode(), nil))
		return w
	}
	if w := authorize("http://localhost:3118/callback"); w.Code != 200 || !strings.Contains(w.Body.String(), "Owner sign-in") {
		t.Fatal("fixed callback port rejected", w.Code, w.Body.String())
	}
	if w := authorize("http://127.0.0.1:3118/callback"); w.Code != 400 || w.Header().Get("Location") != "" {
		t.Fatal("unregistered loopback host accepted", w.Code, w.Header())
	}
	for _, redirect := range []string{"http://localhost:3118/callback", "http://client.example.com/callback", "http://10.0.0.1/callback"} {
		bad := c
		bad.Clients = []Client{{ID: "local", Name: "Local", RedirectURIs: []string{redirect}}}
		if _, err := New(bad, newCoreMemoryStore()); err == nil {
			t.Errorf("port-bearing or non-loopback HTTP callback registered: %s", redirect)
		}
	}
}

func TestNativeCLIBrowserAuthorizationReturnsToLoopback(t *testing.T) {
	for _, tc := range nativeCLICases {
		t.Run(tc.name, func(t *testing.T) {
			var fetched []string
			config := nativeCIMDConfig(t, &fetched)
			h := newBrowserHarnessWithConfig(t, config)
			verifier, _ := browserRandom()
			digest := sha256.Sum256([]byte(verifier))
			params := url.Values{"response_type": {"code"}, "client_id": {tc.clientID}, "code_challenge": {b64(digest[:])}, "code_challenge_method": {"S256"},
				"redirect_uri": {tc.redirect}, "state": {"cli-state"}, "scope": {"mail.read mail.write mail.send"}, "resource": {config.Resource}}
			response := h.get("/oauth/authorize?" + params.Encode())
			if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Owner sign-in") {
				t.Fatal("CLI authorization did not reach owner sign-in", response.Code, response.Body.String())
			}
			raw, err := h.store.Get(context.Background(), "session", h.cookie.Value)
			if err != nil {
				t.Fatal(err)
			}
			var session browserSession
			_ = json.Unmarshal(raw, &session)
			h.enroll()
			response = h.get("/oauth/consent?request=" + session.PendingID)
			for _, text := range []string{tc.name, tc.clientID, tc.redirect + " (an app on this device)"} {
				if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), text) {
					t.Fatalf("consent omitted %q: %d", text, response.Code)
				}
			}
			if csp := response.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "form-action 'self' "+tc.origin+";") {
				t.Fatal("loopback callback origin missing from consent CSP", csp)
			}
			response = h.form("/oauth/consent", url.Values{"request": {session.PendingID}, "decision": {"approve"}, "scope": {"mail.read", "mail.write", "mail.send"}})
			location := response.Header().Get("Location")
			callback, err := url.Parse(location)
			if response.Code != http.StatusSeeOther || err != nil || !strings.HasPrefix(location, tc.redirect+"?") || callback.Query().Get("iss") != config.Issuer || callback.Query().Get("state") != "cli-state" || callback.Query().Get("code") == "" {
				t.Fatal("authorization did not return to the CLI listener", response.Code, location)
			}
			token := url.Values{"grant_type": {"authorization_code"}, "client_id": {tc.clientID}, "redirect_uri": {tc.redirect}, "resource": {config.Resource}, "code": {callback.Query().Get("code")}, "code_verifier": {verifier}}
			response = h.request("POST", "/oauth/token", token.Encode(), "application/x-www-form-urlencoded", "")
			if response.Code != http.StatusOK || coreTokenValues(t, response)["scope"] != "mail.read mail.write mail.send" {
				t.Fatal("CLI code exchange failed", response.Code, response.Body.String())
			}
			if len(fetched) != 1 || fetched[0] != tc.clientID {
				t.Fatal("metadata was not fetched exactly once from its pinned URL", fetched)
			}
		})
	}
}

func TestNativeCLITokenLifecycleMatchesClientRequests(t *testing.T) {
	for _, tc := range nativeCLICases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := New(nativeCIMDConfig(t, nil), newCoreMemoryStore())
			if err != nil {
				t.Fatal(err)
			}
			scopes := []string{ScopeRead, ScopeWrite, ScopeSend}
			verifier := strings.Repeat("n", 64)
			digest := sha256.Sum256([]byte(verifier))
			a := AuthorizationRequest{ClientID: tc.clientID, ClientName: tc.name, RedirectURI: tc.redirect, Resource: s.config.Resource, State: "cli-state", Challenge: base64.RawURLEncoding.EncodeToString(digest[:]), Scopes: scopes}
			redirect, err := s.ApproveAuthorization(context.Background(), a, s.config.OwnerSubject, scopes)
			if err != nil || !strings.HasPrefix(redirect, tc.redirect+"?") {
				t.Fatal("loopback approval failed", redirect, err)
			}
			u, _ := url.Parse(redirect)
			p := url.Values{"grant_type": {"authorization_code"}, "client_id": {tc.clientID}, "resource": {s.config.Resource}, "code": {u.Query().Get("code")}, "code_verifier": {verifier}}
			// A different listener, host spelling, or path must fail before the
			// one-time code is consumed, so the legitimate exchange still works.
			for _, wrong := range tc.wrongRedirects {
				p.Set("redirect_uri", wrong)
				if w := coreToken(s, p); w.Code != http.StatusBadRequest {
					t.Fatal("code redeemed at another callback", wrong, w.Code)
				}
			}
			p.Set("redirect_uri", tc.redirect)
			w := coreToken(s, p)
			if w.Code != http.StatusOK {
				t.Fatal("code exchange failed", w.Code, w.Body.String())
			}
			// Claude Code refreshes with resource only; Codex (rmcp) repeats granted scopes.
			refresh := url.Values{"grant_type": {"refresh_token"}, "client_id": {tc.clientID}, "resource": {s.config.Resource}, "refresh_token": {coreTokenValues(t, w)["refresh_token"].(string)}}
			if tc.refreshScope {
				refresh.Set("scope", "mail.read mail.write mail.send")
			}
			if w = coreToken(s, refresh); w.Code != http.StatusOK || coreTokenValues(t, w)["scope"] != "mail.read mail.write mail.send" {
				t.Fatal("CLI refresh failed", w.Code, w.Body.String())
			}
			// The refreshed access token initializes and lists tools on /mcp.
			access := coreTokenValues(t, w)["access_token"].(string)
			call := multiClientMCP(t, s)
			list := `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`
			if w := call(access, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"cli","version":"1"}}}`); w.Code != http.StatusOK {
				t.Fatal("CLI initialize failed", w.Code, w.Body.String())
			}
			if w := call(access, list); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"mail_query"`) {
				t.Fatal("CLI tools/list failed", w.Code, w.Body.String())
			}
			refresh.Set("refresh_token", coreTokenValues(t, w)["refresh_token"].(string))
			tc.disable(&s.config)
			if w = coreToken(s, refresh); w.Code != http.StatusBadRequest {
				t.Fatal("disabled CLI identity refreshed", w.Code)
			}
			if w := call(access, list); w.Code != http.StatusUnauthorized {
				t.Fatal("disabled CLI identity kept MCP access", w.Code)
			}
		})
	}
}

func TestNativeCIMDPinsDocumentsAndCallbacks(t *testing.T) {
	var fetched []string
	s, err := New(nativeCIMDConfig(t, &fetched), newCoreMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		for _, id := range []string{ClaudeCodeClientID, CodexClientID} {
			if _, err := s.resolveClient(context.Background(), id); err != nil {
				t.Fatal(id, err)
			}
		}
	}
	if strings.Join(fetched, " ") != ClaudeCodeClientID+" "+CodexClientID {
		t.Fatal("metadata documents not fetched once each from pinned URLs", fetched)
	}
	if _, err := s.resolveClient(context.Background(), ChatGPTClientID); err == nil || len(fetched) != 2 {
		t.Fatal("disabled ChatGPT identity resolved or fetched")
	}
	for _, host := range []string{"claude.ai", "chatgpt.com"} {
		if !metadataHost(host) {
			t.Fatal("pinned metadata host rejected", host)
		}
	}
	for _, host := range []string{"claude.ai.evil.example.com", "evil.example.com", "localhost", "api.claude.ai"} {
		if metadataHost(host) {
			t.Fatal("unpinned metadata host allowed", host)
		}
	}
	narrowed := strings.Replace(claudeCodeCIMD, `,"http://127.0.0.1/callback"`, "", 1)
	for _, tc := range []struct{ name, id, body string }{
		{"extra host", ClaudeCodeClientID, strings.Replace(claudeCodeCIMD, `"redirect_uris":[`, `"redirect_uris":["http://evil.example.com/callback",`, 1)},
		{"fixed port", ClaudeCodeClientID, strings.Replace(claudeCodeCIMD, "http://localhost/callback", "http://localhost:8080/callback", 1)},
		{"other path", ClaudeCodeClientID, strings.Replace(claudeCodeCIMD, "http://127.0.0.1/callback", "http://127.0.0.1/other", 1)},
		{"hosted callback", ClaudeCodeClientID, strings.Replace(claudeCodeCIMD, "http://localhost/callback", "https://evil.example.com/callback", 1)},
		{"renamed", ClaudeCodeClientID, strings.Replace(claudeCodeCIMD, `"Claude Code"`, `"Claude"`, 1)},
		{"confidential", ClaudeCodeClientID, strings.Replace(claudeCodeCIMD, `"token_endpoint_auth_method":"none"`, `"token_endpoint_auth_method":"private_key_jwt"`, 1)},
		{"Codex document at Claude Code ID", ClaudeCodeClientID, codexCIMD},
		{"Claude Code document at Codex ID", CodexClientID, claudeCodeCIMD},
		{"ChatGPT callback", CodexClientID, strings.Replace(codexCIMD, "http://localhost/callback", ChatGPTRedirectURI, 1)},
		{"missing refresh", CodexClientID, strings.Replace(codexCIMD, `,"refresh_token"`, "", 1)},
		{"narrowed", ClaudeCodeClientID, narrowed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := nativeCIMDConfig(t, nil)
			c.HTTPClient = &http.Client{Transport: coreRoundTripper(func(*http.Request) (*http.Response, error) { return coreMetadataResponse(tc.body), nil })}
			s, err := New(c, newCoreMemoryStore())
			if err != nil {
				t.Fatal(err)
			}
			client, err := s.resolveClient(context.Background(), tc.id)
			if tc.body == narrowed {
				// A document may drop a pinned callback; it can never add one.
				if err != nil || !client.allowsRedirect("http://localhost:5/callback") || client.allowsRedirect("http://127.0.0.1:5/callback") {
					t.Fatal("narrowed metadata not honored", client, err)
				}
				return
			}
			if err == nil {
				t.Fatal("unsafe metadata accepted", client)
			}
		})
	}
}

func TestNativeCIMDConfigurationAndDiscovery(t *testing.T) {
	for _, id := range []string{ClaudeCodeClientID, CodexClientID} {
		c := coreTestConfig(t)
		c.Clients = []Client{{ID: id, Name: "Spoof", RedirectURIs: []string{"http://localhost/callback"}}}
		if _, err := New(c, newCoreMemoryStore()); err == nil {
			t.Fatal("pinned metadata ID configured as a predefined client", id)
		}
	}
	advertised := func(c Config) any {
		s, err := New(c, newCoreMemoryStore())
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest("GET", c.Issuer+MetadataPath, nil))
		var metadata map[string]any
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &metadata) != nil {
			t.Fatal("metadata unavailable", w.Code)
		}
		if metadata["authorization_response_iss_parameter_supported"] != true || !strings.Contains(w.Body.String(), `"none"`) {
			t.Fatal("CLI clients require issuer-bound responses and public-client authentication", w.Body.String())
		}
		return metadata["client_id_metadata_document_supported"]
	}
	if got := advertised(coreTestConfig(t)); got != false {
		t.Fatal("CIMD advertised without an enabled metadata identity", got)
	}
	c := coreTestConfig(t)
	c.Clients, c.EnableCodexCIMD = nil, true
	if got := advertised(c); got != true {
		t.Fatal("Codex-only CIMD configuration not advertised", got)
	}
	base := coreTestConfig(t)
	for name, value := range map[string]string{
		"ANGELOS_OAUTH_ENABLED": "1", "MCP_OAUTH_ISSUER": Issuer, "MCP_RESOURCE_URL": Resource, "MCP_OAUTH_JWKS_URL": Issuer + JWKSPath,
		"MCP_ALLOWED_SUBJECTS": base.OwnerSubject, "MAIL_FROM": base.OwnerMailbox, "ANGELOS_OAUTH_SIGNING_KEY_PEM": base.SigningKeyPEM, "ANGELOS_OAUTH_SIGNING_KEY_ID": base.SigningKeyID,
		"ANGELOS_OAUTH_CLIENTS_JSON": "", "ANGELOS_OAUTH_VERIFICATION_KEYS_JSON": "", "ANGELOS_OAUTH_BOOTSTRAP_TOKEN_HASH": "", "ANGELOS_OAUTH_CHATGPT_CIMD_ENABLED": "0",
		"ANGELOS_OAUTH_CLAUDE_CODE_CIMD_ENABLED": "1", "ANGELOS_OAUTH_CODEX_CIMD_ENABLED": "1",
	} {
		t.Setenv(name, value)
	}
	got, err := ConfigFromEnv()
	if err != nil || !got.EnableClaudeCodeCIMD || !got.EnableCodexCIMD || got.EnableChatGPTCIMD {
		t.Fatal("CLI metadata switches not loaded", got.EnableClaudeCodeCIMD, got.EnableCodexCIMD, err)
	}
	t.Setenv("ANGELOS_OAUTH_CLAUDE_CODE_CIMD_ENABLED", "true")
	t.Setenv("ANGELOS_OAUTH_CODEX_CIMD_ENABLED", "")
	if _, err := ConfigFromEnv(); err == nil {
		t.Fatal("non-1 switch values enabled a client")
	}
}

package oauth

import (
	"crypto/sha256"
	"encoding/json"
	"html"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Hosted clients may follow the authorization endpoint's redirects before
// opening the final URL in the user's browser. That browser does not have the
// cookie created in the client's HTTP session. Run the real passkey verifier,
// consent handler and token exchange across this exact handoff.
func TestAuthorizationSurvivesClientPreflightWithoutBrowserCookies(t *testing.T) {
	for _, clientID := range []string{"owner-claude", ChatGPTClientID} {
		t.Run(clientID, func(t *testing.T) {
			for _, bootstrap := range []bool{false, true} {
				t.Run(map[bool]string{false: "login", true: "enrollment"}[bootstrap], func(t *testing.T) {
					testAuthorizationBrowserHandoff(t, clientID, bootstrap)
				})
			}
		})
	}
}
func testAuthorizationBrowserHandoff(t *testing.T, clientID string, bootstrap bool) {
	config := multiClientConfig(t)
	h := newBrowserHarnessWithConfig(t, config)
	authenticator := newVirtualAuthenticator(t)
	if !bootstrap {
		authenticator = h.enroll()
		h.logout()
	}
	h.cookie, h.csrf = nil, ""
	client, err := h.browser.server.resolveClient(t.Context(), clientID)
	if err != nil {
		t.Fatal(err)
	}
	verifier, _ := browserRandom()
	digest := sha256.Sum256([]byte(verifier))
	state := "client state + & = / ? % ☁"
	params := url.Values{"client_id": {client.ID}, "redirect_uri": {client.RedirectURIs[0]}, "response_type": {"code"}, "resource": {config.Resource}, "state": {state}, "scope": {"mail.read mail.write mail.send"}, "code_challenge": {b64(digest[:])}, "code_challenge_method": {"S256"}}
	finalPath := "/oauth/authorize?" + params.Encode()
	response := h.get(finalPath)
	for redirects := 0; response.Code == http.StatusSeeOther; redirects++ {
		if redirects >= 3 {
			t.Fatal("authorization redirect loop")
		}
		finalPath = response.Header().Get("Location")
		response = h.get(finalPath)
	}
	if response.Code != http.StatusOK {
		t.Fatal(response.Code, response.Body.String())
	}
	// A separate browser opens the preflight's final URL without its cookies.
	h.cookie, h.csrf = nil, ""
	response = h.get(finalPath)
	if response.Code != http.StatusOK || response.Header().Get("Location") != "" || finalPath != "/oauth/authorize?"+params.Encode() {
		t.Fatal("authorization entrypoint redirected or failed", response.Code, response.Header(), response.Body.String())
	}
	if len(response.Result().Cookies()) != 1 || !strings.Contains(response.Body.String(), `name="csrf-token" content="`+h.csrf+`"`) {
		t.Fatal("rendered login does not belong to its single browser session")
	}
	if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Referrer-Policy") != "same-origin" || !strings.Contains(response.Header().Get("Content-Security-Policy"), "form-action 'self';") {
		t.Fatal("authorization sign-in page lost browser protections")
	}
	ceremony, challenge := h.begin(bootstrap)
	mode := "login"
	authenticator.counter++
	credential := authenticator.assertion(t, challenge, config.Issuer, config.passkeyRPID(), 0x05)
	if bootstrap {
		mode = "register"
		credential = authenticator.registration(t, challenge, config.Issuer, config.passkeyRPID(), 0x45)
	}
	response = h.post("/oauth/passkeys/"+mode+"/finish", map[string]any{"ceremony": ceremony, "credential": credential})
	var result struct {
		Next string `json:"next"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &result) != nil || !strings.HasPrefix(result.Next, "/oauth/consent?request=") {
		t.Fatalf("authorization was lost during browser handoff: %d %s", response.Code, response.Body.String())
	}
	assertNoAuthorizationIssued(t, h)

	response = h.get(result.Next)
	if response.Code != http.StatusOK || !strings.Contains(html.UnescapeString(response.Body.String()), client.Name) || !strings.Contains(response.Body.String(), client.RedirectURIs[0]) {
		t.Fatal("wrong consent", response.Code, response.Body.String())
	}
	continuation, _ := url.Parse(result.Next)
	response = h.form("/oauth/consent", url.Values{"request": {continuation.Query().Get("request")}, "decision": {"approve"}, "scope": {"mail.read", "mail.send"}})
	callback, err := url.Parse(response.Header().Get("Location"))
	if response.Code != http.StatusSeeOther || err != nil || callback.Scheme+"://"+callback.Host+callback.Path != client.RedirectURIs[0] || callback.Query().Get("state") != state || callback.Query().Get("iss") != config.Issuer || callback.Query().Get("code") == "" {
		t.Fatal("authorization callback changed", response.Code, response.Body.String(), callback, err)
	}
	response = h.request("POST", "/oauth/token", url.Values{"grant_type": {"authorization_code"}, "client_id": {client.ID}, "redirect_uri": {client.RedirectURIs[0]}, "resource": {config.Resource}, "code": {callback.Query().Get("code")}, "code_verifier": {verifier}}.Encode(), "application/x-www-form-urlencoded", "")
	if response.Code != http.StatusOK || coreTokenValues(t, response)["scope"] != "mail.read mail.send" {
		t.Fatal("PKCE exchange lost binding or selected scopes", response.Code, response.Body.String())
	}
}

func assertNoAuthorizationIssued(t *testing.T, h *browserHarness) {
	t.Helper()
	if len(h.store.grants) != 0 {
		t.Fatal("passkey sign-in granted access before consent")
	}
	for key := range h.store.values {
		if strings.HasPrefix(key, "code:") {
			t.Fatal("authorization code issued before consent")
		}
	}
}

func TestAuthorizationInterruptedBrowserSessionCanRestart(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(map[bool]string{false: "lost-cookie", true: "expired-session"}[expired], func(t *testing.T) {
			h := newBrowserHarnessWithConfig(t, multiClientConfig(t))
			a := h.enroll()
			h.logout()
			old, _ := h.authorize("mail.read")
			oldCookie := h.cookie.Value
			if expired {
				h.now = h.now.Add(anonymousLifetime + time.Second)
			} else {
				h.cookie, h.csrf = nil, ""
			}
			current, _ := h.authorize("mail.read mail.send")
			if current == old || h.cookie.Value == oldCookie {
				t.Fatal("authorization restart reused stale browser state")
			}
			// A cancelled WebAuthn prompt can be retried without losing the pending request.
			h.begin(false)
			ceremony, challenge := h.begin(false)
			a.counter++
			response := h.post("/oauth/passkeys/login/finish", map[string]any{"ceremony": ceremony, "credential": a.assertion(t, challenge, h.browser.server.config.Issuer, h.browser.server.config.passkeyRPID(), 0x05)})
			var result struct {
				Next string `json:"next"`
			}
			if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &result) != nil || result.Next != "/oauth/consent?request="+current {
				t.Fatal("passkey retry lost fresh request", response.Code, response.Body.String())
			}
			if response = h.get("/oauth/consent?request=" + old); response.Code != 400 {
				t.Fatal("old session consent transferred to new session")
			}
			if response = h.get(result.Next); response.Code != 200 {
				t.Fatal("fresh consent missing", response.Code, response.Body.String())
			}
			assertNoAuthorizationIssued(t, h)
			response = h.form("/oauth/consent", url.Values{"request": {current}, "decision": {"deny"}})
			callback, _ := url.Parse(response.Header().Get("Location"))
			if response.Code != 303 || callback.Query().Get("error") != "access_denied" || callback.Query().Get("state") != "opaque-client-state" {
				t.Fatal("denial lost original request", response.Code, response.Body.String())
			}
			assertNoAuthorizationIssued(t, h)
		})
	}
}

func TestStandaloneLoginCannotAdoptAuthorizationFromURL(t *testing.T) {
	h := newBrowserHarnessWithConfig(t, multiClientConfig(t))
	a := h.enroll()
	h.logout()
	foreign, _ := h.authorize("mail.read mail.write mail.send")
	h.cookie, h.csrf = nil, ""
	// Bare login is intentionally grant management, not an open redirect or a
	// capability to adopt another browser's pending request.
	response := h.get("/oauth/login?" + url.Values{"request": {foreign}, "next": {"https://attacker.example/"}, "return_to": {"//attacker.example/"}}.Encode())
	if response.Code != 200 || response.Header().Get("Location") != "" {
		t.Fatal("untrusted login return URL used")
	}
	ceremony, challenge := h.begin(false)
	a.counter++
	response = h.post("/oauth/passkeys/login/finish", map[string]any{"ceremony": ceremony, "credential": a.assertion(t, challenge, h.browser.server.config.Issuer, h.browser.server.config.passkeyRPID(), 0x05)})
	var result struct {
		Next string `json:"next"`
	}
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &result) != nil || result.Next != "/oauth/grants" {
		t.Fatal("standalone login adopted an untrusted continuation", response.Code, response.Body.String())
	}
	if response = h.get("/oauth/consent?request=" + foreign); response.Code != 400 {
		t.Fatal("cross-session consent accepted")
	}
	assertNoAuthorizationIssued(t, h)
}

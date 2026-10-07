package oauth

import (
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"testing"
)

// TestBrowserChromiumVirtualAuthenticator is opt-in because Go-only CI need not
// install Chromium/Playwright. It exercises the shipped JS, cookies and CSP with
// a CDP virtual authenticator. It does not contact a production hostname.
func TestBrowserChromiumVirtualAuthenticator(t *testing.T) {
	if os.Getenv("ANGELOS_BROWSER_TEST") != "1" {
		t.Skip("set ANGELOS_BROWSER_TEST=1 with Playwright and Chromium installed")
	}
	h := newBrowserHarness(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Host = passkeyRPID
		h.browser.server.Handler().ServeHTTP(w, r)
	}))
	defer server.Close()
	verifier, _ := browserRandom()
	digest := sha256.Sum256([]byte(verifier))
	c := h.browser.server.config.Clients[0]
	path := "/oauth/authorize?" + url.Values{"client_id": {c.ID}, "redirect_uri": {c.RedirectURIs[0]}, "response_type": {"code"}, "resource": {Resource}, "state": {"browser-js-state"}, "scope": {"mail.read mail.write mail.send"}, "code_challenge": {b64(digest[:])}, "code_challenge_method": {"S256"}}.Encode()
	cmd := exec.Command("node", "testdata/browser-passkeys.cjs")
	cmd.Env = append(os.Environ(), "BROWSER_FIXTURE_URL="+server.URL, "BROWSER_AUTHORIZE_PATH="+path, "BROWSER_BOOTSTRAP="+h.bootstrap)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Chromium contract test: %v\n%s", err, output)
	}
	t.Log(string(output))
}

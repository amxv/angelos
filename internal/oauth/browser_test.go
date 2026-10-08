package oauth

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// browserMemoryStore is a deterministic test double only. Production always uses
// RedisStore; virtual authenticators exercise the real WebAuthn verifier.
type browserMemoryStore struct {
	Store
	mu       sync.Mutex
	values   map[string][]byte
	owner    []byte
	disabled bool
	failed   bool
	limited  bool
	grants   map[string]Grant
}

func newBrowserMemoryStore() *browserMemoryStore {
	return &browserMemoryStore{values: map[string][]byte{}, grants: map[string]Grant{}}
}
func (s *browserMemoryStore) Put(_ context.Context, bucket, id string, data []byte, _ time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed {
		return ErrUnavailable
	}
	key := bucket + ":" + id
	if _, ok := s.values[key]; ok {
		return ErrConflict
	}
	s.values[key] = bytes.Clone(data)
	return nil
}
func (s *browserMemoryStore) Get(_ context.Context, bucket, id string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed {
		return nil, ErrUnavailable
	}
	data, ok := s.values[bucket+":"+id]
	if !ok {
		return nil, ErrNotFound
	}
	return bytes.Clone(data), nil
}
func (s *browserMemoryStore) Consume(_ context.Context, bucket, id string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed {
		return nil, ErrUnavailable
	}
	key := bucket + ":" + id
	data, ok := s.values[key]
	if !ok {
		return nil, ErrNotFound
	}
	delete(s.values, key)
	return bytes.Clone(data), nil
}
func (s *browserMemoryStore) Delete(_ context.Context, bucket, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed {
		return ErrUnavailable
	}
	delete(s.values, bucket+":"+id)
	return nil
}
func (s *browserMemoryStore) CompareAndSwap(_ context.Context, bucket, id string, old, next []byte, _ time.Duration) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed {
		return false, ErrUnavailable
	}
	key := bucket + ":" + id
	current, ok := s.values[key]
	if !ok || !bytes.Equal(current, old) {
		return false, nil
	}
	s.values[key] = bytes.Clone(next)
	return true, nil
}
func (s *browserMemoryStore) LoadOwner(_ context.Context) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed {
		return nil, ErrUnavailable
	}
	if s.owner == nil {
		return nil, ErrNotFound
	}
	return bytes.Clone(s.owner), nil
}
func (s *browserMemoryStore) BootstrapOwner(_ context.Context, data []byte) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed {
		return false, ErrUnavailable
	}
	if s.disabled || s.owner != nil {
		return false, nil
	}
	s.owner = bytes.Clone(data)
	s.disabled = true
	return true, nil
}
func (s *browserMemoryStore) CASOwner(_ context.Context, old, next []byte) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed {
		return false, ErrUnavailable
	}
	if s.owner == nil || !bytes.Equal(s.owner, old) {
		return false, nil
	}
	s.owner = bytes.Clone(next)
	return true, nil
}
func (s *browserMemoryStore) Allow(_ context.Context, _ string, _ int, _ time.Duration) (bool, error) {
	if s.failed {
		return false, ErrUnavailable
	}
	return !s.limited, nil
}
func (s *browserMemoryStore) CreateGrant(_ context.Context, grant Grant) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed {
		return ErrUnavailable
	}
	s.grants[grant.ID] = grant
	return nil
}
func (s *browserMemoryStore) GetGrant(_ context.Context, id string) (Grant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed {
		return Grant{}, ErrUnavailable
	}
	g, ok := s.grants[id]
	if !ok {
		return Grant{}, ErrNotFound
	}
	return g, nil
}
func (s *browserMemoryStore) ListGrants(_ context.Context) ([]Grant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed {
		return nil, ErrUnavailable
	}
	var out []Grant
	for _, g := range s.grants {
		out = append(out, g)
	}
	return out, nil
}
func (s *browserMemoryStore) RevokeGrant(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed {
		return ErrUnavailable
	}
	delete(s.grants, id)
	return nil
}

type browserHarness struct {
	t         *testing.T
	store     *browserMemoryStore
	browser   *Browser
	cookie    *http.Cookie
	csrf      string
	bootstrap string
	now       time.Time
}

func newBrowserHarness(t *testing.T) *browserHarness {
	t.Helper()
	store := newBrowserMemoryStore()
	secret, _ := browserRandom()
	h := &browserHarness{t: t, store: store, bootstrap: secret, now: time.Now().Truncate(time.Second)}
	config := coreTestConfig(t)
	config.BootstrapTokenHash = browserHash(secret)
	server, err := New(config, store)
	if err != nil {
		t.Fatal(err)
	}
	server.now = func() time.Time { return h.now }
	h.browser = server.browser
	h.get("/oauth/login")
	return h
}
func (h *browserHarness) request(method, path, body, typ, origin string) *httptest.ResponseRecorder {
	h.t.Helper()
	r := httptest.NewRequest(method, Issuer+path, strings.NewReader(body))
	if h.cookie != nil {
		r.AddCookie(h.cookie)
	}
	r.Header.Set("Origin", origin)
	r.Header.Set("Content-Type", typ)
	r.Header.Set("X-CSRF-Token", h.csrf)
	w := httptest.NewRecorder()
	h.browser.server.Handler().ServeHTTP(w, r)
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == browserCookie {
			if cookie.MaxAge < 0 {
				h.cookie = nil
				h.csrf = ""
			} else {
				h.cookie = cookie
				raw, err := h.store.Get(context.Background(), "session", cookie.Value)
				if err == nil {
					var session browserSession
					_ = json.Unmarshal(raw, &session)
					h.csrf = session.CSRF
				}
			}
		}
	}
	return w
}
func (h *browserHarness) get(path string) *httptest.ResponseRecorder {
	h.t.Helper()
	return h.request(http.MethodGet, path, "", "", "")
}
func (h *browserHarness) post(path string, body any) *httptest.ResponseRecorder {
	h.t.Helper()
	raw, _ := json.Marshal(body)
	return h.request(http.MethodPost, path, string(raw), "application/json", Issuer)
}
func (h *browserHarness) form(path string, values url.Values) *httptest.ResponseRecorder {
	h.t.Helper()
	values.Set("csrf", h.csrf)
	return h.request(http.MethodPost, path, values.Encode(), "application/x-www-form-urlencoded", Issuer)
}
func (h *browserHarness) begin(register bool) (string, string) {
	h.t.Helper()
	mode := "login"
	body := map[string]string{}
	if register {
		mode = "register"
		body["bootstrap_token"] = h.bootstrap
	}
	response := h.post("/oauth/passkeys/"+mode+"/begin", body)
	if response.Code != 200 {
		h.t.Fatalf("begin %s: %d %s", mode, response.Code, response.Body)
	}
	var result struct {
		Ceremony string `json:"ceremony"`
		Options  struct {
			PublicKey struct {
				Challenge string `json:"challenge"`
			} `json:"publicKey"`
		} `json:"options"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		h.t.Fatal(err)
	}
	if result.Ceremony == "" || result.Options.PublicKey.Challenge == "" {
		h.t.Fatal(response.Body.String())
	}
	return result.Ceremony, result.Options.PublicKey.Challenge
}

type virtualAuthenticator struct {
	key     *ecdsa.PrivateKey
	id      []byte
	counter uint32
}

func newVirtualAuthenticator(t *testing.T) *virtualAuthenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 32)
	_, _ = rand.Read(id)
	return &virtualAuthenticator{key: key, id: id}
}
func b64(data []byte) string { return base64.RawURLEncoding.EncodeToString(data) }
func (a *virtualAuthenticator) registration(t *testing.T, challenge, origin, rp string, flags byte) map[string]any {
	t.Helper()
	cose, err := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: a.key.X.FillBytes(make([]byte, 32)), -3: a.key.Y.FillBytes(make([]byte, 32))})
	if err != nil {
		t.Fatal(err)
	}
	rpHash := sha256.Sum256([]byte(rp))
	authData := append([]byte{}, rpHash[:]...)
	authData = append(authData, flags)
	authData = binary.BigEndian.AppendUint32(authData, a.counter)
	authData = append(authData, make([]byte, 16)...)
	authData = binary.BigEndian.AppendUint16(authData, uint16(len(a.id)))
	authData = append(authData, a.id...)
	authData = append(authData, cose...)
	attestation, err := cbor.Marshal(map[string]any{"fmt": "none", "authData": authData, "attStmt": map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	clientData, _ := json.Marshal(map[string]any{"type": "webauthn.create", "challenge": challenge, "origin": origin, "crossOrigin": false})
	return map[string]any{"id": b64(a.id), "rawId": b64(a.id), "type": "public-key", "clientExtensionResults": map[string]any{}, "response": map[string]any{"clientDataJSON": b64(clientData), "attestationObject": b64(attestation), "transports": []string{"internal"}}}
}
func (a *virtualAuthenticator) assertion(t *testing.T, challenge, origin, rp string, flags byte) map[string]any {
	t.Helper()
	clientData, _ := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": challenge, "origin": origin, "crossOrigin": false})
	clientHash := sha256.Sum256(clientData)
	rpHash := sha256.Sum256([]byte(rp))
	authData := append([]byte{}, rpHash[:]...)
	authData = append(authData, flags)
	authData = binary.BigEndian.AppendUint32(authData, a.counter)
	signed := append(bytes.Clone(authData), clientHash[:]...)
	digest := sha256.Sum256(signed)
	signature, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{"id": b64(a.id), "rawId": b64(a.id), "type": "public-key", "clientExtensionResults": map[string]any{}, "response": map[string]any{"clientDataJSON": b64(clientData), "authenticatorData": b64(authData), "signature": b64(signature)}}
}
func (h *browserHarness) enroll() *virtualAuthenticator {
	h.t.Helper()
	a := newVirtualAuthenticator(h.t)
	id, challenge := h.begin(true)
	response := h.post("/oauth/passkeys/register/finish", map[string]any{"ceremony": id, "credential": a.registration(h.t, challenge, Issuer, passkeyRPID, 0x45)})
	if response.Code != 200 {
		h.t.Fatalf("enroll: %d %s", response.Code, response.Body)
	}
	return a
}
func (h *browserHarness) logout() {
	h.t.Helper()
	response := h.form("/oauth/logout", url.Values{})
	if response.Code != 303 {
		h.t.Fatalf("logout: %d %s", response.Code, response.Body)
	}
	h.get("/oauth/login")
}

func TestVirtualPasskeyEnrollmentLoginAndSecondAuthenticator(t *testing.T) {
	h := newBrowserHarness(t)
	old := h.cookie.Value
	a := h.enroll()
	if h.cookie.Value == old {
		t.Fatal("session not rotated")
	}
	if _, err := h.store.Get(context.Background(), "session", old); !errors.Is(err, ErrNotFound) {
		t.Fatal("old session survived")
	}
	if !h.cookie.Secure || !h.cookie.HttpOnly || h.cookie.SameSite != http.SameSiteLaxMode || h.cookie.Path != "/" || h.cookie.Domain != "" {
		t.Fatal("insecure cookie")
	}
	second := h.enroll()
	if bytes.Equal(a.id, second.id) {
		t.Fatal("fixture duplicate")
	}
	var owner ownerRecord
	_ = json.Unmarshal(h.store.owner, &owner)
	if len(owner.Credentials) != 2 || !h.store.disabled {
		t.Fatal("owner credentials not permanently bound")
	}
	h.logout()
	id, challenge := h.begin(false)
	a.counter = 1
	old = h.cookie.Value
	response := h.post("/oauth/passkeys/login/finish", map[string]any{"ceremony": id, "credential": a.assertion(t, challenge, Issuer, passkeyRPID, 0x05)})
	if response.Code != 200 || h.cookie.Value == old {
		t.Fatalf("login: %d %s", response.Code, response.Body)
	}
	_ = json.Unmarshal(h.store.owner, &owner)
	if owner.Credentials[0].Authenticator.SignCount != 1 {
		t.Fatal("counter not persisted")
	}
	// An independent stateless instance can use the same durable owner and session.
	other, err := NewBrowser(h.browser.server)
	if err != nil {
		t.Fatal(err)
	}
	h.browser = other
	h.browser.server.browser = other
	if response = h.get("/oauth/grants"); response.Code != 200 || !strings.Contains(response.Body.String(), "2 enrolled") {
		t.Fatal(response.Code, response.Body.String())
	}
}
func TestPasskeyRejectsOriginRPIDUVChallengeSignatureAndReplay(t *testing.T) {
	for _, fault := range []string{"origin", "rpid", "uv", "challenge", "signature", "credential-id", "backup-state"} {
		t.Run(fault, func(t *testing.T) {
			h := newBrowserHarness(t)
			a := h.enroll()
			h.logout()
			id, challenge := h.begin(false)
			origin, rp, flags := Issuer, passkeyRPID, byte(0x05)
			a.counter = 1
			switch fault {
			case "origin":
				origin = "https://attacker.example"
			case "rpid":
				rp = "ashray.xyz"
			case "uv":
				flags = 0x01
			case "challenge":
				challenge = b64(bytes.Repeat([]byte{4}, 32))
			case "backup-state":
				flags = 0x15
			}
			credential := a.assertion(t, challenge, origin, rp, flags)
			if fault == "signature" {
				credential["response"].(map[string]any)["signature"] = b64(bytes.Repeat([]byte{1}, 70))
			}
			if fault == "credential-id" {
				credential["id"] = b64([]byte("unknown"))
			}
			body := map[string]any{"ceremony": id, "credential": credential}
			response := h.post("/oauth/passkeys/login/finish", body)
			if response.Code != 400 {
				t.Fatalf("accepted %s: %d %s", fault, response.Code, response.Body)
			}
			response = h.post("/oauth/passkeys/login/finish", body)
			if response.Code != 400 || !strings.Contains(response.Body.String(), "already used") {
				t.Fatal("ceremony was reusable")
			}
		})
	}
}
func TestPasskeyBootstrapAndBindingBoundaries(t *testing.T) {
	h := newBrowserHarness(t)
	if response := h.post("/oauth/passkeys/register/begin", map[string]string{"bootstrap_token": "short"}); response.Code != 403 {
		t.Fatal("weak bootstrap accepted")
	}
	id, challenge := h.begin(true)
	a := newVirtualAuthenticator(t)
	cookie, csrf := h.cookie, h.csrf
	h.cookie = nil
	h.get("/oauth/login")
	if response := h.post("/oauth/passkeys/register/finish", map[string]any{"ceremony": id, "credential": a.registration(t, challenge, Issuer, passkeyRPID, 0x45)}); response.Code != 400 {
		t.Fatal("cross-session enrollment accepted")
	}
	h.cookie, h.csrf = cookie, csrf
	h.enroll()
	h.logout()
	if response := h.post("/oauth/passkeys/register/begin", map[string]string{"bootstrap_token": h.bootstrap}); response.Code != 401 {
		t.Fatal("bootstrap reusable")
	}
	// Even accidental loss of only the owner record must not reopen bootstrap.
	h.store.owner = nil
	id, challenge = h.begin(true)
	if response := h.post("/oauth/passkeys/register/finish", map[string]any{"ceremony": id, "credential": a.registration(t, challenge, Issuer, passkeyRPID, 0x45)}); response.Code != 409 {
		t.Fatal("permanent bootstrap marker ignored")
	}
}
func TestPasskeyCounterRollbackAndRecentAuthentication(t *testing.T) {
	h := newBrowserHarness(t)
	a := h.enroll()
	h.logout()
	id, challenge := h.begin(false)
	a.counter = 10
	if response := h.post("/oauth/passkeys/login/finish", map[string]any{"ceremony": id, "credential": a.assertion(t, challenge, Issuer, passkeyRPID, 0x05)}); response.Code != 200 {
		t.Fatal(response.Body.String())
	}
	h.now = h.now.Add(recentAuthentication + time.Second)
	if response := h.post("/oauth/passkeys/register/begin", map[string]string{}); response.Code != 401 {
		t.Fatal("stale session enrolled authenticator")
	}
	h.logout()
	id, challenge = h.begin(false)
	a.counter = 9
	if response := h.post("/oauth/passkeys/login/finish", map[string]any{"ceremony": id, "credential": a.assertion(t, challenge, Issuer, passkeyRPID, 0x05)}); response.Code != 400 {
		t.Fatal("counter rollback accepted")
	}
}
func TestBrowserCSRFCSPAndFailureBoundaries(t *testing.T) {
	h := newBrowserHarness(t)
	for _, origin := range []string{"", "https://attacker.example", "null", Issuer + "/"} {
		if response := h.request("POST", "/oauth/passkeys/register/begin", `{}`, "application/json", origin); response.Code != 403 {
			t.Fatalf("origin accepted %q", origin)
		}
	}
	csrf := h.csrf
	h.csrf = "wrong"
	if response := h.post("/oauth/passkeys/register/begin", map[string]string{}); response.Code != 403 {
		t.Fatal("bad CSRF accepted")
	}
	h.csrf = csrf
	if response := h.request("POST", "/oauth/passkeys/register/begin", `{"bootstrap_token":"a","bootstrap_token":"b"}`, "application/json", Issuer); response.Code != 400 {
		t.Fatal("duplicate JSON accepted")
	}
	if response := h.request("POST", "/oauth/passkeys/register/begin", strings.Repeat("x", (64<<10)+1), "application/json", Issuer); response.Code != 413 {
		t.Fatal("oversized request accepted")
	}
	response := h.get("/oauth/login")
	csp := response.Header().Get("Content-Security-Policy")
	if strings.Contains(csp, "unsafe-inline") || !strings.Contains(csp, "frame-ancestors 'none'") || response.Header().Get("Referrer-Policy") != "same-origin" || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("browser protections missing")
	}
	// Only rendered HTML forms relax the referrer policy to same-origin. The
	// general OAuth endpoints, errors and assets must not disclose referrers.
	if got := h.get("/oauth/assets/app.js").Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Fatal("asset referrer policy changed", got)
	}
	if strings.Contains(response.Body.String(), "<script>") || !strings.Contains(response.Body.String(), "/oauth/assets/app.js") {
		t.Fatal("inline script")
	}
	h.store.limited = true
	if h.get("/oauth/login").Code != 429 {
		t.Fatal("rate limit ignored")
	}
	h.store.limited = false
	h.store.failed = true
	if h.get("/oauth/login").Code != 503 {
		t.Fatal("Redis failure not closed")
	}
}
func TestBrowserSessionIdleAbsoluteExpiryAndLogout(t *testing.T) {
	h := newBrowserHarness(t)
	h.enroll()
	original := h.now
	h.now = h.now.Add(sessionIdle - time.Second)
	if h.get("/oauth/grants").Code != 200 {
		t.Fatal("early idle expiry")
	}
	h.now = h.now.Add(sessionIdle)
	if h.get("/oauth/grants").Code != 401 {
		t.Fatal("idle expiry ignored")
	}
	h = newBrowserHarness(t)
	h.enroll()
	original = h.now
	for h.now.Before(original.Add(sessionLifetime - time.Minute)) {
		h.now = h.now.Add(20 * time.Minute)
		if h.now.Before(original.Add(sessionLifetime)) {
			if h.get("/oauth/grants").Code != 200 {
				t.Fatal("active session expired early")
			}
		}
	}
	h.now = original.Add(sessionLifetime)
	if h.get("/oauth/grants").Code != 401 {
		t.Fatal("absolute expiry ignored")
	}
	h = newBrowserHarness(t)
	h.enroll()
	token := h.cookie.Value
	h.logout()
	if _, err := h.store.Get(context.Background(), "session", token); !errors.Is(err, ErrNotFound) {
		t.Fatal("logout did not revoke")
	}
}

func (s *browserMemoryStore) CreateRefresh(ctx context.Context, token string, ref Refresh) error {
	raw, _ := json.Marshal(ref)
	return s.Put(ctx, "refresh", token, raw, time.Hour)
}

func (h *browserHarness) authorize(scopes string) (string, string) {
	h.t.Helper()
	verifier, _ := browserRandom()
	digest := sha256.Sum256([]byte(verifier))
	c := h.browser.server.config.Clients[0]
	params := url.Values{"client_id": {c.ID}, "redirect_uri": {c.RedirectURIs[0]}, "response_type": {"code"}, "resource": {Resource}, "state": {"opaque-client-state"}, "scope": {scopes}, "code_challenge": {b64(digest[:])}, "code_challenge_method": {"S256"}}
	response := h.get("/oauth/authorize?" + params.Encode())
	if response.Code != 303 {
		h.t.Fatalf("authorize: %d %s", response.Code, response.Body)
	}
	raw, err := h.store.Get(context.Background(), "session", h.cookie.Value)
	if err != nil {
		h.t.Fatal(err)
	}
	var session browserSession
	_ = json.Unmarshal(raw, &session)
	return session.PendingID, verifier
}
func TestBrowserFullAuthorizationPasskeyConsentCodeExchangeAndRevoke(t *testing.T) {
	h := newBrowserHarness(t)
	id, verifier := h.authorize("mail.read mail.write mail.send")
	h.enroll() // Initial bootstrap also completes real UV registration then rotates the owner session.
	response := h.get("/oauth/consent?request=" + id)
	if response.Code != 200 {
		t.Fatal(response.Code, response.Body.String())
	}
	if got := response.Header().Get("Referrer-Policy"); got != "same-origin" {
		t.Fatal("native consent form must use same-origin referrer policy", got)
	}
	for _, text := range []string{"Test Client", "test@example.com", "mail.write", "mail.send", "permanently delete", "cannot be undone", "https://client.example.com/callback"} {
		if !strings.Contains(response.Body.String(), text) {
			t.Fatalf("consent omitted %q", text)
		}
	}
	csp := response.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "form-action 'self' https://client.example.com") || strings.Contains(csp, "form-action *") {
		t.Fatal("callback redirect blocked or CSP too broad", csp)
	}
	response = h.form("/oauth/consent", url.Values{"request": {id}, "decision": {"approve"}, "scope": {"mail.read", "mail.send"}})
	if response.Code != 303 {
		t.Fatal(response.Code, response.Body.String())
	}
	callback, err := url.Parse(response.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if callback.Host != "client.example.com" || callback.Query().Get("iss") != Issuer || callback.Query().Get("state") != "opaque-client-state" || callback.Query().Get("code") == "" {
		t.Fatal("invalid issuer/state/callback", callback)
	}
	c := h.browser.server.config.Clients[0]
	params := url.Values{"grant_type": {"authorization_code"}, "client_id": {c.ID}, "resource": {Resource}, "redirect_uri": {c.RedirectURIs[0]}, "code": {callback.Query().Get("code")}, "code_verifier": {verifier}}
	// OAuth backchannel token requests deliberately do not require browser cookies or CSRF.
	response = h.request("POST", "/oauth/token", params.Encode(), "application/x-www-form-urlencoded", "")
	if response.Code != 200 {
		t.Fatal(response.Code, response.Body.String())
	}
	var result struct {
		Access  string `json:"access_token"`
		Refresh string `json:"refresh_token"`
		Scope   string `json:"scope"`
	}
	_ = json.Unmarshal(response.Body.Bytes(), &result)
	if result.Access == "" || result.Refresh == "" || result.Scope != "mail.read mail.send" {
		t.Fatal("incorrect approved permissions")
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.Split(result.Access, ".")[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims accessClaims
	_ = json.Unmarshal(payload, &claims)
	if claims.Scope != "mail.read mail.send" || claims.Subject != h.browser.server.config.OwnerSubject || claims.Audience != Resource || claims.Issuer != Issuer {
		t.Fatal("wrong access claims")
	}
	if response = h.form("/oauth/consent", url.Values{"request": {id}, "decision": {"approve"}, "scope": {"mail.read"}}); response.Code != 400 {
		t.Fatal("consent was reusable")
	}
	if response = h.get("/oauth/grants"); response.Code != 200 || !strings.Contains(response.Body.String(), "mail.read, mail.send") {
		t.Fatal("grant missing")
	}
	if got := response.Header().Get("Referrer-Policy"); got != "same-origin" {
		t.Fatal("native grant/revoke form must use same-origin referrer policy", got)
	}
	if response = h.form("/oauth/grants", url.Values{"grant": {claims.GrantID}}); response.Code != 303 {
		t.Fatal(response.Code, response.Body.String())
	}
	if err = h.browser.server.GrantActive(context.Background(), claims.GrantID, c.ID, claims.Subject, []string{"mail.read"}); !errors.Is(err, ErrNotFound) {
		t.Fatal("revoked access still active")
	}
}
func TestBrowserConsentDenialExpansionSupersessionAndExpiry(t *testing.T) {
	h := newBrowserHarness(t)
	h.enroll()
	id, _ := h.authorize("mail.read")
	if response := h.form("/oauth/consent", url.Values{"request": {id}, "decision": {"approve"}, "scope": {"mail.read", "mail.write"}}); response.Code != 400 {
		t.Fatal("scope expansion accepted")
	}
	if len(h.store.grants) != 0 {
		t.Fatal("invalid consent created grant")
	}
	response := h.form("/oauth/consent", url.Values{"request": {id}, "decision": {"deny"}})
	callback, _ := url.Parse(response.Header().Get("Location"))
	if response.Code != 303 || callback.Query().Get("error") != "access_denied" || callback.Query().Get("iss") != Issuer || len(h.store.grants) != 0 {
		t.Fatal("invalid denial", response.Code, response.Body.String())
	}
	old, _ := h.authorize("mail.read")
	current, _ := h.authorize("mail.read mail.send")
	if h.get("/oauth/consent?request="+old).Code != 400 {
		t.Fatal("superseded request accepted")
	}
	if h.get("/oauth/consent?request="+current).Code != 200 {
		t.Fatal("current request rejected")
	}
	h.now = h.now.Add(consentLifetime)
	if h.get("/oauth/consent?request="+current).Code != 400 {
		t.Fatal("expired consent accepted")
	}
}
func TestVirtualRegistrationRequiresUVAndExactRelyingParty(t *testing.T) {
	for _, fault := range []string{"origin", "rpid", "uv", "challenge"} {
		t.Run(fault, func(t *testing.T) {
			h := newBrowserHarness(t)
			id, challenge := h.begin(true)
			a := newVirtualAuthenticator(t)
			origin, rp, flags := Issuer, passkeyRPID, byte(0x45)
			switch fault {
			case "origin":
				origin = "https://attacker.example"
			case "rpid":
				rp = "ashray.xyz"
			case "uv":
				flags = 0x41
			case "challenge":
				challenge = b64(bytes.Repeat([]byte{8}, 32))
			}
			response := h.post("/oauth/passkeys/register/finish", map[string]any{"ceremony": id, "credential": a.registration(t, challenge, origin, rp, flags)})
			if response.Code != 400 || h.store.owner != nil || h.store.disabled {
				t.Fatalf("bad registration accepted: %d %s", response.Code, response.Body)
			}
		})
	}
}

func TestPasskeyExpiredCeremonyAndLoginCSPRemainClosed(t *testing.T) {
	h := newBrowserHarness(t)
	id, challenge := h.begin(true)
	a := newVirtualAuthenticator(t)
	h.now = h.now.Add(ceremonyLifetime)
	response := h.post("/oauth/passkeys/register/finish", map[string]any{"ceremony": id, "credential": a.registration(t, challenge, Issuer, passkeyRPID, 0x45)})
	if response.Code != 400 || h.store.owner != nil {
		t.Fatal("expired ceremony accepted")
	}
	csp := h.get("/oauth/login").Header().Get("Content-Security-Policy")
	if strings.Contains(csp, "client.example.com") || !strings.Contains(csp, "form-action 'self';") {
		t.Fatal("consent exception leaked to login policy")
	}
	for _, headers := range []http.Header{{"Origin": {"null"}}, {"Origin": {Issuer, Issuer}}, {"Origin": {Issuer}, "Sec-Fetch-Site": {"same-origin", "cross-site"}}, {"Origin": {Issuer}, "Sec-Fetch-Site": {"cross-site"}}} {
		r := httptest.NewRequest("POST", Issuer+"/oauth/logout", nil)
		r.Header = headers
		if browserOrigin(r) {
			t.Fatal("ambiguous/cross-site origin accepted")
		}
	}
	for _, headers := range []http.Header{{"Origin": {Issuer}}, {"Origin": {Issuer}, "Sec-Fetch-Site": {"same-origin"}}} {
		r := httptest.NewRequest("POST", Issuer+"/oauth/logout", nil)
		r.Header = headers
		if !browserOrigin(r) {
			t.Fatal("legitimate same-origin browser submission rejected")
		}
	}
}

// Opt-in, synthetic-only visual fixtures let us inspect all three private
// browser pages in a real browser without logging in to the production mailbox.
// Serve the output directory over a temporary localhost HTTP server.
func TestExportOAuthVisualFixtures(t *testing.T) {
	dir := os.Getenv("ANGELOS_OAUTH_VISUAL_FIXTURES")
	if dir == "" {
		t.Skip("set ANGELOS_OAUTH_VISUAL_FIXTURES to export synthetic HTML/CSS for visual QA")
	}
	assets := filepath.Join(dir, "oauth", "assets")
	if err := os.MkdirAll(assets, 0700); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{"app.css": browserCSS, "app.js": browserJS} {
		if err := os.WriteFile(filepath.Join(assets, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	h := newBrowserHarness(t)
	write := func(name string, response *httptest.ResponseRecorder) {
		t.Helper()
		if response.Code != 200 {
			t.Fatalf("%s: HTTP %d", name, response.Code)
		}
		if err := os.WriteFile(filepath.Join(dir, name+".html"), response.Body.Bytes(), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("login", h.get("/oauth/login"))
	h.enroll()
	write("signin", h.get("/oauth/login"))
	id, _ := h.authorize("mail.read mail.write mail.send")
	write("consent", h.get("/oauth/consent?request="+id))
	response := h.form("/oauth/consent", url.Values{"request": {id}, "decision": {"approve"}, "scope": {"mail.read", "mail.write", "mail.send"}})
	if response.Code != http.StatusSeeOther {
		t.Fatal("synthetic consent failed", response.Code)
	}
	write("grants", h.get("/oauth/grants"))
}

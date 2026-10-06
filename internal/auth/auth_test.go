package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return fn(r) }

var testRSAOnce sync.Once
var testRSA *rsa.PrivateKey
var testRSAErr error

func rsaKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	testRSAOnce.Do(func() { testRSA, testRSAErr = rsa.GenerateKey(rand.Reader, 2048) })
	if testRSAErr != nil {
		t.Fatal(testRSAErr)
	}
	return testRSA
}

func publicRSA(k *rsa.PrivateKey, kid string) map[string]any {
	return map[string]any{"kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig", "n": rawBase64.EncodeToString(k.N.Bytes()), "e": rawBase64.EncodeToString(big.NewInt(int64(k.E)).Bytes())}
}

func publicEC(k *ecdsa.PrivateKey, kid string) map[string]any {
	return map[string]any{"kty": "EC", "kid": kid, "alg": "ES256", "use": "sig", "crv": "P-256", "x": rawBase64.EncodeToString(k.X.FillBytes(make([]byte, 32))), "y": rawBase64.EncodeToString(k.Y.FillBytes(make([]byte, 32)))}
}

func jsonBytes(t *testing.T, value any) []byte {
	t.Helper()
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type fixture struct {
	a *Authenticator
	now time.Time
	body string
	status int
	requests atomic.Int32
	key *rsa.PrivateKey
}

func testConfig() Config {
	return Config{ResourceURL: "https://mail.example.com/mcp", Issuer: "https://login.example.com/", JWKSURL: "https://login.example.com/.well-known/jwks.json", AllowedSubjects: []string{"owner-123"}}
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{now: time.Unix(1800000000, 0), status: http.StatusOK, key: rsaKey(t)}
	f.body = string(jsonBytes(t, map[string]any{"keys": []any{publicRSA(f.key, "key-1")}}))
	c := testConfig()
	c.HTTPClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		f.requests.Add(1)
		if r.URL.String() != c.JWKSURL || r.Method != http.MethodGet {
			t.Errorf("unexpected outbound request: %s %s", r.Method, r.URL)
		}
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Error("bearer credentials leaked to JWKS fetch")
		}
		if _, ok := r.Context().Deadline(); !ok {
			t.Error("JWKS request lacks deadline")
		}
		return &http.Response{StatusCode: f.status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(f.body)), Request: r}, nil
	})}
	var err error
	f.a, err = New(c)
	if err != nil {
		t.Fatal(err)
	}
	f.a.now = func() time.Time { return f.now }
	return f
}

func (f *fixture) claims() map[string]any {
	return map[string]any{"iss": f.a.config.Issuer, "aud": f.a.config.ResourceURL, "sub": "owner-123", "exp": f.now.Add(time.Hour).Unix(), "iat": f.now.Add(-time.Minute).Unix(), "nbf": f.now.Unix(), "scope": ScopeRead + " " + ScopeWrite + " " + ScopeSend}
}

func rsaToken(t *testing.T, key *rsa.PrivateKey, header, claims any) string {
	t.Helper()
	return rsaTokenRaw(t, key, jsonBytes(t, header), jsonBytes(t, claims))
}

func rsaTokenRaw(t *testing.T, key *rsa.PrivateKey, header, claims []byte) string {
	t.Helper()
	payload := rawBase64.EncodeToString(header) + "." + rawBase64.EncodeToString(claims)
	digest := sha256.Sum256([]byte(payload))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return payload + "." + rawBase64.EncodeToString(sig)
}

func tokenHeader() map[string]any { return map[string]any{"alg": "RS256", "kid": "key-1", "typ": "at+jwt"} }

func call(a *Authenticator, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "https://mail.example.com/mcp", nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(w, r)
	return w
}

func TestValidRSAAndPrincipal(t *testing.T) {
	f := newFixture(t)
	token := rsaToken(t, f.key, tokenHeader(), f.claims())
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	r.Header.Set("Authorization", "bEaReR   "+token)
	w := httptest.NewRecorder()
	called := false
	f.a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		p, ok := PrincipalFromContext(r.Context())
		if !ok || p.Subject != "owner-123" || len(p.Scopes) != 3 {
			t.Fatalf("unexpected principal: %#v, %v", p, ok)
		}
		p.Scopes[0] = "attacker.scope"
		if !HasScope(r.Context(), ScopeRead) || HasScope(r.Context(), "attacker.scope") || RequireScope(r.Context(), ScopeSend) != nil {
			t.Fatal("principal mutation changed stored scopes")
		}
		if !errors.Is(RequireScope(r.Context(), "admin"), ErrInsufficientScope) {
			t.Fatal("unknown scope allowed")
		}
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(w, r)
	if !called || w.Code != http.StatusNoContent || f.requests.Load() != 1 {
		t.Fatalf("status=%d called=%v fetches=%d", w.Code, called, f.requests.Load())
	}
	if HasScope(context.Background(), ScopeRead) {
		t.Fatal("anonymous context has a scope")
	}
	if _, ok := PrincipalFromContext(context.Background()); ok {
		t.Fatal("anonymous context has a principal")
	}
}

func TestValidES256(t *testing.T) {
	f := newFixture(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.body = string(jsonBytes(t, map[string]any{"keys": []any{publicEC(key, "ec-1")}}))
	header := map[string]any{"alg": "ES256", "kid": "ec-1", "typ": "JWT"}
	payload := rawBase64.EncodeToString(jsonBytes(t, header)) + "." + rawBase64.EncodeToString(jsonBytes(t, f.claims()))
	digest := sha256.Sum256([]byte(payload))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	token := payload + "." + rawBase64.EncodeToString(sig)
	if got := call(f.a, token).Code; got != http.StatusNoContent {
		t.Fatalf("valid ES256: status %d", got)
	}
	for _, bad := range [][]byte{sig[:63], make([]byte, 64), append(sig, 0)} {
		if got := call(f.a, payload+"."+rawBase64.EncodeToString(bad)).Code; got != http.StatusUnauthorized {
			t.Fatalf("invalid ES256 accepted: status %d", got)
		}
	}
}

func TestClaimsValidation(t *testing.T) {
	tests := []struct {
		name string
		change func(map[string]any, *fixture)
		status int
	}{
		{"audience array", func(c map[string]any, f *fixture) { c["aud"] = []string{"other", f.a.config.ResourceURL} }, 204},
		{"missing typ irrelevant to claims", func(c map[string]any, f *fixture) { delete(c, "iat"); delete(c, "nbf") }, 204},
		{"case aliases do not override", func(c map[string]any, f *fixture) { c["ISS"] = "attacker"; c["AUD"] = "attacker"; c["SUB"] = "attacker" }, 204},
		{"wrong issuer", func(c map[string]any, f *fixture) { c["iss"] = "https://attacker.example.com/" }, 401},
		{"issuer trailing slash exact", func(c map[string]any, f *fixture) { c["iss"] = strings.TrimSuffix(f.a.config.Issuer, "/") }, 401},
		{"missing issuer", func(c map[string]any, f *fixture) { delete(c, "iss"); c["ISS"] = f.a.config.Issuer }, 401},
		{"wrong audience", func(c map[string]any, f *fixture) { c["aud"] = "https://mail.example.com/other" }, 401},
		{"missing audience", func(c map[string]any, f *fixture) { delete(c, "aud") }, 401},
		{"mixed audience types", func(c map[string]any, f *fixture) { c["aud"] = []any{f.a.config.ResourceURL, 2} }, 401},
		{"null audience entry", func(c map[string]any, f *fixture) { c["aud"] = []any{f.a.config.ResourceURL, nil} }, 401},
		{"empty audience entry", func(c map[string]any, f *fixture) { c["aud"] = []string{f.a.config.ResourceURL, ""} }, 401},
		{"wrong subject", func(c map[string]any, f *fixture) { c["sub"] = "another-user" }, 401},
		{"missing subject", func(c map[string]any, f *fixture) { delete(c, "sub") }, 401},
		{"expired", func(c map[string]any, f *fixture) { c["exp"] = f.now.Unix() - 1 }, 401},
		{"expires now", func(c map[string]any, f *fixture) { c["exp"] = f.now.Unix() }, 401},
		{"missing expiration", func(c map[string]any, f *fixture) { delete(c, "exp") }, 401},
		{"string expiration", func(c map[string]any, f *fixture) { c["exp"] = "9999999999" }, 401},
		{"fractional expiration", func(c map[string]any, f *fixture) { c["exp"] = 9999999999.5 }, 401},
		{"null expiration", func(c map[string]any, f *fixture) { c["exp"] = nil }, 401},
		{"future not before", func(c map[string]any, f *fixture) { c["nbf"] = f.now.Unix() + 1 }, 401},
		{"future issued at", func(c map[string]any, f *fixture) { c["iat"] = f.now.Unix() + 1 }, 401},
		{"negative issued at", func(c map[string]any, f *fixture) { c["iat"] = -1 }, 401},
		{"null not before", func(c map[string]any, f *fixture) { c["nbf"] = nil }, 401},
		{"id token use", func(c map[string]any, f *fixture) { c["token_use"] = "id" }, 401},
		{"access token use", func(c map[string]any, f *fixture) { c["token_use"] = "access" }, 204},
		{"missing scope", func(c map[string]any, f *fixture) { delete(c, "scope") }, 403},
		{"empty scope", func(c map[string]any, f *fixture) { c["scope"] = "" }, 403},
		{"wrong scope", func(c map[string]any, f *fixture) { c["scope"] = "mail.reader mail.send" }, 403},
		{"scope array rejected", func(c map[string]any, f *fixture) { c["scope"] = []string{ScopeRead} }, 401},
		{"scope control rejected", func(c map[string]any, f *fixture) { c["scope"] = "mail.read\tmail.send" }, 401},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newFixture(t)
			claims := f.claims()
			test.change(claims, f)
			w := call(f.a, rsaToken(t, f.key, tokenHeader(), claims))
			if w.Code != test.status {
				t.Fatalf("status %d; want %d", w.Code, test.status)
			}
			if w.Code == 403 && !strings.Contains(w.Header().Get("WWW-Authenticate"), `error="insufficient_scope"`) {
				t.Fatal("missing insufficient-scope challenge")
			}
		})
	}
}

func TestHeaderAndSignatureValidation(t *testing.T) {
	for _, test := range []struct { name string; change func(map[string]any) }{
		{"none", func(h map[string]any) { h["alg"] = "none" }},
		{"HS confusion", func(h map[string]any) { h["alg"] = "HS256" }},
		{"unsupported RSA", func(h map[string]any) { h["alg"] = "RS512" }},
		{"key type confusion", func(h map[string]any) { h["alg"] = "ES256" }},
		{"missing algorithm", func(h map[string]any) { delete(h, "alg") }},
		{"case-sensitive algorithm", func(h map[string]any) { delete(h, "alg"); h["ALG"] = "RS256" }},
		{"missing kid", func(h map[string]any) { delete(h, "kid") }},
		{"unknown kid", func(h map[string]any) { h["kid"] = "attacker" }},
		{"oversized kid", func(h map[string]any) { h["kid"] = strings.Repeat("x", 257) }},
		{"unexpected type", func(h map[string]any) { h["typ"] = "id_token" }},
		{"critical extensions", func(h map[string]any) { h["crit"] = []string{} }},
		{"detached encoding", func(h map[string]any) { h["b64"] = true }},
		{"remote JWK URL", func(h map[string]any) { h["jku"] = "https://127.0.0.1/private" }},
		{"remote certificate URL", func(h map[string]any) { h["x5u"] = "https://attacker.example.com/keys" }},
		{"embedded JWK", func(h map[string]any) { h["jwk"] = map[string]any{} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newFixture(t)
			header := tokenHeader()
			test.change(header)
			if got := call(f.a, rsaToken(t, f.key, header, f.claims())).Code; got != 401 {
				t.Fatalf("status %d; want 401", got)
			}
		})
	}
	f := newFixture(t)
	token := rsaToken(t, f.key, tokenHeader(), f.claims())
	parts := strings.Split(token, ".")
	sig, _ := rawBase64.DecodeString(parts[2])
	sig[0] ^= 1
	badSignature := parts[0] + "." + parts[1] + "." + rawBase64.EncodeToString(sig)
	for _, invalid := range []string{badSignature, "static-secret", "a.b.c", token + ".suffix", token + "=", token + "\n", strings.Repeat("x", maxTokenBytes+1)} {
		if got := call(f.a, invalid).Code; got != 401 {
			t.Fatalf("malformed token status %d", got)
		}
	}
}

func TestDuplicateJSONIsRejected(t *testing.T) {
	f := newFixture(t)
	header := jsonBytes(t, tokenHeader())
	claims := jsonBytes(t, f.claims())
	dupHeader := []byte(`{"alg":"none","alg":"RS256","kid":"key-1"}`)
	dupClaims := append(append([]byte(nil), claims[:len(claims)-1]...), []byte(`,"sub":"owner-123"}`)...)
	for _, token := range []string{rsaTokenRaw(t, f.key, dupHeader, claims), rsaTokenRaw(t, f.key, header, dupClaims)} {
		if got := call(f.a, token).Code; got != 401 {
			t.Fatalf("duplicate JSON accepted: %d", got)
		}
	}
	if f.requests.Load() != 0 {
		t.Fatal("invalid JSON caused a network fetch")
	}
}

func TestMiddlewareRejectsAlternateCredentials(t *testing.T) {
	f := newFixture(t)
	token := rsaToken(t, f.key, tokenHeader(), f.claims())
	for _, test := range []struct { name, url string; headers []string; cookie string }{
		{name: "absent", url: "/mcp"},
		{name: "query", url: "/mcp?access_token=" + token},
		{name: "query plus header", url: "/mcp?access_token=x", headers: []string{"Bearer " + token}},
		{name: "cookie", url: "/mcp", cookie: "access_token=" + token},
		{name: "duplicate headers", url: "/mcp", headers: []string{"Bearer " + token, "Bearer " + token}},
		{name: "basic", url: "/mcp", headers: []string{"Basic " + token}},
		{name: "tab separator", url: "/mcp", headers: []string{"Bearer\t" + token}},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, test.url, strings.NewReader("access_token="+token))
			for _, h := range test.headers { r.Header.Add("Authorization", h) }
			r.Header.Set("Cookie", test.cookie)
			w := httptest.NewRecorder()
			f.a.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("unauthorized handler called") })).ServeHTTP(w, r)
			if w.Code != 401 || !strings.Contains(w.Header().Get("WWW-Authenticate"), f.a.MetadataURL()) || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("incorrect denial: %#v", w.Result())
			}
			if strings.Contains(w.Body.String(), token) || strings.Contains(w.Body.String(), "owner-123") {
				t.Fatal("authentication response leaked private detail")
			}
		})
	}
}

func TestMetadataAndChallenge(t *testing.T) {
	f := newFixture(t)
	r := httptest.NewRequest(http.MethodGet, "https://attacker.example.com"+MetadataPath, nil)
	r.Header.Set("X-Forwarded-Host", "attacker.example.com")
	w := httptest.NewRecorder()
	f.a.MetadataHandler().ServeHTTP(w, r)
	var metadata struct {
		Resource string `json:"resource"`
		AuthorizationServers []string `json:"authorization_servers"`
		Scopes []string `json:"scopes_supported"`
		Methods []string `json:"bearer_methods_supported"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &metadata); err != nil { t.Fatal(err) }
	if w.Code != 200 || metadata.Resource != f.a.config.ResourceURL || len(metadata.AuthorizationServers) != 1 || metadata.AuthorizationServers[0] != f.a.config.Issuer || len(metadata.Scopes) != 3 || len(metadata.Methods) != 1 || metadata.Methods[0] != "header" {
		t.Fatalf("wrong metadata: %#v", metadata)
	}
	if f.a.MetadataURL() != "https://mail.example.com"+MetadataPath || strings.Contains(f.a.Challenge("\"\r\nInjected: x"), "Injected") {
		t.Fatal("untrusted challenge URL or scope")
	}
	for _, scope := range []string{ScopeRead, ScopeWrite, ScopeSend} {
		wanted := scope
		if scope != ScopeRead { wanted = ScopeRead + " " + scope }
		if !strings.Contains(f.a.Challenge(scope), `scope="`+wanted+`"`) { t.Fatal("challenge lost scope") }
	}
	for _, method := range []string{http.MethodHead, http.MethodPost} {
		w := httptest.NewRecorder()
		f.a.MetadataHandler().ServeHTTP(w, httptest.NewRequest(method, MetadataPath, nil))
		if method == http.MethodHead && (w.Code != 200 || w.Body.Len() != 0) { t.Fatal("incorrect HEAD response") }
		if method == http.MethodPost && (w.Code != 405 || w.Header().Get("Allow") != "GET, HEAD") { t.Fatal("incorrect method rejection") }
	}
	if f.requests.Load() != 0 { t.Fatal("public metadata fetched signing keys") }
}

func TestKeyCacheRotationAndThrottling(t *testing.T) {
	f := newFixture(t)
	token := rsaToken(t, f.key, tokenHeader(), f.claims())
	for i := 0; i < 4; i++ {
		if got := call(f.a, token).Code; got != 204 { t.Fatalf("valid cached token: %d", got) }
	}
	header := tokenHeader()
	header["kid"] = "rotated"
	rotated := rsaToken(t, f.key, header, f.claims())
	for i := 0; i < 8; i++ {
		if got := call(f.a, rotated).Code; got != 401 { t.Fatalf("unknown kid accepted: %d", got) }
	}
	if f.requests.Load() != 1 { t.Fatalf("unknown kids caused %d fetches", f.requests.Load()) }
	f.now = f.now.Add(keyRefreshInterval)
	f.body = string(jsonBytes(t, map[string]any{"keys": []any{publicRSA(f.key, "rotated")}}))
	if got := call(f.a, rotated).Code; got != 204 { t.Fatalf("rotated key not loaded: %d", got) }
	if got := call(f.a, token).Code; got != 401 { t.Fatalf("removed key still accepted: %d", got) }
	if f.requests.Load() != 2 { t.Fatalf("rotation made %d fetches", f.requests.Load()) }
	f.now = f.now.Add(keyCacheTTL)
	f.status = http.StatusServiceUnavailable
	if got := call(f.a, rotated).Code; got != 401 { t.Fatalf("stale key accepted on error: %d", got) }
	if got := call(f.a, rotated).Code; got != 401 { t.Fatalf("stale key accepted on retry: %d", got) }
	if f.requests.Load() != 3 { t.Fatal("failed refresh was not throttled") }
}

func TestConcurrentRequestsCoalesceJWKS(t *testing.T) {
	f := newFixture(t)
	token := rsaToken(t, f.key, tokenHeader(), f.claims())
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if got := call(f.a, token).Code; got != 204 { t.Errorf("concurrent request: %d", got) }
		}()
	}
	wg.Wait()
	if f.requests.Load() != 1 { t.Fatalf("concurrent requests made %d fetches", f.requests.Load()) }
}

func TestExpirationRecheckedAfterFetch(t *testing.T) {
	f := newFixture(t)
	claims := f.claims()
	claims["exp"] = f.now.Add(time.Second).Unix()
	token := rsaToken(t, f.key, tokenHeader(), claims)
	original := f.a.client.Transport
	f.a.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		f.now = f.now.Add(2 * time.Second)
		return original.RoundTrip(r)
	})
	if got := call(f.a, token).Code; got != 401 { t.Fatalf("token expired during fetch accepted: %d", got) }
}

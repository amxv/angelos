package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// Records exactly which durable identities are allowed to create counters.
// State operations still use the existing deterministic browser/core stores.
type quotaStore struct {
	Store
	mu     sync.Mutex
	counts map[string]int
	fail   string
}

func newQuotaStore(store Store) *quotaStore {
	return &quotaStore{Store: store, counts: map[string]int{}}
}
func (q *quotaStore) Allow(_ context.Context, bucket string, limit int, _ time.Duration) (bool, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.fail == bucket {
		return false, ErrUnavailable
	}
	if q.counts[bucket] >= limit {
		return false, nil
	}
	q.counts[bucket]++
	return true, nil
}

func TestAnonymousFloodCannotBlockExistingLoginConsentOrRevocation(t *testing.T) {
	h := newBrowserHarness(t)
	authenticator := h.enroll()
	h.logout() // A separate, valid anonymous session is now ready for sign-in.
	q := newQuotaStore(h.store)
	h.browser.server.store = q
	// Simulate anonymous requests from arbitrarily spoofed proxies/cookies.
	// No attacker-controlled value may cause an independent Redis rate key.
	for i := 0; i < 240; i++ {
		r := httptest.NewRequest("GET", h.browser.server.config.Issuer+"/oauth/login", nil)
		r.Header.Set("Forwarded", fmt.Sprintf("for=192.0.2.%d", i))
		r.Header.Set("X-Forwarded-For", fmt.Sprintf("203.0.113.%d", i))
		r.AddCookie(&http.Cookie{Name: browserCookie, Value: strings.Repeat("x", 42) + "A"})
		w := httptest.NewRecorder()
		h.browser.server.Handler().ServeHTTP(w, r)
		want := 200
		if i >= anonymousSessionLimit {
			want = 429
		}
		if w.Code != want {
			t.Fatalf("anonymous request %d: %d, want %d", i, w.Code, want)
		}
	}
	if len(q.counts) != 1 || q.counts["browser:new-session"] != anonymousSessionLimit {
		t.Fatalf("untrusted input created rate identities: %v", q.counts)
	}
	if w := h.get("/oauth/login"); w.Code != 200 {
		t.Fatalf("existing sign-in blocked: %d %s", w.Code, w.Body.String())
	}
	id, challenge := h.begin(false)
	authenticator.counter++
	w := h.post("/oauth/passkeys/login/finish", map[string]any{"ceremony": id, "credential": authenticator.assertion(t, challenge, h.browser.server.config.Issuer, h.browser.server.config.passkeyRPID(), 0x05)})
	if w.Code != 200 {
		t.Fatalf("passkey sign-in blocked: %d %s", w.Code, w.Body.String())
	}
	pending, _ := h.authorize(ScopeRead)
	if w = h.get("/oauth/consent?request=" + pending); w.Code != 200 {
		t.Fatalf("consent blocked: %d %s", w.Code, w.Body.String())
	}
	w = h.form("/oauth/consent", url.Values{"request": {pending}, "decision": {"approve"}, "scope": {ScopeRead}})
	if w.Code != 303 {
		t.Fatalf("approval blocked: %d %s", w.Code, w.Body.String())
	}
	var grantID string
	for id := range h.store.grants {
		grantID = id
	}
	if grantID == "" {
		t.Fatal("no approved grant")
	}
	if w = h.form("/oauth/grants", url.Values{"grant": {grantID}}); w.Code != 303 {
		t.Fatalf("revocation blocked: %d %s", w.Code, w.Body.String())
	}
	if _, err := h.store.GetGrant(context.Background(), grantID); !errors.Is(err, ErrNotFound) {
		t.Fatal("grant survived revocation", err)
	}
}

func TestPasskeyAndAuthorizationBudgetsAreSessionBound(t *testing.T) {
	h := newBrowserHarness(t)
	h.enroll()
	h.logout()
	q := newQuotaStore(h.store)
	h.browser.server.store = q
	otherToken, otherSession, err := h.browser.newSession(context.Background(), "", "")
	if err != nil {
		t.Fatal(err)
	}
	attacker := &browserHarness{t: t, store: h.store, browser: h.browser, cookie: &http.Cookie{Name: browserCookie, Value: otherToken}, csrf: otherSession.CSRF}
	for i := 0; i < 20; i++ {
		attacker.begin(false)
	}
	if w := attacker.post("/oauth/passkeys/login/begin", map[string]string{}); w.Code != 429 {
		t.Fatal("per-session ceremony limit not enforced", w.Code)
	}
	h.begin(false) // The attacker's valid anonymous session cannot debit this one.
	q.counts["browser:authorize:"+otherToken] = authorizationSessionLimit
	id, _ := h.authorize(ScopeRead)
	if id == "" {
		t.Fatal("separate authorization did not proceed")
	}
}

func TestUnknownBrowserRequestsDoNotAllocateRateCounters(t *testing.T) {
	h := newBrowserHarness(t)
	q := newQuotaStore(h.store)
	h.browser.server.store = q
	for i := 0; i < 300; i++ {
		for _, path := range []string{"/oauth/unknown", "/oauth/grants"} {
			r := httptest.NewRequest("GET", h.browser.server.config.Issuer+path, nil)
			token, _ := browserRandom()
			r.AddCookie(&http.Cookie{Name: browserCookie, Value: token})
			w := httptest.NewRecorder()
			h.browser.server.Handler().ServeHTTP(w, r)
			if w.Code != 401 && w.Code != 404 {
				t.Fatalf("unexpected anonymous response: %d", w.Code)
			}
		}
	}
	if len(q.counts) != 0 {
		t.Fatal("unknown cookies/paths allocated rate counters", q.counts)
	}
}

func TestCodeProofPrecedesQuotaAndConsumption(t *testing.T) {
	s, state := coreServer(t)
	p, codeToken := coreCode(t, s)
	q := newQuotaStore(state)
	s.store = q
	bad, _ := url.ParseQuery(p.Encode())
	bad.Set("code_verifier", strings.Repeat("w", 64))
	var wg sync.WaitGroup
	for range 180 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if w := coreToken(s, bad); w.Code != 400 {
				t.Errorf("bad proof: %d", w.Code)
			}
		}()
	}
	wg.Wait()
	if len(q.counts) != 0 {
		t.Fatal("unproven code charged a quota", q.counts)
	}
	if _, err := state.Get(context.Background(), "code", codeToken); err != nil {
		t.Fatal("invalid verifier burned code", err)
	}
	if w := coreToken(s, p); w.Code != 200 {
		t.Fatalf("valid exchange blocked after flood: %d %s", w.Code, w.Body.String())
	}
	if len(q.counts) != 1 {
		t.Fatal("valid exchange did not use exactly its grant quota", q.counts)
	}
}

func TestCodeRateDenialAndFailureDoNotConsumeCode(t *testing.T) {
	for _, unavailable := range []bool{false, true} {
		t.Run(fmt.Sprint(unavailable), func(t *testing.T) {
			s, state := coreServer(t)
			p, token := coreCode(t, s)
			raw, _ := state.Get(context.Background(), "code", token)
			var code AuthorizationCode
			_ = json.Unmarshal(raw, &code)
			q := newQuotaStore(state)
			s.store = q
			bucket := tokenRateBucket(code.GrantID)
			q.counts[bucket] = tokenGrantLimit
			want := 429
			if unavailable {
				q.fail = bucket
				want = 503
			}
			if w := coreToken(s, p); w.Code != want {
				t.Fatal(w.Code, w.Body.String())
			}
			if _, err := state.Get(context.Background(), "code", token); err != nil {
				t.Fatal("quota denial burned code", err)
			}
			q.fail = ""
			q.counts[bucket] = 0
			if w := coreToken(s, p); w.Code != 200 {
				t.Fatal("code not usable after quota recovery", w.Code)
			}
		})
	}
}

func TestTokenGuessesDoNotAllocateQuotaKeysOrFetchMetadata(t *testing.T) {
	var fetches int
	s := coreCIMDServer(t, func(*http.Request) (*http.Response, error) {
		fetches++
		return nil, errors.New("metadata unavailable")
	})
	q := newQuotaStore(s.store)
	s.store = q
	for range 180 {
		token, _ := opaqueToken()
		p := url.Values{"grant_type": {"authorization_code"}, "client_id": {ChatGPTClientID}, "resource": {s.config.Resource}, "redirect_uri": {ChatGPTRedirectURI}, "code": {token}, "code_verifier": {strings.Repeat("v", 64)}}
		if w := coreToken(s, p); w.Code != 400 {
			t.Fatal(w.Code, w.Body.String())
		}
		p = url.Values{"grant_type": {"refresh_token"}, "client_id": {ChatGPTClientID}, "resource": {s.config.Resource}, "refresh_token": {token}}
		if w := coreToken(s, p); w.Code != 400 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	if fetches != 0 || len(q.counts) != 0 {
		t.Fatalf("guesses performed outbound/counter writes: fetches=%d keys=%v", fetches, q.counts)
	}
}

func TestExistingCIMDGrantSurvivesMetadataOutageButNotDisabledClient(t *testing.T) {
	var fetches int
	s := coreCIMDServer(t, func(*http.Request) (*http.Response, error) {
		fetches++
		return coreMetadataResponse(coreCIMD), nil
	})
	a, verifier := coreAuthorization(s)
	a.ClientID, a.ClientName, a.RedirectURI = ChatGPTClientID, "ChatGPT", ChatGPTRedirectURI
	redirect, err := s.ApproveAuthorization(context.Background(), a, s.config.OwnerSubject, a.Scopes)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(redirect)
	p := url.Values{"grant_type": {"authorization_code"}, "client_id": {a.ClientID}, "resource": {s.config.Resource}, "redirect_uri": {a.RedirectURI}, "code": {u.Query().Get("code")}, "code_verifier": {verifier}}
	s.clientCacheUntil = time.Time{}
	s.clientHTTP.Transport = coreRoundTripper(func(*http.Request) (*http.Response, error) {
		t.Error("token flow fetched metadata")
		return nil, ErrUnavailable
	})
	s.config.EnableChatGPTCIMD = false
	if w := coreToken(s, p); w.Code != 400 {
		t.Fatal("disabled client code accepted", w.Code)
	}
	s.config.EnableChatGPTCIMD = true
	w := coreToken(s, p)
	if w.Code != 200 {
		t.Fatal("bound grant depended on metadata", w.Code, w.Body.String())
	}
	result := coreTokenValues(t, w)
	claims := coreClaims(t, result["access_token"].(string))
	otherParams, _ := coreCode(t, s)
	otherResponse := coreToken(s, otherParams)
	if otherResponse.Code != 200 {
		t.Fatal("predefined client blocked", otherResponse.Code)
	}
	otherClaims := coreClaims(t, coreTokenValues(t, otherResponse)["access_token"].(string))
	p = url.Values{"grant_type": {"refresh_token"}, "client_id": {a.ClientID}, "resource": {s.config.Resource}, "refresh_token": {result["refresh_token"].(string)}}
	s.config.EnableChatGPTCIMD = false
	if err := s.GrantActive(context.Background(), claims.GrantID, claims.ClientID, claims.Subject, a.Scopes); !errors.Is(err, ErrNotFound) {
		t.Fatal("disabled client retained existing access", err)
	}
	if err := s.GrantActive(context.Background(), otherClaims.GrantID, otherClaims.ClientID, otherClaims.Subject, a.Scopes); err != nil {
		t.Fatal("disabling metadata client blocked another grant", err)
	}
	if w = coreToken(s, p); w.Code != 400 {
		t.Fatal("disabled client refresh accepted", w.Code)
	}
	s.config.EnableChatGPTCIMD = true
	if w = coreToken(s, p); w.Code != 200 {
		t.Fatal("refresh failed after reenable", w.Code, w.Body.String())
	}
	if fetches != 1 {
		t.Fatal("unexpected metadata fetch count", fetches)
	}
}

func TestGrantQuotasAreIndependentForSamePublicClient(t *testing.T) {
	s, state := coreServer(t)
	first, firstToken := coreCode(t, s)
	second, _ := coreCode(t, s)
	q := newQuotaStore(state)
	s.store = q
	raw, _ := state.Get(context.Background(), "code", firstToken)
	var record AuthorizationCode
	_ = json.Unmarshal(raw, &record)
	q.counts[tokenRateBucket(record.GrantID)] = tokenGrantLimit
	if w := coreToken(s, first); w.Code != 429 || w.Header().Get("Retry-After") != "60" {
		t.Fatal("exhausted grant accepted", w.Code)
	}
	if w := coreToken(s, second); w.Code != 200 {
		t.Fatal("one grant blocked another client's grant", w.Code, w.Body.String())
	}
}

func TestCIMDCachedMetadataDoesNotSpendFetchBudget(t *testing.T) {
	var fetches int
	s := coreCIMDServer(t, func(*http.Request) (*http.Response, error) {
		fetches++
		return coreMetadataResponse(coreCIMD), nil
	})
	q := newQuotaStore(s.store)
	s.store = q
	if _, err := s.resolveClient(context.Background(), ChatGPTClientID); err != nil {
		t.Fatal(err)
	}
	q.counts["client-metadata:fetch"] = 12
	for range 200 {
		if _, err := s.resolveClient(context.Background(), ChatGPTClientID); err != nil {
			t.Fatal("cached client blocked by fetch quota", err)
		}
	}
	s.clientCacheUntil = time.Time{}
	if _, err := s.resolveClient(context.Background(), ChatGPTClientID); !errors.Is(err, ErrRateLimited) {
		t.Fatal("unbounded outbound metadata fetch", err)
	}
	if fetches != 1 {
		t.Fatal("unexpected outbound request", fetches)
	}
}

func TestRemovingPredefinedClientDeniesCodeRefreshAndExistingAccess(t *testing.T) {
	s, _ := coreServer(t)
	issued, _ := coreCode(t, s)
	w := coreToken(s, issued)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	result := coreTokenValues(t, w)
	claims := coreClaims(t, result["access_token"].(string))
	unspentCode, _ := coreCode(t, s)
	refresh := url.Values{"grant_type": {"refresh_token"}, "client_id": {claims.ClientID}, "resource": {s.config.Resource}, "refresh_token": {result["refresh_token"].(string)}}
	configured := s.config.Clients
	s.config.Clients = nil
	for _, p := range []url.Values{unspentCode, refresh} {
		if w := coreToken(s, p); w.Code != 400 || coreTokenValues(t, w)["error"] != "invalid_client" {
			t.Fatal("removed client retained token endpoint access", w.Code)
		}
	}
	if err := s.GrantActive(context.Background(), claims.GrantID, claims.ClientID, claims.Subject, []string{ScopeRead}); !errors.Is(err, ErrNotFound) {
		t.Fatal("removed client retained existing access", err)
	}
	// Disabling is not implicit consent revocation. Re-adding a still-valid
	// client restores its unrevoked grant; owners can explicitly revoke it.
	s.config.Clients = configured
	if w := coreToken(s, refresh); w.Code != 200 {
		t.Fatal("disabled-client rejection consumed refresh", w.Code)
	}
}

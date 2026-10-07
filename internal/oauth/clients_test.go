package oauth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type coreRoundTripper func(*http.Request) (*http.Response, error)

func (f coreRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

const coreCIMD = `{"client_id":"https://chatgpt.com/oauth/client.json","client_name":"ChatGPT","client_uri":"https://chatgpt.com/","redirect_uris":["https://chatgpt.com/connector_platform_oauth_redirect"],"token_endpoint_auth_method":"private_key_jwt","token_endpoint_auth_methods_supported":["none","private_key_jwt"],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"jwks_uri":"https://chatgpt.com/oauth/jwks.json"}`

func coreCIMDServer(t *testing.T, roundTrip coreRoundTripper) *Server {
	t.Helper()
	c := coreTestConfig(t)
	c.EnableChatGPTCIMD = true
	c.HTTPClient = &http.Client{Transport: roundTrip}
	s, e := New(c, newCoreMemoryStore())
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func coreMetadataResponse(body string) *http.Response {
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}, "Cache-Control": {"max-age=60"}}, Body: io.NopCloser(strings.NewReader(body))}
}

func TestCoreCIMDPluralMethodsCacheAndExactIdentity(t *testing.T) {
	var calls atomic.Int32
	s := coreCIMDServer(t, func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		if r.URL.String() != ChatGPTClientID || r.Method != "GET" || r.Header.Get("Authorization") != "" {
			t.Fatal("unsafe metadata request", r.URL)
		}
		return coreMetadataResponse(coreCIMD), nil
	})
	client, e := s.resolveClient(context.Background(), ChatGPTClientID)
	if e != nil || client.ID != ChatGPTClientID || !client.allowsRedirect(ChatGPTRedirectURI) {
		t.Fatal(client, e)
	}
	if _, e := s.resolveClient(context.Background(), ChatGPTClientID); e != nil || calls.Load() != 1 {
		t.Fatal("metadata not cached", calls.Load(), e)
	}
	for _, id := range []string{"https://evil.example.com/client.json", "https://chatgpt.com/oauth/client.json?url=evil", "https://chatgpt.com./oauth/client.json", "https://127.0.0.1/client.json", "https://chatgpt.com/oauth/custom/client.json"} {
		if _, e := s.resolveClient(context.Background(), id); e == nil {
			t.Fatal("unapproved metadata ID", id)
		}
	}
	if calls.Load() != 1 {
		t.Fatal("unapproved ID caused network request")
	}
	if client.allowsRedirect(ChatGPTRedirectURI + "/other") {
		t.Fatal("callback prefix accepted")
	}
}

func TestCoreCIMDRejectsUnsafeMetadata(t *testing.T) {
	for _, tc := range []struct {
		name   string
		body   string
		status int
		media  string
	}{
		{"mismatched ID", strings.Replace(coreCIMD, ChatGPTClientID, "https://evil.example.com/client.json", 1), 200, "application/json"},
		{"missing name", strings.Replace(coreCIMD, `"client_name":"ChatGPT",`, "", 1), 200, "application/json"},
		{"renamed client", strings.Replace(coreCIMD, `"ChatGPT"`, `"Forged"`, 1), 200, "application/json"},
		{"extra callback", strings.Replace(coreCIMD, `"redirect_uris":[`, `"redirect_uris":["https://evil.example.com/callback",`, 1), 200, "application/json"},
		{"callback substitution", strings.Replace(coreCIMD, ChatGPTRedirectURI, ChatGPTRedirectURI+"/other", 1), 200, "application/json"},
		{"private only", strings.Replace(coreCIMD, `["none","private_key_jwt"]`, `["private_key_jwt"]`, 1), 200, "application/json"},
		{"duplicate ID", strings.Replace(coreCIMD, `"client_id":`, `"client_id":"https://evil.example.com", "client_id":`, 1), 200, "application/json"},
		{"case alias", strings.Replace(coreCIMD, `"client_id":`, `"CLIENT_ID":"https://evil.example.com", "client_id":`, 1), 200, "application/json"},
		{"uppercase ID", strings.Replace(coreCIMD, `"client_id":`, `"CLIENT_ID":`, 1), 200, "application/json"},
		{"uppercase auth methods", strings.Replace(coreCIMD, `"token_endpoint_auth_methods_supported":`, `"TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED":`, 1), 200, "application/json"},
		{"Unicode auth methods", strings.Replace(coreCIMD, `"token_endpoint_auth_methods_supported":`, `"token_endpoint_auth_methodſ_supported":`, 1), 200, "application/json"},
		{"missing refresh", strings.Replace(coreCIMD, `,"refresh_token"`, "", 1), 200, "application/json"},
		{"too big", coreCIMD + strings.Repeat(" ", 32768), 200, "application/json"},
		{"HTML", coreCIMD, 200, "text/html"},
		{"server error", coreCIMD, 503, "application/json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := coreCIMDServer(t, func(*http.Request) (*http.Response, error) {
				res := coreMetadataResponse(tc.body)
				res.StatusCode = tc.status
				res.Header.Set("Content-Type", tc.media)
				return res, nil
			})
			if _, e := s.resolveClient(context.Background(), ChatGPTClientID); e == nil {
				t.Fatal("unsafe metadata accepted")
			}
		})
	}
}

func TestCoreCIMDFailureBackoffNoStaleReuse(t *testing.T) {
	var calls int
	fail := true
	now := time.Now()
	s := coreCIMDServer(t, func(*http.Request) (*http.Response, error) {
		calls++
		if fail {
			return nil, errors.New("network failed")
		}
		return coreMetadataResponse(coreCIMD), nil
	})
	s.now = func() time.Time { return now }
	for range 10 {
		if _, e := s.resolveClient(context.Background(), ChatGPTClientID); e == nil {
			t.Fatal("failure accepted")
		}
	}
	if calls != 1 {
		t.Fatal("failure created unbounded fetches", calls)
	}
	now = now.Add(6 * time.Second)
	fail = false
	if _, e := s.resolveClient(context.Background(), ChatGPTClientID); e != nil {
		t.Fatal(e)
	}
	now = now.Add(61 * time.Second)
	fail = true
	if _, e := s.resolveClient(context.Background(), ChatGPTClientID); e == nil {
		t.Fatal("stale metadata allowed")
	}
	if calls != 3 {
		t.Fatal("unexpected fetch count", calls)
	}
}

func TestCoreCIMDNoStoreAndRedirectDenial(t *testing.T) {
	var calls int
	s := coreCIMDServer(t, func(*http.Request) (*http.Response, error) {
		calls++
		res := coreMetadataResponse(coreCIMD)
		res.Header.Set("Cache-Control", "no-store")
		return res, nil
	})
	for range 2 {
		if _, e := s.resolveClient(context.Background(), ChatGPTClientID); e != nil {
			t.Fatal(e)
		}
	}
	if calls != 2 {
		t.Fatal("no-store metadata cached")
	}
	calls = 0
	s = coreCIMDServer(t, func(*http.Request) (*http.Response, error) {
		calls++
		res := coreMetadataResponse("")
		res.StatusCode = 302
		res.Header.Set("Location", "https://evil.example.com/client.json")
		return res, nil
	})
	if _, e := s.resolveClient(context.Background(), ChatGPTClientID); e == nil || calls != 1 {
		t.Fatal("redirect followed", e, calls)
	}
}

func TestCoreMetadataPublicIPAndRateBeforeFetch(t *testing.T) {
	for _, value := range []string{"127.0.0.1", "10.1.2.3", "169.254.169.254", "100.64.0.1", "192.0.2.1", "198.18.0.1", "203.0.113.1", "::1", "::ffff:127.0.0.1", "fc00::1", "fe80::1", "2001:db8::1", "2002::1"} {
		if metadataPublicIP(netip.MustParseAddr(value)) {
			t.Fatal("private address allowed", value)
		}
	}
	for _, value := range []string{"1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"} {
		if !metadataPublicIP(netip.MustParseAddr(value)) {
			t.Fatal("public address rejected", value)
		}
	}
	var calls int
	s := coreCIMDServer(t, func(*http.Request) (*http.Response, error) { calls++; return coreMetadataResponse(coreCIMD), nil })
	m := s.store.(*coreMemoryStore)
	m.fail = true
	r := httptest.NewRequest("GET", Issuer+"/oauth/authorize?client_id="+ChatGPTClientID, nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 503 || calls != 0 {
		t.Fatal("metadata fetched before durable rate check", w.Code, calls)
	}
}

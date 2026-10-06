package auth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestConfigurationFailsClosed(t *testing.T) {
	for _, name := range []string{"MCP_RESOURCE_URL", "MCP_OAUTH_ISSUER", "MCP_OAUTH_JWKS_URL", "MCP_ALLOWED_SUBJECTS"} {
		t.Setenv(name, "")
	}
	if _, err := ConfigFromEnv(); err == nil { t.Fatal("empty environment enabled authentication") }
	t.Setenv("MCP_RESOURCE_URL", "https://mail.example.com/mcp")
	t.Setenv("MCP_OAUTH_ISSUER", "https://login.example.com/")
	t.Setenv("MCP_OAUTH_JWKS_URL", "https://login.example.com/jwks")
	t.Setenv("MCP_ALLOWED_SUBJECTS", " owner-123, owner-456 ")
	c, err := ConfigFromEnv()
	if err != nil || len(c.AllowedSubjects) != 2 || c.AllowedSubjects[0] != "owner-123" { t.Fatalf("valid configuration rejected: %#v %v", c, err) }
	for _, name := range []string{"MCP_RESOURCE_URL", "MCP_OAUTH_ISSUER", "MCP_OAUTH_JWKS_URL", "MCP_ALLOWED_SUBJECTS"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, "")
			if _, err := ConfigFromEnv(); err == nil { t.Fatalf("missing %s did not fail closed", name) }
		})
	}
	for _, test := range []struct { name string; change func(*Config) }{
		{"no subjects", func(c *Config) { c.AllowedSubjects = nil }},
		{"empty subject", func(c *Config) { c.AllowedSubjects = []string{""} }},
		{"whitespace subject", func(c *Config) { c.AllowedSubjects = []string{" owner "} }},
		{"control subject", func(c *Config) { c.AllowedSubjects = []string{"owner\n"} }},
		{"too many subjects", func(c *Config) { c.AllowedSubjects = make([]string, 33) }},
		{"other JWKS origin", func(c *Config) { c.JWKSURL = "https://keys.example.com/jwks" }},
		{"missing issuer", func(c *Config) { c.Issuer = "" }},
		{"missing resource", func(c *Config) { c.ResourceURL = "" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := testConfig()
			test.change(&c)
			if _, err := New(c); err == nil { t.Fatal("invalid configuration accepted") }
		})
	}
}

func TestPublicURLValidation(t *testing.T) {
	for _, raw := range []string{
		"", "/mcp", "http://mail.example.com/mcp", "https://localhost/mcp", "https://mail.local/mcp", "https://mail.internal/mcp", "https://mail.test/mcp",
		"https://127.0.0.1/mcp", "https://[::1]/mcp", "https://10.0.0.1/mcp", "https://192.168.1.1/mcp", "https://169.254.169.254/mcp", "https://8.8.8.8/mcp",
		"https://login.example.com:8443/jwks", "https://login.example.com:/jwks", "https://user:pass@login.example.com/jwks", "https://login.example.com/jwks?key=x", "https://login.example.com/jwks?", "https://login.example.com/jwks#part", "https://login.example.com/jwks#", "https://login.example.com/%00jwks", "https://login.example.com/%5Cjwks",
		"https://login.example.com./jwks", "https://-login.example.com/jwks", "https://login..example.com/jwks", "https://foo_bar.example.com/jwks",
		"https://login.example.com/../jwks", "https://login.example.com/%2e%2e/jwks", "https://login.example.com/a\\b", "https://login.example.com/a\nb",
	} {
		t.Run(raw, func(t *testing.T) { if _, err := publicHTTPSURL(raw); err == nil { t.Fatalf("unsafe URL allowed: %q", raw) } })
	}
	for _, raw := range []string{"https://example.com", "https://login.example.com/", "https://login.example.com/tenant/jwks", "https://login.example.com:443/jwks"} {
		if _, err := publicHTTPSURL(raw); err != nil { t.Fatalf("valid URL rejected %q: %v", raw, err) }
	}
}

func TestPublicIPValidation(t *testing.T) {
	for _, raw := range []string{"0.0.0.0", "127.0.0.1", "10.0.0.1", "100.64.0.1", "169.254.169.254", "172.16.0.1", "192.168.1.1", "192.0.2.1", "198.18.0.1", "198.51.100.1", "203.0.113.1", "224.0.0.1", "255.255.255.255", "::", "::1", "::ffff:127.0.0.1", "fd00::1", "fe80::1", "2001:db8::1", "2002:a00:1::", "64:ff9b::7f00:1", "ff02::1"} {
		if publicIP(netip.MustParseAddr(raw)) { t.Errorf("non-public address accepted: %s", raw) }
	}
	for _, raw := range []string{"1.1.1.1", "8.8.8.8", "2606:4700:4700::1111", "2001:4860:4860::8888", "::ffff:8.8.8.8"} {
		if !publicIP(netip.MustParseAddr(raw)) { t.Errorf("public address rejected: %s", raw) }
	}
	if publicIP(netip.Addr{}) { t.Error("invalid address accepted") }
}

func TestHTTPClientIsBoundedAndDoesNotFollowRedirects(t *testing.T) {
	for _, timeout := range []time.Duration{0, time.Hour, time.Second} {
		c := testConfig()
		c.HTTPClient = &http.Client{Timeout: timeout}
		a, err := New(c)
		if err != nil { t.Fatal(err) }
		if a.client.Timeout <= 0 || a.client.Timeout > requestTimeout { t.Fatal("unbounded timeout") }
		if c.HTTPClient.Timeout != timeout { t.Fatal("constructor modified caller client") }
		if err := a.client.CheckRedirect(nil, nil); !errors.Is(err, http.ErrUseLastResponse) { t.Fatal("redirect following enabled") }
	}
	c := testConfig()
	requests := 0
	c.HTTPClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		requests++
		return &http.Response{StatusCode: 302, Header: http.Header{"Location": []string{"https://attacker.example.com/jwks"}}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
	})}
	a, err := New(c)
	if err != nil { t.Fatal(err) }
	if _, err := a.fetchKeys(context.Background()); err == nil || requests != 1 { t.Fatalf("redirect handled unsafely: err=%v requests=%d", err, requests) }
	production := newPublicClient()
	transport, ok := production.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil || transport.DialContext == nil || transport.TLSHandshakeTimeout <= 0 || transport.ResponseHeaderTimeout <= 0 || transport.MaxResponseHeaderBytes == 0 { t.Fatal("production transport lacks network boundaries") }
}

func TestFetchRespectsCancellationAndSizeLimit(t *testing.T) {
	c := testConfig()
	c.HTTPClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		<-r.Context().Done()
		return nil, r.Context().Err()
	})}
	a, err := New(c)
	if err != nil { t.Fatal(err) }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a.fetchKeys(ctx); err == nil { t.Fatal("canceled fetch succeeded") }
	f := newFixture(t)
	f.body = strings.Repeat(" ", maxJWKSBytes+1)
	if _, err := f.a.fetchKeys(context.Background()); err == nil { t.Fatal("oversized key set accepted") }
	f.body = `{"keys":[]}`
	if _, err := f.a.fetchKeys(context.Background()); err == nil { t.Fatal("empty key set accepted") }
}

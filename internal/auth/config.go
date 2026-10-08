// Package auth implements the OAuth resource-server boundary for the private MCP
// endpoint. It validates access tokens; it never issues tokens or manages grants.
package auth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
	"unicode"
)

const (
	ScopeRead      = "mail.read"
	ScopeWrite     = "mail.write"
	ScopeSend      = "mail.send"
	MetadataPath   = "/.well-known/oauth-protected-resource"
	requestTimeout = 5 * time.Second
)

// Config contains only public issuer information and an explicit owner allowlist.
// Issuer and ResourceURL are compared byte-for-byte with token claims. JWKSURL
// must be an HTTPS endpoint on the issuer's origin; discovery is never taken from
// token headers. No static-bearer or development bypass is supported.
type Config struct {
	ResourceURL     string
	Issuer          string
	JWKSURL         string
	AllowedSubjects []string
	// InitialScopes controls only the scopes requested on a new 401 sign-in.
	// Empty preserves the read-only default. It never adds scopes to a token.
	InitialScopes []string
	// HTTPClient is an optional trusted test transport. Leave nil in production
	// to use the public-IP-only transport. Redirects and timeouts remain bounded.
	HTTPClient *http.Client
	// LocalJWKS is an optional immutable public key set supplied by the same
	// process's authorization server. It is never obtained from a request.
	LocalJWKS []byte
	// CheckGrant enables the stricter first-party access-token profile and an
	// online authorization check after cryptographic verification. Errors deny
	// access, including unavailable or missing durable authorization state.
	CheckGrant func(context.Context, string, string, string, []string) error
}

// ConfigFromEnv fails closed if any required environment variable is missing.
func ConfigFromEnv() (Config, error) {
	c := Config{
		ResourceURL: os.Getenv("MCP_RESOURCE_URL"),
		Issuer:      os.Getenv("MCP_OAUTH_ISSUER"),
		JWKSURL:     os.Getenv("MCP_OAUTH_JWKS_URL"),
	}
	for _, subject := range strings.Split(os.Getenv("MCP_ALLOWED_SUBJECTS"), ",") {
		if subject = strings.TrimSpace(subject); subject != "" {
			c.AllowedSubjects = append(c.AllowedSubjects, subject)
		}
	}
	if value := os.Getenv("MCP_OAUTH_INITIAL_SCOPES"); value != "" {
		c.InitialScopes = strings.Split(value, " ")
	}
	if err := c.validate(); err != nil {
		return Config{}, err
	}
	// A deployment can request only capabilities its explicit server gates
	// enable. Disabling a gate also narrows subsequent connection requests.
	requested := initialScopes(c.InitialScopes)
	c.InitialScopes = []string{ScopeRead}
	for _, scope := range requested[1:] {
		if scope == ScopeWrite && os.Getenv("MAIL_ENABLE_WRITES") == "1" || scope == ScopeSend && os.Getenv("MAIL_ENABLE_SEND") == "1" {
			c.InitialScopes = append(c.InitialScopes, scope)
		}
	}
	return c, nil
}

func (c Config) validate() error {
	for name, value := range map[string]string{
		"MCP_RESOURCE_URL":   c.ResourceURL,
		"MCP_OAUTH_ISSUER":   c.Issuer,
		"MCP_OAUTH_JWKS_URL": c.JWKSURL,
	} {
		if _, err := publicHTTPSURL(value); err != nil {
			return fmt.Errorf("%s must be a public HTTPS URL without credentials, query, or fragment", name)
		}
	}
	issuer, _ := url.Parse(c.Issuer)
	jwks, _ := url.Parse(c.JWKSURL)
	if !strings.EqualFold(issuer.Hostname(), jwks.Hostname()) || effectivePort(issuer) != effectivePort(jwks) {
		return errors.New("MCP_OAUTH_JWKS_URL must use the MCP_OAUTH_ISSUER origin")
	}
	if len(c.AllowedSubjects) == 0 || len(c.AllowedSubjects) > 32 {
		return errors.New("MCP_ALLOWED_SUBJECTS must list 1 to 32 exact OAuth subject identifiers")
	}
	for _, subject := range c.AllowedSubjects {
		if !validSubject(subject) {
			return errors.New("MCP_ALLOWED_SUBJECTS contains an invalid subject identifier")
		}
	}
	if len(c.InitialScopes) > 3 {
		return errors.New("MCP_OAUTH_INITIAL_SCOPES must contain mail.read and optional mail.write and mail.send")
	}
	seen := map[string]bool{}
	for _, scope := range c.InitialScopes {
		if seen[scope] || (scope != ScopeRead && scope != ScopeWrite && scope != ScopeSend) {
			return errors.New("MCP_OAUTH_INITIAL_SCOPES contains an invalid or duplicate scope")
		}
		seen[scope] = true
	}
	if len(c.InitialScopes) > 0 && !seen[ScopeRead] {
		return errors.New("MCP_OAUTH_INITIAL_SCOPES must include mail.read")
	}
	return nil
}

// initialScopes returns a fresh canonical list after configuration validation.
func initialScopes(scopes []string) []string {
	result := []string{ScopeRead}
	for _, wanted := range []string{ScopeWrite, ScopeSend} {
		for _, scope := range scopes {
			if scope == wanted {
				result = append(result, wanted)
			}
		}
	}
	return result
}

func validSubject(s string) bool {
	return s != "" && len(s) <= 512 && strings.TrimSpace(s) == s && !strings.ContainsFunc(s, unicode.IsControl)
}

func publicHTTPSURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || raw == "" || strings.ContainsAny(raw, "\r\n\t \\?#") || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || u.Opaque != "" || u.RawPath != "" {
		return nil, errors.New("invalid public HTTPS URL")
	}
	if strings.HasSuffix(u.Host, ":") || (u.Port() != "" && u.Port() != "443") {
		return nil, errors.New("only the standard HTTPS port is supported")
	}
	if strings.ContainsFunc(u.Path, unicode.IsControl) || strings.ContainsAny(u.Path, "\\") {
		return nil, errors.New("invalid URL path")
	}
	host := strings.ToLower(u.Hostname())
	if net.ParseIP(host) != nil || !strings.Contains(host, ".") || len(host) > 253 {
		return nil, errors.New("a public DNS hostname is required")
	}
	for _, suffix := range []string{".localhost", ".local", ".internal", ".invalid", ".test", ".onion"} {
		if strings.HasSuffix(host, suffix) {
			return nil, errors.New("a public DNS hostname is required")
		}
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return nil, errors.New("invalid DNS hostname")
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z') && !(ch >= '0' && ch <= '9') && ch != '-' {
				return nil, errors.New("invalid DNS hostname")
			}
		}
	}
	for _, segment := range strings.Split(u.Path, "/") {
		if segment == "." || segment == ".." {
			return nil, errors.New("ambiguous URL path")
		}
	}
	return u, nil
}

func effectivePort(u *url.URL) string {
	if u.Port() == "" {
		return "443"
	}
	return u.Port()
}

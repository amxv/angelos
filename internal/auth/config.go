// Package auth implements the OAuth resource-server boundary for the private MCP
// endpoint. It validates access tokens; it never issues tokens or manages grants.
package auth

import (
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
	ScopeRead = "mail.read"
	ScopeWrite = "mail.write"
	ScopeSend = "mail.send"
	MetadataPath = "/.well-known/oauth-protected-resource"
	requestTimeout = 5 * time.Second
)

// Config contains only public issuer information and an explicit owner allowlist.
// Issuer and ResourceURL are compared byte-for-byte with token claims. JWKSURL
// must be an HTTPS endpoint on the issuer's origin; discovery is never taken from
// token headers. No static-bearer or development bypass is supported.
type Config struct {
	ResourceURL string
	Issuer string
	JWKSURL string
	AllowedSubjects []string
	// HTTPClient is an optional trusted test transport. Leave nil in production
	// to use the public-IP-only transport. Redirects and timeouts remain bounded.
	HTTPClient *http.Client
}

// ConfigFromEnv fails closed if any required environment variable is missing.
func ConfigFromEnv() (Config, error) {
	c := Config{
		ResourceURL: os.Getenv("MCP_RESOURCE_URL"),
		Issuer: os.Getenv("MCP_OAUTH_ISSUER"),
		JWKSURL: os.Getenv("MCP_OAUTH_JWKS_URL"),
	}
	for _, subject := range strings.Split(os.Getenv("MCP_ALLOWED_SUBJECTS"), ",") {
		if subject = strings.TrimSpace(subject); subject != "" {
			c.AllowedSubjects = append(c.AllowedSubjects, subject)
		}
	}
	if err := c.validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

func (c Config) validate() error {
	for name, value := range map[string]string{
		"MCP_RESOURCE_URL": c.ResourceURL,
		"MCP_OAUTH_ISSUER": c.Issuer,
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
	return nil
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

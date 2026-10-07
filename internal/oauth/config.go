// Package oauth implements Angelos's single-owner, first-party authorization server.
// All durable authorization state is kept in a separate Redis namespace.
package oauth

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"strings"
	"time"
	"unicode"
)

const (
	Issuer       = "https://api.angelos.ashray.xyz"
	Resource     = Issuer + "/mcp"
	MetadataPath = "/.well-known/oauth-authorization-server"
	JWKSPath     = "/oauth/jwks.json"
	AccessTTL    = 5 * time.Minute
	CodeTTL      = 5 * time.Minute
	GrantTTL     = 30 * 24 * time.Hour
	ScopeRead    = "mail.read"
	ScopeWrite   = "mail.write"
	ScopeSend    = "mail.send"
)

var ErrDisabled = errors.New("first-party OAuth is disabled")

// Config deliberately has no dynamic issuer or development authentication mode.
// HTTPClient is a trusted test seam; production uses a public-address-only client.
type Config struct {
	Enabled             bool
	Issuer              string
	Resource            string
	OwnerSubject        string
	OwnerMailbox        string
	SigningKeyPEM       string
	SigningKeyID        string
	VerificationKeysPEM map[string]string
	BootstrapTokenHash  string
	Clients             []Client
	EnableChatGPTCIMD   bool
	HTTPClient          *http.Client
}

func ConfigFromEnv() (Config, error) {
	if os.Getenv("ANGELOS_OAUTH_ENABLED") != "1" {
		return Config{}, ErrDisabled
	}
	c := Config{
		Enabled:            true,
		Issuer:             os.Getenv("MCP_OAUTH_ISSUER"),
		Resource:           os.Getenv("MCP_RESOURCE_URL"),
		OwnerSubject:       os.Getenv("MCP_ALLOWED_SUBJECTS"),
		OwnerMailbox:       os.Getenv("MAIL_FROM"),
		SigningKeyPEM:      os.Getenv("ANGELOS_OAUTH_SIGNING_KEY_PEM"),
		SigningKeyID:       os.Getenv("ANGELOS_OAUTH_SIGNING_KEY_ID"),
		BootstrapTokenHash: os.Getenv("ANGELOS_OAUTH_BOOTSTRAP_TOKEN_HASH"),
		EnableChatGPTCIMD:  os.Getenv("ANGELOS_OAUTH_CHATGPT_CIMD_ENABLED") == "1",
	}
	if os.Getenv("MCP_OAUTH_JWKS_URL") != Issuer+JWKSPath {
		return Config{}, errors.New("MCP_OAUTH_JWKS_URL must be the canonical first-party JWKS URL")
	}
	if value := os.Getenv("ANGELOS_OAUTH_CLIENTS_JSON"); value != "" {
		if len(value) > 32768 || strictJSON([]byte(value), &c.Clients) != nil {
			return Config{}, errors.New("invalid ANGELOS_OAUTH_CLIENTS_JSON")
		}
	}
	if value := os.Getenv("ANGELOS_OAUTH_VERIFICATION_KEYS_JSON"); value != "" {
		if len(value) > 32768 || strictJSON([]byte(value), &c.VerificationKeysPEM) != nil {
			return Config{}, errors.New("invalid ANGELOS_OAUTH_VERIFICATION_KEYS_JSON")
		}
	}
	if err := c.validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

func (c Config) validate() error {
	if !c.Enabled {
		return ErrDisabled
	}
	if c.Issuer != Issuer || c.Resource != Resource {
		return errors.New("first-party issuer and MCP resource must match the canonical production URLs")
	}
	if !boundedText(c.OwnerSubject, 512) || strings.Contains(c.OwnerSubject, ",") {
		return errors.New("MCP_ALLOWED_SUBJECTS must contain exactly one explicit owner subject")
	}
	address, err := mail.ParseAddress(c.OwnerMailbox)
	if err != nil || address.Address != c.OwnerMailbox || !boundedText(c.OwnerMailbox, 254) {
		return errors.New("MAIL_FROM must identify the connected owner mailbox")
	}
	if !boundedText(c.SigningKeyID, 128) || len(c.SigningKeyPEM) > 16384 || c.SigningKeyPEM == "" {
		return errors.New("a durable signing private key and key ID are required")
	}
	if len(c.VerificationKeysPEM) > 4 {
		return errors.New("at most four retiring verification keys are supported")
	}
	for id, value := range c.VerificationKeysPEM {
		if !boundedText(id, 128) || id == c.SigningKeyID || value == "" || len(value) > 16384 {
			return errors.New("invalid or duplicate retiring signing key")
		}
	}
	if c.BootstrapTokenHash != "" {
		value, err := hex.DecodeString(c.BootstrapTokenHash)
		if err != nil || len(value) != 32 || c.BootstrapTokenHash != strings.ToLower(c.BootstrapTokenHash) {
			return errors.New("bootstrap token hash must be a lowercase SHA-256 digest")
		}
	}
	if len(c.Clients) > 16 || (len(c.Clients) == 0 && !c.EnableChatGPTCIMD) {
		return errors.New("at least one explicitly configured OAuth client is required")
	}
	seen := map[string]bool{}
	for _, client := range c.Clients {
		if err := client.validate(); err != nil {
			return err
		}
		if seen[client.ID] || client.ID == ChatGPTClientID {
			return errors.New("duplicate or reserved OAuth client ID")
		}
		seen[client.ID] = true
	}
	return nil
}

func boundedText(value string, max int) bool {
	return value != "" && len(value) <= max && strings.TrimSpace(value) == value && !strings.ContainsFunc(value, unicode.IsControl)
}

func canonicalScopes(scopes []string) ([]string, error) {
	if len(scopes) == 0 || len(scopes) > 3 {
		return nil, errors.New("invalid scopes")
	}
	seen := map[string]bool{}
	for _, scope := range scopes {
		if seen[scope] || (scope != ScopeRead && scope != ScopeWrite && scope != ScopeSend) {
			return nil, errors.New("invalid scopes")
		}
		seen[scope] = true
	}
	// Every MCP connection requires read scope to initialize and discover tools.
	if !seen[ScopeRead] {
		return nil, errors.New("mail.read is required")
	}
	result := []string{ScopeRead}
	if seen[ScopeWrite] {
		result = append(result, ScopeWrite)
	}
	if seen[ScopeSend] {
		result = append(result, ScopeSend)
	}
	return result, nil
}

func parseScopes(value string) ([]string, error) {
	if len(value) > 64 || value == "" || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\t\r\n") {
		return nil, errors.New("invalid scopes")
	}
	return canonicalScopes(strings.Split(value, " "))
}

func scopeSubset(scopes, allowed []string) bool {
	for _, scope := range scopes {
		found := false
		for _, candidate := range allowed {
			if candidate == scope {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func validRedirect(raw string) bool {
	if len(raw) > 2048 || !boundedText(raw, 2048) || strings.ContainsAny(raw, "\\\r\n\t ") {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Host == "" || u.Hostname() == "" || u.Fragment != "" || u.RawFragment != "" || u.Opaque != "" || u.RawPath != "" || u.ForceQuery {
		return false
	}
	if u.Port() != "" && u.Port() != "443" {
		return false
	}
	if strings.HasSuffix(u.Host, ":") || !strings.Contains(u.Hostname(), ".") {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if net.ParseIP(host) != nil || len(host) > 253 {
		return false
	}
	for _, suffix := range []string{".localhost", ".local", ".internal", ".invalid", ".test", ".onion"} {
		if strings.HasSuffix(host, suffix) {
			return false
		}
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '-' {
				return false
			}
		}
	}
	for _, segment := range strings.Split(u.Path, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	// OAuth response parameter names must not already be embedded in a callback.
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return false
	}
	for _, name := range []string{"code", "error", "error_description", "state", "iss"} {
		if _, ok := q[name]; ok {
			return false
		}
	}
	return true
}

func strictJSON(data []byte, out any) error {
	// Reject duplicate members at all depths before decoding; security metadata
	// must have one unambiguous interpretation across JSON implementations.
	dec := json.NewDecoder(strings.NewReader(string(data)))
	if err := uniqueJSONValue(dec, 0); err != nil {
		return err
	}
	if _, err := dec.Token(); err == nil {
		return errors.New("trailing JSON")
	} else if !errors.Is(err, io.EOF) {
		return err
	}
	return json.Unmarshal(data, out)
}

func uniqueJSONValue(dec *json.Decoder, depth int) error {
	if depth > 32 {
		return errors.New("JSON nesting limit exceeded")
	}
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, composite := tok.(json.Delim)
	if !composite {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for dec.More() {
			key, err := dec.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			// Go's struct decoder is case insensitive; aliases must not bypass
			// the duplicate-member check (for example client_id and CLIENT_ID).
			folded := foldedJSONName(name)
			if !ok || seen[folded] {
				return errors.New("duplicate JSON member")
			}
			seen[folded] = true
			if err := uniqueJSONValue(dec, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for dec.More() {
			if err := uniqueJSONValue(dec, depth+1); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("invalid JSON delimiter")
	}
	_, err = dec.Token()
	return err
}

// encoding/json matches struct fields using Unicode simple case folding, not
// just ASCII or lowercasing. In particular long s and Kelvin sign alias s and k.
// Use one stable representative of each fold cycle to detect every such alias.
func foldedJSONName(name string) string {
	var out strings.Builder
	for _, r := range name {
		minimum := r
		for folded := unicode.SimpleFold(r); folded != r; folded = unicode.SimpleFold(folded) {
			if folded < minimum {
				minimum = folded
			}
		}
		out.WriteRune(minimum)
	}
	return out.String()
}

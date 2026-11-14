package oauth

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

const (
	ChatGPTClientID    = "https://chatgpt.com/oauth/client.json"
	ChatGPTRedirectURI = "https://chatgpt.com/connector_platform_oauth_redirect"
	// Native CLI identities publish port-free loopback callbacks. Each login
	// adds its local listener port, which loopback matching accepts.
	ClaudeCodeClientID = "https://claude.ai/oauth/claude-code-client-metadata"
	CodexClientID      = "https://chatgpt.com/oauth/codex/client.json"
)

// metadataClient is one exact Client ID Metadata Document this server may
// fetch. The ID is the only URL fetched, Host is the only dial destination, and
// Redirects is the complete callback allowlist; documents cannot widen it.
type metadataClient struct {
	ID        string
	Name      string
	Host      string
	Redirects []string
}

var metadataClients = []metadataClient{
	{ID: ChatGPTClientID, Name: "ChatGPT", Host: "chatgpt.com", Redirects: []string{ChatGPTRedirectURI}},
	{ID: ClaudeCodeClientID, Name: "Claude Code", Host: "claude.ai", Redirects: []string{"http://localhost/callback", "http://127.0.0.1/callback"}},
	{ID: CodexClientID, Name: "Codex", Host: "chatgpt.com", Redirects: []string{"http://127.0.0.1/callback", "http://localhost/callback"}},
}

type metadataCacheEntry struct {
	client     *Client
	until      time.Time
	retryAfter time.Time
}

// metadataClient returns the pinned identity only when its operator switch is on.
func (c Config) metadataClient(id string) (metadataClient, bool) {
	enabled := map[string]bool{ChatGPTClientID: c.EnableChatGPTCIMD, ClaudeCodeClientID: c.EnableClaudeCodeCIMD, CodexClientID: c.EnableCodexCIMD}
	for _, client := range metadataClients {
		if client.ID == id && enabled[id] {
			return client, true
		}
	}
	return metadataClient{}, false
}

func (c Config) metadataClientsEnabled() bool {
	return c.EnableChatGPTCIMD || c.EnableClaudeCodeCIMD || c.EnableCodexCIMD
}

func reservedClientID(id string) bool {
	for _, client := range metadataClients {
		if client.ID == id {
			return true
		}
	}
	return false
}

// Client is an operator-predefined public client. Exact redirect URIs must be
// copied from the client's connection UI; wildcard and guessed callbacks fail.
type Client struct {
	ID           string   `json:"client_id"`
	Name         string   `json:"client_name"`
	RedirectURIs []string `json:"redirect_uris"`
}

func (c Client) validate() error {
	if !boundedText(c.ID, 512) || !boundedText(c.Name, 128) || len(c.RedirectURIs) == 0 || len(c.RedirectURIs) > 8 {
		return errors.New("invalid predefined OAuth client")
	}
	seen := map[string]bool{}
	for _, redirect := range c.RedirectURIs {
		if !(validRedirect(redirect) || validLoopbackRedirect(redirect)) || seen[redirect] {
			return errors.New("OAuth clients require exact HTTPS redirect URIs or port-free loopback callbacks such as http://localhost/callback")
		}
		seen[redirect] = true
	}
	return nil
}

// allowsRedirect is exact for HTTPS callbacks. A registered port-free loopback
// callback also matches the same callback with a login-time port (RFC 8252).
func (c Client) allowsRedirect(redirect string) bool {
	for _, allowed := range c.RedirectURIs {
		if redirect == allowed || loopbackRedirectMatches(allowed, redirect) {
			return true
		}
	}
	return false
}

func (s *Server) knownClient(id string) bool {
	for _, client := range s.config.Clients {
		if client.ID == id {
			return true
		}
	}
	_, ok := s.config.metadataClient(id)
	return ok
}

// Token redemption relies on the immutable client binding established by a
// validated authorization and owner consent. It does not re-fetch a public
// metadata URL before proving a code/refresh token. The configured allowlist is
// still authoritative: disabling a client prevents further redemption.
func (s *Server) tokenClient(id string) (Client, error) {
	for _, client := range s.config.Clients {
		if client.ID == id {
			return client, nil
		}
	}
	if pinned, ok := s.config.metadataClient(id); ok {
		return Client{ID: pinned.ID, Name: pinned.Name, RedirectURIs: append([]string(nil), pinned.Redirects...)}, nil
	}
	return Client{}, errors.New("unknown OAuth client")
}

func (s *Server) resolveClient(ctx context.Context, id string) (Client, error) {
	for _, c := range s.config.Clients {
		if id == c.ID {
			return c, nil
		}
	}
	pinned, ok := s.config.metadataClient(id)
	if !ok {
		return Client{}, errors.New("unknown OAuth client")
	}
	// The pinned endpoints are the entire allowlist. Never fetch a request-provided
	// URL, logo, client_uri, jwks_uri, or redirect and never follow HTTP redirects.
	s.clientMu.Lock()
	defer s.clientMu.Unlock()
	if s.metadataCache == nil {
		s.metadataCache = map[string]metadataCacheEntry{}
	}
	entry := s.metadataCache[pinned.ID]
	if entry.client != nil && s.now().Before(entry.until) {
		return *entry.client, nil
	}
	if s.now().Before(entry.retryAfter) {
		return Client{}, errors.New("client metadata temporarily unavailable")
	}
	// Bound outbound work across stateless instances, not requests by public
	// client ID. A fresh cached document never spends this shared fetch budget.
	if err := allowRate(ctx, s.store, "client-metadata:fetch", 12); err != nil {
		return Client{}, err
	}
	success := false
	defer func() {
		if !success {
			s.metadataCache[pinned.ID] = metadataCacheEntry{retryAfter: s.now().Add(5 * time.Second)}
		}
	}()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pinned.ID, nil)
	if err != nil {
		return Client{}, err
	}
	req.Header.Set("Accept", "application/json")
	response, err := s.clientHTTP.Do(req)
	if err != nil {
		return Client{}, errors.New("client metadata unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return Client{}, errors.New("client metadata unavailable")
	}
	media, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return Client{}, errors.New("invalid client metadata media type")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 32769))
	if err != nil || len(data) > 32768 {
		return Client{}, errors.New("client metadata exceeds limit")
	}
	var metadata struct {
		Client
		AuthMethods []string `json:"token_endpoint_auth_methods_supported"`
		AuthMethod  string   `json:"token_endpoint_auth_method"`
		Grants      []string `json:"grant_types"`
		Responses   []string `json:"response_types"`
	}
	if strictJSON(data, &metadata) != nil || metadata.ID != pinned.ID || metadata.Name != pinned.Name || len(metadata.RedirectURIs) == 0 || len(metadata.RedirectURIs) > 8 {
		return Client{}, errors.New("invalid pinned client metadata")
	}
	var exact map[string]json.RawMessage
	if json.Unmarshal(data, &exact) != nil || exact["client_id"] == nil || exact["client_name"] == nil || exact["redirect_uris"] == nil || exact["grant_types"] == nil || exact["response_types"] == nil {
		return Client{}, errors.New("client metadata requires exact member names")
	}
	if exact["token_endpoint_auth_methods_supported"] == nil && exact["token_endpoint_auth_method"] == nil {
		return Client{}, errors.New("client metadata requires an authentication method")
	}
	for name := range exact {
		for _, canonical := range []string{"client_id", "client_name", "redirect_uris", "grant_types", "response_types", "token_endpoint_auth_method", "token_endpoint_auth_methods_supported"} {
			if name != canonical && foldedJSONName(name) == foldedJSONName(canonical) {
				return Client{}, errors.New("client metadata requires exact member names")
			}
		}
	}
	// The current plural field expresses capability, not a preference. We support
	// only its public-client intersection, even if legacy singular prefers JWT.
	methods := metadata.AuthMethods
	if len(methods) == 0 {
		methods = []string{metadata.AuthMethod}
	}
	if !contains(methods, "none") || !contains(metadata.Grants, "authorization_code") || !contains(metadata.Grants, "refresh_token") || !contains(metadata.Responses, "code") {
		return Client{}, errors.New("pinned client metadata does not support the configured public-client flow")
	}
	// Every published callback must already be pinned, compared byte for byte.
	// The usable set is the pinned callbacks the document still publishes.
	for _, redirect := range metadata.RedirectURIs {
		if !contains(pinned.Redirects, redirect) {
			return Client{}, errors.New("unexpected pinned client redirect URI")
		}
	}
	client := Client{ID: pinned.ID, Name: pinned.Name}
	for _, redirect := range pinned.Redirects {
		if contains(metadata.RedirectURIs, redirect) {
			client.RedirectURIs = append(client.RedirectURIs, redirect)
		}
	}
	// A bounded cache never extends stale metadata after a retrieval failure.
	// no-store/no-cache causes the document to be revalidated on the next request.
	ttl := 5 * time.Minute
	cacheControl := strings.ToLower(response.Header.Get("Cache-Control"))
	if strings.Contains(cacheControl, "no-store") || strings.Contains(cacheControl, "no-cache") {
		ttl = 0
	}
	for _, directive := range strings.Split(cacheControl, ",") {
		name, value, ok := strings.Cut(strings.TrimSpace(directive), "=")
		if ok && name == "max-age" {
			if age, err := time.ParseDuration(strings.Trim(value, "\"") + "s"); err == nil && age >= 0 && age < ttl {
				ttl = age
			}
		}
	}
	cached := client
	cached.RedirectURIs = append([]string(nil), client.RedirectURIs...)
	s.metadataCache[pinned.ID] = metadataCacheEntry{client: &cached, until: s.now().Add(ttl)}
	success = true
	return client, nil
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func metadataHTTPClient(test *http.Client) *http.Client {
	var client http.Client
	if test != nil {
		client = *test
	} else {
		dialer := &net.Dialer{Timeout: 3 * time.Second}
		client.Transport = &http.Transport{
			Proxy:                  nil,
			TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout:    3 * time.Second,
			ResponseHeaderTimeout:  3 * time.Second,
			MaxResponseHeaderBytes: 16 * 1024,
			MaxConnsPerHost:        2,
			IdleConnTimeout:        time.Minute,
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(address)
				if err != nil || !metadataHost(host) || port != "443" {
					return nil, errors.New("unapproved client metadata destination")
				}
				ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
				if err != nil || len(ips) == 0 || len(ips) > 32 {
					return nil, errors.New("client metadata DNS unavailable")
				}
				for _, ip := range ips {
					if !metadataPublicIP(ip) {
						return nil, errors.New("private client metadata destination")
					}
				}
				for _, ip := range ips {
					if conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port)); err == nil {
						return conn, nil
					}
				}
				return nil, errors.New("client metadata connection unavailable")
			},
		}
	}
	client.Timeout = 5 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return errors.New("client metadata redirects denied") }
	return &client
}

// metadataHost permits only the fixed hosts of pinned metadata documents.
func metadataHost(host string) bool {
	for _, client := range metadataClients {
		if host == client.Host {
			return true
		}
	}
	return false
}

func metadataPublicIP(ip netip.Addr) bool {
	if !ip.IsValid() || ip.Zone() != "" {
		return false
	}
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	if ip.Is6() && !netip.MustParsePrefix("2000::/3").Contains(ip) {
		return false
	}
	for _, prefix := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "2001::/23", "2001:db8::/32", "2002::/16"} {
		if netip.MustParsePrefix(prefix).Contains(ip) {
			return false
		}
	}
	return true
}

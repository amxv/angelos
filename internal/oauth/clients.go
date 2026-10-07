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
)

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
		if !validRedirect(redirect) || seen[redirect] {
			return errors.New("OAuth clients require exact HTTPS redirect URIs")
		}
		seen[redirect] = true
	}
	return nil
}

func (c Client) allowsRedirect(redirect string) bool {
	for _, allowed := range c.RedirectURIs {
		if redirect == allowed {
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
	return s.config.EnableChatGPTCIMD && id == ChatGPTClientID
}

func (s *Server) resolveClient(ctx context.Context, id string) (Client, error) {
	for _, c := range s.config.Clients {
		if id == c.ID {
			return c, nil
		}
	}
	if !s.config.EnableChatGPTCIMD || id != ChatGPTClientID {
		return Client{}, errors.New("unknown OAuth client")
	}
	// This endpoint is the entire allowlist. Never fetch a request-provided URL,
	// logo, client_uri, jwks_uri, or redirect and never follow HTTP redirects.
	s.clientMu.Lock()
	defer s.clientMu.Unlock()
	if s.cachedClient != nil && s.now().Before(s.clientCacheUntil) {
		return *s.cachedClient, nil
	}
	if s.now().Before(s.clientRetryAfter) {
		return Client{}, errors.New("client metadata temporarily unavailable")
	}
	success := false
	defer func() {
		if success {
			s.clientRetryAfter = time.Time{}
		} else {
			s.clientRetryAfter = s.now().Add(5 * time.Second)
		}
	}()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ChatGPTClientID, nil)
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
	if strictJSON(data, &metadata) != nil || metadata.ID != ChatGPTClientID || metadata.Name != "ChatGPT" || len(metadata.RedirectURIs) == 0 || len(metadata.RedirectURIs) > 8 {
		return Client{}, errors.New("invalid ChatGPT client metadata")
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
	if !contains(methods, "none") || !contains(metadata.Grants, "authorization_code") || !contains(metadata.Grants, "refresh_token") || !contains(metadata.Responses, "code") || !metadata.allowsRedirect(ChatGPTRedirectURI) {
		return Client{}, errors.New("ChatGPT client metadata does not support the configured public-client flow")
	}
	for _, redirect := range metadata.RedirectURIs {
		if redirect != ChatGPTRedirectURI {
			return Client{}, errors.New("unexpected ChatGPT client redirect URI")
		}
	}
	client := Client{ID: ChatGPTClientID, Name: "ChatGPT", RedirectURIs: []string{ChatGPTRedirectURI}}
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
	s.cachedClient = &client
	s.clientCacheUntil = s.now().Add(ttl)
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
				if err != nil || host != "chatgpt.com" || port != "443" {
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

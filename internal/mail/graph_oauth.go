package mail

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/amxv/angelos/internal/config"
)

const (
	microsoftTokenHost        = "login.microsoftonline.com"
	microsoftGraphScopes      = "https://graph.microsoft.com/User.Read https://graph.microsoft.com/Mail.ReadWrite https://graph.microsoft.com/Mail.Send"
	maxMicrosoftTokenResponse = 64 << 10
)

type microsoftAccessToken struct {
	value       string
	usableUntil time.Time
	key         [32]byte
}

type microsoftTokenFlight struct {
	done  chan struct{}
	key   [32]byte
	token microsoftAccessToken
	err   error
}

// Access tokens stay in backend memory. Rotated refresh tokens are retained in
// memory and authenticated encrypted durable storage; config is never changed.
type microsoftTokenCache struct {
	mu           sync.Mutex
	token        microsoftAccessToken
	flight       *microsoftTokenFlight
	refreshKey   [32]byte
	refreshToken string
}

func (b *GraphBackend) microsoftCredentialKey() [32]byte {
	return sha256.Sum256([]byte(strings.Join([]string{
		b.config.MicrosoftClientID, b.config.MicrosoftClientSecret,
		b.config.MicrosoftRefreshToken, b.config.MicrosoftTenantID,
		b.config.MicrosoftAccountID, b.config.From, b.config.MicrosoftTokenEncryptionKey,
	}, "\x00")))
}

// graphToken coalesces concurrent refreshes. Waiting callers can cancel without
// canceling the refresh owner. Owner cancellation fails that flight; subsequent
// calls can start another, but never fall back to an expired access token.
func (b *GraphBackend) graphToken(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, b.config.Timeout)
	defer cancel()
	key := b.microsoftCredentialKey()
	cache := &b.tokens
	for {
		cache.mu.Lock()
		if cache.token.key == key && cache.token.value != "" && time.Now().Before(cache.token.usableUntil) {
			token := cache.token.value
			cache.mu.Unlock()
			return token, nil
		}
		if flight := cache.flight; flight != nil {
			cache.mu.Unlock()
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-flight.done:
				if err := ctx.Err(); err != nil {
					return "", err
				}
				if flight.key != key {
					continue
				}
				if flight.err != nil {
					return "", flight.err
				}
				if !time.Now().Before(flight.token.usableUntil) {
					return "", ErrUnavailable
				}
				return flight.token.value, nil
			}
		}
		store := b.tokenStore
		if store == nil || store.config != key {
			cache.mu.Unlock()
			return "", ErrUnavailable
		}
		flight := &microsoftTokenFlight{done: make(chan struct{}), key: key}
		cache.flight = flight
		cache.mu.Unlock()

		previous, err := store.load(ctx, b.config.MicrosoftRefreshToken)
		var token microsoftAccessToken
		var refreshToken string
		if err == nil {
			var rotated string
			token, rotated, err = b.refreshMicrosoftToken(ctx, previous.token)
			if err == nil {
				if rotated == "" {
					rotated = previous.token
				}
				refreshToken, err = store.advance(ctx, previous, rotated)
			}
		}
		if err == nil {
			if ctx.Err() != nil {
				err = ctx.Err()
			} else if !time.Now().Before(token.usableUntil) {
				err = ErrUnavailable
			}
		}
		if err != nil {
			token = microsoftAccessToken{}
		}
		cache.mu.Lock()
		if err == nil {
			token.key = key
			cache.token = token
			cache.refreshKey = key
			cache.refreshToken = refreshToken
		}
		flight.token, flight.err = token, err
		cache.flight = nil
		close(flight.done)
		cache.mu.Unlock()
		return token.value, err
	}
}

// A late rejection of a different access token must not invalidate a newer one.
// A same-value reissue may conservatively require one additional refresh.
func (b *GraphBackend) graphInvalidateToken(token string) {
	cache := &b.tokens
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if token != "" && cache.token.value == token {
		cache.token = microsoftAccessToken{}
	}
}

// The authority is pinned independently of the configured tenant. In
// particular, common, organizations, domains, URL delimiters and path escapes
// are not accepted as tenants.
func microsoftTokenURL(tenant string) (string, bool) {
	if tenant != "consumers" {
		if len(tenant) != 36 {
			return "", false
		}
		for i, c := range tenant {
			if i == 8 || i == 13 || i == 18 || i == 23 {
				if c != '-' {
					return "", false
				}
			} else if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
				return "", false
			}
		}
	}
	return "https://" + microsoftTokenHost + "/" + tenant + "/oauth2/v2.0/token", true
}

type microsoftRefreshConn struct {
	net.Conn
	cleanup func()
	once    sync.Once
}

func (c *microsoftRefreshConn) Close() error {
	c.once.Do(c.cleanup)
	return nil
}

func (b *GraphBackend) refreshMicrosoftToken(ctx context.Context, refreshToken string) (microsoftAccessToken, string, error) {
	tokenURL, ok := microsoftTokenURL(b.config.MicrosoftTenantID)
	if !ok || b.transport == nil || b.config.Timeout <= 0 || !validMicrosoftRefreshToken(refreshToken) {
		return microsoftAccessToken{}, "", ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, b.config.Timeout)
	defer cancel()
	started := time.Now()
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {b.config.MicrosoftClientID},
		"client_secret": {b.config.MicrosoftClientSecret},
		"refresh_token": {refreshToken},
		"scope":         {microsoftGraphScopes},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return microsoftAccessToken{}, "", ErrUnavailable
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	transport := &http.Transport{
		// No environment proxy, redirect or second DNS lookup can receive the
		// grant. Backend.openConn vets all DNS answers before dialing an IP.
		Proxy: nil,
		DialContext: func(_ context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != microsoftTokenHost+":443" {
				return nil, ErrUnavailable
			}
			conn, cleanup, err := b.transport.openConn(ctx, config.Endpoint{Host: microsoftTokenHost, Port: 443, TLSMode: "tls"})
			if err != nil {
				return nil, err
			}
			return &microsoftRefreshConn{Conn: conn, cleanup: cleanup}, nil
		},
		TLSClientConfig:        b.transport.tlsConfig(microsoftTokenHost),
		TLSHandshakeTimeout:    b.config.Timeout,
		ResponseHeaderTimeout:  b.config.Timeout,
		MaxResponseHeaderBytes: 16 << 10,
		DisableKeepAlives:      true,
		DisableCompression:     true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: b.config.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return microsoftAccessToken{}, "", ctx.Err()
		}
		return microsoftAccessToken{}, "", ErrUnavailable
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return microsoftAccessToken{}, "", ErrUnavailable
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxMicrosoftTokenResponse+1))
	if ctx.Err() != nil {
		return microsoftAccessToken{}, "", ctx.Err()
	}
	if err != nil || len(body) > maxMicrosoftTokenResponse {
		return microsoftAccessToken{}, "", ErrUnavailable
	}
	fields, err := microsoftTokenFields(body)
	if err != nil {
		return microsoftAccessToken{}, "", ErrUnavailable
	}
	if _, failed := fields["error"]; failed {
		return microsoftAccessToken{}, "", ErrUnavailable
	}
	var access, tokenType, scope, rotated string
	var expires int64
	if json.Unmarshal(fields["access_token"], &access) != nil || !validMicrosoftAccessToken(access) ||
		json.Unmarshal(fields["token_type"], &tokenType) != nil || !strings.EqualFold(tokenType, "Bearer") ||
		json.Unmarshal(fields["expires_in"], &expires) != nil || expires <= 0 || expires > int64((1<<63-1)/time.Second) ||
		json.Unmarshal(fields["scope"], &scope) != nil || !hasMicrosoftGraphScopes(scope) {
		return microsoftAccessToken{}, "", ErrUnavailable
	}
	if raw, present := fields["refresh_token"]; present {
		if json.Unmarshal(raw, &rotated) != nil || !validMicrosoftRefreshToken(rotated) {
			return microsoftAccessToken{}, "", ErrUnavailable
		}
	}
	lifetime := time.Duration(expires) * time.Second
	margin := min(30*time.Second, lifetime/10)
	token := microsoftAccessToken{value: access, usableUntil: started.Add(lifetime - margin)}
	if err := ctx.Err(); err != nil {
		return microsoftAccessToken{}, "", err
	}
	if !time.Now().Before(token.usableUntil) {
		return microsoftAccessToken{}, "", ErrUnavailable
	}
	return token, rotated, nil
}

func hasMicrosoftGraphScopes(scope string) bool {
	var readUser, readWriteMail, sendMail bool
	for _, value := range strings.Fields(scope) {
		switch value {
		case "User.Read", "https://graph.microsoft.com/User.Read":
			readUser = true
		case "Mail.ReadWrite", "https://graph.microsoft.com/Mail.ReadWrite":
			readWriteMail = true
		case "Mail.Send", "https://graph.microsoft.com/Mail.Send":
			sendMail = true
		}
	}
	return readUser && readWriteMail && sendMail
}

// Graph access tokens are opaque. This only checks the RFC 6750 bearer syntax
// needed to construct a header; it does not decode a JWT or verify identity.
// Identity is established separately by Graph's /me response over verified TLS.
func validMicrosoftAccessToken(value string) bool {
	if len(value) == 0 || len(value) > 16<<10 {
		return false
	}
	padding := false
	for _, r := range value {
		if r == '=' {
			padding = true
			continue
		}
		if padding || !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-._~+/", r)) {
			return false
		}
	}
	return value[0] != '='
}

func validMicrosoftRefreshToken(value string) bool {
	if len(value) == 0 || len(value) > 16<<10 {
		return false
	}
	for _, r := range value {
		if r < 0x21 || r > 0x7e {
			return false
		}
	}
	return true
}

// Accept additive response metadata but reject duplicate fields, trailing JSON
// or non-object bodies. None of these fields are ever used as error messages.
func microsoftTokenFields(body []byte) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(strings.NewReader(string(body)))
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return nil, ErrUnavailable
	}
	fields := make(map[string]json.RawMessage)
	for d.More() {
		key, err := d.Token()
		name, ok := key.(string)
		if err != nil || !ok {
			return nil, ErrUnavailable
		}
		if _, exists := fields[name]; exists {
			return nil, ErrUnavailable
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return nil, ErrUnavailable
		}
		fields[name] = value
	}
	if last, err := d.Token(); err != nil || last != json.Delim('}') {
		return nil, ErrUnavailable
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, ErrUnavailable
	}
	return fields, nil
}

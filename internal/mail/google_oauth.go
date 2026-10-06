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
	googleTokenHost        = "oauth2.googleapis.com"
	googleTokenURL         = "https://oauth2.googleapis.com/token"
	googleMailScope        = "https://mail.google.com/"
	maxGoogleTokenResponse = 64 << 10
)

// Credentials and access tokens stay in this backend's memory. Neither refresh
// responses nor authentication exchanges are logged or included in errors.
type googleAccessToken struct {
	value       string
	usableUntil time.Time
	key         [32]byte
	generation  uint64
}

type googleTokenFlight struct {
	done  chan struct{}
	token googleAccessToken
	err   error
}

type googleTokenCache struct {
	mu         sync.Mutex
	token      googleAccessToken
	flight     *googleTokenFlight
	generation uint64
}

func (b *Backend) googleCredentialKey() [32]byte {
	return sha256.Sum256([]byte(b.config.GoogleClientID + "\x00" + b.config.GoogleClientSecret + "\x00" + b.config.GoogleRefreshToken + "\x00" + b.config.Username))
}

// googleToken shares one refresh among concurrent mailbox connections. A
// waiting caller can cancel independently. Cancellation of the refresh owner
// fails that flight; a subsequent operation may try a new refresh, never an
// expired cached token or password fallback.
func (b *Backend) googleToken(ctx context.Context) (googleAccessToken, error) {
	if err := ctx.Err(); err != nil {
		return googleAccessToken{}, err
	}
	key := b.googleCredentialKey()
	cache := &b.googleTokens
	cache.mu.Lock()
	if cache.token.key == key && cache.token.value != "" && time.Now().Before(cache.token.usableUntil) {
		token := cache.token
		cache.mu.Unlock()
		return token, nil
	}
	if flight := cache.flight; flight != nil {
		cache.mu.Unlock()
		select {
		case <-ctx.Done():
			return googleAccessToken{}, ctx.Err()
		case <-flight.done:
			if flight.err != nil {
				return googleAccessToken{}, flight.err
			}
			if flight.token.key != key || !time.Now().Before(flight.token.usableUntil) {
				return googleAccessToken{}, ErrUnavailable
			}
			return flight.token, nil
		}
	}
	flight := &googleTokenFlight{done: make(chan struct{})}
	cache.flight = flight
	cache.mu.Unlock()

	token, err := b.refreshGoogleToken(ctx)
	cache.mu.Lock()
	if err == nil {
		cache.generation++
		token.key = key
		token.generation = cache.generation
		cache.token = token
	}
	flight.token, flight.err = token, err
	cache.flight = nil
	close(flight.done)
	cache.mu.Unlock()
	return token, err
}

// A failed old authentication must not invalidate a newer concurrent refresh,
// even if Google happened to return the same token string again.
func (b *Backend) invalidateGoogleToken(token googleAccessToken) {
	cache := &b.googleTokens
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if cache.token.key == token.key && cache.token.generation == token.generation {
		cache.token = googleAccessToken{}
	}
}

// Bind raw transport lifetime and deadlines to the refresh request, including
// cancellation while TLS is closing or the HTTP transport is still dialing.
type googleRefreshConn struct {
	net.Conn
	cleanup func()
	once    sync.Once
}

func (c *googleRefreshConn) Close() error {
	c.once.Do(c.cleanup)
	return nil
}

func (b *Backend) refreshGoogleToken(ctx context.Context) (googleAccessToken, error) {
	ctx, cancel := context.WithTimeout(ctx, b.config.Timeout)
	defer cancel()
	started := time.Now()
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {b.config.GoogleClientID},
		"client_secret": {b.config.GoogleClientSecret},
		"refresh_token": {b.config.GoogleRefreshToken},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, googleTokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return googleAccessToken{}, ErrUnavailable
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	transport := &http.Transport{
		// No environment proxies, redirects, alternate endpoints or second DNS
		// lookup may receive these credentials. dial vets every DNS answer.
		Proxy: nil,
		DialContext: func(_ context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != googleTokenHost+":443" {
				return nil, ErrUnavailable
			}
			conn, cleanup, err := b.openConn(ctx, config.Endpoint{Host: googleTokenHost, Port: 443, TLSMode: "tls"})
			if err != nil {
				return nil, err
			}
			return &googleRefreshConn{Conn: conn, cleanup: cleanup}, nil
		},
		TLSClientConfig:        b.tlsConfig(googleTokenHost),
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
			return googleAccessToken{}, ctx.Err()
		}
		return googleAccessToken{}, ErrUnavailable
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return googleAccessToken{}, ErrUnavailable
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxGoogleTokenResponse+1))
	if err != nil || len(body) > maxGoogleTokenResponse {
		return googleAccessToken{}, ErrUnavailable
	}
	fields, err := googleTokenFields(body)
	if err != nil {
		return googleAccessToken{}, ErrUnavailable
	}
	if _, failed := fields["error"]; failed {
		return googleAccessToken{}, ErrUnavailable
	}
	var access, tokenType string
	var expires int64
	if json.Unmarshal(fields["access_token"], &access) != nil || !validGoogleAccessToken(access) ||
		json.Unmarshal(fields["token_type"], &tokenType) != nil || !strings.EqualFold(tokenType, "Bearer") ||
		json.Unmarshal(fields["expires_in"], &expires) != nil || expires <= 0 || expires > int64((1<<63-1)/time.Second) {
		return googleAccessToken{}, ErrUnavailable
	}
	if rawScope, present := fields["scope"]; present {
		var scope string
		if json.Unmarshal(rawScope, &scope) != nil {
			return googleAccessToken{}, ErrUnavailable
		}
		found := false
		for _, value := range strings.Fields(scope) {
			found = found || value == googleMailScope
		}
		if !found {
			return googleAccessToken{}, ErrUnavailable
		}
	}
	lifetime := time.Duration(expires) * time.Second
	margin := min(30*time.Second, lifetime/10)
	token := googleAccessToken{value: access, usableUntil: started.Add(lifetime - margin)}
	if ctx.Err() != nil {
		return googleAccessToken{}, ctx.Err()
	}
	if !time.Now().Before(token.usableUntil) {
		return googleAccessToken{}, ErrUnavailable
	}
	return token, nil
}

// Accept additive Google fields (including a new refresh_token, which is never
// persisted), but reject duplicate keys, trailing JSON and non-object bodies.
func googleTokenFields(body []byte) (map[string]json.RawMessage, error) {
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

func validGoogleAccessToken(value string) bool {
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

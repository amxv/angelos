package mail

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/amxv/angelos/internal/config"
)

const fakeMicrosoftTokenResponse = `{"access_token":"opaque-test-access-token","token_type":"Bearer","expires_in":120,"scope":"User.Read Mail.ReadWrite Mail.Send"}`

func microsoftOAuthTestCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: microsoftTokenHost},
		DNSNames: []string{microsoftTokenHost, "graph.microsoft.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, roots
}

func microsoftRefreshBackend(t *testing.T, handler http.HandlerFunc) *GraphBackend {
	t.Helper()
	c := config.Config{
		Provider: "microsoft", AuthMode: "microsoft_graph", From: "person@example.com",
		MicrosoftClientID: "synthetic-client-id", MicrosoftClientSecret: "synthetic-client-secret",
		MicrosoftRefreshToken: "synthetic-refresh-token", MicrosoftTenantID: "consumers",
		MicrosoftAccountID: "synthetic-account", MicrosoftTokenEncryptionKey: strings.Repeat("12", 32), Timeout: 2 * time.Second,
	}
	b := &GraphBackend{config: c, transport: &Backend{config: c}}
	if err := b.ConfigureTokenStore(newMicrosoftMemoryTokenStore()); err != nil {
		t.Fatal(err)
	}
	cert, roots := microsoftOAuthTestCertificate(t)
	b.transport.roots = roots
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Host != microsoftTokenHost || r.URL.Path != "/"+b.config.MicrosoftTenantID+"/oauth2/v2.0/token" || r.URL.RawQuery != "" || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || r.Header.Get("Authorization") != "" || r.Header.Get("Accept") != "application/json" {
			t.Error("incorrect refresh request metadata")
		}
		if err := r.ParseForm(); err != nil {
			t.Error("unable to parse synthetic refresh grant")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		handler(w, r)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	t.Cleanup(server.Close)
	b.transport.dialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != microsoftTokenHost+":443" {
			t.Error("unapproved OAuth destination")
			return nil, ErrUnavailable
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
	}
	return b
}

func expireMicrosoftToken(b *GraphBackend) {
	b.tokens.mu.Lock()
	defer b.tokens.mu.Unlock()
	b.tokens.token.usableUntil = time.Now().Add(-time.Second)
}

func TestMicrosoftRefreshFormCacheExpiryAndRotation(t *testing.T) {
	var calls atomic.Int32
	b := microsoftRefreshBackend(t, func(w http.ResponseWriter, r *http.Request) {
		call := calls.Add(1)
		if len(r.PostForm) != 5 || r.PostForm.Get("grant_type") != "refresh_token" || r.PostForm.Get("client_id") != "synthetic-client-id" || r.PostForm.Get("client_secret") != "synthetic-client-secret" || r.PostForm.Get("scope") != microsoftGraphScopes {
			t.Error("incorrect refresh form")
		}
		wantRefresh := "synthetic-refresh-token"
		if call > 1 {
			wantRefresh = "rotated-refresh-token"
		}
		if r.PostForm.Get("refresh_token") != wantRefresh {
			t.Error("refresh rotation was not retained in memory")
		}
		if call == 1 {
			fmt.Fprint(w, strings.TrimSuffix(fakeMicrosoftTokenResponse, "}")+`,"refresh_token":"rotated-refresh-token"}`)
		} else {
			fmt.Fprint(w, fakeMicrosoftTokenResponse)
		}
	})
	started := time.Now()
	first, err := b.graphToken(context.Background())
	if err != nil || first != "opaque-test-access-token" {
		t.Fatalf("refresh failed: %v", err)
	}
	if b.tokens.token.usableUntil.Before(started.Add(107*time.Second)) || b.tokens.token.usableUntil.After(time.Now().Add(108*time.Second)) {
		t.Fatal("response lifetime and safety margin were not used")
	}
	if second, err := b.graphToken(context.Background()); err != nil || second != first || calls.Load() != 1 {
		t.Fatal("token was not cached")
	}
	expireMicrosoftToken(b)
	if _, err := b.graphToken(context.Background()); err != nil || calls.Load() != 2 {
		t.Fatal("expired token did not refresh")
	}
	b.graphInvalidateToken(first)
	if _, err := b.graphToken(context.Background()); err != nil || calls.Load() != 3 {
		t.Fatal("rejected token did not refresh")
	}
	if b.config.MicrosoftRefreshToken != "synthetic-refresh-token" || b.tokens.refreshToken != "rotated-refresh-token" {
		t.Fatal("rotated token escaped memory or was discarded")
	}
}

func TestMicrosoftRefreshCacheBoundToCredentialsAndIdentity(t *testing.T) {
	var calls atomic.Int32
	b := microsoftRefreshBackend(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		want := "synthetic-refresh-token"
		if calls.Load() == 3 {
			want = "rotated-refresh-token" // Client-secret change keeps this grant.
		}
		if r.PostForm.Get("refresh_token") != want {
			t.Error("rotation crossed an authorization generation")
		}
		fmt.Fprint(w, strings.TrimSuffix(fakeMicrosoftTokenResponse, "}")+`,"refresh_token":"rotated-refresh-token"}`)
	})
	if _, err := b.graphToken(context.Background()); err != nil {
		t.Fatal(err)
	}
	changes := []func(){
		func() { b.config.MicrosoftClientID = "changed-client" },
		func() { b.config.MicrosoftClientSecret = "changed-secret" },
		func() { b.config.MicrosoftTenantID = "12345678-1234-1234-1234-123456789ABC" },
		func() { b.config.MicrosoftAccountID = "changed-account" },
		func() { b.config.From = "changed@example.com" },
	}
	for i, change := range changes {
		change()
		if _, err := b.graphToken(context.Background()); err != ErrUnavailable {
			t.Fatal("changed runtime identity reused a differently bound store")
		}
		client := b.tokenStore.client
		b.tokens = microsoftTokenCache{}
		b.tokenStore = nil
		if err := b.ConfigureTokenStore(client); err != nil {
			t.Fatal(err)
		}
		if _, err := b.graphToken(context.Background()); err != nil || int(calls.Load()) != i+2 {
			t.Fatal("cache was not bound to configured credentials and identity")
		}
	}
	// An explicit configured refresh-token replacement starts a new cache too.
	b.config.MicrosoftRefreshToken = "changed-refresh"
	oldKey := b.tokens.token.key
	if b.microsoftCredentialKey() == oldKey {
		t.Fatal("refresh credential was not included in cache key")
	}
}

func TestMicrosoftRefreshConcurrentCallers(t *testing.T) {
	var calls atomic.Int32
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	b := microsoftRefreshBackend(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		once.Do(func() { close(entered) })
		select {
		case <-release:
			fmt.Fprint(w, fakeMicrosoftTokenResponse)
		case <-r.Context().Done():
		}
	})
	const count = 32
	var wg sync.WaitGroup
	wg.Add(count)
	for range count {
		go func() {
			defer wg.Done()
			token, err := b.graphToken(context.Background())
			if err != nil || token != "opaque-test-access-token" {
				t.Errorf("concurrent token refresh failed: %v", err)
			}
		}()
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("refresh did not start")
	}
	close(release)
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatal("concurrent callers did not share refresh")
	}
	b.graphInvalidateToken("different-old-token")
	if _, err := b.graphToken(context.Background()); err != nil || calls.Load() != 1 {
		t.Fatal("old rejection cleared different current token")
	}
}

func TestMicrosoftRefreshOwnerAndWaiterCancellation(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	b := microsoftRefreshBackend(t, func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(entered) })
		select {
		case <-release:
			fmt.Fprint(w, fakeMicrosoftTokenResponse)
		case <-r.Context().Done():
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	owner := make(chan error, 1)
	go func() { _, err := b.graphToken(ctx); owner <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("refresh did not start")
	}
	waiting, stopWaiting := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer stopWaiting()
	if _, err := b.graphToken(waiting); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiting cancellation failed: %v", err)
	}
	select {
	case <-owner:
		t.Fatal("waiting cancellation canceled refresh owner")
	default:
	}
	cancel()
	select {
	case err := <-owner:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("owner cancellation failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("owner cancellation did not stop refresh")
	}
	if b.tokens.token.value != "" || b.tokens.refreshToken != "" {
		t.Fatal("canceled refresh populated cache")
	}
	close(release)
	if _, err := b.graphToken(context.Background()); err != nil {
		t.Fatalf("operation could not recover after canceled refresh: %v", err)
	}
	if _, err := b.graphToken(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("cache hit ignored canceled context")
	}
}

func TestMicrosoftRefreshRequiresExactScopes(t *testing.T) {
	for _, scopes := range []string{
		"User.Read Mail.ReadWrite Mail.Send", microsoftGraphScopes,
		"https://graph.microsoft.com/User.Read Mail.ReadWrite https://graph.microsoft.com/Mail.Send",
		"openid profile User.Read Mail.ReadWrite Mail.Send",
	} {
		t.Run(scopes, func(t *testing.T) {
			body := strings.Replace(fakeMicrosoftTokenResponse, "User.Read Mail.ReadWrite Mail.Send", scopes, 1)
			b := microsoftRefreshBackend(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) })
			if _, err := b.graphToken(context.Background()); err != nil {
				t.Fatalf("complete exact scopes rejected: %v", err)
			}
		})
	}
	for _, scopes := range []string{
		"", "Mail.ReadWrite Mail.Send", "User.Read Mail.Send", "User.Read Mail.ReadWrite",
		"User.Read Mail.ReadWrite.Shared Mail.Send", "User.Read Mail.ReadWrite Mail.Send.Shared",
		"User.Read Mail.Read Mail.Send", "User.Read Mail.ReadWrite fake.Mail.Send",
		"user.read Mail.ReadWrite Mail.Send", "User.Read Mail.ReadWrite mail.send",
		"User.Read Mail.ReadWrite https://attacker.example/Mail.Send",
		"User.Read Mail.ReadWrite https://graph.microsoft.com/Mail.Send/",
		"User.Read Mail.ReadWrite https://graph.microsoft.com//Mail.Send",
	} {
		if hasMicrosoftGraphScopes(scopes) {
			t.Errorf("unapproved scopes accepted: %q", scopes)
		}
	}
}

func TestMicrosoftRefreshMalformedResponsesAndStaticErrors(t *testing.T) {
	bodies := []string{"", "null", "[]", "{}", fakeMicrosoftTokenResponse + "{}", strings.Repeat(" ", maxMicrosoftTokenResponse+1),
		strings.TrimSuffix(fakeMicrosoftTokenResponse, "}") + `,"access_token":"duplicate"}`,
		strings.TrimSuffix(fakeMicrosoftTokenResponse, "}") + `,"error":"fake-access-token synthetic-client-secret synthetic-refresh-token"}`,
	}
	var base map[string]any
	if err := json.Unmarshal([]byte(fakeMicrosoftTokenResponse), &base); err != nil {
		t.Fatal(err)
	}
	changes := map[string][]any{
		"access_token":  {nil, "", "token\r\ninjected", "token secret", "\x01", "bad=padding", "=", "a\u00e9", strings.Repeat("a", 16<<10+1)},
		"token_type":    {nil, "", "Basic", "Bearer "},
		"expires_in":    {nil, 0, -1, 0.5, "3600", json.Number("9223372036854775807")},
		"scope":         {nil, "", 1, []string{"User.Read", "Mail.ReadWrite", "Mail.Send"}, "User.Read Mail.ReadWrite"},
		"refresh_token": {nil, "", "bad\r\ntoken", "bad token", strings.Repeat("a", 16<<10+1)},
	}
	for field, values := range changes {
		for _, value := range values {
			changed := make(map[string]any, len(base))
			for k, v := range base {
				changed[k] = v
			}
			changed[field] = value
			body, err := json.Marshal(changed)
			if err != nil {
				t.Fatal(err)
			}
			bodies = append(bodies, string(body))
		}
	}
	for _, field := range []string{"access_token", "token_type", "expires_in", "scope"} {
		changed := make(map[string]any, len(base))
		for k, v := range base {
			if k != field {
				changed[k] = v
			}
		}
		body, _ := json.Marshal(changed)
		bodies = append(bodies, string(body))
	}
	for i, body := range bodies {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			b := microsoftRefreshBackend(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) })
			if token, err := b.graphToken(context.Background()); err != ErrUnavailable || token != "" {
				t.Fatalf("malformed response did not fail statically: %v", err)
			}
			if b.tokens.token.value != "" || b.tokens.refreshToken != "" {
				t.Fatal("malformed response changed credentials")
			}
		})
	}
	for _, status := range []int{400, 401, 403, 429, 500} {
		b := microsoftRefreshBackend(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
			fmt.Fprint(w, `{"error_description":"synthetic-client-secret synthetic-refresh-token opaque-test-access-token"}`)
		})
		if _, err := b.graphToken(context.Background()); err != ErrUnavailable {
			t.Fatal("provider error data escaped static errors")
		}
	}
}

func TestMicrosoftRefreshPinsAuthorityAndRejectsRedirects(t *testing.T) {
	for _, tenant := range []string{"consumers", "12345678-1234-1234-1234-123456789aBc"} {
		got, ok := microsoftTokenURL(tenant)
		if !ok || got != "https://login.microsoftonline.com/"+tenant+"/oauth2/v2.0/token" {
			t.Fatal("valid pinned authority rejected")
		}
	}
	var calls atomic.Int32
	b := microsoftRefreshBackend(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1); fmt.Fprint(w, fakeMicrosoftTokenResponse) })
	for _, tenant := range []string{"", "common", "organizations", "example.com", "consumers/..", "consumers?x=", "consumers#x", "consumers%2f..", "https://attacker.example", "12345678-1234-1234-1234-123456789ABC/", "12345678-1234-1234-1234-123456789ABG", "123456781123411234112341123456789ABC"} {
		b.config.MicrosoftTenantID = tenant
		if _, err := b.graphToken(context.Background()); err != ErrUnavailable || calls.Load() != 0 {
			t.Fatal("unsafe tenant reached network")
		}
	}
	for _, location := range []string{"https://attacker.example/token", "https://login.microsoftonline.com/consumers/oauth2/v2.0/token", "http://login.microsoftonline.com/consumers/oauth2/v2.0/token"} {
		var calls atomic.Int32
		b := microsoftRefreshBackend(t, func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			w.Header().Set("Location", location)
			w.WriteHeader(http.StatusTemporaryRedirect)
		})
		if _, err := b.graphToken(context.Background()); err != ErrUnavailable || calls.Load() != 1 {
			t.Fatal("refresh redirect followed")
		}
	}
}

func TestMicrosoftRefreshTLSAndPublicDNS(t *testing.T) {
	var sent atomic.Bool
	b := microsoftRefreshBackend(t, func(w http.ResponseWriter, r *http.Request) {
		sent.Store(true)
		fmt.Fprint(w, fakeMicrosoftTokenResponse)
	})
	b.transport.roots = x509.NewCertPool()
	if _, err := b.graphToken(context.Background()); err != ErrUnavailable || sent.Load() {
		t.Fatal("credentials sent before verified TLS")
	}
	b.transport.dialContext = nil
	b.transport.lookupIP = func(ctx context.Context, network, host string) ([]net.IP, error) {
		if host != microsoftTokenHost {
			t.Error("wrong token DNS host")
		}
		return []net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("127.0.0.1")}, nil
	}
	if _, err := b.graphToken(context.Background()); err != ErrUnavailable {
		t.Fatal("mixed public/private DNS answer accepted")
	}
}

func TestMicrosoftRefreshIgnoresProxyAndExpiresFailClosed(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	var revoked atomic.Bool
	b := microsoftRefreshBackend(t, func(w http.ResponseWriter, r *http.Request) {
		if revoked.Load() {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"invalid_grant"}`)
			return
		}
		fmt.Fprint(w, fakeMicrosoftTokenResponse)
	})
	if _, err := b.graphToken(context.Background()); err != nil {
		t.Fatalf("environment proxy affected pinned refresh: %v", err)
	}
	expireMicrosoftToken(b)
	revoked.Store(true)
	if token, err := b.graphToken(context.Background()); err != ErrUnavailable || token != "" {
		t.Fatal("expired token used after revoked grant")
	}
}

func TestMicrosoftRefreshBoundedDeadline(t *testing.T) {
	b := microsoftRefreshBackend(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, fakeMicrosoftTokenResponse) })
	b.config.Timeout = 20 * time.Millisecond // Synthetic seam, not accepted by config.Load.
	b.transport.dialContext = func(ctx context.Context, _, _ string) (net.Conn, error) { <-ctx.Done(); return nil, ctx.Err() }
	started := time.Now()
	if _, err := b.graphToken(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("refresh deadline not enforced: %v", err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("refresh exceeded bounded deadline")
	}
}

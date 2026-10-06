package mail

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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

const fakeGoogleResponse = `{"access_token":"fake-access-token","token_type":"Bearer","expires_in":3600,"scope":"https://mail.google.com/"}`

func googleOAuthTestCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: googleTokenHost}, DNSNames: []string{googleTokenHost, "imap.gmail.com", "smtp.gmail.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
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

func googleRefreshBackend(t *testing.T, handler http.HandlerFunc) *Backend {
	t.Helper()
	values := map[string]string{"MAIL_PROVIDER": "gmail", "MAIL_USERNAME": "person@example.com", "GOOGLE_CLIENT_ID": "fake-client-id", "GOOGLE_CLIENT_SECRET": "fake-client-secret", "GOOGLE_REFRESH_TOKEN": "fake-refresh-token", "MAIL_TIMEOUT": "2s"}
	c, err := config.Load(func(key string) string { return values[key] })
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	cert, roots := googleOAuthTestCertificate(t)
	b.roots = roots
	b.dialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != googleTokenHost+":443" {
			t.Error("unexpected refresh destination")
			return nil, ErrUnavailable
		}
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		go func() {
			defer listener.Close()
			server, err := listener.Accept()
			if err != nil {
				return
			}
			defer server.Close()
			server.SetDeadline(time.Now().Add(3 * time.Second))
			secure := tls.Server(server, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
			defer secure.Close()
			req, err := http.ReadRequest(bufio.NewReader(secure))
			if err != nil {
				return
			}
			defer req.Body.Close()
			if req.Method != "POST" || req.Host != googleTokenHost || req.URL.Path != "/token" || req.URL.RawQuery != "" || req.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || req.Header.Get("Authorization") != "" {
				t.Error("incorrect refresh request metadata")
			}
			recorder := httptest.NewRecorder()
			recorder.Header().Set("Content-Type", "application/json")
			// Drain the bounded synthetic refresh body before deliberately stalling.
			if err := req.ParseForm(); err != nil {
				return
			}
			handler(recorder, req)
			response := recorder.Result()
			defer response.Body.Close()
			response.Write(secure)
		}()
		client, err := (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
		if err != nil {
			listener.Close()
		}
		return client, err
	}
	return b
}

func TestGoogleRefreshFormCacheExpiryAndCredentials(t *testing.T) {
	var calls atomic.Int32
	b := googleRefreshBackend(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		if len(r.PostForm) != 4 || r.PostForm.Get("grant_type") != "refresh_token" || r.PostForm.Get("client_id") != "fake-client-id" || r.PostForm.Get("client_secret") != "fake-client-secret" || !strings.HasPrefix(r.PostForm.Get("refresh_token"), "fake-refresh-token") {
			t.Error("refresh grant fields incorrect")
		}
		fmt.Fprint(w, `{"access_token":"fake-access-token","token_type":"Bearer","expires_in":120,"refresh_token":"ignored-new-refresh-token","scope":"other https://mail.google.com/"}`)
	})
	start := time.Now()
	first, err := b.googleToken(context.Background())
	if err != nil || first.value != "fake-access-token" {
		t.Fatalf("refresh failed: %v", err)
	}
	// Use the returned 120s lifetime with its 12s safety margin, never a fixed hour.
	if first.usableUntil.Before(start.Add(107*time.Second)) || first.usableUntil.After(time.Now().Add(108*time.Second)) {
		t.Fatal("incorrect returned expiry")
	}
	second, err := b.googleToken(context.Background())
	if err != nil || second.generation != first.generation || calls.Load() != 1 {
		t.Fatal("cache miss")
	}
	if b.config.GoogleRefreshToken != "fake-refresh-token" {
		t.Fatal("refresh response persisted credentials")
	}
	b.googleTokens.mu.Lock()
	b.googleTokens.token.usableUntil = time.Now().Add(-time.Second)
	b.googleTokens.mu.Unlock()
	third, err := b.googleToken(context.Background())
	if err != nil || third.generation == first.generation || calls.Load() != 2 {
		t.Fatal("expired token reused")
	}
	b.config.GoogleRefreshToken = "fake-refresh-token-changed"
	fourth, err := b.googleToken(context.Background())
	if err != nil || fourth.key == third.key || calls.Load() != 3 {
		t.Fatal("cache not bound to credentials")
	}
	b.invalidateGoogleToken(third)
	if _, err := b.googleToken(context.Background()); err != nil || calls.Load() != 3 {
		t.Fatal("old rejection invalidated new credentials")
	}
}

func TestGoogleRefreshConcurrentCallers(t *testing.T) {
	var calls atomic.Int32
	entered, release := make(chan struct{}), make(chan struct{})
	b := googleRefreshBackend(t, func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			close(entered)
		}
		<-release
		fmt.Fprint(w, fakeGoogleResponse)
	})
	const count = 32
	var wg sync.WaitGroup
	wg.Add(count)
	results := make(chan googleAccessToken, count)
	for range count {
		go func() {
			defer wg.Done()
			token, err := b.googleToken(context.Background())
			if err != nil {
				t.Errorf("concurrent refresh failed: %v", err)
			}
			results <- token
		}()
	}
	<-entered
	close(release)
	wg.Wait()
	close(results)
	var first googleAccessToken
	for token := range results {
		if first.value == "" {
			first = token
		}
		if token.generation != first.generation || token.value != first.value {
			t.Fatal("callers got inconsistent tokens")
		}
	}
	if calls.Load() != 1 {
		t.Fatal("refresh was not shared")
	}
	// Same value, newer generation: a late failure must not wipe the new cache.
	b.invalidateGoogleToken(first)
	second, err := b.googleToken(context.Background())
	if err != nil || second.generation == first.generation {
		t.Fatal("token invalidation did not refresh")
	}
	b.invalidateGoogleToken(first)
	if _, err := b.googleToken(context.Background()); err != nil || calls.Load() != 2 {
		t.Fatal("late failure wiped newer generation")
	}
}

func TestGoogleRefreshCancellationAndWaitingCancellation(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	b := googleRefreshBackend(t, func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(entered) })
		<-release
		fmt.Fprint(w, fakeGoogleResponse)
	})
	ctx, cancel := context.WithCancel(context.Background())
	owner := make(chan error, 1)
	go func() { _, err := b.googleToken(ctx); owner <- err }()
	<-entered
	waiting, stopWaiting := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer stopWaiting()
	if _, err := b.googleToken(waiting); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiting cancellation: %v", err)
	}
	cancel()
	select {
	case err := <-owner:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("refresh owner cancellation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("owner cancellation did not interrupt refresh")
	}
	close(release)
	if b.googleTokens.token.value != "" {
		t.Fatal("canceled refresh cached a token")
	}
	if _, err := b.googleToken(context.Background()); err != nil {
		t.Fatalf("new operation could not refresh after cancellation: %v", err)
	}
	canceled, done := context.WithCancel(context.Background())
	done()
	if _, err := b.googleToken(canceled); !errors.Is(err, context.Canceled) {
		t.Fatal("cached token ignored cancellation")
	}
}

func TestGoogleRefreshMalformedResponsesAndRedaction(t *testing.T) {
	bodies := []string{
		``, `null`, `[]`, `{}`, `{"access_token":"fake-access-token","token_type":"Bearer"}`,
		`{"access_token":"fake-access-token","token_type":"Basic","expires_in":3600}`,
		`{"access_token":"fake-access-token","token_type":"Bearer ","expires_in":3600}`,
		`{"access_token":"fake-access-token","token_type":"Bearer","expires_in":0}`,
		`{"access_token":"fake-access-token","token_type":"Bearer","expires_in":-1}`,
		`{"access_token":"fake-access-token","token_type":"Bearer","expires_in":1.5}`,
		`{"access_token":"fake-access-token","token_type":"Bearer","expires_in":"3600"}`,
		`{"access_token":"fake-access-token","token_type":"Bearer","expires_in":9223372036854775807}`,
		`{"access_token":"fake-access-token","token_type":"Bearer","expires_in":3600,"scope":"https://www.googleapis.com/auth/gmail.readonly"}`,
		`{"access_token":"fake-access-token","token_type":"Bearer","expires_in":3600,"scope":"https://mail.google.com"}`,
		`{"access_token":"fake-access-token","token_type":"Bearer","expires_in":3600,"scope":null}`,
		`{"access_token":"fake-access-token","access_token":"other","token_type":"Bearer","expires_in":3600}`,
		fakeGoogleResponse + `{}`,
		`{"error":"invalid_grant","access_token":"fake-access-token","token_type":"Bearer","expires_in":3600}`,
		`{"access_token":null,"token_type":"Bearer","expires_in":3600}`,
		`{"access_token":"fake-access-token","token_type":null,"expires_in":3600}`,
		`{"access_token":"fake-access-token","token_type":"Bearer","expires_in":null}`,
		`{"access_token":"fake-access-token","token_type":"Bearer","expires_in":3600,"scope":""}`,
		`{"access_token":"fake-access-token","token_type":"Bearer","expires_in":3600,"scope":["https://mail.google.com/"]}`,
		`{"access_token":"bad\r\ntoken","token_type":"Bearer","expires_in":3600}`,
		`{"access_token":"bad\u0001token","token_type":"Bearer","expires_in":3600}`,
		`{"access_token":"bad token","token_type":"Bearer","expires_in":3600}`,
		`{"access_token":"bad=padding","token_type":"Bearer","expires_in":3600}`,
		`{"access_token":"=","token_type":"Bearer","expires_in":3600}`,
		`{"access_token":"` + strings.Repeat("a", 16<<10+1) + `","token_type":"Bearer","expires_in":3600}`,
		strings.Repeat(" ", maxGoogleTokenResponse+1),
	}
	for i, body := range bodies {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			b := googleRefreshBackend(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) })
			if _, err := b.googleToken(context.Background()); err != ErrUnavailable {
				t.Fatalf("response did not fail statically: %v", err)
			}
			if b.googleTokens.token.value != "" {
				t.Fatal("malformed response cached")
			}
		})
	}
	for _, status := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests, http.StatusInternalServerError} {
		b := googleRefreshBackend(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
			fmt.Fprint(w, `{"error":"invalid_grant","error_description":"fake-client-secret fake-refresh-token fake-access-token"}`)
		})
		if _, err := b.googleToken(context.Background()); err != ErrUnavailable {
			t.Fatal("provider error leaked")
		}
	}
}

func TestGoogleRefreshDoesNotFollowRedirects(t *testing.T) {
	for _, location := range []string{"https://attacker.example/token", googleTokenURL, "http://oauth2.googleapis.com/token"} {
		var calls atomic.Int32
		b := googleRefreshBackend(t, func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			w.Header().Set("Location", location)
			w.WriteHeader(http.StatusTemporaryRedirect)
		})
		if _, err := b.googleToken(context.Background()); err != ErrUnavailable || calls.Load() != 1 {
			t.Fatal("refresh redirect followed")
		}
	}
}

func TestGoogleRefreshValidatesTLSAndDNS(t *testing.T) {
	var sent atomic.Bool
	b := googleRefreshBackend(t, func(w http.ResponseWriter, r *http.Request) { sent.Store(true); fmt.Fprint(w, fakeGoogleResponse) })
	b.roots = x509.NewCertPool()
	if _, err := b.googleToken(context.Background()); err != ErrUnavailable || sent.Load() {
		t.Fatal("credentials sent before verified TLS")
	}
	b.dialContext = nil
	b.lookupIP = func(ctx context.Context, network, host string) ([]net.IP, error) {
		if host != googleTokenHost {
			t.Error("incorrect token DNS host")
		}
		return []net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("127.0.0.1")}, nil
	}
	if _, err := b.googleToken(context.Background()); err != ErrUnavailable {
		t.Fatal("private token DNS answer accepted")
	}
}

func TestGoogleRefreshNoExpiredFallback(t *testing.T) {
	var fail atomic.Bool
	b := googleRefreshBackend(t, func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"invalid_grant"}`)
			return
		}
		fmt.Fprint(w, fakeGoogleResponse)
	})
	if _, err := b.googleToken(context.Background()); err != nil {
		t.Fatal(err)
	}
	b.googleTokens.mu.Lock()
	b.googleTokens.token.usableUntil = time.Now().Add(-time.Second)
	b.googleTokens.mu.Unlock()
	fail.Store(true)
	if token, err := b.googleToken(context.Background()); err != ErrUnavailable || token.value != "" {
		t.Fatal("expired token used after revoked grant")
	}
}

func TestGoogleRefreshMissingOptionalScopeAndBoundedDeadline(t *testing.T) {
	b := googleRefreshBackend(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"access_token":"fake-access-token","token_type":"bearer","expires_in":3600}`)
	})
	if _, err := b.googleToken(context.Background()); err != nil {
		t.Fatal("optional scope rejected")
	}
	b = googleRefreshBackend(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, fakeGoogleResponse) })
	b.config.Timeout = 20 * time.Millisecond // Private synthetic seam; never accepted by config.Load.
	b.dialContext = func(ctx context.Context, _, _ string) (net.Conn, error) { <-ctx.Done(); return nil, ctx.Err() }
	start := time.Now()
	if _, err := b.googleToken(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("unbounded refresh: %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("refresh exceeded deadline")
	}
}

func TestXOAUTH2PayloadAndChallengeState(t *testing.T) {
	c := &xoauth2Client{username: "person@example.com", token: "fake-access-token"}
	mech, response, err := c.Start()
	if err != nil || mech != "XOAUTH2" || string(response) != "user=person@example.com\x01auth=Bearer fake-access-token\x01\x01" {
		t.Fatal("incorrect raw XOAUTH2 payload")
	}
	response, err = c.Next([]byte(`{"status":"401"}`))
	if err != nil || response == nil || len(response) != 0 || !c.challenged {
		t.Fatal("challenge must get non-nil empty response")
	}
	if _, err := c.Next([]byte("again")); err != ErrUnavailable {
		t.Fatal("repeated challenge accepted")
	}
	if _, _, err := c.Start(); err != ErrUnavailable {
		t.Fatal("client restarted")
	}
	c = &xoauth2Client{}
	if _, err := c.Next(nil); err != ErrUnavailable {
		t.Fatal("challenge before initial response accepted")
	}
	for _, token := range []string{"", "a\x01b", "a\nb", "a b", "=", "a=b"} {
		c = &xoauth2Client{username: "person@example.com", token: token}
		if _, _, err := c.Start(); err != ErrUnavailable {
			t.Fatal("unsafe token accepted")
		}
	}
}

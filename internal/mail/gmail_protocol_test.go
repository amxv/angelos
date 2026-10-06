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
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/amxv/angelos/internal/config"
)

const (
	gmailProtocolMailbox = "person@workspace.example"
	gmailProtocolAccess  = "synthetic-access-token"
	gmailProtocolRefresh = "synthetic-refresh-token"
	gmailProtocolSecret  = "synthetic-client-secret"
	gmailProtocolCanary  = "provider-private-diagnostic-canary"
)

// These tests use real ephemeral loopback TLS connections and fake credentials.
// The production endpoint, TLS ServerName and certificate validation are kept.
func gmailProtocolCertificate(t *testing.T, hosts ...string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(23), Subject: pkix.Name{CommonName: hosts[0]}, DNSNames: hosts,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
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

type gmailProtocolOptions struct {
	protocol              string
	startTLS              bool
	saslIR                bool
	auth                  string
	outcome               string
	untrusted             bool
	wrongHostname         bool
	newerGeneration       bool
	finalGate             <-chan struct{}
	challengeAcknowledged chan<- struct{}
}

type gmailProtocolObservation struct {
	lines           []string
	tls             bool
	serverName      string
	auth            bool
	initialResponse bool
	emptyResponses  int
	canceled        bool
	mail            bool
	data            bool
	list            bool
	err             error
}

type gmailProtocolServer struct {
	conn        net.Conn
	reader      *bufio.Reader
	cert        tls.Certificate
	options     gmailProtocolOptions
	observation gmailProtocolObservation
	onChallenge func()
}

func (s *gmailProtocolServer) write(format string, args ...any) bool {
	_, err := fmt.Fprintf(s.conn, format, args...)
	return err == nil
}

func (s *gmailProtocolServer) read() (string, bool) {
	line, err := s.reader.ReadString('\n')
	if err != nil {
		return "", false
	}
	line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
	s.observation.lines = append(s.observation.lines, line)
	return line, true
}

func (s *gmailProtocolServer) fail(format string, args ...any) {
	if s.observation.err == nil {
		s.observation.err = fmt.Errorf(format, args...)
	}
}

func (s *gmailProtocolServer) handshake() bool {
	secure := tls.Server(s.conn, &tls.Config{Certificates: []tls.Certificate{s.cert}, MinVersion: tls.VersionTLS12})
	if err := secure.Handshake(); err != nil {
		return false
	}
	s.observation.tls = true
	s.observation.serverName = secure.ConnectionState().ServerName
	s.conn = secure
	s.reader = bufio.NewReader(secure)
	return true
}

func (s *gmailProtocolServer) checkResponse(encoded string) {
	if !s.observation.tls {
		s.fail("credential transmitted before TLS")
	}
	got, err := base64.StdEncoding.DecodeString(encoded)
	want := "user=" + gmailProtocolMailbox + "\x01auth=Bearer " + gmailProtocolAccess + "\x01\x01"
	if err != nil || string(got) != want {
		s.fail("XOAUTH2 payload was not the exact single-base64-encoded response")
	}
	s.observation.auth = true
}

func (s *gmailProtocolServer) challenge() string {
	if s.onChallenge != nil {
		s.onChallenge()
	}
	if s.options.auth == "malformed_base64" {
		return "%%%not-base64%%%"
	}
	if s.options.auth == "malformed_json" {
		return base64.StdEncoding.EncodeToString([]byte("not JSON " + gmailProtocolCanary))
	}
	return base64.StdEncoding.EncodeToString([]byte(`{"status":"401","schemes":"bearer","scope":"https://mail.google.com/","canary":"` + gmailProtocolCanary + ` ` + gmailProtocolAccess + ` ` + gmailProtocolRefresh + ` ` + gmailProtocolSecret + `"}`))
}

func (s *gmailProtocolServer) awaitFinal() bool {
	if s.options.finalGate == nil {
		return true
	}
	select {
	case s.options.challengeAcknowledged <- struct{}{}:
	case <-time.After(time.Second):
		s.fail("challenge acknowledgement observer timed out")
		return false
	}
	select {
	case <-s.options.finalGate:
		return true
	case <-time.After(time.Second):
		s.fail("terminal authentication reply gate timed out")
		return false
	}
}

func (s *gmailProtocolServer) serveIMAP() {
	if !s.handshake() {
		return
	}
	caps := "IMAP4rev1 AUTH=PLAIN AUTH=LOGIN"
	if s.options.auth != "absent" {
		caps += " AUTH=XOAUTH2"
	}
	if s.options.saslIR {
		caps += " SASL-IR"
	}
	if !s.write("* OK [CAPABILITY %s] local Gmail fixture\r\n", caps) {
		return
	}
	for {
		line, ok := s.read()
		if !ok {
			return
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			s.fail("unexpected IMAP command")
			return
		}
		tag, command := fields[0], strings.ToUpper(fields[1])
		switch command {
		case "CAPABILITY":
			if !s.write("* CAPABILITY %s\r\n%s OK capability\r\n", caps, tag) {
				return
			}
		case "AUTHENTICATE":
			if len(fields) < 3 || fields[2] != "XOAUTH2" {
				s.fail("IMAP authentication downgrade")
				return
			}
			if s.options.saslIR {
				if len(fields) != 4 {
					s.fail("missing IMAP SASL-IR response")
					return
				}
				s.observation.initialResponse = true
				s.checkResponse(fields[3])
			} else {
				if len(fields) != 3 {
					s.fail("unsolicited IMAP SASL initial response")
					return
				}
				if !s.write("+ \r\n") {
					return
				}
				response, ok := s.read()
				if !ok {
					return
				}
				s.checkResponse(response)
			}
			if s.options.auth == "success" {
				if !s.write("%s OK [CAPABILITY %s] authenticated\r\n", tag, caps) {
					return
				}
				continue
			}
			if s.options.auth == "reject" {
				if !s.write("%s NO %s\r\n", tag, gmailProtocolCanary) {
					return
				}
				continue
			}
			if !s.write("+ %s\r\n", s.challenge()) {
				return
			}
			response, ok := s.read()
			if !ok {
				return
			}
			if response == "*" {
				s.observation.canceled = true
				s.write("%s BAD canceled\r\n", tag)
				continue
			}
			if response != "=" {
				s.fail("IMAP error challenge response was not empty")
				return
			}
			s.observation.emptyResponses++
			if !s.awaitFinal() {
				return
			}
			switch s.options.auth {
			case "repeated_challenge":
				if !s.write("+ %s\r\n", s.challenge()) {
					return
				}
				response, ok = s.read()
				if !ok {
					return
				}
				if response == "*" {
					s.observation.canceled = true
					s.write("%s BAD canceled\r\n", tag)
					continue
				}
				s.fail("IMAP accepted a repeated challenge")
				return
			case "false_success":
				if !s.write("%s OK authenticated\r\n", tag) {
					return
				}
			default:
				if !s.write("%s NO %s\r\n", tag, gmailProtocolCanary) {
					return
				}
			}
		case "LIST":
			s.observation.list = true
			if !s.write("* LIST (\\Inbox) \"/\" INBOX\r\n%s OK listed\r\n", tag) {
				return
			}
		case "LOGIN":
			s.fail("IMAP LOGIN downgrade")
			return
		default:
			s.fail("unexpected IMAP command %s", command)
			return
		}
	}
}

func (s *gmailProtocolServer) serveSMTP() {
	if !s.options.startTLS && !s.handshake() {
		return
	}
	if !s.write("220 smtp.gmail.com ESMTP local fixture\r\n") {
		return
	}
	challengePending, challenged := false, false
	for {
		line, ok := s.read()
		if !ok {
			return
		}
		upper := strings.ToUpper(line)
		if line == "*" {
			s.observation.canceled = true
			challengePending = false
			if !s.write("501 5.7.0 canceled\r\n") {
				return
			}
			continue
		}
		if challengePending {
			if line != "" {
				s.fail("SMTP error challenge response was not empty")
				return
			}
			s.observation.emptyResponses++
			if !s.awaitFinal() {
				return
			}
			if challenged {
				s.fail("SMTP accepted a repeated challenge")
				return
			}
			challenged = true
			if s.options.auth == "repeated_challenge" {
				if !s.write("334 %s\r\n", s.challenge()) {
					return
				}
				continue
			}
			challengePending = false
			if s.options.auth == "false_success" {
				if !s.write("235 2.7.0 authenticated\r\n") {
					return
				}
			} else if !s.write("535 5.7.8 %s\r\n", gmailProtocolCanary) {
				return
			}
			continue
		}
		switch {
		case strings.HasPrefix(upper, "EHLO "):
			if !s.observation.tls {
				// Advertise tempting plaintext AUTH as well as STARTTLS: the client
				// must still upgrade before sending any credentials.
				if s.options.auth == "missing_starttls" {
					if !s.write("250-smtp.gmail.com\r\n250 AUTH XOAUTH2 PLAIN LOGIN\r\n") {
						return
					}
				} else if !s.write("250-smtp.gmail.com\r\n250-AUTH XOAUTH2 PLAIN LOGIN\r\n250 STARTTLS\r\n") {
					return
				}
			} else if s.options.auth == "absent" {
				if !s.write("250-smtp.gmail.com\r\n250-AUTH PLAIN LOGIN\r\n250 SIZE 6000000\r\n") {
					return
				}
			} else if !s.write("250-smtp.gmail.com\r\n250-AUTH XOAUTH2 PLAIN LOGIN\r\n250 SIZE 6000000\r\n") {
				return
			}
		case upper == "STARTTLS":
			if s.observation.tls || !s.options.startTLS {
				s.fail("unexpected STARTTLS")
				return
			}
			if !s.write("220 2.0.0 begin TLS\r\n") || !s.handshake() {
				return
			}
		case strings.HasPrefix(upper, "AUTH "):
			fields := strings.Fields(line)
			if len(fields) != 3 || fields[1] != "XOAUTH2" {
				s.fail("SMTP authentication downgrade or missing initial response")
				return
			}
			s.checkResponse(fields[2])
			s.observation.initialResponse = true
			if s.options.auth == "success" {
				if !s.write("235 2.7.0 authenticated\r\n") {
					return
				}
			} else if s.options.auth == "reject" {
				if !s.write("535 5.7.8 %s\r\n", gmailProtocolCanary) {
					return
				}
			} else {
				challengePending = true
				if !s.write("334 %s\r\n", s.challenge()) {
					return
				}
			}
		case strings.HasPrefix(upper, "MAIL FROM:"):
			s.observation.mail = true
			if !s.write("250 2.1.0 accepted\r\n") {
				return
			}
		case strings.HasPrefix(upper, "RCPT TO:"):
			if s.options.outcome == "rcpt_reject" {
				if !s.write("550 5.1.1 %s\r\n", gmailProtocolCanary) {
					return
				}
			} else if !s.write("250 2.1.5 accepted\r\n") {
				return
			}
		case upper == "DATA":
			s.observation.data = true
			if !s.write("354 enter message\r\n") {
				return
			}
			for {
				part, ok := s.read()
				if !ok {
					return
				}
				if part == "." {
					break
				}
			}
			switch s.options.outcome {
			case "unknown":
				return
			case "data_reject":
				if !s.write("550 5.7.1 %s\r\n", gmailProtocolCanary) {
					return
				}
			default:
				if !s.write("250 2.0.0 accepted\r\n") {
					return
				}
			}
		default:
			s.fail("unexpected SMTP command")
			return
		}
	}
}

func gmailProtocolBackend(t *testing.T, options gmailProtocolOptions) (*Backend, func() gmailProtocolObservation) {
	t.Helper()
	hosts := []string{"imap.gmail.com", "smtp.gmail.com"}
	if options.wrongHostname {
		hosts = []string{"mail.invalid"}
	}
	cert, roots := gmailProtocolCertificate(t, hosts...)
	c := config.Config{
		Provider: "gmail", AuthMode: "google_oauth2", Username: gmailProtocolMailbox, From: gmailProtocolMailbox,
		GoogleClientID: "synthetic-client-id", GoogleClientSecret: gmailProtocolSecret, GoogleRefreshToken: gmailProtocolRefresh,
		IMAP: config.Endpoint{Host: "imap.gmail.com", Port: 993, TLSMode: "tls"},
		SMTP: config.Endpoint{Host: "smtp.gmail.com", Port: 465, TLSMode: "tls"}, Timeout: 2 * time.Second,
	}
	if options.startTLS {
		c.SMTP = config.Endpoint{Host: "smtp.gmail.com", Port: 587, TLSMode: "starttls"}
	}
	b, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	b.roots = roots
	if options.untrusted {
		b.roots = x509.NewCertPool()
	}
	b.googleTokens.token = googleAccessToken{value: gmailProtocolAccess, usableUntil: time.Now().Add(time.Hour), key: b.googleCredentialKey(), generation: 41}
	b.googleTokens.generation = 41
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan gmailProtocolObservation, 1)
	var dials atomic.Int32
	b.dialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		ep := c.IMAP
		if options.protocol == "smtp" {
			ep = c.SMTP
		}
		attempt := dials.Add(1)
		if network != "tcp" || address != net.JoinHostPort(ep.Host, fmt.Sprint(ep.Port)) || attempt != 1 {
			return nil, errors.New("unexpected network destination or retry")
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
	}
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			results <- gmailProtocolObservation{err: err}
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		s := &gmailProtocolServer{conn: conn, reader: bufio.NewReader(conn), cert: cert, options: options}
		if options.newerGeneration {
			s.onChallenge = func() {
				b.googleTokens.mu.Lock()
				defer b.googleTokens.mu.Unlock()
				// A concurrent refresh may return the same token value.
				b.googleTokens.token.generation = 42
				b.googleTokens.generation = 42
			}
		}
		if options.protocol == "smtp" {
			s.serveSMTP()
		} else {
			s.serveIMAP()
		}
		results <- s.observation
	}()
	var result gmailProtocolObservation
	waited := false
	wait := func() gmailProtocolObservation {
		t.Helper()
		if !waited {
			select {
			case result = <-results:
				waited = true
			case <-time.After(4 * time.Second):
				t.Fatal("local Gmail protocol fixture did not terminate")
			}
		}
		if result.err != nil {
			t.Fatal(result.err)
		}
		if dials.Load() != 1 {
			t.Fatalf("mailbox connection attempts = %d, want exactly one", dials.Load())
		}
		return result
	}
	t.Cleanup(func() { listener.Close(); wait() })
	return b, wait
}

func gmailProtocolCheckRedacted(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("error = %v, want unavailable", err)
	}
	for _, secret := range []string{gmailProtocolAccess, gmailProtocolRefresh, gmailProtocolSecret, gmailProtocolCanary, "synthetic-client-id"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatal("provider error or OAuth credential leaked")
		}
	}
}

func gmailProtocolCheckCache(t *testing.T, b *Backend, invalidated bool, generation uint64) {
	t.Helper()
	b.googleTokens.mu.Lock()
	defer b.googleTokens.mu.Unlock()
	if invalidated {
		if b.googleTokens.token.value != "" {
			t.Fatal("rejected access-token generation was not invalidated")
		}
	} else if b.googleTokens.token.value != gmailProtocolAccess || b.googleTokens.token.generation != generation {
		t.Fatal("unrelated or successful access-token generation was invalidated")
	}
}

func TestGmailIMAPXOAUTH2Protocol(t *testing.T) {
	for _, saslIR := range []bool{false, true} {
		for _, auth := range []string{"success", "absent", "reject", "error_challenge", "malformed_json", "malformed_base64", "repeated_challenge", "false_success"} {
			t.Run(fmt.Sprintf("sasl_ir_%t/%s", saslIR, auth), func(t *testing.T) {
				b, wait := gmailProtocolBackend(t, gmailProtocolOptions{protocol: "imap", saslIR: saslIR, auth: auth})
				folders, err := b.ListFolders(context.Background())
				seen := wait()
				if !seen.tls || seen.serverName != "imap.gmail.com" {
					t.Fatal("IMAP TLS or SNI not verified")
				}
				if seen.auth != (auth != "absent") || seen.initialResponse != (saslIR && auth != "absent") {
					t.Fatal("unexpected IMAP authentication exchange")
				}
				if auth == "success" {
					if err != nil || len(folders) != 1 || folders[0].Name != "INBOX" || !seen.list {
						t.Fatalf("IMAP success = %v, %v", folders, err)
					}
				} else {
					gmailProtocolCheckRedacted(t, err)
					if seen.list {
						t.Fatal("IMAP command sent after authentication failure")
					}
				}
				wantEmpty := 0
				if auth == "error_challenge" || auth == "malformed_json" || auth == "repeated_challenge" || auth == "false_success" {
					wantEmpty = 1
				}
				if seen.emptyResponses != wantEmpty {
					t.Fatalf("empty challenge replies = %d, want %d", seen.emptyResponses, wantEmpty)
				}
				gmailProtocolCheckCache(t, b, auth != "success" && auth != "absent", 41)
			})
		}
	}
}

func gmailProtocolSend(b *Backend) (SendResult, error) {
	raw := []byte("From: " + gmailProtocolMailbox + "\r\nTo: recipient@example.net\r\nSubject: local fixture\r\n\r\nsynthetic message\r\n")
	return b.Send(context.Background(), Envelope{From: gmailProtocolMailbox, To: []string{"recipient@example.net"}}, raw)
}

func TestGmailSMTPXOAUTH2Protocol(t *testing.T) {
	for _, startTLS := range []bool{false, true} {
		for _, auth := range []string{"success", "absent", "reject", "error_challenge", "malformed_json", "malformed_base64", "repeated_challenge", "false_success"} {
			t.Run(fmt.Sprintf("starttls_%t/%s", startTLS, auth), func(t *testing.T) {
				b, wait := gmailProtocolBackend(t, gmailProtocolOptions{protocol: "smtp", startTLS: startTLS, auth: auth})
				result, err := gmailProtocolSend(b)
				seen := wait()
				if !seen.tls || seen.serverName != "smtp.gmail.com" {
					t.Fatal("SMTP TLS or SNI not verified")
				}
				if seen.auth != (auth != "absent") || seen.initialResponse != (auth != "absent") {
					t.Fatal("unexpected SMTP authentication exchange")
				}
				if auth == "success" {
					if err != nil || result.Status != "accepted" || result.Stage != "acknowledgement" || !seen.mail || !seen.data {
						t.Fatalf("SMTP success = %+v, %v", result, err)
					}
				} else {
					gmailProtocolCheckRedacted(t, err)
					if result.Status != "rejected" || result.Stage != "authentication" || seen.mail || seen.data {
						t.Fatalf("SMTP auth failure advanced to sending: %+v", result)
					}
				}
				wantEmpty := 0
				if auth == "error_challenge" || auth == "malformed_json" || auth == "repeated_challenge" || auth == "false_success" {
					wantEmpty = 1
				}
				if seen.emptyResponses != wantEmpty {
					t.Fatalf("empty challenge replies = %d, want %d", seen.emptyResponses, wantEmpty)
				}
				gmailProtocolCheckCache(t, b, auth != "success" && auth != "absent", 41)
			})
		}
	}
}

func TestGmailSMTPOutcomes(t *testing.T) {
	for _, startTLS := range []bool{false, true} {
		for _, tc := range []struct {
			outcome, status, stage string
			data                   bool
		}{
			{"rcpt_reject", "rejected", "envelope", false},
			{"data_reject", "rejected", "acknowledgement", true},
			{"unknown", "unknown", "acknowledgement", true},
		} {
			t.Run(fmt.Sprintf("starttls_%t/%s", startTLS, tc.outcome), func(t *testing.T) {
				b, wait := gmailProtocolBackend(t, gmailProtocolOptions{protocol: "smtp", startTLS: startTLS, auth: "success", outcome: tc.outcome})
				result, err := gmailProtocolSend(b)
				seen := wait()
				gmailProtocolCheckRedacted(t, err)
				if result.Status != tc.status || result.Stage != tc.stage || !seen.mail || seen.data != tc.data {
					t.Fatalf("SMTP outcome = %+v, DATA %t", result, seen.data)
				}
				gmailProtocolCheckCache(t, b, false, 41)
			})
		}
	}
}

func TestGmailTLSRequiredBeforeCredentials(t *testing.T) {
	for _, protocol := range []string{"imap", "smtp"} {
		for _, startTLS := range []bool{false, true} {
			if protocol == "imap" && startTLS {
				continue
			}
			for _, failure := range []string{"untrusted", "wrong_hostname", "missing_starttls"} {
				if failure == "missing_starttls" && !startTLS {
					continue
				}
				t.Run(fmt.Sprintf("%s/starttls_%t/%s", protocol, startTLS, failure), func(t *testing.T) {
					options := gmailProtocolOptions{protocol: protocol, startTLS: startTLS, auth: "success", untrusted: failure == "untrusted", wrongHostname: failure == "wrong_hostname"}
					if failure == "missing_starttls" {
						options.auth = failure
					}
					b, wait := gmailProtocolBackend(t, options)
					var err error
					if protocol == "smtp" {
						var result SendResult
						result, err = gmailProtocolSend(b)
						if result.Status != "rejected" || result.Stage != "connection" {
							t.Fatalf("TLS failure advanced toward sending: %+v", result)
						}
					} else {
						_, err = b.ListFolders(context.Background())
					}
					seen := wait()
					gmailProtocolCheckRedacted(t, err)
					if seen.auth || seen.mail || seen.data || seen.list {
						t.Fatal("credentials or mail commands sent without authenticated TLS")
					}
					for _, line := range seen.lines {
						if strings.Contains(line, gmailProtocolAccess) || strings.Contains(line, "AUTH XOAUTH2") || strings.Contains(line, "AUTHENTICATE") || strings.Contains(line, "LOGIN") {
							t.Fatal("authentication data sent before TLS")
						}
					}
					gmailProtocolCheckCache(t, b, false, 41)
				})
			}
		}
	}
}

func TestGmailAuthRejectionPreservesNewerTokenGeneration(t *testing.T) {
	for _, protocol := range []string{"imap", "smtp"} {
		t.Run(protocol, func(t *testing.T) {
			b, wait := gmailProtocolBackend(t, gmailProtocolOptions{protocol: protocol, auth: "error_challenge", newerGeneration: true})
			var err error
			if protocol == "smtp" {
				_, err = gmailProtocolSend(b)
			} else {
				_, err = b.ListFolders(context.Background())
			}
			seen := wait()
			gmailProtocolCheckRedacted(t, err)
			if seen.emptyResponses != 1 || seen.mail || seen.data || seen.list {
				t.Fatal("auth error challenge did not terminate safely")
			}
			gmailProtocolCheckCache(t, b, false, 42)
		})
	}
}

func TestGmailXOAUTH2WaitsForTerminalAuthFailure(t *testing.T) {
	for _, protocol := range []string{"imap", "smtp"} {
		t.Run(protocol, func(t *testing.T) {
			gate := make(chan struct{})
			acknowledged := make(chan struct{})
			released := false
			t.Cleanup(func() {
				if !released {
					close(gate)
				}
			})
			b, wait := gmailProtocolBackend(t, gmailProtocolOptions{protocol: protocol, auth: "error_challenge", finalGate: gate, challengeAcknowledged: acknowledged})
			done := make(chan error, 1)
			go func() {
				var err error
				if protocol == "smtp" {
					_, err = gmailProtocolSend(b)
				} else {
					_, err = b.ListFolders(context.Background())
				}
				done <- err
			}()
			select {
			case <-acknowledged:
			case err := <-done:
				t.Fatalf("authentication finished without acknowledging error challenge: %v", err)
			case <-time.After(time.Second):
				t.Fatal("error challenge was not acknowledged")
			}
			select {
			case err := <-done:
				t.Fatalf("authentication finished before terminal server reply: %v", err)
			case <-time.After(30 * time.Millisecond):
			}
			close(gate)
			released = true
			select {
			case err := <-done:
				gmailProtocolCheckRedacted(t, err)
			case <-time.After(time.Second):
				t.Fatal("authentication did not finish after terminal reply")
			}
			seen := wait()
			if seen.emptyResponses != 1 || seen.mail || seen.data || seen.list {
				t.Fatal("authentication error advanced mailbox operations")
			}
			gmailProtocolCheckCache(t, b, true, 41)
		})
	}
}

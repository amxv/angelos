package mail

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/amxv/angelos/internal/config"
)

func backendTestCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "mail.test"}, DNSNames: []string{"mail.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	cert, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, roots
}
func backendForTest(t *testing.T, handler func(net.Conn), implicit bool) *Backend {
	t.Helper()
	cert, roots := backendTestCertificate(t)
	c := config.Config{Username: "person@example.com", Password: "test-only", From: "person@example.com", IMAP: config.Endpoint{Host: "mail.test", Port: 993, TLSMode: "tls"}, SMTP: config.Endpoint{Host: "mail.test", Port: 465, TLSMode: "tls"}, Timeout: time.Second}
	b, e := New(c)
	if e != nil {
		t.Fatal(e)
	}
	b.roots = roots
	b.dialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			server.SetDeadline(time.Now().Add(3 * time.Second))
			var conn net.Conn = server
			if implicit {
				conn = tls.Server(server, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
			}
			handler(conn)
		}()
		return client, nil
	}
	return b
}
func TestPublicAddressPolicy(t *testing.T) {
	for _, addr := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254", "100.100.100.200", "172.16.1.2", "192.168.1.1", "198.18.0.1", "192.0.2.1", "224.0.0.1", "240.1.1.1", "::1", "fe80::1", "fc00::1", "::ffff:127.0.0.1", "64:ff9b::a00:1", "2001:db8::1", "2002:7f00:1::"} {
		if publicIP(net.ParseIP(addr)) {
			t.Errorf("accepted %s", addr)
		}
	}
	for _, addr := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"} {
		if !publicIP(net.ParseIP(addr)) {
			t.Errorf("rejected %s", addr)
		}
	}
}
func TestMixedDNSAnswersRejected(t *testing.T) {
	b := &Backend{lookupIP: func(context.Context, string, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("127.0.0.1")}, nil
	}}
	if _, e := b.dial(context.Background(), config.Endpoint{Host: "mail.test", Port: 993}); e == nil {
		t.Fatal("private DNS answer accepted")
	}
}
func TestIMAPContextClosesStalledConnection(t *testing.T) {
	b := backendForTest(t, func(c net.Conn) { buf := make([]byte, 1); c.Read(buf) }, true)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, e := b.ListFolders(ctx); e == nil {
		t.Fatal("stalled server succeeded")
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatal("context cancellation not enforced")
	}
}
func TestIMAPRejectsUntrustedCertificate(t *testing.T) {
	b := backendForTest(t, func(c net.Conn) { c.Write([]byte("* OK hello\r\n")) }, true)
	b.roots = x509.NewCertPool()
	if _, e := b.ListFolders(context.Background()); e == nil {
		t.Fatal("untrusted TLS accepted")
	}
}
func TestWireByteBudget(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	go func() { defer server.Close(); server.Write([]byte("abcd")) }()
	bounded := &boundedConn{Conn: client, deadline: time.Now().Add(time.Second), remaining: 3}
	buf := make([]byte, 10)
	n, e := bounded.Read(buf)
	if e != nil || n != 3 {
		t.Fatalf("initial bounded read %d %v", n, e)
	}
	if _, e := bounded.Read(buf); e != ErrLimit {
		t.Fatalf("budget error %v", e)
	}
}

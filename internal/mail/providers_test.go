package mail

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/amxv/angelos/internal/config"
)

type providerTraceConn struct {
	net.Conn
	trace *imapTrace
}

func (c providerTraceConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.trace.add(string(p[:n]))
	}
	return n, err
}

// All connections terminate in local net.Pipe TLS fixtures. These tests neither
// contact providers nor establish real-account compatibility or Sent behavior.
func TestAppPasswordPresetsUseExistingTLSBackend(t *testing.T) {
	for _, provider := range []string{"icloud", "yahoo"} {
		for _, protocol := range []string{"imap", "smtp"} {
			t.Run(provider+"/"+protocol, func(t *testing.T) {
				values := map[string]string{"MAIL_PROVIDER": provider, "MAIL_USERNAME": "person@example.com", "MAIL_PASSWORD": "synthetic-app-password", "MAIL_TIMEOUT": "2s"}
				cfg, err := config.Load(func(k string) string { return values[k] })
				if err != nil {
					t.Fatal(err)
				}
				cert, roots := gmailProtocolCertificate(t, cfg.IMAP.Host, cfg.SMTP.Host)
				b, err := New(cfg)
				if err != nil {
					t.Fatal(err)
				}
				b.roots = roots
				trace := &imapTrace{}
				var data atomic.Bool
				done := make(chan struct{})
				b.dialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
					client, server := net.Pipe()
					go func() {
						defer close(done)
						defer server.Close()
						if deadline, ok := ctx.Deadline(); ok {
							server.SetDeadline(deadline)
						}
						ep := cfg.IMAP
						if protocol == "smtp" {
							ep = cfg.SMTP
						}
						if ep.TLSMode == "starttls" {
							fmt.Fprint(server, "220 local.test ESMTP\r\n")
							r := bufio.NewReader(server)
							line, _ := r.ReadString('\n')
							if !strings.HasPrefix(line, "EHLO ") {
								return
							}
							fmt.Fprint(server, "250-local.test\r\n250 STARTTLS\r\n")
							line, _ = r.ReadString('\n')
							if strings.TrimSpace(line) != "STARTTLS" {
								return
							}
							fmt.Fprint(server, "220 begin TLS\r\n")
						}
						secure := tls.Server(server, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
						if err := secure.Handshake(); err != nil {
							return
						}
						if secure.ConnectionState().ServerName != ep.Host {
							t.Error("wrong TLS server name")
						}
						if protocol == "imap" {
							imapFixture("", "", trace)(secure)
						} else {
							serveSMTPFixture(providerTraceConn{secure, trace}, "accept", &data, ep.TLSMode == "tls")
						}
					}()
					return client, nil
				}
				if protocol == "imap" {
					caps, err := b.Capabilities(context.Background())
					if err != nil {
						t.Fatal(err)
					}
					if len(caps.SpecialFolders["sent"]) != 1 || caps.SpecialFolders["sent"][0] != "Sent Mail" {
						t.Fatalf("special-use folders not discovered: %+v", caps.SpecialFolders)
					}
					if caps.GmailLabels || caps.SMTPStoresSent || caps.UIDExpunge || caps.PermanentDelete {
						t.Fatal("unadvertised capabilities invented")
					}
				} else {
					got, err := b.Send(context.Background(), Envelope{From: cfg.From, To: []string{"recipient@example.net"}}, testMessage)
					if err != nil || got.Status != "accepted" || !data.Load() {
						t.Fatalf("SMTP fixture failed: %+v %v", got, err)
					}
				}
				<-done
				wire := trace.String()
				if protocol == "imap" {
					if !strings.Contains(wire, cfg.Username) || !strings.Contains(wire, cfg.Password) {
						t.Fatal("IMAP credentials missing")
					}
				} else {
					expected := base64.StdEncoding.EncodeToString([]byte("\x00" + cfg.Username + "\x00" + cfg.Password))
					if !strings.Contains(wire, expected) {
						t.Fatal("SMTP app-password authentication missing")
					}
				}
			})
		}
	}
}

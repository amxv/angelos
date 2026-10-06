package mail

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/amxv/angelos/internal/config"
)

// BackendForCompositionTesting exports a fully local TLS/IMAP fixture only to
// the external integration test package. No raw-source production API is added.
func BackendForCompositionTesting(t *testing.T, raw string) (*Backend, func() string) {
	t.Helper()
	trace := &imapTrace{}
	backend := backendForTest(t, imapFixture(raw, "", trace), true)
	return backend, trace.String
}

// BackendForGmailSendTesting uses real TLS/SMTP with a synthetic app password.
// It exercises Gmail filing policy; mailbox XOAUTH2 has separate protocol tests.
// Only _test.go exposes the private local transport seam to mail_test.
func BackendForGmailSendTesting(t *testing.T) (*Backend, config.Config, func() (int32, int32, bool)) {
	t.Helper()
	var data atomic.Bool
	var smtp, imap atomic.Int32
	b := backendForTest(t, smtpFixture("accept", &data), true)
	b.config.Provider, b.config.AuthMode = "gmail", "app_password"
	dial := b.dialContext
	b.dialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if strings.HasSuffix(address, ":993") {
			imap.Add(1)
			return nil, ErrUnavailable
		}
		smtp.Add(1)
		return dial(ctx, network, address)
	}
	return b, b.config, func() (int32, int32, bool) { return smtp.Load(), imap.Load(), data.Load() }
}

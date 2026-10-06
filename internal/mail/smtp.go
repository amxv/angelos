package mail

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	stdmail "net/mail"
	"strings"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
)

type Envelope struct {
	From string   `json:"from"`
	To   []string `json:"to"`
}
type SendResult struct {
	// accepted means SMTP accepted DATA, not that any recipient received it.
	// unknown means the final DATA acknowledgement was lost: never auto-retry.
	Status string `json:"status"`
	Stage  string `json:"stage"`
}

// Send transmits once. It is intentionally separate from the read-only Reader
// interface. An application exposing it must obtain explicit authorization and
// implement persistent idempotency before calling it. No automatic retries.
func (b *Backend) Send(ctx context.Context, envelope Envelope, raw []byte) (SendResult, error) {
	result := SendResult{Status: "rejected", Stage: "validation"}
	if envelope.From != b.config.From || !bareAddress(envelope.From) || len(envelope.To) == 0 || len(envelope.To) > 100 || len(raw) == 0 || len(raw) > maxMessageBytes {
		return result, ErrInvalidInput
	}
	for _, to := range envelope.To {
		if !bareAddress(to) {
			return result, ErrInvalidInput
		}
	}
	msg, err := stdmail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return result, ErrInvalidInput
	}
	if msg.Header.Get("Bcc") != "" {
		return result, ErrInvalidInput
	}
	from, err := stdmail.ParseAddress(msg.Header.Get("From"))
	if err != nil || from.Address != b.config.From {
		return result, ErrInvalidInput
	}
	result.Stage = "connection"
	conn, done, err := b.openConn(ctx, b.config.SMTP)
	if err != nil {
		return result, err
	}
	defer done()
	var client *smtp.Client
	if b.config.SMTP.TLSMode == "tls" {
		secure := tls.Client(conn, b.tlsConfig(b.config.SMTP.Host))
		if err := secure.HandshakeContext(ctx); err != nil {
			return result, ErrUnavailable
		}
		client = smtp.NewClient(secure)
	} else {
		client, err = smtp.NewClientStartTLS(conn, b.tlsConfig(b.config.SMTP.Host))
		if err != nil {
			return result, ErrUnavailable
		}
	}
	defer client.Close()
	client.CommandTimeout = b.config.Timeout
	client.SubmissionTimeout = b.config.Timeout
	result.Stage = "authentication"
	if !client.SupportsAuth("PLAIN") {
		return result, ErrUnavailable
	}
	if err := client.Auth(sasl.NewPlainClient("", b.config.Username, b.config.Password)); err != nil {
		return result, ErrUnavailable
	}
	result.Stage = "envelope"
	if err := client.Mail(envelope.From, &smtp.MailOptions{Size: int64(len(raw))}); err != nil {
		return result, safeError(err)
	}
	for _, recipient := range envelope.To {
		if err := client.Rcpt(recipient, nil); err != nil {
			return result, safeError(err)
		}
	}
	result.Stage = "data"
	writer, err := client.Data()
	if err != nil {
		return result, safeError(err)
	}
	if _, err := io.Copy(writer, bytes.NewReader(raw)); err != nil {
		// Do not close the DATA writer: Close would submit the incomplete message.
		client.Close()
		return result, ErrUnavailable
	}
	result.Stage = "acknowledgement"
	if err := writer.Close(); err != nil {
		var rejection *smtp.SMTPError
		if !errors.As(err, &rejection) || rejection.Code < 400 || rejection.Code > 599 {
			result.Status = "unknown"
		}
		return result, ErrUnavailable
	}
	result.Status = "accepted"
	return result, nil
}
func bareAddress(s string) bool {
	if len(s) > 254 || strings.ContainsAny(s, "\r\n\x00") {
		return false
	}
	for _, r := range s {
		if r > 127 {
			return false
		}
	}
	parsed, err := stdmail.ParseAddress(s)
	return err == nil && parsed.Address == s
}

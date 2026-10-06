package mail_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/amxv/angelos/internal/app"
	"github.com/amxv/angelos/internal/compose"
	"github.com/amxv/angelos/internal/dispatch"
	"github.com/amxv/angelos/internal/mail"
)

type gmailIntegrationStore struct {
	integrationStore
	owner     string
	claimed   bool
	completes int
	status    string
}

func (s *gmailIntegrationStore) Put(ctx context.Context, p compose.Prepared, owner string) error {
	s.owner, s.status = owner, "prepared"
	return s.integrationStore.Put(ctx, p, owner)
}
func (s *gmailIntegrationStore) Claim(_ context.Context, id, digest, owner string, now time.Time) (dispatch.Record, bool, error) {
	s.claims++
	if len(s.messages) != 1 {
		return dispatch.Record{}, false, errors.New("expected one preparation")
	}
	p := s.messages[0]
	if p.ID != id || p.Digest != digest || s.owner == "" || s.owner != owner || !now.Before(p.ExpiresAt) {
		return dispatch.Record{}, false, errors.New("invalid claim")
	}
	rec := dispatch.Record{Message: p, Owner: owner, Status: s.status}
	if s.claimed {
		return rec, false, nil
	}
	s.claimed, s.status = true, "sending"
	return rec, true, nil
}
func (s *gmailIntegrationStore) Complete(_ context.Context, _ string, status, _ string) error {
	s.completes++
	s.status = status
	return nil
}

func TestGmailRealTLSSubmissionThroughSignedOAuthMCP(t *testing.T) {
	f := newIntegrationAuthFixture(t)
	backend, cfg, trace := mail.BackendForGmailSendTesting(t)
	store := &gmailIntegrationStore{}
	a := &app.App{Mail: backend, Config: cfg, Store: store, EnableSend: true, EnableWrites: true, EnableDelete: true}
	status, out := f.call(t, a, "mail.read mail.send", "mail_prepare", `{"action":"new","message":{"to":["recipient@example.net"],"subject":"Synthetic Gmail send","text":"Approved fixture body"}}`)
	prepared := integrationResult(t, status, out)
	args := fmt.Sprintf(`{"prepared_id":%q,"confirmed_digest":%q,"append_sent":true}`, prepared["prepared_id"], prepared["digest"])
	status, out = f.call(t, a, "mail.read mail.send mail.write", "mail_send_confirmed", args)
	result, ok := out["result"].(map[string]any)
	encoded, _ := json.Marshal(out)
	if status != 200 || !ok || result["isError"] != true || !strings.Contains(string(encoded), "append_sent=false") || !strings.Contains(string(encoded), "no message was sent") {
		t.Fatalf("duplicate filing was not clearly rejected: %s", encoded)
	}
	smtp, imap, data := trace()
	if store.claims != 0 || store.completes != 0 || smtp != 0 || imap != 0 || data {
		t.Fatalf("pre-claim rejection had side effects: claims=%d SMTP=%d IMAP=%d DATA=%v", store.claims, smtp, imap, data)
	}
	// Permanent deletion is independently blocked at the same authenticated MCP
	// boundary despite both write gates being enabled; no IMAP connection occurs.
	status, out = f.call(t, a, "mail.read mail.write", "mail_delete_permanently", integrationReference)
	result, ok = out["result"].(map[string]any)
	if status != 200 || !ok || result["isError"] != true {
		t.Fatalf("Gmail permanent deletion succeeded: %#v", out)
	}
	smtp, imap, data = trace()
	if smtp != 0 || imap != 0 || data {
		t.Fatal("permanent delete touched mail transports")
	}
	// Correcting only the flag keeps the original preparation usable. With no
	// write scope or write enablement, exactly one TLS SMTP submission succeeds.
	a.EnableWrites = false
	args = strings.Replace(args, `"append_sent":true`, `"append_sent":false`, 1)
	status, out = f.call(t, a, "mail.read mail.send", "mail_send_confirmed", args)
	sent := integrationResult(t, status, out)
	if sent["status"] != "accepted" || sent["delivery_verified"] != false {
		t.Fatalf("submission: %#v", sent)
	}
	status, out = f.call(t, a, "mail.read mail.send", "mail_send_confirmed", args)
	repeated := integrationResult(t, status, out)
	smtp, imap, data = trace()
	if repeated["resent"] != false || store.claims != 2 || store.completes != 1 || smtp != 1 || imap != 0 || !data {
		t.Fatalf("wrong single-send/no-APPEND result: %#v claims=%d completed=%d SMTP=%d IMAP=%d DATA=%v", repeated, store.claims, store.completes, smtp, imap, data)
	}
}

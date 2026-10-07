package app

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/amxv/angelos/internal/config"
	"github.com/amxv/angelos/internal/mail"
)

func TestGmailSentGuardPrecedesClaimAndSubmission(t *testing.T) {
	f := newGroupedAuthFixture(t)
	for _, cfg := range []config.Config{{Provider: "gmail"}, {Provider: "custom", SMTP: config.Endpoint{Host: "smtp.gmail.com"}}, {SMTP: config.Endpoint{Host: "SMTP.GoogleMail.Com"}}} {
		for _, writes := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s_%s_writes_%v", cfg.Provider, cfg.SMTP.Host, writes), func(t *testing.T) {
				a, backend, store := newGroupedApp()
				cfg.From = "owner@example.com"
				a.Config, a.EnableWrites = cfg, writes
				prepareStatusFixture(t, f, a, store)
				args := fmt.Sprintf(`{"prepared_id":%q,"confirmed_digest":%q,"append_sent":true}`, store.record.Message.ID, store.record.Message.Digest)
				status, out := f.call(t, a, "mail.read mail.send mail.write", "mail_send_confirmed", args)
				groupedExpectError(t, status, out)
				encoded, _ := json.Marshal(out)
				if !strings.Contains(string(encoded), "append_sent=false") || !strings.Contains(string(encoded), "no message was sent") {
					t.Fatalf("unclear rejection: %s", encoded)
				}
				if store.claims != 0 || store.claimed || store.completes != 0 || len(backend.calls) != 0 {
					t.Fatalf("rejection reached store or mail: %#v, calls %v", store, backend.calls)
				}
				args = strings.Replace(args, `"append_sent":true`, `"append_sent":false`, 1)
				// The rejected request has not consumed the ID. Neither write enablement
				// nor mail.write scope is needed when Gmail performs its own Sent filing.
				for i := 0; i < 2; i++ {
					status, out = f.call(t, a, "mail.read mail.send", "mail_send_confirmed", args)
					groupedResult(t, status, out)
				}
				if !reflect.DeepEqual(backend.calls, []string{"send"}) || store.claims != 2 || store.completes != 1 {
					t.Fatalf("expected one send and no append: %v %#v", backend.calls, store)
				}
			})
		}
	}
}

func TestGmailDirectSendGuardPrecedesClaim(t *testing.T) {
	a, backend, store := newGroupedApp()
	a.Config.Provider = "gmail"
	if _, err := a.send(context.Background(), sendInput{AppendSent: true}); err == nil {
		t.Fatal("direct send accepted duplicate filing")
	}
	if store.claims != 0 || len(backend.calls) != 0 {
		t.Fatal("direct call consumed ID or sent")
	}
}

func TestGmailPermanentDeleteNeverReachesBackend(t *testing.T) {
	f := newGroupedAuthFixture(t)
	for _, cfg := range []config.Config{{Provider: "gmail"}, {Provider: "custom", IMAP: config.Endpoint{Host: "imap.gmail.com"}}, {IMAP: config.Endpoint{Host: "IMAP.GoogleMail.Com"}}} {
		for _, gate := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s_%s_delete_%v", cfg.Provider, cfg.IMAP.Host, gate), func(t *testing.T) {
				a, backend, store := newGroupedApp()
				a.Config, a.EnableDelete = cfg, gate
				status, out := f.call(t, a, "mail.read mail.write", "mail_delete_permanently", groupedReferenceJSON)
				groupedExpectError(t, status, out)
				encoded, _ := json.Marshal(out)
				if !strings.Contains(string(encoded), "unsupported for Gmail/Workspace") {
					t.Fatalf("wrong reason: %s", encoded)
				}
				if len(backend.calls) != 0 || store.claims != 0 {
					t.Fatal("Gmail deletion reached backend")
				}
			})
		}
	}
}

type googleCapabilitiesBackend struct {
	*groupedBackend
	capabilities mail.Capabilities
}

func (b *googleCapabilitiesBackend) Capabilities(context.Context) (mail.Capabilities, error) {
	b.called("capabilities")
	return b.capabilities, nil
}

func TestEffectiveCapabilitiesRespectProviderAndGates(t *testing.T) {
	f := newGroupedAuthFixture(t)
	for _, tc := range []struct {
		name                                                                       string
		cfg                                                                        config.Config
		writes, delete, uidPlus, gmailLabels, smtpStoresSent, wantDelete, wantSent bool
	}{
		{name: "gmail", cfg: config.Config{Provider: "gmail"}, writes: true, delete: true, uidPlus: true, wantSent: true},
		{name: "custom_google_imap", cfg: config.Config{Provider: "custom", IMAP: config.Endpoint{Host: "imap.gmail.com"}}, writes: true, delete: true, uidPlus: true},
		{name: "custom_google_extension", writes: true, delete: true, uidPlus: true, gmailLabels: true},
		{name: "spacemail", cfg: config.Config{Provider: "spacemail"}, writes: true, delete: true, uidPlus: true, wantDelete: true},
		{name: "write_gate_off", delete: true, uidPlus: true},
		{name: "delete_gate_off", writes: true, uidPlus: true},
		{name: "uidplus_missing", writes: true, delete: true},
		{name: "google_smtp_only", cfg: config.Config{Provider: "custom", SMTP: config.Endpoint{Host: "smtp.gmail.com"}}, writes: true, delete: true, uidPlus: true, wantDelete: true, wantSent: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, base, _ := newGroupedApp()
			a.Config, a.EnableWrites, a.EnableDelete = tc.cfg, tc.writes, tc.delete
			a.Mail = &googleCapabilitiesBackend{groupedBackend: base, capabilities: mail.Capabilities{UIDExpunge: tc.uidPlus, PermanentDelete: tc.uidPlus && !tc.gmailLabels, GmailLabels: tc.gmailLabels, SMTPStoresSent: tc.smtpStoresSent}}
			status, out := f.call(t, a, "mail.read", "mail_query", `{"action":"capabilities"}`)
			c := groupedResult(t, status, out)["structuredContent"].(map[string]any)
			if c["permanent_delete_enabled"] != tc.wantDelete || c["smtp_stores_sent"] != tc.wantSent {
				t.Fatalf("wrong effective gates: %#v", c)
			}
			if tc.cfg.IsGmailIMAP() || tc.gmailLabels {
				if c["permanent_delete_restriction"] != mail.ErrGmailDelete.Error() {
					t.Fatalf("missing Gmail restriction: %#v", c)
				}
			}
		})
	}
}

func TestGmailScopesAndSendGatesRemainRequired(t *testing.T) {
	f := newGroupedAuthFixture(t)
	for _, tc := range []struct {
		name, scope    string
		enabled, store bool
	}{
		{"missing_send_scope", "mail.read mail.write", true, true},
		{"missing_base_scope", "mail.send mail.write", true, true},
		{"send_disabled", "mail.read mail.send mail.write", false, true},
		{"store_missing", "mail.read mail.send mail.write", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, backend, store := newGroupedApp()
			args := groupedSeedSend(t, store)
			a.Config.Provider, a.EnableSend = "gmail", tc.enabled
			if !tc.store {
				a.Store = nil
			}
			status, out := f.call(t, a, tc.scope, "mail_send_confirmed", args)
			groupedExpectError(t, status, out)
			if store.claims != 0 || len(backend.calls) != 0 {
				t.Fatalf("Gmail bypassed send gate: %#v %v", store, backend.calls)
			}
		})
	}
}

func TestGmailDiscoveryContainsRestrictionsAndVersion(t *testing.T) {
	if Version != "0.6.0" {
		t.Fatalf("version: %s", Version)
	}
	out := callProtocol(t, &App{}, `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`)
	listed := out["result"].(map[string]any)["tools"].([]any)
	for _, raw := range listed {
		tool := raw.(map[string]any)
		desc := tool["description"].(string)
		switch tool["name"] {
		case "mail_query":
			if !strings.Contains(desc, "Gmail labels overlap; All is not Archive") {
				t.Fatal(desc)
			}
		case "mail_delete_permanently":
			if !strings.Contains(desc, "Unavailable for Gmail/Workspace") {
				t.Fatal(desc)
			}
		case "mail_send_confirmed":
			if !strings.Contains(desc, "false for Gmail") {
				t.Fatal(desc)
			}
		}
	}
}

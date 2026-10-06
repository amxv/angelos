package mail

import (
	"context"
	"errors"
	"net"
	"reflect"
	"testing"

	"github.com/amxv/angelos/internal/config"
)

const googleListRoles = "* LIST (\\All) \"/\" \"[Gmail]/Todo el correo\"\r\n" +
	"* LIST (\\Trash) \"/\" \"[Gmail]/Papelera\"\r\n" +
	"* LIST (\\Sent) \"/\" \"[Gmail]/Enviados\"\r\n" +
	"* LIST (\\Drafts) \"/\" \"[Gmail]/Borradores\"\r\n" +
	"* LIST (\\Noselect \\Trash) \"/\" \"[Gmail]\"\r\n" +
	"* LIST () \"/\" \"Archive\"\r\n"

func googleListStep(listing string) writeStep {
	return writeStep{exact: `LIST "" "*"`, reply: listing + "{tag} OK listed\r\n"}
}

func TestGoogleSpecialUseFromOrdinaryList(t *testing.T) {
	for _, provider := range []string{"", "gmail", "custom"} {
		t.Run("provider_"+provider, func(t *testing.T) {
			// Google advertises X-GM-EXT-1 but need not advertise SPECIAL-USE.
			b := writeTestBackend(t, "IMAP4rev1 UIDPLUS X-GM-EXT-1", []writeStep{googleListStep(googleListRoles)})
			b.config.Provider = provider
			if provider == "gmail" {
				b.config.AuthMode = "app_password"
			}
			got, err := b.Capabilities(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			want := map[string][]string{"all": {"[Gmail]/Todo el correo"}, "trash": {"[Gmail]/Papelera"}, "sent": {"[Gmail]/Enviados"}, "drafts": {"[Gmail]/Borradores"}}
			if !got.SpecialUse || !got.GmailLabels || got.PermanentDelete || !got.UIDExpunge || got.Move || !reflect.DeepEqual(got.SpecialFolders, want) {
				t.Fatalf("incorrect Google capabilities: %+v", got)
			}
			if got.SMTPStoresSent != (provider == "gmail") {
				t.Fatalf("IMAP capabilities inferred SMTP policy: %+v", got)
			}
		})
	}
}

func TestSpecialUseIsNeitherGuessedNorRequiredForOrdinaryServer(t *testing.T) {
	b := writeTestBackend(t, "IMAP4rev1 UIDPLUS", []writeStep{googleListStep("* LIST () \"/\" \"Sent\"\r\n* LIST () \"/\" \"Archive\"\r\n")})
	got, err := b.Capabilities(context.Background())
	if err != nil || got.SpecialUse || len(got.SpecialFolders) != 0 || !got.PermanentDelete || got.GmailLabels || got.SMTPStoresSent {
		t.Fatalf("unexpected capabilities %+v: %v", got, err)
	}
}

func TestGoogleSpecialUseAmbiguityAndDuplicates(t *testing.T) {
	listing := googleListRoles + "* LIST (\\Trash) \"/\" \"[Gmail]/Papelera\"\r\n* LIST (\\Trash) \"/\" \"Corbeille\"\r\n"
	t.Run("reported", func(t *testing.T) {
		b := writeTestBackend(t, "IMAP4rev1 X-GM-EXT-1 MOVE", []writeStep{googleListStep(listing)})
		got, err := b.Capabilities(context.Background())
		if err != nil || !reflect.DeepEqual(got.SpecialFolders["trash"], []string{"Corbeille", "[Gmail]/Papelera"}) || !got.SpecialUse {
			t.Fatalf("roles changed: %+v %v", got, err)
		}
	})
	for name, roles := range map[string]string{"ambiguous": listing, "missing": "* LIST () \"/\" \"Trash\"\r\n"} {
		t.Run(name, func(t *testing.T) {
			b := writeTestBackend(t, "IMAP4rev1 X-GM-EXT-1 MOVE", []writeStep{googleListStep(roles)})
			if _, err := b.Trash(context.Background(), testWriteRef()); !errors.Is(err, ErrUnsupported) {
				t.Fatalf("unsafe Trash: %v", err)
			}
		})
	}
	t.Run("all_is_not_archive", func(t *testing.T) {
		b := writeTestBackend(t, "IMAP4rev1 X-GM-EXT-1", []writeStep{googleListStep(googleListRoles)})
		s, err := b.connectIMAP(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		defer s.close()
		if name, err := resolveSpecialFolder(s, "archive"); !errors.Is(err, ErrUnsupported) || name != "" {
			t.Fatalf("mapped All to Archive: %q %v", name, err)
		}
	})
}

func TestGoogleTrashNeedsNativeMoveAndPreservesUIDMapping(t *testing.T) {
	t.Run("no_native_move", func(t *testing.T) {
		b := writeTestBackend(t, "IMAP4rev1 UIDPLUS X-GM-EXT-1", nil)
		if _, err := b.Trash(context.Background(), testWriteRef()); !errors.Is(err, ErrUnsupported) {
			t.Fatal(err)
		}
	})
	for _, mapping := range []bool{false, true} {
		name := "without_copyuid"
		response := "{tag} OK moved\r\n"
		if mapping {
			name, response = "with_copyuid", "* OK [COPYUID 22 17 58] copied\r\n* 4 EXPUNGE\r\n{tag} OK moved\r\n"
		}
		t.Run(name, func(t *testing.T) {
			b := writeTestBackend(t, "IMAP4rev1 UIDPLUS X-GM-EXT-1 MOVE", []writeStep{googleListStep(googleListRoles), selectWriteStep(9, false), fetchFlagStep("", 0), {exact: `UID MOVE 17 "[Gmail]/Papelera"`, reply: response}})
			got, err := b.Trash(context.Background(), testWriteRef())
			if err != nil {
				t.Fatal(err)
			}
			if mapping {
				want := Reference{Folder: "[Gmail]/Papelera", UIDValidity: 22, UID: 58}
				if got.Status != "moved" || got.Destination == nil || *got.Destination != want {
					t.Fatalf("lost destination identity: %+v", got)
				}
			} else if got.Status != "accepted" || got.Destination != nil || len(got.Warnings) == 0 {
				t.Fatalf("invented destination identity: %+v", got)
			}
		})
	}
	t.Run("stale_reference", func(t *testing.T) {
		b := writeTestBackend(t, "IMAP4rev1 UIDPLUS X-GM-EXT-1 MOVE", []writeStep{googleListStep(googleListRoles), selectWriteStep(10, false)})
		if _, err := b.Trash(context.Background(), testWriteRef()); !errors.Is(err, ErrStaleReference) {
			t.Fatal(err)
		}
	})
}

func TestGmailDeleteIsBlockedBeforeConnecting(t *testing.T) {
	for _, cfg := range []config.Config{{Provider: "gmail"}, {Provider: "custom", IMAP: config.Endpoint{Host: "imap.gmail.com"}}, {IMAP: config.Endpoint{Host: "IMAP.GoogleMail.Com"}}} {
		t.Run(cfg.Provider+cfg.IMAP.Host, func(t *testing.T) {
			b := &Backend{config: cfg, dialContext: func(context.Context, string, string) (net.Conn, error) {
				t.Error("Gmail delete connected")
				return nil, ErrUnavailable
			}}
			got, err := b.Delete(context.Background(), testWriteRef())
			if !errors.Is(err, ErrGmailDelete) || got.Status != "not_applied" || got.Source == nil || *got.Source != testWriteRef() {
				t.Fatalf("Gmail delete: %+v %v", got, err)
			}
		})
	}
}

func TestCustomGoogleDeleteIsBlockedBeforeSelectingOrMutating(t *testing.T) {
	// Unexpected SELECT, UID STORE, UID EXPUNGE or ordinary EXPUNGE fails the script.
	b := writeTestBackend(t, "IMAP4rev1 UIDPLUS CONDSTORE X-GM-EXT-1", nil)
	b.config.Provider = "custom"
	got, err := b.Delete(context.Background(), testWriteRef())
	if !errors.Is(err, ErrGmailDelete) || got.Status != "not_applied" {
		t.Fatalf("Google delete: %+v %v", got, err)
	}
}

func TestGmailAppendSentIsBlockedBeforeConnecting(t *testing.T) {
	for _, cfg := range []config.Config{{Provider: "gmail"}, {Provider: "custom", SMTP: config.Endpoint{Host: "smtp.gmail.com"}}, {SMTP: config.Endpoint{Host: "SMTP.GoogleMail.Com"}}} {
		t.Run(cfg.Provider+cfg.SMTP.Host, func(t *testing.T) {
			b := &Backend{config: cfg, dialContext: func(context.Context, string, string) (net.Conn, error) {
				t.Error("Gmail AppendSent connected")
				return nil, ErrUnavailable
			}}
			got, err := b.AppendSent(context.Background(), testMessage)
			if !errors.Is(err, ErrAutomaticSent) || got.Status != "not_applied" {
				t.Fatalf("Gmail AppendSent: %+v %v", got, err)
			}
		})
	}
}

func TestCustomGoogleIMAPDoesNotInventSMTPSentPolicy(t *testing.T) {
	raw := string(testMessage)
	b := writeTestBackend(t, "IMAP4rev1 UIDPLUS X-GM-EXT-1", []writeStep{googleListStep(googleListRoles), {contains: `APPEND "[Gmail]/Enviados" (\Seen)`, literal: raw, reply: "{tag} OK [APPENDUID 32 71] appended\r\n"}})
	b.config.Provider = "custom"
	got, err := b.AppendSent(context.Background(), testMessage)
	if err != nil || got.Status != "appended" || got.Destination == nil || got.Destination.Folder != "[Gmail]/Enviados" {
		t.Fatalf("non-Google SMTP filing changed: %+v %v", got, err)
	}
}

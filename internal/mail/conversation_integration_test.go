package mail_test

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/amxv/angelos/internal/app"
	"github.com/amxv/angelos/internal/mail"
)

func TestRealIMAPOAuthMCPConversationPagination(t *testing.T) {
	f := newIntegrationAuthFixture(t)
	for _, order := range []string{"newest", "oldest"} {
		t.Run(order, func(t *testing.T) {
			backend, anchor, trace := mail.BackendForConversationTesting(t)
			b, store := &integrationBackend{Backend: backend}, &integrationStore{}
			a := &app.App{Mail: b, Store: store} // Read-only deployment, no write/send gates.
			wantUIDs := []uint32{25, 24, 23, 14, 13}
			if order == "oldest" {
				wantUIDs = []uint32{13, 14, 23, 24, 25}
			}
			cursor := ""
			var gotUIDs []uint32
			for page := 0; page < 3; page++ {
				args := map[string]any{"action": "conversation", "reference": anchor, "search": map[string]any{"folder": "INBOX", "order": order, "limit": 2, "cursor": cursor}}
				if page == 1 {
					args["detail"] = "full"
				}
				status, out := f.call(t, a, "mail.read", "mail_query", inboxIntegrationArgs(t, args))
				fields := inboxIntegrationWire(t, status, out)
				var gotAnchor mail.Reference
				if err := json.Unmarshal(fields["anchor"], &gotAnchor); err != nil || gotAnchor != anchor {
					t.Fatalf("anchor changed: %s: %v", fields["anchor"], err)
				}
				if string(fields["folder"]) != `"INBOX"` || string(fields["uid_validity"]) != "7" || string(fields["order"]) != fmt.Sprintf("%q", order) {
					t.Fatalf("wrong mailbox scope/order: %#v", fields)
				}
				var scanned int
				if err := json.Unmarshal(fields["scanned_uids"], &scanned); err != nil || scanned < 1 || scanned > 1000 {
					t.Fatalf("unbounded or missing scan metadata: %s: %v", fields["scanned_uids"], err)
				}
				rows := inboxIntegrationRows(t, fields)
				wantRows := 2
				if page == 2 {
					wantRows = 1
				}
				if len(rows) != wantRows {
					t.Fatalf("page %d size=%d want %d", page, len(rows), wantRows)
				}
				for _, row := range rows {
					var ref mail.Reference
					if page == 1 {
						if err := json.Unmarshal(row["reference"], &ref); err != nil || row["uid"] != nil {
							t.Fatalf("full summary lost nested reference: %#v: %v", row, err)
						}
					} else {
						ref.Folder, ref.UIDValidity = "INBOX", 7
						if err := json.Unmarshal(row["uid"], &ref.UID); err != nil || row["reference"] != nil {
							t.Fatalf("compact summary lost shared identity: %#v: %v", row, err)
						}
					}
					if ref != (mail.Reference{Folder: "INBOX", UIDValidity: 7, UID: wantUIDs[len(gotUIDs)]}) {
						t.Fatalf("wrong exact ID match/page order: %+v; preceding UIDs %v", ref, gotUIDs)
					}
					gotUIDs = append(gotUIDs, ref.UID)
					if string(row["modseq"]) != "9007199254740993" {
						t.Fatalf("real IMAP uint64 MODSEQ rounded through MCP: %s", row["modseq"])
					}
					// Every fixture message has the same subject, including false
					// positives. Exact header links must determine membership.
					if string(row["subject"]) != `"Shared subject"` {
						t.Fatalf("unexpected fixture summary: %#v", row)
					}
					var flags []string
					if err := json.Unmarshal(row["flags"], &flags); err != nil || !reflect.DeepEqual(flags, []string{`\Flagged`}) {
						t.Fatalf("conversation marked messages Seen or lost flags: %s: %v", row["flags"], err)
					}
					for _, key := range []string{"headers", "text", "html", "attachments", "bcc", "message_id", "references", "in_reply_to"} {
						if row[key] != nil {
							t.Fatalf("conversation leaked private header/content field %q", key)
						}
					}
				}
				coverage := string(fields["coverage"])
				for _, note := range []string{"Same-folder", "case-sensitive", "fixed ID set", "no subject matching or recursive expansion", "Other folders", "Headers are untrusted"} {
					if !strings.Contains(coverage, note) {
						t.Fatalf("missing coverage limit %q: %s", note, coverage)
					}
				}
				encoded := inboxIntegrationArgs(t, out)
				for _, headerID := range []string{"Anchor@Example.NET", "Root@Example.NET", "Parent@Example.NET", "Sibling@example"} {
					if strings.Contains(encoded, headerID) {
						t.Fatalf("selected header value leaked from conversation index: %s", headerID)
					}
				}
				previousCursor := cursor
				cursor = ""
				if raw := fields["next_cursor"]; raw != nil {
					if err := json.Unmarshal(raw, &cursor); err != nil {
						t.Fatal(err)
					}
				}
				if page < 2 && (cursor == "" || cursor == previousCursor) {
					t.Fatalf("conversation pagination stalled on page %d: %q", page, cursor)
				}
				if page == 2 && cursor != "" {
					t.Fatalf("conversation did not terminate: %q", cursor)
				}
			}
			if !reflect.DeepEqual(gotUIDs, wantUIDs) {
				t.Fatalf("ID equality/fixed-seed membership changed: %v want %v", gotUIDs, wantUIDs)
			}
			if b.sends != 0 || store.claims != 0 || len(store.messages) != 0 {
				t.Fatal("conversation touched send/preparation state")
			}
			commands := trace()
			const selectedHeaderPEEK = `BODY.PEEK[HEADER.FIELDS ("Message-ID" "References" "In-Reply-To")]<0.65537>`
			if !strings.Contains(commands, " EXAMINE INBOX") || !strings.Contains(commands, "UID SEARCH") || !strings.Contains(commands, selectedHeaderPEEK) {
				t.Fatalf("missing real read-only selected-header search: %s", commands)
			}
			for _, line := range strings.Split(commands, "\n") {
				if strings.Contains(line, "UID FETCH") && strings.Count(line, selectedHeaderPEEK) != 1 {
					t.Fatalf("fetch did not request exactly the bounded PEEK header set: %s", line)
				}
			}
			for _, forbidden := range []string{" SELECT ", " STORE ", " APPEND ", " COPY ", " MOVE ", " EXPUNGE", "BODY.PEEK[]", "BODY[", "BINARY", "SUBJECT", "BCC", `\Seen`} {
				if strings.Contains(commands, forbidden) {
					t.Fatalf("unsafe/unrelated IMAP operation %q: %s", forbidden, commands)
				}
			}
		})
	}
}

func TestRealIMAPOAuthMCPConversationRejectsBeforeConnection(t *testing.T) {
	f := newIntegrationAuthFixture(t)
	for _, tc := range []struct{ scope, extra string }{
		{"mail.send mail.write", ""},
		{"mail.read", `,"search":{"subject":""}`},
		{"mail.read", `,"search":{"attention":false}`},
		{"mail.read", `,"search":{"folder":"Other"}`},
		{"mail.read", `,"search":{"cursor":"malformed"}`},
		{"mail.read", `,"search":{"limit":101}`},
	} {
		t.Run(tc.scope+tc.extra, func(t *testing.T) {
			backend, ref, trace := mail.BackendForConversationTesting(t)
			store := &integrationStore{}
			a := &app.App{Mail: backend, Store: store}
			args := `{"action":"conversation","reference":` + inboxIntegrationArgs(t, ref) + tc.extra + `}`
			status, out := f.call(t, a, tc.scope, "mail_query", args)
			inboxIntegrationError(t, status, out)
			if trace() != "" || len(store.messages) != 0 || store.claims != 0 {
				t.Fatalf("rejected request connected to IMAP/store: %s", trace())
			}
		})
	}
}

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

// Read text JSON from the actual signed MCP response without float64 decoding,
// so the integration assertions cover UID and uint64 MODSEQ wire fidelity.
func inboxIntegrationWire(t *testing.T, status int, out map[string]any) map[string]json.RawMessage {
	t.Helper()
	integrationResult(t, status, out)
	r := out["result"].(map[string]any)
	content := r["content"].([]any)[0].(map[string]any)["text"].(string)
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(content), &fields); err != nil {
		t.Fatal(err)
	}
	return fields
}

func inboxIntegrationArgs(t *testing.T, args any) string {
	t.Helper()
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func inboxIntegrationError(t *testing.T, status int, out map[string]any) {
	t.Helper()
	if status >= 400 || out["error"] != nil {
		return
	}
	result, ok := out["result"].(map[string]any)
	if !ok || result["isError"] != true {
		t.Fatalf("unauthorized/invalid call succeeded HTTP %d: %#v", status, out)
	}
}

func inboxIntegrationRows(t *testing.T, fields map[string]json.RawMessage) []map[string]json.RawMessage {
	t.Helper()
	var rows []map[string]json.RawMessage
	if err := json.Unmarshal(fields["messages"], &rows); err != nil {
		t.Fatal(err)
	}
	return rows
}

func TestRealIMAPOAuthMCPTriagePagination(t *testing.T) {
	f := newIntegrationAuthFixture(t)
	for _, order := range []string{"newest", "oldest"} {
		t.Run(order, func(t *testing.T) {
			backend, trace := mail.BackendForTriageTesting(t)
			b, store := &integrationBackend{Backend: backend}, &integrationStore{}
			a := &app.App{Mail: b, Store: store} // Every mutation gate is disabled.
			firstUIDs, lastUID := []uint32{3, 2}, uint32(1)
			firstCounts := map[string]int{"messages": 2, "unread": 1, "flagged": 2, "unread_and_flagged": 1}
			lastCounts := map[string]int{"messages": 1, "unread": 1, "flagged": 0, "unread_and_flagged": 0}
			if order == "oldest" {
				firstUIDs, lastUID = []uint32{1, 2}, 3
				firstCounts["flagged"], firstCounts["unread_and_flagged"] = 1, 0
				lastCounts["flagged"], lastCounts["unread_and_flagged"] = 1, 1
			}
			cursor := ""
			var validity uint32
			for page := 0; page < 2; page++ {
				args := map[string]any{"action": "triage", "search": map[string]any{"subject": "Due", "order": order, "limit": 2, "cursor": cursor}}
				if page == 1 {
					args["detail"] = "full"
				}
				status, out := f.call(t, a, "mail.read", "mail_query", inboxIntegrationArgs(t, args))
				fields := inboxIntegrationWire(t, status, out)
				rows := inboxIntegrationRows(t, fields)
				var pageValidity uint32
				if err := json.Unmarshal(fields["uid_validity"], &pageValidity); err != nil || pageValidity == 0 {
					t.Fatalf("missing mailbox epoch: %s: %v", fields["uid_validity"], err)
				}
				if page == 0 {
					validity = pageValidity
				} else if pageValidity != validity {
					t.Fatal("mailbox epoch changed across pages")
				}
				if string(fields["folder"]) != `"INBOX"` || string(fields["order"]) != fmt.Sprintf("%q", order) {
					t.Fatalf("page scope changed: %#v", fields)
				}
				var scanned int
				if err := json.Unmarshal(fields["scanned_uids"], &scanned); err != nil || scanned < 1 || scanned > 1000 {
					t.Fatalf("unbounded or missing scan metadata: %s: %v", fields["scanned_uids"], err)
				}
				var counts map[string]int
				if err := json.Unmarshal(fields["page_counts"], &counts); err != nil {
					t.Fatal(err)
				}
				wantCounts, wantUIDs := firstCounts, firstUIDs
				if page == 1 {
					wantCounts, wantUIDs = lastCounts, []uint32{lastUID}
				}
				if !reflect.DeepEqual(counts, wantCounts) || len(rows) != len(wantUIDs) {
					t.Fatalf("page %d counts/rows: %v rows=%d want %v UIDs=%v", page, counts, len(rows), wantCounts, wantUIDs)
				}
				for i, row := range rows {
					var ref mail.Reference
					if page == 0 {
						ref.Folder, ref.UIDValidity = "INBOX", validity
						if err := json.Unmarshal(row["uid"], &ref.UID); err != nil || row["reference"] != nil {
							t.Fatalf("compact identity malformed: %#v: %v", row, err)
						}
					} else if err := json.Unmarshal(row["reference"], &ref); err != nil || row["uid"] != nil {
						t.Fatalf("full identity malformed: %#v: %v", row, err)
					}
					if ref != (mail.Reference{Folder: "INBOX", UIDValidity: validity, UID: wantUIDs[i]}) || string(row["subject"]) != `"Due"` {
						t.Fatalf("OR/AND filtering or exact identity changed: %#v", row)
					}
				}
				if !strings.Contains(string(fields["selection"]), "returned rows only") || !strings.Contains(string(fields["selection"]), "Flags can change") {
					t.Fatal("page counts represented as mailbox totals/stable snapshot")
				}
				encoded := inboxIntegrationArgs(t, out)
				for _, secret := range []string{"private@example.com", "private body"} {
					if strings.Contains(encoded, secret) {
						t.Fatalf("private mail data leaked in MCP output: %s", secret)
					}
				}
				for _, row := range rows {
					for _, key := range []string{"headers", "bcc", "text", "html", "attachments"} {
						if row[key] != nil {
							t.Fatalf("triage fetched/exposed content field %q", key)
						}
					}
				}
				cursor = ""
				if raw := fields["next_cursor"]; raw != nil {
					if err := json.Unmarshal(raw, &cursor); err != nil {
						t.Fatal(err)
					}
				}
				if (page == 0 && cursor == "") || (page == 1 && cursor != "") {
					t.Fatalf("unexpected continuation page %d: %q", page, cursor)
				}
			}
			// A repeated page must still see the original unread flags.
			status, out := f.call(t, a, "mail.read", "mail_query", inboxIntegrationArgs(t, map[string]any{"action": "triage", "search": map[string]any{"subject": "Due", "order": order, "limit": 2}}))
			fields := inboxIntegrationWire(t, status, out)
			var counts map[string]int
			if err := json.Unmarshal(fields["page_counts"], &counts); err != nil || !reflect.DeepEqual(counts, firstCounts) {
				t.Fatalf("triage changed message flags: %v: %v", counts, err)
			}
			if b.sends != 0 || store.claims != 0 || len(store.messages) != 0 {
				t.Fatal("triage touched send/preparation state")
			}
			commands := strings.ToUpper(trace())
			for _, forbidden := range []string{"BODY", "BINARY", " STORE ", " SELECT ", " APPEND ", " COPY ", " MOVE ", " EXPUNGE", "BCC"} {
				if strings.Contains(commands, forbidden) {
					t.Fatalf("triage fetched content or mutated mailbox (%s): %s", forbidden, commands)
				}
			}
			for _, required := range []string{" EXAMINE ", "UID SEARCH", "OR (UNSEEN) (FLAGGED)", "SUBJECT", "UID FETCH", "ENVELOPE", "FLAGS"} {
				if !strings.Contains(commands, required) {
					t.Fatalf("missing real read-only/filter operation %q: %s", required, commands)
				}
			}
		})
	}
}

func TestRealIMAPOAuthMCPTriageRejectsBeforeConnection(t *testing.T) {
	f := newIntegrationAuthFixture(t)
	for _, tc := range []struct{ scope, args string }{
		{"mail.send mail.write", `{"action":"triage"}`},
		{"mail.read", `{"action":"triage","search":{"attention":false}}`},
		{"mail.read", `{"action":"triage","reference":{"folder":"INBOX","uid_validity":1,"uid":1}}`},
	} {
		t.Run(tc.scope+tc.args, func(t *testing.T) {
			backend, trace := mail.BackendForTriageTesting(t)
			store := &integrationStore{}
			a := &app.App{Mail: backend, Store: store}
			status, out := f.call(t, a, tc.scope, "mail_query", tc.args)
			inboxIntegrationError(t, status, out)
			if trace() != "" || len(store.messages) != 0 || store.claims != 0 {
				t.Fatalf("rejected request reached IMAP/store: %s", trace())
			}
		})
	}
}

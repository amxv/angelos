package app

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/amxv/angelos/internal/mail"
)

// Exercise the real signed MCP boundary while keeping read/write entry points
// observable. Page contents are independent of the presentation helpers.
type inboxProtocolBackend struct {
	*groupedBackend
	page mail.SearchResult
}

func (b *inboxProtocolBackend) Search(_ context.Context, in mail.SearchRequest) (mail.SearchResult, error) {
	b.called("search")
	b.search = in
	return b.page, nil
}

func (b *inboxProtocolBackend) Conversation(_ context.Context, ref mail.Reference, in mail.SearchRequest) (mail.SearchResult, error) {
	b.called("conversation")
	b.reference, b.search = ref, in
	return b.page, nil
}

func assertInboxStoreUntouched(t *testing.T, store *groupedStore) {
	t.Helper()
	if store.puts+store.claims+store.completes+store.statuses != 0 {
		t.Fatalf("read-only action touched dispatch store: %#v", store)
	}
}

func TestInboxProtocolExactCompactAndFullPages(t *testing.T) {
	f := newGroupedAuthFixture(t)
	const maxModSeq uint64 = 18446744073709551615
	const validity uint32 = 4294967295
	for _, action := range []string{"triage", "conversation"} {
		for _, detail := range []string{"summary", "full"} {
			t.Run(action+"/"+detail, func(t *testing.T) {
				a, base, store := newGroupedApp()
				a.EnableWrites, a.EnableSend, a.EnableDelete = false, false, false
				base.message.Text = "body must never be read"
				page := mail.SearchResult{UIDValidity: validity, Order: "newest", ScannedUIDs: 1000, NextCursor: "bounded-page-cursor"}
				for i, flags := range [][]string{{`\Flagged`}, {`\sEeN`, `\fLaGgEd`}, {"custom-keyword"}} {
					row := base.message.Summary
					row.Reference = mail.Reference{Folder: "INBOX", UIDValidity: validity, UID: 4294967295 - uint32(i)}
					row.Flags, row.ModSeq = flags, maxModSeq
					page.Messages = append(page.Messages, row)
				}
				b := &inboxProtocolBackend{groupedBackend: base, page: page}
				a.Mail = b
				args := map[string]any{"action": action, "detail": detail}
				if action == "conversation" {
					args["reference"] = page.Messages[0].Reference
				}
				status, out := f.call(t, a, "mail.read", "mail_query", string(jsonBytes(t, args)))
				fields := protocolContent(t, groupedResult(t, status, out))
				if string(fields["folder"]) != `"INBOX"` || string(fields["uid_validity"]) != "4294967295" || string(fields["order"]) != `"newest"` || string(fields["scanned_uids"]) != "1000" || string(fields["next_cursor"]) != `"bounded-page-cursor"` {
					t.Fatalf("page metadata changed: %s", jsonBytes(t, fields))
				}
				var rows []map[string]json.RawMessage
				if err := json.Unmarshal(fields["messages"], &rows); err != nil || len(rows) != len(page.Messages) {
					t.Fatalf("invalid rows: %s: %v", fields["messages"], err)
				}
				for i, row := range rows {
					if string(row["modseq"]) != "18446744073709551615" {
						t.Fatalf("MODSEQ rounded at signed MCP boundary: %s", row["modseq"])
					}
					for _, key := range []string{"headers", "text", "html", "attachments", "bcc"} {
						if _, present := row[key]; present {
							t.Fatalf("summary leaked %s", key)
						}
					}
					if detail == "full" {
						if !reflect.DeepEqual(row, decoded(t, page.Messages[i])) {
							t.Fatalf("full summary/reference changed: %s", jsonBytes(t, row))
						}
					} else {
						if row["reference"] != nil || string(row["uid"]) != fmt.Sprint(page.Messages[i].Reference.UID) {
							t.Fatalf("compact identity changed: %s", jsonBytes(t, row))
						}
						for _, key := range []string{"subject", "from", "to", "date", "flags", "size_bytes", "modseq"} {
							if !reflect.DeepEqual(row[key], decoded(t, page.Messages[i])[key]) {
								t.Fatalf("compact row lost %s", key)
							}
						}
					}
				}
				wantCall := "conversation"
				if action == "triage" {
					wantCall = "search"
					if !b.search.Attention {
						t.Fatal("omitted attention did not become true")
					}
					var counts map[string]int
					if err := json.Unmarshal(fields["page_counts"], &counts); err != nil || !reflect.DeepEqual(counts, map[string]int{"messages": 3, "unread": 2, "flagged": 2, "unread_and_flagged": 1}) {
						t.Fatalf("case-insensitive overlapping page counts changed: %s: %v", fields["page_counts"], err)
					}
					for _, note := range []string{"Unread OR flagged", "AND supplied search filters", "returned rows only", "not mailbox totals or urgency", "Flags can change"} {
						if !strings.Contains(string(fields["selection"]), note) {
							t.Fatalf("missing triage scope disclosure %q: %s", note, fields["selection"])
						}
					}
				} else {
					if !reflect.DeepEqual(fields["anchor"], json.RawMessage(jsonBytes(t, page.Messages[0].Reference))) || b.reference != page.Messages[0].Reference {
						t.Fatal("exact conversation anchor changed")
					}
					for _, note := range []string{"Same-folder", "case-sensitive", "no subject matching or recursive expansion", "Headers are untrusted", "Read exact references"} {
						if !strings.Contains(string(fields["coverage"]), note) {
							t.Fatalf("missing conversation coverage disclosure %q: %s", note, fields["coverage"])
						}
					}
				}
				if !reflect.DeepEqual(b.calls, []string{wantCall}) {
					t.Fatalf("unexpected body read or mutation: %v", b.calls)
				}
				assertInboxStoreUntouched(t, store)
			})
		}
	}
}

func TestInboxProtocolSearchArgumentRouting(t *testing.T) {
	f := newGroupedAuthFixture(t)
	for _, search := range []string{
		`{"folder":"Projects","query":"invoice","order":"oldest","from":"sender@example.com","to":"owner@example.com","subject":"Due","message_id":"<Case@Example.com>","participant":"Person","since":"2026-01-01","before":"2026-02-01","unread":false,"flagged":false,"cursor":"triage-page","limit":7}`,
		`{"attention":true,"subject":"Due"}`,
	} {
		a, b, store := newGroupedApp()
		var want mail.SearchRequest
		if err := json.Unmarshal([]byte(search), &want); err != nil {
			t.Fatal(err)
		}
		want.Attention = true
		status, out := f.call(t, a, "mail.read", "mail_query", `{"action":"triage","search":`+search+`}`)
		groupedResult(t, status, out)
		if !reflect.DeepEqual(b.search, want) || !reflect.DeepEqual(b.calls, []string{"search"}) {
			t.Fatalf("triage changed supplied filters: %+v want %+v; calls %v", b.search, want, b.calls)
		}
		assertInboxStoreUntouched(t, store)
	}
	for _, search := range []string{`{}`, `{"folder":"INBOX","order":"oldest","cursor":"conversation-page","limit":7}`, `{"order":""}`} {
		a, b, store := newGroupedApp()
		var want mail.SearchRequest
		if err := json.Unmarshal([]byte(search), &want); err != nil {
			t.Fatal(err)
		}
		status, out := f.call(t, a, "mail.read", "mail_query", `{"action":"conversation","reference":`+groupedReferenceJSON+`,"search":`+search+`}`)
		groupedResult(t, status, out)
		if !reflect.DeepEqual(b.search, want) || b.reference != groupedReference || !reflect.DeepEqual(b.calls, []string{"conversation"}) {
			t.Fatalf("conversation changed anchor/options: %+v %+v %v", b.reference, b.search, b.calls)
		}
		assertInboxStoreUntouched(t, store)
	}
}

func TestInboxProtocolRejectsInvalidFieldsBeforeBackend(t *testing.T) {
	f := newGroupedAuthFixture(t)
	args := []string{
		`{"action":"triage","reference":` + groupedReferenceJSON + `}`,
		`{"action":"triage","index":1}`,
		`{"action":"triage","prepared_id":"00000000000000000000000000000000"}`,
		`{"action":"triage","search":null}`,
		`{"action":"triage","search":{"attention":false}}`,
		`{"action":"triage","search":{"attention":null}}`,
		`{"action":"triage","search":{"attention":"true"}}`,
		`{"action":"triage","search":{"unknown":true}}`,
		`{"action":"conversation"}`,
		`{"action":"conversation","reference":null}`,
		`{"action":"conversation","reference":` + groupedReferenceJSON + `,"index":1}`,
		`{"action":"conversation","reference":` + groupedReferenceJSON + `,"search":null}`,
	}
	// Even zero-valued forbidden filters must fail: accepting them would silently
	// discard caller intent and make the shared search schema misleading.
	for _, field := range []string{`"query":""`, `"from":""`, `"to":""`, `"subject":""`, `"since":""`, `"before":""`, `"message_id":""`, `"participant":""`, `"unread":false`, `"flagged":false`, `"attention":false`, `"attention":true`, `"unknown":0`} {
		args = append(args, `{"action":"conversation","reference":`+groupedReferenceJSON+`,"search":{`+field+`}}`)
	}
	for _, action := range []string{"triage", "conversation"} {
		for _, detail := range []string{`null`, `"verbose"`} {
			ref := ""
			if action == "conversation" {
				ref = `,"reference":` + groupedReferenceJSON
			}
			args = append(args, `{"action":"`+action+`"`+ref+`,"detail":`+detail+`}`)
		}
	}
	for _, args := range args {
		t.Run(args, func(t *testing.T) {
			a, b, store := newGroupedApp()
			status, out := f.call(t, a, "mail.read mail.write mail.send", "mail_query", args)
			groupedExpectError(t, status, out)
			if len(b.calls) != 0 {
				t.Fatalf("invalid arguments reached backend: %v", b.calls)
			}
			assertInboxStoreUntouched(t, store)
		})
	}
}

func TestInboxProtocolReadScopeAndDeploymentIsolation(t *testing.T) {
	f := newGroupedAuthFixture(t)
	for _, args := range []string{`{"action":"triage"}`, `{"action":"conversation","reference":` + groupedReferenceJSON + `}`} {
		for _, scope := range []string{"", "mail.write", "mail.send", "mail.write mail.send", "mail.read"} {
			t.Run(args+"/"+scope, func(t *testing.T) {
				a, b, store := newGroupedApp()
				a.EnableWrites, a.EnableSend, a.EnableDelete, a.Store = false, false, false, nil
				status, out := f.call(t, a, scope, "mail_query", args)
				if scope == "mail.read" {
					groupedResult(t, status, out)
					if len(b.calls) != 1 {
						t.Fatalf("read needs mutation gate or store: %v", b.calls)
					}
				} else {
					groupedExpectError(t, status, out)
					if len(b.calls) != 0 {
						t.Fatalf("missing read scope reached backend: %v", b.calls)
					}
				}
				assertInboxStoreUntouched(t, store)
			})
		}
	}
}

func TestInboxProtocolEmptyBoundedPagesRetainCursor(t *testing.T) {
	f := newGroupedAuthFixture(t)
	for _, action := range []string{"triage", "conversation"} {
		a, base, store := newGroupedApp()
		a.Mail = &inboxProtocolBackend{groupedBackend: base, page: mail.SearchResult{Messages: []mail.Summary{}, UIDValidity: 9, ScannedUIDs: 1000, NextCursor: "continue-empty-page", Order: "newest"}}
		args := map[string]any{"action": action}
		if action == "conversation" {
			args["reference"] = groupedReference
		}
		status, out := f.call(t, a, "mail.read", "mail_query", string(jsonBytes(t, args)))
		fields := protocolContent(t, groupedResult(t, status, out))
		if string(fields["messages"]) != "[]" || string(fields["next_cursor"]) != `"continue-empty-page"` || string(fields["scanned_uids"]) != "1000" {
			t.Fatalf("empty page lost continuation: %s", jsonBytes(t, fields))
		}
		if action == "triage" {
			var counts map[string]int
			if err := json.Unmarshal(fields["page_counts"], &counts); err != nil || !reflect.DeepEqual(counts, map[string]int{"messages": 0, "unread": 0, "flagged": 0, "unread_and_flagged": 0}) {
				t.Fatalf("empty page counted scan window as mail: %s: %v", fields["page_counts"], err)
			}
		}
		assertInboxStoreUntouched(t, store)
	}
}

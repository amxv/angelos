package app

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/amxv/angelos/internal/compose"
	"github.com/amxv/angelos/internal/mail"
)

func jsonBytes(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func decoded(t *testing.T, v any) map[string]json.RawMessage {
	t.Helper()
	var m map[string]json.RawMessage
	if e := json.Unmarshal(jsonBytes(t, v), &m); e != nil {
		t.Fatal(e)
	}
	return m
}
func TestSearchSummaryLossless(t *testing.T) {
	page := mail.SearchResult{UIDValidity: 4294967295, ScannedUIDs: 1000, Order: "oldest", NextCursor: "opaque-freshness-cursor"}
	for i := 0; i < 25; i++ {
		page.Messages = append(page.Messages, mail.Summary{Reference: mail.Reference{Folder: "INBOX", UIDValidity: page.UIDValidity, UID: uint32(100 + i)}, Subject: "Quarterly status update", From: []mail.Address{{Name: "Alice", Address: "alice@example.com"}}, To: []mail.Address{{Address: "owner@example.com"}}, Date: time.Date(2026, 10, 6, 10, 0, 0, 0, time.UTC), Flags: []string{`\Seen`}, Size: 18000, ModSeq: 18446744073709551615})
	}
	compact := searchSummary(page, "INBOX")
	if compact["uid_validity"] != page.UIDValidity || compact["folder"] != "INBOX" || compact["next_cursor"] != page.NextCursor || compact["order"] != page.Order || compact["scanned_uids"] != page.ScannedUIDs {
		t.Fatal(compact)
	}
	for i, row := range compact["messages"].([]result) {
		restored := result{}
		for k, v := range row {
			restored[k] = v
		}
		delete(restored, "uid")
		restored["reference"] = mail.Reference{Folder: "INBOX", UIDValidity: page.UIDValidity, UID: row["uid"].(uint32)}
		if !reflect.DeepEqual(decoded(t, restored), decoded(t, page.Messages[i])) {
			t.Fatalf("row %d loses data", i)
		}
	}
	before, after := len(jsonBytes(t, page)), len(jsonBytes(t, compact))
	if after >= before {
		t.Fatal("search summary did not shrink")
	}
	t.Logf("25-result search payload JSON bytes: %d -> %d; approximate ceil(bytes/4): %d -> %d", before, after, (before+3)/4, (after+3)/4)
	empty := searchSummary(mail.SearchResult{UIDValidity: 7, NextCursor: "more", Order: "newest", ScannedUIDs: 1000}, "")
	if empty["folder"] != "INBOX" || empty["next_cursor"] != "more" || len(empty["messages"].([]result)) != 0 {
		t.Fatal(empty)
	}
	page.Messages[0].Reference.Folder = "Other"
	if searchSummary(page, "INBOX")["messages"].([]result)[0]["reference"] != page.Messages[0].Reference {
		t.Fatal("unexpected reference lost")
	}
}
func TestReadSummaryPreservesSafetyAndFullText(t *testing.T) {
	original := mail.Message{Summary: mail.Summary{Reference: mail.Reference{Folder: "INBOX", UIDValidity: 7, UID: 9}, Flags: []string{`\Flagged`}, ModSeq: 18446744073709551615}, Headers: map[string]string{"Reply-To": "reply@example.com", "Cc": "copy@example.com", "Message-Id": "<id@example.com>", "References": "<prev@example.com>"}, Text: strings.Repeat("界", 6000), Attachments: []mail.Attachment{{Index: 1, Filename: "report.pdf", ContentType: "application/pdf", Size: 99}}, Warnings: []string{"fixture warning"}, Truncated: true}
	compact := messageSummary(original)
	text := compact["text"].(string)
	if !utf8.ValidString(text) || len(text) > summaryTextBytes || !strings.HasPrefix(original.Text, text) || compact["text_clipped"] != true || compact["text_bytes"] != len(original.Text) || compact["full_text_hint"] == nil {
		t.Fatal("invalid clipped text")
	}
	old, new := decoded(t, original), decoded(t, compact)
	for _, field := range []string{"reference", "headers", "flags", "modseq", "attachments", "warnings", "truncated"} {
		if !reflect.DeepEqual(old[field], new[field]) {
			t.Fatal("lost safety field", field)
		}
	}
	if len(original.Text) != 18000 || !original.Truncated {
		t.Fatal("mutated backend message")
	}
	before, after := len(jsonBytes(t, original)), len(jsonBytes(t, compact))
	t.Logf("18KB-text read payload JSON bytes: %d -> %d; approximate ceil(bytes/4): %d -> %d", before, after, (before+3)/4, (after+3)/4)
	original.Text = "short"
	original.Truncated = false
	if _, ok := messageSummary(original)["text_clipped"]; ok {
		t.Fatal("false clipping")
	}
	original.Attachments = nil
	original.Headers = nil
	summary := messageSummary(original)
	if _, ok := summary["attachments"]; ok {
		t.Fatal("empty attachment metadata not omitted")
	}
	if _, ok := summary["truncated"]; !ok {
		t.Fatal("false safety marker omitted")
	}
}
func TestPreparationPreviewIsNeverCompacted(t *testing.T) {
	p := compose.Prepared{ID: "id", Digest: "digest", From: "from@example.com", To: []string{"to@example.com"}, Cc: []string{}, Bcc: []string{"hidden@example.com"}, Text: strings.Repeat("a", 10000), Attachments: []compose.AttachmentSummary{{Filename: "file", SHA256: "hash"}}, MessageID: "<id@example.com>", ExpiresAt: time.Now()}
	r := preview(p)
	if r["text"] != p.Text || !reflect.DeepEqual(r["bcc"], p.Bcc) || r["digest"] != p.Digest || !reflect.DeepEqual(r["attachments"], p.Attachments) {
		t.Fatal("preview loses approval content")
	}
	for _, field := range []string{"to", "cc", "bcc", "confirmation", "expires_at", "prepared_id", "digest", "message_id", "encoded_bytes", "status"} {
		if _, ok := r[field]; !ok {
			t.Fatal("missing preview field", field)
		}
	}
}

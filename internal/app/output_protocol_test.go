package app

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/amxv/angelos/internal/mail"
)

func protocolContent(t *testing.T, r map[string]any) map[string]json.RawMessage {
	t.Helper()
	content := r["content"].([]any)[0].(map[string]any)["text"].(string)
	var out map[string]json.RawMessage
	if e := json.Unmarshal([]byte(content), &out); e != nil {
		t.Fatal(e)
	}
	// The helper's structured map was decoded as float64; assert exact integer
	// fidelity against text JSON copied from the real wire response instead.
	if r["structuredContent"] == nil {
		t.Fatal("missing structured MCP representation")
	}
	return out
}
func TestFullReadAndSearchProtocolParity(t *testing.T) {
	f := newGroupedAuthFixture(t)
	a, b, _ := newGroupedApp()
	b.message.Summary.ModSeq = 18446744073709551615
	b.message.Text = strings.Repeat("example body ", 1000)
	b.message.Warnings = []string{"preserved warning"}
	status, out := f.call(t, a, "mail.read", "mail_query", `{"action":"read","reference":`+groupedReferenceJSON+`,"detail":"full"}`)
	full := groupedResult(t, status, out)
	if !reflect.DeepEqual(protocolContent(t, full), decoded(t, b.message)) {
		t.Fatal("full read differs from original backend output")
	}
	status, out = f.call(t, a, "mail.read", "mail_query", `{"action":"read","reference":`+groupedReferenceJSON+`}`)
	summary := groupedResult(t, status, out)
	summaryFields := protocolContent(t, summary)
	if string(summaryFields["modseq"]) != "18446744073709551615" {
		t.Fatal("MODSEQ changed on wire", string(summaryFields["modseq"]))
	}
	for _, key := range []string{"reference", "headers", "flags", "modseq", "warnings", "truncated", "attachments"} {
		if !reflect.DeepEqual(summaryFields[key], decoded(t, b.message)[key]) {
			t.Fatal("compact read loses", key)
		}
	}
	if string(summaryFields["text_clipped"]) != "true" {
		t.Fatal("missing clipped marker")
	}
	t.Logf("actual MCP read result JSON bytes (text + structured): full=%d summary=%d", len(jsonBytes(t, full)), len(jsonBytes(t, summary)))
	status, out = f.call(t, a, "mail.read", "mail_query", `{"action":"search","detail":"full"}`)
	full = groupedResult(t, status, out)
	expected := mail.SearchResult{Messages: []mail.Summary{b.message.Summary}, UIDValidity: groupedReference.UIDValidity, NextCursor: "cursor-next", ScannedUIDs: 1000, Order: "oldest"}
	if !reflect.DeepEqual(protocolContent(t, full), decoded(t, expected)) {
		t.Fatal("full search differs from original backend output")
	}
	status, out = f.call(t, a, "mail.read", "mail_query", `{"action":"search"}`)
	summary = groupedResult(t, status, out)
	if !reflect.DeepEqual(protocolContent(t, summary), decoded(t, searchSummary(expected, "INBOX"))) {
		t.Fatal("summary search differs on wire")
	}
}

type partialBackend struct{ *groupedBackend }

func (b *partialBackend) Read(context.Context, mail.Reference) (mail.Message, error) {
	return b.message, errors.New("fixture partial read")
}
func (b *partialBackend) Move(context.Context, mail.Reference, string) (mail.MutationResult, error) {
	return mail.MutationResult{Source: &groupedReference, Status: "unknown", Warnings: []string{"may have succeeded; verify before retrying"}}, mail.ErrOutcomeUnknown
}
func (b *partialBackend) SetFlags(context.Context, mail.FlagRequest) (mail.FlagResult, error) {
	return mail.FlagResult{Reference: groupedReference, ModSeq: 999, Conditional: true}, mail.ErrConflict
}
func TestGroupedErrorsPreservePartialOutcomes(t *testing.T) {
	f := newGroupedAuthFixture(t)
	for _, tc := range []struct {
		name, args string
		retry      bool
	}{
		{"mail_query", `{"action":"read","reference":` + groupedReferenceJSON + `}`, true},
		{"mail_modify", `{"action":"move","reference":` + groupedReferenceJSON + `,"destination":"Archive"}`, false},
		{"mail_modify", `{"action":"flags","reference":` + groupedReferenceJSON + `,"operation":"add","flags":["\\Seen"],"unchanged_since":1}`, false},
	} {
		a, b, _ := newGroupedApp()
		a.Mail = &partialBackend{b}
		b.message.Text = strings.Repeat("unclipped partial data ", 1000)
		b.message.Truncated = true
		b.message.Warnings = []string{"partial source"}
		status, out := f.call(t, a, "mail.read mail.write", tc.name, tc.args)
		groupedExpectError(t, status, out)
		r := out["result"].(map[string]any)
		payload := r["structuredContent"].(map[string]any)
		if payload["retry_safe"] != tc.retry || payload["error"] == nil || payload["outcome"] == nil {
			t.Fatal("error contract changed", payload)
		}
		partial := payload["outcome"].(map[string]any)
		if tc.retry {
			if partial["text"] != b.message.Text || partial["truncated"] != true || partial["warnings"] == nil {
				t.Fatal("partial read compacted", partial)
			}
		}
		if strings.Contains(tc.args, `"move"`) {
			if partial["status"] != "unknown" || partial["warnings"] == nil || partial["source"] == nil {
				t.Fatal("uncertain mutation information lost", partial)
			}
		}
		if strings.Contains(tc.args, `"flags"`) {
			if partial["modseq"] != float64(999) || partial["conditional"] != true {
				t.Fatal("conflict information lost", partial)
			}
		}
	}
}

func TestModSeqInputRemainsExactThroughSDK(t *testing.T) {
	f := newGroupedAuthFixture(t)
	for _, value := range []string{"9007199254740995", "18446744073709551615"} {
		a, b, _ := newGroupedApp()
		status, out := f.call(t, a, "mail.read mail.write", "mail_modify", `{"action":"flags","reference":`+groupedReferenceJSON+`,"operation":"add","flags":["\\Seen"],"unchanged_since":`+value+`}`)
		groupedResult(t, status, out)
		if string(jsonBytes(t, b.flag.UnchangedSince)) != value {
			t.Fatalf("MODSEQ precondition rounded: got %d want %s", b.flag.UnchangedSince, value)
		}
	}
}

func TestExplicitEmptySearchOrderRetainsDefault(t *testing.T) {
	f := newGroupedAuthFixture(t)
	a, b, _ := newGroupedApp()
	status, out := f.call(t, a, "mail.read", "mail_query", `{"action":"search","search":{"order":""}}`)
	groupedResult(t, status, out)
	if b.search.Order != "" {
		t.Fatal("default order changed")
	}
}

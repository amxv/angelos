package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/amxv/angelos/internal/compose"
	"github.com/amxv/angelos/internal/mail"
)

type draftBackend struct {
	*groupedBackend
	source             mail.Draft
	readErr, appendErr error
}

func (b *draftBackend) ReadDraft(_ context.Context, ref mail.Reference) (mail.Draft, error) {
	b.called("read_draft")
	b.reference = ref
	return b.source, b.readErr
}
func (b *draftBackend) AppendDraft(ctx context.Context, folder string, raw []byte) (mail.MutationResult, error) {
	if b.appendErr != nil {
		b.called("draft")
		return mail.MutationResult{Status: "unknown"}, b.appendErr
	}
	return b.groupedBackend.AppendDraft(ctx, folder, raw)
}
func newDraftApp(t *testing.T) (*App, *draftBackend, *groupedStore) {
	t.Helper()
	a, b, s := newGroupedApp()
	input := compose.Input{To: []string{"to@example.com"}, Cc: []string{"cc@example.com"}, Bcc: []string{"hidden@example.com"}, Subject: "Original", Text: "Original text", HTML: "<p>Original HTML</p>", InReplyTo: "<Parent@Example.COM>", References: []string{"<Root@Example.COM>"}, Attachments: []compose.Attachment{{Filename: "binary.dat", ContentType: "application/octet-stream", DataBase64: "AP+A"}}}
	p, err := compose.BuildDraft(a.Config.From, input, strings.Repeat("a", 32), time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := compose.DraftBytes(p)
	if err != nil {
		t.Fatal(err)
	}
	content, err := compose.ParseDraft(raw)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	backend := &draftBackend{groupedBackend: b, source: mail.Draft{Reference: groupedReference, SourceDigest: hex.EncodeToString(sum[:]), Flags: []string{`\dRaFt`}, DraftContent: content, Warnings: []string{"Normalized rebuild; original retained."}}}
	a.Mail = backend
	return a, backend, s
}
func draftArgs(b *draftBackend, action string) string {
	return `{"action":"` + action + `","reference":` + groupedReferenceJSON + `,"source_digest":"` + b.source.SourceDigest + `"}`
}

func TestDraftQueryCompleteAndReadOnly(t *testing.T) {
	f := newGroupedAuthFixture(t)
	a, b, s := newDraftApp(t)
	a.EnableWrites, a.EnableSend, a.EnableDelete, a.Store = false, false, false, nil
	status, out := f.call(t, a, "mail.read", "mail_query", `{"action":"draft","reference":`+groupedReferenceJSON+`}`)
	body := groupedResult(t, status, out)["structuredContent"].(map[string]any)
	message := body["message"].(map[string]any)
	if body["source_digest"] != b.source.SourceDigest || message["html"] != b.source.Message.HTML || message["text"] != b.source.Message.Text || message["in_reply_to"] != "<Parent@Example.COM>" {
		t.Fatalf("incomplete draft: %#v", body)
	}
	encoded, _ := json.Marshal(body)
	for _, needle := range []string{"hidden@example.com", "cc@example.com", "to@example.com", "AP+A", "binary.dat"} {
		if !bytes.Contains(encoded, []byte(needle)) {
			t.Fatalf("draft omitted %s", needle)
		}
	}

	if !reflect.DeepEqual(message["references"], []any{"<Root@Example.COM>"}) {
		t.Fatal("thread references omitted")
	}
	if !reflect.DeepEqual(b.calls, []string{"read_draft"}) || s.puts+s.claims != 0 {
		t.Fatalf("read side effects: %v", b.calls)
	}
}

func TestReviseDraftAppendsPreservingSourceAndFields(t *testing.T) {
	f := newGroupedAuthFixture(t)
	a, b, s := newDraftApp(t)
	before, _ := json.Marshal(b.source)
	args := strings.TrimSuffix(draftArgs(b, "revise_draft"), "}") + `,"changes":{"subject":"Revised","text":"New text","html":"<p>New HTML</p>"}}`
	status, out := f.call(t, a, "mail.read mail.write", "mail_create", args)
	body := groupedResult(t, status, out)["structuredContent"].(map[string]any)
	after, _ := json.Marshal(b.source)
	if !bytes.Equal(before, after) || body["original_retained"] != true || b.name != groupedReference.Folder || !reflect.DeepEqual(b.calls, []string{"read_draft", "draft"}) || s.puts+s.claims != 0 {
		t.Fatalf("destructive revision: %#v %v", body, b.calls)
	}
	revised, err := compose.ParseDraft(b.draft)
	if err != nil {
		t.Fatal(err)
	}
	if revised.Message.Subject != "Revised" || revised.Message.Text != "New text" || revised.Message.HTML != "<p>New HTML</p>" || !reflect.DeepEqual(revised.Message.Bcc, b.source.Message.Bcc) || !reflect.DeepEqual(revised.Message.Attachments, b.source.Message.Attachments) || revised.Message.InReplyTo != b.source.Message.InReplyTo || !reflect.DeepEqual(revised.Message.References, b.source.Message.References) {
		t.Fatalf("revision lost source fields: %+v", revised)
	}
	if revised.MessageID == b.source.MessageID {
		t.Fatal("revision reused source identity")
	}
	revision := body["revision"].(map[string]any)
	if revision["status"] != "appended" || revision["source"].(map[string]any)["uid"] != float64(groupedReference.UID) {
		t.Fatalf("missing exact outcome: %#v", revision)
	}
}

func TestReviseDraftExplicitEmptyFieldsAndDestination(t *testing.T) {
	f := newGroupedAuthFixture(t)
	a, b, _ := newDraftApp(t)
	args := strings.TrimSuffix(draftArgs(b, "revise_draft"), "}") + `,"folder":"Draft Revisions","changes":{"to":[],"cc":[],"bcc":[],"text":"","html":"<p>Original HTML</p>","attachments":[],"in_reply_to":"","references":[]}}`
	status, out := f.call(t, a, "mail.read mail.write", "mail_create", args)
	groupedResult(t, status, out)
	d, err := compose.ParseDraft(b.draft)
	if err != nil {
		t.Fatal(err)
	}
	if b.name != "Draft Revisions" || len(d.Message.To)+len(d.Message.Cc)+len(d.Message.Bcc)+len(d.Message.Attachments)+len(d.Message.References) != 0 || d.Message.InReplyTo != "" || d.Message.Text != "" || d.Message.HTML != b.source.Message.HTML {
		t.Fatalf("clear failed: %+v", d)
	}
}

func TestPrepareDraftSnapshotWithoutMessageOrCleanup(t *testing.T) {
	f := newGroupedAuthFixture(t)
	a, b, s := newDraftApp(t)
	a.EnableWrites = false
	status, out := f.call(t, a, "mail.read mail.send", "mail_prepare", draftArgs(b, "draft"))
	body := groupedResult(t, status, out)["structuredContent"].(map[string]any)
	p := s.record.Message
	if body["source_digest"] != b.source.SourceDigest || body["original_retained"] != true || body["in_reply_to"] != b.source.Message.InReplyTo || body["html"] != p.HTML || body["text"] != p.Text || p.Digest != compose.WireDigest(p.From, p.Recipients, p.Raw) || len(p.Attachments) != 1 || !strings.Contains(p.Bcc[0], "hidden@example.com") || bytes.Contains(p.Raw, []byte("Bcc:")) {
		t.Fatalf("unsafe snapshot: %#v", body)
	}
	if !reflect.DeepEqual(b.calls, []string{"read_draft"}) || s.puts != 1 || s.claims != 0 {
		t.Fatalf("prepare mutated mailbox/sent: %v", b.calls)
	}
	saved := append([]byte(nil), p.Raw...)
	b.source.Message.Text = "Changed concurrently"
	b.source.SourceDigest = strings.Repeat("f", 64)
	if !bytes.Equal(s.record.Message.Raw, saved) || s.record.Message.Digest != p.Digest {
		t.Fatal("prepared snapshot followed later source mutation")
	}
}

func TestDraftActionsRejectBeforeBackend(t *testing.T) {
	f := newGroupedAuthFixture(t)
	for _, tc := range []struct{ tool, args string }{
		{"mail_prepare", `{"action":"draft","reference":` + groupedReferenceJSON + `}`},
		{"mail_prepare", `{"action":"draft","reference":` + groupedReferenceJSON + `,"source_digest":"bad"}`},
		{"mail_prepare", `{"action":"draft","reference":` + groupedReferenceJSON + `,"source_digest":"` + strings.Repeat("A", 64) + `"}`},
		{"mail_prepare", `{"action":"draft","reference":` + groupedReferenceJSON + `,"source_digest":"` + strings.Repeat("a", 64) + `","message":{}}`},
		{"mail_query", `{"action":"draft","reference":` + groupedReferenceJSON + `,"detail":"full"}`},
		{"mail_query", `{"action":"draft","reference":{"folder":"INBOX","uid":0,"uid_validity":9}}`},
		{"mail_create", `{"action":"draft","message":{"text":"","html":"<p>x</p>","preserve_empty_text":true}}`},
	} {
		a, b, s := newDraftApp(t)
		status, out := f.call(t, a, "mail.read mail.write mail.send", tc.tool, tc.args)
		groupedExpectError(t, status, out)
		if len(b.calls) != 0 || s.puts+s.claims != 0 {
			t.Fatalf("invalid request reached backend: %s %v", tc.args, b.calls)
		}
	}
	for _, changes := range []string{`{}`, `null`, `{"subject":null}`, `{"bcc":null}`, `{"attachments":null}`, `{"text":null}`, `{"from":"other@example.com"}`, `{"raw":"fake"}`, `{"preserve_empty_text":true}`} {
		a, b, s := newDraftApp(t)
		args := strings.TrimSuffix(draftArgs(b, "revise_draft"), "}") + `,"changes":` + changes + `}`
		status, out := f.call(t, a, "mail.read mail.write", "mail_create", args)
		groupedExpectError(t, status, out)
		if len(b.calls) != 0 || s.puts+s.claims != 0 {
			t.Fatalf("invalid patch reached backend: %s %v", changes, b.calls)
		}
	}
}

func TestDraftActionsScopeAndDeploymentGates(t *testing.T) {
	f := newGroupedAuthFixture(t)
	for _, mode := range []string{"read scope", "write scope", "send scope", "write disabled", "send disabled", "store missing"} {
		t.Run(mode, func(t *testing.T) {
			a, b, s := newDraftApp(t)
			tool, scope, args := "mail_prepare", "mail.read mail.send", draftArgs(b, "draft")
			switch mode {
			case "read scope":
				tool, scope, args = "mail_query", "mail.send", `{"action":"draft","reference":`+groupedReferenceJSON+`}`
			case "write scope", "write disabled":
				tool, scope, args = "mail_create", "mail.read mail.write", strings.TrimSuffix(draftArgs(b, "revise_draft"), "}")+`,"changes":{"subject":"changed"}}`
				if mode == "write scope" {
					scope = "mail.read"
				} else {
					a.EnableWrites = false
				}
			case "send scope":
				scope = "mail.read"
			case "send disabled":
				a.EnableSend = false
			case "store missing":
				a.Store = nil
			}
			status, out := f.call(t, a, scope, tool, args)
			groupedExpectError(t, status, out)
			if len(b.calls) != 0 || s.puts+s.claims != 0 {
				t.Fatalf("gate bypass: %v", b.calls)
			}
		})
	}
}

func TestDraftConflictAndSourceFailuresNeverMutate(t *testing.T) {
	f := newGroupedAuthFixture(t)
	for _, action := range []string{"draft", "revise_draft"} {
		for _, mode := range []string{"digest changed", "not draft", "deleted", "wrong reference", "malformed backend digest", "stale", "unsupported", "wrong sender"} {
			t.Run(action+"/"+mode, func(t *testing.T) {
				a, b, s := newDraftApp(t)
				args := draftArgs(b, action)
				tool, scope := "mail_prepare", "mail.read mail.send"
				if action == "revise_draft" {
					tool, scope = "mail_create", "mail.read mail.write"
					args = strings.TrimSuffix(args, "}") + `,"changes":{"subject":"changed"}}`
				}
				switch mode {
				case "digest changed":
					b.source.SourceDigest = strings.Repeat("f", 64)
				case "not draft":
					b.source.Flags = []string{`\Seen`}
				case "deleted":
					b.source.Flags = append(b.source.Flags, `\Deleted`)
				case "wrong reference":
					b.source.Reference.UID++
				case "malformed backend digest":
					b.source.SourceDigest = "bad"
				case "stale":
					b.readErr = mail.ErrStaleReference
				case "unsupported":
					b.readErr = mail.ErrUnsupported
				case "wrong sender":
					b.source.From = "other@example.com"
				}
				status, out := f.call(t, a, scope, tool, args)
				groupedExpectError(t, status, out)
				if !reflect.DeepEqual(b.calls, []string{"read_draft"}) || s.puts+s.claims != 0 {
					t.Fatalf("unsafe failure: %v", b.calls)
				}
				if mode == "digest changed" {
					r := out["result"].(map[string]any)["structuredContent"].(map[string]any)
					if r["error_code"] != "conflict" {
						t.Fatalf("wrong conflict code: %#v", r)
					}
					const message = "draft source changed; read the draft again before revising or preparing"
					const recovery = "Read the complete draft again and review its new source_digest before revising or preparing. The original was not changed by this operation."
					if r["error"] != message || r["recovery"] != recovery || r["retry_safe"] != false || r["outcome"] != nil {
						t.Fatalf("incorrect draft conflict guidance: %#v", r)
					}
					retry := r["retry"].(map[string]any)
					if retry["action"] != "refresh_reference" || retry["transport_retry_safe"] != false {
						t.Fatalf("draft conflict retry semantics changed: %#v", retry)
					}
					content := out["result"].(map[string]any)["content"].([]any)
					var textPayload map[string]any
					if err := json.Unmarshal([]byte(content[0].(map[string]any)["text"].(string)), &textPayload); err != nil || !reflect.DeepEqual(textPayload, r) {
						t.Fatalf("text and structured conflict payloads differ: %v", err)
					}
				}
			})
		}
	}
}

func TestDraftRevisionUncertainAppendPreservesOutcome(t *testing.T) {
	f := newGroupedAuthFixture(t)
	a, b, s := newDraftApp(t)
	b.appendErr = mail.ErrOutcomeUnknown
	args := strings.TrimSuffix(draftArgs(b, "revise_draft"), "}") + `,"changes":{"subject":"changed"}}`
	status, out := f.call(t, a, "mail.read mail.write", "mail_create", args)
	groupedExpectError(t, status, out)
	result := out["result"].(map[string]any)["structuredContent"].(map[string]any)
	outcome := result["outcome"].(map[string]any)
	if result["error_code"] != "outcome_unknown" || outcome["original_retained"] != true || outcome["revision"].(map[string]any)["status"] != "unknown" || !reflect.DeepEqual(b.calls, []string{"read_draft", "draft"}) || s.puts+s.claims != 0 {
		t.Fatalf("uncertain append lost: %#v %v", result, b.calls)
	}
}

func TestDraftPreparationRejectsRecipientlessAndMissingRawBackend(t *testing.T) {
	f := newGroupedAuthFixture(t)
	a, b, s := newDraftApp(t)
	b.source.Message.To, b.source.Message.Cc, b.source.Message.Bcc = nil, nil, nil
	status, out := f.call(t, a, "mail.read mail.send", "mail_prepare", draftArgs(b, "draft"))
	groupedExpectError(t, status, out)
	if s.puts+s.claims != 0 {
		t.Fatal("recipientless snapshot saved")
	}
	a.Mail = b.groupedBackend
	status, out = f.call(t, a, "mail.read", "mail_query", `{"action":"draft","reference":`+groupedReferenceJSON+`}`)
	groupedExpectError(t, status, out)
	if len(b.calls) != 1 {
		t.Fatal("fell back to lossy display read")
	}
}

type failingDraftStore struct{ *groupedStore }

func (s failingDraftStore) Put(context.Context, compose.Prepared, string) error {
	return errors.New("synthetic storage failure")
}
func TestDraftPreparationStoreFailureNeverSends(t *testing.T) {
	f := newGroupedAuthFixture(t)
	a, b, s := newDraftApp(t)
	a.Store = failingDraftStore{s}
	status, out := f.call(t, a, "mail.read mail.send", "mail_prepare", draftArgs(b, "draft"))
	groupedExpectError(t, status, out)
	if !reflect.DeepEqual(b.calls, []string{"read_draft"}) || s.claims != 0 {
		t.Fatal("storage failure sent or mutated")
	}
}

func TestDraftPayloadLimitsReturnNoPartialOrMutation(t *testing.T) {
	f := newGroupedAuthFixture(t)
	for _, mode := range []string{"read", "revision source", "revision replacement", "prepare source", "prepare generated preview"} {
		t.Run(mode, func(t *testing.T) {
			a, b, s := newDraftApp(t)
			tool, scope, args := "mail_query", "mail.read", `{"action":"draft","reference":`+groupedReferenceJSON+`}`
			switch mode {
			case "read":
				b.source.Message.Text = strings.Repeat("x", maxDraftResponseBytes)
			case "revision source":
				tool, scope, args = "mail_create", "mail.read mail.write", strings.TrimSuffix(draftArgs(b, "revise_draft"), "}")+`,"changes":{"subject":"changed"}}`
				b.source.Message.Text = strings.Repeat("x", maxDraftResponseBytes)
			case "revision replacement":
				tool, scope, args = "mail_create", "mail.read mail.write", strings.TrimSuffix(draftArgs(b, "revise_draft"), "}")+`,"changes":{"text":"`+strings.Repeat("x", maxDraftResponseBytes)+`","html":""}}`
			case "prepare source":
				tool, scope, args = "mail_prepare", "mail.read mail.send", draftArgs(b, "draft")
				b.source.Message.Text = strings.Repeat("x", maxDraftResponseBytes)
			case "prepare generated preview":
				tool, scope, args = "mail_prepare", "mail.read mail.send", draftArgs(b, "draft")
				b.source.Message.Text = ""
				b.source.Message.PreserveEmptyText = false
				b.source.Message.HTML = "<p>" + strings.Repeat("x", 600000) + "</p>"
			}
			status, out := f.call(t, a, scope, tool, args)
			groupedExpectError(t, status, out)
			r := out["result"].(map[string]any)["structuredContent"].(map[string]any)
			if r["error_code"] != "safety_limit" || r["outcome"] != nil || !reflect.DeepEqual(b.calls, []string{"read_draft"}) || s.puts+s.claims != 0 {
				t.Fatalf("unsafe limit result: %#v %v", r, b.calls)
			}
		})
	}
}

func TestDraftBodyAlternativesRequireExplicitChoice(t *testing.T) {
	f := newGroupedAuthFixture(t)
	for _, tc := range []struct {
		name, sourceText, sourceHTML, patch string
		preserveText, reject                bool
	}{
		{"text leaves old HTML", "old", "<p>old</p>", `{"text":"new"}`, true, true},
		{"HTML leaves old text", "old", "<p>old</p>", `{"html":"<p>new</p>"}`, true, true},
		{"clearing HTML requires text choice", "old", "<p>old</p>", `{"html":""}`, true, true},
		{"adding HTML requires text choice", "old", "", `{"html":"<p>new</p>"}`, true, true},
		{"adding text requires HTML choice", "", "<p>old</p>", `{"text":"new"}`, false, true},
		{"explicit empty plain alternative", "", "<p>old</p>", `{"html":"<p>new</p>"}`, true, true},
		{"both updated", "old", "<p>old</p>", `{"text":"new","html":"<p>new</p>"}`, true, false},
		{"HTML explicitly cleared", "old", "<p>old</p>", `{"text":"new","html":""}`, true, false},
		{"text-only edit", "old", "", `{"text":"new"}`, true, false},
		{"HTML-only derives new text", "", "<p>old</p>", `{"html":"<p>new</p>"}`, false, false},
		{"subject-only preserves both", "old", "<p>old</p>", `{"subject":"new"}`, true, false},
		{"recipient-only preserves both", "old", "<p>old</p>", `{"to":["other@example.com"]}`, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b, _ := newDraftApp(t)
			b.source.Message.Text, b.source.Message.HTML = tc.sourceText, tc.sourceHTML
			b.source.Message.PreserveEmptyText = tc.preserveText
			args := strings.TrimSuffix(draftArgs(b, "revise_draft"), "}") + `,"changes":` + tc.patch + `}`
			status, out := f.call(t, a, "mail.read mail.write", "mail_create", args)
			if tc.reject {
				groupedExpectError(t, status, out)
				r := out["result"].(map[string]any)
				payload := r["structuredContent"].(map[string]any)
				if payload["error_code"] != "invalid_arguments" || !strings.Contains(payload["error"].(string), "supply both changes.text and changes.html") || !reflect.DeepEqual(b.calls, []string{"read_draft"}) {
					t.Fatalf("unsafe alternative revision: %#v %v", payload, b.calls)
				}
				return
			}
			groupedResult(t, status, out)
			if !reflect.DeepEqual(b.calls, []string{"read_draft", "draft"}) {
				t.Fatal(b.calls)
			}
			parsed, err := compose.ParseDraft(b.draft)
			if err != nil {
				t.Fatal(err)
			}
			if tc.name == "HTML-only derives new text" && parsed.Message.Text != "new" {
				t.Fatalf("stale derived text: %+v", parsed.Message)
			}
		})
	}
}

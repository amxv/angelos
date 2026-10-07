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

type batchBackend struct {
	*groupedBackend
	refs     []mail.Reference
	failures map[uint32]error
}

func (b *batchBackend) Read(_ context.Context, ref mail.Reference) (mail.Message, error) {
	b.refs = append(b.refs, ref)
	m := b.message
	m.Reference = ref
	return m, b.failures[ref.UID]
}
func batchRefs(n int) []mail.Reference {
	r := make([]mail.Reference, n)
	for i := range r {
		r[i] = mail.Reference{Folder: "INBOX", UIDValidity: 4294967295, UID: uint32(i + 1)}
	}
	return r
}
func TestReadManyBoundedOrderedProtocol(t *testing.T) {
	f := newGroupedAuthFixture(t)
	a, b, _ := newGroupedApp()
	backend := &batchBackend{groupedBackend: b, failures: map[uint32]error{2: mail.ErrStaleReference, 4: mail.ErrNotFound}}
	a.Mail = backend
	b.message.ModSeq = 18446744073709551615
	args := jsonBytes(t, map[string]any{"action": "read_many", "references": batchRefs(5)})
	status, response := f.call(t, a, "mail.read", "mail_query", string(args))
	fields := protocolContent(t, groupedResult(t, status, response))
	var items []struct {
		Reference mail.Reference
		Status    string
		Message   map[string]json.RawMessage
		Error     map[string]any
	}
	if err := json.Unmarshal(fields["items"], &items); err != nil {
		t.Fatal(err)
	}
	if len(items) != 5 || !reflect.DeepEqual(backend.refs, batchRefs(5)) {
		t.Fatal("wrong order or count", items, backend.refs)
	}
	for i, item := range items {
		if i == 1 || i == 3 {
			if item.Status != "error" || item.Error["error_code"] == nil {
				t.Fatal(item)
			}
		} else if item.Status != "ok" || string(item.Message["modseq"]) != "18446744073709551615" {
			t.Fatal(item)
		}
	}
	if string(fields["next_index"]) != "" {
		t.Fatal("unexpected continuation")
	}
}
func TestReadManyBudgetsAndContinuation(t *testing.T) {
	for _, detail := range []string{"summary", "full"} {
		t.Run(detail, func(t *testing.T) {
			a, b, _ := newGroupedApp()
			backend := &batchBackend{groupedBackend: b}
			a.Mail = backend
			b.message.Text = strings.Repeat("界", 3000)
			value, err := a.readMany(context.Background(), queryInput{References: batchRefs(10), Detail: detail, MaxResponseBytes: 16000})
			if err != nil {
				t.Fatal(err)
			}
			out := value.(batchResult)
			raw := jsonBytes(t, out)
			if len(raw) > 16000 || out.ResponseBytes != len(raw) || out.NextIndex == nil || out.StopReason != "response_limit" {
				t.Fatal("unbounded/missing continuation", len(raw), out)
			}
			next := *out.NextIndex
			if len(backend.refs) != next+1 || out.Items[next].Status != "not_returned" {
				t.Fatal("unexpected fetches", next, len(backend.refs))
			}
			for _, item := range out.Items[next+1:] {
				if item.Status != "not_read" {
					t.Fatal(item)
				}
			}
		})
	}
	a, b, _ := newGroupedApp()
	backend := &batchBackend{groupedBackend: b}
	a.Mail = backend
	b.message.Text = strings.Repeat("x", maxBatchMessageBytes+1)
	value, err := a.readMany(context.Background(), queryInput{References: batchRefs(2)})
	if err != nil {
		t.Fatal(err)
	}
	out := value.(batchResult)
	if out.StopReason != "message_limit" || *out.NextIndex != 0 || len(backend.refs) != 1 || out.AdmittedMessageBytes > maxBatchMessageBytes {
		t.Fatal(out)
	}
}
func TestReadManyRejectsBeforeBackend(t *testing.T) {
	a, b, _ := newGroupedApp()
	backend := &batchBackend{groupedBackend: b}
	a.Mail = backend
	for _, in := range []queryInput{{}, {References: batchRefs(11)}, {References: batchRefs(1), MaxResponseBytes: -1}, {References: batchRefs(1), MaxResponseBytes: maxBatchResponseBytes + 1}, {References: []mail.Reference{groupedReference, groupedReference}}, {References: []mail.Reference{{Folder: "INBOX", UID: 1}}}, {References: []mail.Reference{{Folder: "bad\nfolder", UID: 1, UIDValidity: 1}}}} {
		if _, err := a.readMany(context.Background(), in); !errors.Is(err, mail.ErrInvalidInput) {
			t.Fatal(in, err)
		}
	}
	if len(backend.refs) != 0 {
		t.Fatal("invalid input reached backend")
	}
	f := newGroupedAuthFixture(t)
	for _, args := range []string{`{"action":"read_many","references":[]}`, `{"action":"read_many","references":null}`, `{"action":"read_many","references":[{"folder":"INBOX","uid_validity":9,"uid":1}],"reference":` + groupedReferenceJSON + `}`} {
		status, out := f.call(t, a, "mail.read", "mail_query", args)
		groupedExpectError(t, status, out)
	}
	status, out := f.call(t, a, "mail.send", "mail_query", string(jsonBytes(t, map[string]any{"action": "read_many", "references": batchRefs(1)})))
	groupedExpectError(t, status, out)
	if len(backend.refs) != 0 {
		t.Fatal("unauthorized/invalid protocol input reached backend")
	}
}
func TestReadManyWorkflowMetrics(t *testing.T) {
	f := newGroupedAuthFixture(t)
	a, b, _ := newGroupedApp()
	backend := &batchBackend{groupedBackend: b}
	a.Mail = backend
	b.message.Text = strings.Repeat("Useful message text. ", 20)
	before := 0
	for _, ref := range batchRefs(5) {
		status, out := f.call(t, a, "mail.read", "mail_query", string(jsonBytes(t, map[string]any{"action": "read", "reference": ref})))
		before += len(jsonBytes(t, groupedResult(t, status, out)))
	}
	status, out := f.call(t, a, "mail.read", "mail_query", string(jsonBytes(t, map[string]any{"action": "read_many", "references": batchRefs(5)})))
	after := len(jsonBytes(t, groupedResult(t, status, out)))
	t.Logf("five selected messages: MCP calls 5 -> 1; complete MCP result JSON bytes %d -> %d (batch metadata is explicit overhead)", before, after)
}

func TestReadManyCancellationAndEscapedBudget(t *testing.T) {
	a, b, _ := newGroupedApp()
	backend := &batchBackend{groupedBackend: b}
	a.Mail = backend
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	value, err := a.readMany(ctx, queryInput{References: batchRefs(2)})
	if err != nil {
		t.Fatal(err)
	}
	out := value.(batchResult)
	if out.StopReason != "cancelled" || out.NextIndex == nil || *out.NextIndex != 0 || len(backend.refs) != 0 {
		t.Fatal(out)
	}
	refs := batchRefs(10)
	for i := range refs {
		refs[i].Folder = strings.Repeat("<", 1024)
	}
	if _, err = a.readMany(context.Background(), queryInput{References: refs, MaxResponseBytes: 4096}); !errors.Is(err, mail.ErrInvalidInput) || len(backend.refs) != 0 {
		t.Fatal("metadata budget not enforced before I/O", err)
	}
	b.message.Text = strings.Repeat("<&界", 500)
	value, err = a.readMany(context.Background(), queryInput{References: batchRefs(5), Detail: "full", MaxResponseBytes: 12000})
	if err != nil {
		t.Fatal(err)
	}
	out = value.(batchResult)
	if out.NextIndex == nil || len(jsonBytes(t, out)) > 12000 {
		t.Fatal("escaped JSON not bounded", out)
	}
}

func TestReadManyFullAndSuffix(t *testing.T) {
	f := newGroupedAuthFixture(t)
	a, b, _ := newGroupedApp()
	backend := &batchBackend{groupedBackend: b, failures: map[uint32]error{2: mail.ErrNotFound}}
	a.Mail = backend
	b.message.ModSeq = 18446744073709551615
	b.message.Text = strings.Repeat("body ", 500)
	input := queryInput{References: batchRefs(5), Detail: "full", MaxResponseBytes: 8000}
	value, err := a.readMany(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	out := value.(batchResult)
	if out.NextIndex == nil || *out.NextIndex != 3 || out.Items[1].Status != "error" {
		t.Fatal("mixed prefix", out)
	}
	next := *out.NextIndex
	backend.refs = nil
	value, err = a.readMany(context.Background(), queryInput{References: input.References[next:], Detail: "full"})
	if err != nil {
		t.Fatal(err)
	}
	if value.(batchResult).NextIndex != nil || !reflect.DeepEqual(backend.refs, input.References[next:]) {
		t.Fatal("bad continuation", value)
	}
	status, response := f.call(t, a, "mail.read", "mail_query", string(jsonBytes(t, map[string]any{"action": "read_many", "references": batchRefs(1), "detail": "full"})))
	fields := protocolContent(t, groupedResult(t, status, response))
	var items []struct{ Message json.RawMessage }
	if err = json.Unmarshal(fields["items"], &items); err != nil {
		t.Fatal(err)
	}
	want := b.message
	want.Reference = batchRefs(1)[0]
	if string(items[0].Message) != string(jsonBytes(t, want)) {
		t.Fatal("full batch changed original message fields/uint64", string(items[0].Message))
	}
}

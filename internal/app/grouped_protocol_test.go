package app

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/amxv/angelos/internal/auth"
	"github.com/amxv/angelos/internal/compose"
	"github.com/amxv/angelos/internal/config"
	"github.com/amxv/angelos/internal/dispatch"
	"github.com/amxv/angelos/internal/mail"
)

const groupedReferenceJSON = `{"folder":"INBOX","uid_validity":9,"uid":17}`
const groupedMessageJSON = `{"to":["To Person <to@example.com>"],"cc":["cc@example.com"],"bcc":["hidden@example.com"],"subject":"Review me","text":"Exact body","attachments":[{"filename":"note.txt","content_type":"text/plain","data_base64":"aGk="}],"in_reply_to":"<seed@example.com>","references":["<seed-parent@example.com>"]}`

var groupedReference = mail.Reference{Folder: "INBOX", UIDValidity: 9, UID: 17}

// These tests use the actual JWT verifier and MCP protocol boundary. No test-only
// principal injection or production authentication bypass is needed.
type groupedRoundTripper func(*http.Request) (*http.Response, error)

func (fn groupedRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return fn(r) }

type groupedAuthFixture struct {
	auth *auth.Authenticator
	key  *ecdsa.PrivateKey
}

func newGroupedAuthFixture(t *testing.T) *groupedAuthFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk := map[string]any{
		"kty": "EC", "kid": "grouped-test-key", "alg": "ES256", "use": "sig", "crv": "P-256",
		"x": base64.RawURLEncoding.EncodeToString(key.X.FillBytes(make([]byte, 32))),
		"y": base64.RawURLEncoding.EncodeToString(key.Y.FillBytes(make([]byte, 32))),
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/jwks" {
			t.Errorf("unexpected JWKS request: %s %s", r.Method, r.URL)
		}
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Error("credentials leaked to JWKS endpoint")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{jwk}})
	}))
	t.Cleanup(server.Close)
	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	transport := server.Client().Transport
	gate, err := auth.New(auth.Config{
		ResourceURL: "https://mail.example.com/mcp", Issuer: "https://login.example.com/",
		JWKSURL: "https://login.example.com/jwks", AllowedSubjects: []string{"grouped-test-owner", "grouped-test-other"},
		HTTPClient: &http.Client{Transport: groupedRoundTripper(func(r *http.Request) (*http.Response, error) {
			if r.URL.String() != "https://login.example.com/jwks" {
				return nil, fmt.Errorf("unexpected outbound URL: %s", r.URL)
			}
			local := r.Clone(r.Context())
			local.URL.Scheme, local.URL.Host = target.Scheme, target.Host
			local.Host = target.Host
			return transport.RoundTrip(local)
		})},
	})
	if err != nil {
		t.Fatal(err)
	}
	return &groupedAuthFixture{auth: gate, key: key}
}

func (f *groupedAuthFixture) token(t *testing.T, scope string) string {
	t.Helper()
	return f.tokenFor(t, scope, "grouped-test-owner")
}

func (f *groupedAuthFixture) tokenFor(t *testing.T, scope, subject string) string {
	t.Helper()
	encode := func(v any) string {
		data, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(data)
	}
	now := time.Now()
	payload := encode(map[string]any{"alg": "ES256", "kid": "grouped-test-key", "typ": "at+jwt"}) + "." + encode(map[string]any{
		"iss": "https://login.example.com/", "aud": "https://mail.example.com/mcp", "sub": subject,
		"scope": scope, "iat": now.Add(-time.Minute).Unix(), "exp": now.Add(time.Hour).Unix(),
	})
	digest := sha256.Sum256([]byte(payload))
	r, s, err := ecdsa.Sign(rand.Reader, f.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return payload + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func (f *groupedAuthFixture) call(t *testing.T, a *App, scope, name, arguments string) (int, map[string]any) {
	t.Helper()
	return f.callFor(t, a, scope, "grouped-test-owner", name, arguments)
}

func (f *groupedAuthFixture) callFor(t *testing.T, a *App, scope, subject, name, arguments string) (int, map[string]any) {
	t.Helper()
	payload := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":` + fmt.Sprintf("%q", name) + `,"arguments":` + arguments + `}}`
	r := httptest.NewRequest(http.MethodPost, "https://mail.example.com/mcp", strings.NewReader(payload))
	r.Header.Set("Authorization", "Bearer "+f.tokenFor(t, scope, subject))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	r.Header.Set("MCP-Protocol-Version", "2025-11-25")
	w := httptest.NewRecorder()
	a.AuthChallenge = f.auth.Challenge
	f.auth.Middleware(a.Handler()).ServeHTTP(w, r)
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("HTTP %d: invalid JSON: %v: %s", w.Code, err, w.Body.String())
	}
	return w.Code, out
}

func groupedResult(t *testing.T, status int, out map[string]any) map[string]any {
	t.Helper()
	r, ok := out["result"].(map[string]any)
	if status != http.StatusOK || !ok || out["error"] != nil || r["isError"] == true {
		t.Fatalf("tool failed: HTTP %d: %#v", status, out)
	}
	return r
}

func groupedExpectError(t *testing.T, status int, out map[string]any) {
	t.Helper()
	if status >= 400 || out["error"] != nil {
		return
	}
	r, ok := out["result"].(map[string]any)
	if !ok || r["isError"] != true {
		t.Fatalf("invalid request succeeded: HTTP %d: %#v", status, out)
	}
}

// All methods record entry, making unauthorized and invalid calls detectable
// even when their output would otherwise look harmless.
type groupedBackend struct {
	calls         []string
	reference     mail.Reference
	search        mail.SearchRequest
	flag          mail.FlagRequest
	name, newName string
	destination   string
	index         int
	draft         []byte
	message       mail.Message
}

func newGroupedBackend() *groupedBackend {
	return &groupedBackend{message: mail.Message{
		Summary: mail.Summary{Reference: groupedReference, Subject: "Original subject", From: []mail.Address{{Name: "Original", Address: "from@example.com"}}, To: []mail.Address{{Address: "owner@example.com"}}, Date: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), Flags: []string{`\Seen`}, Size: 1024, ModSeq: 44},
		Headers: map[string]string{"From": "from@example.com", "Reply-To": "reply@example.com", "Cc": "other@example.com", "Message-Id": "<source@example.com>", "References": "<earlier@example.com>"},
		Text:    "Original body", Attachments: []mail.Attachment{{Index: 1, Filename: "source.txt", ContentType: "text/plain", Size: 2}},
	}}
}
func (b *groupedBackend) called(name string) { b.calls = append(b.calls, name) }
func (b *groupedBackend) Capabilities(context.Context) (mail.Capabilities, error) {
	b.called("capabilities")
	return mail.Capabilities{IMAP: []string{"IMAP4rev1", "UIDPLUS", "MOVE", "CONDSTORE"}, Move: true, UIDExpunge: true, PermanentDelete: true, CondStore: true, SpecialUse: true, SpecialFolders: map[string][]string{"trash": {"Trash"}}}, nil
}
func (b *groupedBackend) ListFolders(context.Context) ([]mail.Folder, error) {
	b.called("folders")
	return []mail.Folder{{Name: "INBOX", Delimiter: "/", Attributes: []string{`\Inbox`}}}, nil
}
func (b *groupedBackend) Search(_ context.Context, in mail.SearchRequest) (mail.SearchResult, error) {
	b.called("search")
	b.search = in
	return mail.SearchResult{Messages: []mail.Summary{b.message.Summary}, UIDValidity: groupedReference.UIDValidity, NextCursor: "cursor-next", ScannedUIDs: 1000, Order: "oldest"}, nil
}
func (b *groupedBackend) Conversation(_ context.Context, ref mail.Reference, in mail.SearchRequest) (mail.SearchResult, error) {
	b.called("conversation")
	b.reference, b.search = ref, in
	return mail.SearchResult{Messages: []mail.Summary{b.message.Summary}, UIDValidity: ref.UIDValidity, NextCursor: "conversation-next", ScannedUIDs: 1000, Order: "newest"}, nil
}
func (b *groupedBackend) Read(_ context.Context, ref mail.Reference) (mail.Message, error) {
	b.called("read")
	b.reference = ref
	return b.message, nil
}
func (b *groupedBackend) GetAttachment(_ context.Context, ref mail.Reference, index int) (mail.AttachmentResult, error) {
	b.called("attachment")
	b.reference, b.index = ref, index
	return mail.AttachmentResult{Reference: ref, Attachment: b.message.Attachments[0], DataBase64: "aGk="}, nil
}
func (b *groupedBackend) SetFlags(_ context.Context, in mail.FlagRequest) (mail.FlagResult, error) {
	b.called("flags")
	b.flag, b.reference = in, in.Reference
	return mail.FlagResult{Reference: in.Reference, Flags: in.Flags, ModSeq: 45, Conditional: true}, nil
}
func (b *groupedBackend) CreateFolder(_ context.Context, name string) error {
	b.called("folder")
	b.name = name
	return nil
}
func (b *groupedBackend) RenameFolder(_ context.Context, old, new string) error {
	b.called("rename")
	b.name, b.newName = old, new
	return nil
}
func (b *groupedBackend) transfer(action string, ref mail.Reference, destination string) (mail.MutationResult, error) {
	b.called(action)
	b.reference, b.destination = ref, destination
	dst := mail.Reference{Folder: destination, UIDValidity: 10, UID: 23}
	return mail.MutationResult{Source: &ref, Destination: &dst, Status: action}, nil
}
func (b *groupedBackend) Copy(_ context.Context, ref mail.Reference, destination string) (mail.MutationResult, error) {
	return b.transfer("copy", ref, destination)
}
func (b *groupedBackend) Move(_ context.Context, ref mail.Reference, destination string) (mail.MutationResult, error) {
	return b.transfer("move", ref, destination)
}
func (b *groupedBackend) Trash(_ context.Context, ref mail.Reference) (mail.MutationResult, error) {
	return b.transfer("trash", ref, "Trash")
}
func (b *groupedBackend) Delete(_ context.Context, ref mail.Reference) (mail.MutationResult, error) {
	b.called("delete")
	b.reference = ref
	return mail.MutationResult{Source: &ref, Status: "deleted"}, nil
}
func (b *groupedBackend) AppendDraft(_ context.Context, folder string, raw []byte) (mail.MutationResult, error) {
	b.called("draft")
	b.name, b.draft = folder, append([]byte(nil), raw...)
	dst := mail.Reference{Folder: folder, UIDValidity: 12, UID: 31}
	return mail.MutationResult{Destination: &dst, Status: "appended"}, nil
}
func (b *groupedBackend) Send(context.Context, mail.Envelope, []byte) (mail.SendResult, error) {
	b.called("send")
	return mail.SendResult{Status: "accepted", Stage: "acknowledgement"}, nil
}
func (b *groupedBackend) AppendSent(context.Context, []byte) (mail.MutationResult, error) {
	b.called("append_sent")
	return mail.MutationResult{Status: "appended"}, nil
}

type groupedStore struct {
	memoryStore
	puts, claims, completes, statuses int
}

func (s *groupedStore) Put(ctx context.Context, p compose.Prepared, owner string) error {
	s.puts++
	return s.memoryStore.Put(ctx, p, owner)
}
func (s *groupedStore) Claim(ctx context.Context, id, digest, owner string, now time.Time) (dispatch.Record, bool, error) {
	s.claims++
	return s.memoryStore.Claim(ctx, id, digest, owner, now)
}
func (s *groupedStore) Complete(ctx context.Context, id, status, detail string) error {
	s.completes++
	return s.memoryStore.Complete(ctx, id, status, detail)
}

func (s *groupedStore) Status(ctx context.Context, id, owner string, now time.Time) (dispatch.SendStatus, error) {
	s.statuses++
	return s.memoryStore.Status(ctx, id, owner, now)
}

func newGroupedApp() (*App, *groupedBackend, *groupedStore) {
	backend, store := newGroupedBackend(), &groupedStore{}
	return &App{Mail: backend, Store: store, Config: config.Config{From: "owner@example.com"}, EnableWrites: true, EnableSend: true, EnableDelete: true}, backend, store
}

func groupedSeedSend(t *testing.T, store *groupedStore) string {
	t.Helper()
	p, err := compose.Build("owner@example.com", compose.Input{To: []string{"to@example.com"}, Subject: "Seed", Text: "Approved"}, strings.Repeat("a", 32), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// Seeding test state is not a tool invocation and must not count as one.
	if err := store.memoryStore.Put(context.Background(), p, ""); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf(`{"prepared_id":%q,"confirmed_digest":%q,"append_sent":false}`, p.ID, p.Digest)
}

type groupedOperation struct {
	name, tool, args, scope string
	calls                   []string
	puts                    int
}

func groupedOperations() []groupedOperation {
	ref, msg := groupedReferenceJSON, groupedMessageJSON
	return []groupedOperation{
		{"capabilities", "mail_query", `{"action":"capabilities"}`, "mail.read", []string{"capabilities"}, 0},
		{"folders", "mail_query", `{"action":"folders"}`, "mail.read", []string{"folders"}, 0},
		{"search", "mail_query", `{"action":"search","search":{"folder":"INBOX","query":"invoice","order":"oldest","from":"from@example.com","to":"owner@example.com","subject":"Due","message_id":"<Case@Example.com>","participant":"Person","since":"2026-01-01","before":"2026-02-01","unread":false,"flagged":false,"cursor":"input-cursor","limit":7}}`, "mail.read", []string{"search"}, 0},
		{"triage", "mail_query", `{"action":"triage","search":{"folder":"INBOX","limit":7}}`, "mail.read", []string{"search"}, 0},
		{"conversation", "mail_query", `{"action":"conversation","reference":` + ref + `,"search":{"limit":7}}`, "mail.read", []string{"conversation"}, 0},
		{"read", "mail_query", `{"action":"read","reference":` + ref + `}`, "mail.read", []string{"read"}, 0},
		{"attachment", "mail_query", `{"action":"attachment","reference":` + ref + `,"index":1}`, "mail.read", []string{"attachment"}, 0},
		{"folder", "mail_create", `{"action":"folder","name":"Projects"}`, "mail.write", []string{"folder"}, 0},
		{"copy", "mail_create", `{"action":"copy","reference":` + ref + `,"destination":"Archive"}`, "mail.write", []string{"copy"}, 0},
		{"draft", "mail_create", `{"action":"draft","folder":"Draft Mail","message":` + msg + `}`, "mail.write", []string{"draft"}, 0},
		{"flags", "mail_modify", `{"action":"flags","reference":` + ref + `,"operation":"remove","flags":["\\Seen"],"unchanged_since":44}`, "mail.write", []string{"flags"}, 0},
		{"rename", "mail_modify", `{"action":"rename","old":"Old","new":"New"}`, "mail.write", []string{"rename"}, 0},
		{"move", "mail_modify", `{"action":"move","reference":` + ref + `,"destination":"Archive"}`, "mail.write", []string{"move"}, 0},
		{"trash", "mail_modify", `{"action":"trash","reference":` + ref + `}`, "mail.write", []string{"trash"}, 0},
		{"delete", "mail_delete_permanently", ref, "mail.write", []string{"delete"}, 0},
		{"new", "mail_prepare", `{"action":"new","message":` + msg + `}`, "mail.send", nil, 1},
		{"reply", "mail_prepare", `{"action":"reply","reference":` + ref + `,"message":` + msg + `}`, "mail.send", []string{"read"}, 1},
		{"reply_all", "mail_prepare", `{"action":"reply_all","reference":` + ref + `,"message":` + msg + `}`, "mail.send", []string{"read"}, 1},
		{"forward", "mail_prepare", `{"action":"forward","reference":` + ref + `,"message":` + msg + `}`, "mail.send", []string{"read"}, 1},
		{"send", "mail_send_confirmed", "", "mail.send", []string{"send"}, 0},
	}
}

func TestGroupedProtocolRoutesAllOperations(t *testing.T) {
	f := newGroupedAuthFixture(t)
	for _, op := range groupedOperations() {
		t.Run(op.name, func(t *testing.T) {
			a, backend, store := newGroupedApp()
			args := op.args
			if op.name == "send" {
				args = groupedSeedSend(t, store)
			}
			scope := "mail.read"
			if op.scope != scope {
				scope += " " + op.scope
			}
			status, out := f.call(t, a, scope, op.tool, args)
			r := groupedResult(t, status, out)
			if !reflect.DeepEqual(backend.calls, op.calls) || store.puts != op.puts {
				t.Fatalf("calls=%v puts=%d; want %v puts=%d", backend.calls, store.puts, op.calls, op.puts)
			}
			if backend.reference.UID != 0 && backend.reference != groupedReference {
				t.Fatalf("reference changed: %#v", backend.reference)
			}
			switch op.name {
			case "search":
				var input struct {
					Search mail.SearchRequest `json:"search"`
				}
				if err := json.Unmarshal([]byte(args), &input); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(backend.search, input.Search) {
					t.Fatalf("search arguments changed: got %#v want %#v", backend.search, input.Search)
				}
			case "attachment":
				if backend.index != 1 {
					t.Fatal("attachment index changed")
				}
			case "folder":
				if backend.name != "Projects" {
					t.Fatal("folder name changed")
				}
			case "copy", "move":
				if backend.destination != "Archive" {
					t.Fatal("destination changed")
				}
			case "rename":
				if backend.name != "Old" || backend.newName != "New" {
					t.Fatal("rename arguments changed")
				}
			case "flags":
				if backend.flag.Operation != "remove" || backend.flag.UnchangedSince != 44 || !reflect.DeepEqual(backend.flag.Flags, []string{`\Seen`}) {
					t.Fatalf("flags changed: %#v", backend.flag)
				}
			case "draft":
				if backend.name != "Draft Mail" || !bytes.Contains(backend.draft, []byte("Bcc: <hidden@example.com>")) {
					t.Fatalf("draft destination/BCC changed: folder=%q", backend.name)
				}
			case "new", "reply", "reply_all", "forward":
				p := store.record.Message
				if len(p.Bcc) != 1 || !strings.Contains(p.Bcc[0], "hidden@example.com") || len(p.Attachments) != 1 || p.Attachments[0].SHA256 == "" {
					t.Fatalf("incomplete prepared message: %#v", p)
				}
				previewBytes, _ := json.Marshal(r["structuredContent"])
				for _, needle := range []string{p.ID, p.Digest, "hidden@example.com", p.Text, p.Attachments[0].SHA256} {
					// String values need JSON escaping when inspecting the encoded payload.
					encoded, _ := json.Marshal(needle)
					if !bytes.Contains(previewBytes, encoded[1:len(encoded)-1]) {
						t.Fatalf("prepared preview omitted %q: %s", needle, previewBytes)
					}
				}
				if op.name == "new" && (!bytes.Contains(p.Raw, []byte("In-Reply-To: <seed@example.com>")) || !bytes.Contains(p.Raw, []byte("References: <seed-parent@example.com>"))) {
					t.Fatal("explicit new-message threading omitted")
				}
				if op.name == "reply" && (!bytes.Contains(p.Raw, []byte("In-Reply-To: <source@example.com>")) || !bytes.Contains(p.Raw, []byte("References: <earlier@example.com> <source@example.com>"))) {
					t.Fatal("reply threading missing")
				}
				if op.name == "forward" && (!strings.Contains(p.Text, "Original body") || bytes.Contains(p.Raw, []byte("In-Reply-To:"))) {
					t.Fatal("forward text/threading changed")
				}
			case "send":
				if store.claims != 1 || store.completes != 1 {
					t.Fatalf("send store calls: claims=%d complete=%d", store.claims, store.completes)
				}
			}
		})
	}
}

func TestGroupedProtocolEnforcesEveryActionScope(t *testing.T) {
	f := newGroupedAuthFixture(t)
	for _, op := range groupedOperations() {
		t.Run(op.name, func(t *testing.T) {
			a, backend, store := newGroupedApp()
			args := op.args
			if op.name == "send" {
				args = groupedSeedSend(t, store)
			}
			scope := strings.TrimSpace(strings.ReplaceAll("mail.read mail.write mail.send", op.scope, ""))
			status, out := f.call(t, a, scope, op.tool, args)
			groupedExpectError(t, status, out)
			if len(backend.calls) != 0 || store.puts+store.claims+store.completes != 0 {
				t.Fatalf("unauthorized action reached backend/store: calls=%v store=%#v", backend.calls, store)
			}
			if op.scope == "mail.read" {
				if status != http.StatusForbidden {
					t.Fatalf("missing base scope returned HTTP %d", status)
				}
			} else {
				r, ok := out["result"].(map[string]any)
				if !ok {
					t.Fatalf("missing MCP scope error: %#v", out)
				}
				meta, ok := r["_meta"].(map[string]any)
				if !ok || meta["mcp/www_authenticate"] == nil {
					t.Fatalf("missing scope challenge: %#v", r)
				}
				challenge, _ := json.Marshal(meta["mcp/www_authenticate"])
				if !bytes.Contains(challenge, []byte(op.scope)) {
					t.Fatalf("challenge omitted %s: %s", op.scope, challenge)
				}
			}
		})
	}
}

func TestGroupedProtocolRejectsInvalidActionsBeforeBackend(t *testing.T) {
	f := newGroupedAuthFixture(t)
	cases := []struct{ name, tool, args string }{
		{"missing query action", "mail_query", `{}`},
		{"missing create action", "mail_create", `{"name":"Projects"}`},
		{"missing modify action", "mail_modify", `{"reference":` + groupedReferenceJSON + `}`},
		{"missing prepare action", "mail_prepare", `{"message":` + groupedMessageJSON + `}`},
		{"query cannot send", "mail_query", `{"action":"send"}`},
		{"create cannot delete", "mail_create", `{"action":"delete"}`},
		{"modify cannot delete", "mail_modify", `{"action":"delete"}`},
		{"prepare cannot send", "mail_prepare", `{"action":"send","message":` + groupedMessageJSON + `}`},
		{"unknown field", "mail_query", `{"action":"folders","credential":"secret"}`},
		{"read detail enum", "mail_query", `{"action":"read","reference":` + groupedReferenceJSON + `,"detail":"brief"}`},
		{"flags operation enum", "mail_modify", `{"action":"flags","reference":` + groupedReferenceJSON + `,"operation":"replace","flags":["\\Seen"]}`},
	}
	// Inapplicable fields must be rejected based on key presence, including values
	// that disappear if validation examines only decoded Go zero values.
	for _, extra := range []string{`"reference":null`, `"index":0`, `"detail":""`, `"search":{}`} {
		cases = append(cases, struct{ name, tool, args string }{"irrelevant query " + extra, "mail_query", `{"action":"folders",` + extra + `}`})
	}
	for _, extra := range []string{`"reference":null`, `"folder":""`, `"message":null`, `"destination":""`} {
		cases = append(cases, struct{ name, tool, args string }{"irrelevant create " + extra, "mail_create", `{"action":"folder","name":"Projects",` + extra + `}`})
	}
	for _, extra := range []string{`"flags":[]`, `"operation":""`, `"unchanged_since":0`, `"destination":null`} {
		cases = append(cases, struct{ name, tool, args string }{"irrelevant modify " + extra, "mail_modify", `{"action":"trash","reference":` + groupedReferenceJSON + `,` + extra + `}`})
	}
	cases = append(cases, struct{ name, tool, args string }{"irrelevant prepare null", "mail_prepare", `{"action":"new","message":` + groupedMessageJSON + `,"reference":null}`})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, backend, store := newGroupedApp()
			status, out := f.call(t, a, "mail.read mail.write mail.send", tc.tool, tc.args)
			groupedExpectError(t, status, out)
			if len(backend.calls) != 0 || store.puts+store.claims+store.completes != 0 {
				t.Fatalf("invalid action reached backend/store: calls=%v store=%#v", backend.calls, store)
			}
		})
	}
}

func TestGroupedProtocolRequiresEveryActionField(t *testing.T) {
	f := newGroupedAuthFixture(t)
	required := map[string][]string{
		"read": {"reference"}, "attachment": {"reference", "index"},
		"folder": {"name"}, "copy": {"reference", "destination"}, "draft": {"message"},
		"flags": {"reference", "operation", "flags"}, "rename": {"old", "new"},
		"move": {"reference", "destination"}, "trash": {"reference"},
		"new": {"message"}, "reply": {"reference", "message"}, "reply_all": {"reference", "message"}, "forward": {"reference", "message"},
	}
	for _, op := range groupedOperations() {
		for _, key := range required[op.name] {
			for _, null := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/null=%t", op.name, key, null), func(t *testing.T) {
					var args map[string]any
					if err := json.Unmarshal([]byte(op.args), &args); err != nil {
						t.Fatal(err)
					}
					if null {
						args[key] = nil
					} else {
						delete(args, key)
					}
					encoded, err := json.Marshal(args)
					if err != nil {
						t.Fatal(err)
					}
					a, backend, store := newGroupedApp()
					status, out := f.call(t, a, "mail.read mail.write mail.send", op.tool, string(encoded))
					groupedExpectError(t, status, out)
					if len(backend.calls) != 0 || store.puts+store.claims+store.completes != 0 {
						t.Fatalf("missing field reached backend/store: calls=%v store=%#v", backend.calls, store)
					}
				})
			}
		}
	}
}

func TestGroupedProtocolEnforcesDeploymentGates(t *testing.T) {
	f := newGroupedAuthFixture(t)
	for _, op := range groupedOperations() {
		if op.scope == "mail.read" {
			continue
		}
		t.Run(op.name, func(t *testing.T) {
			for _, missingStore := range []bool{false, true} {
				if missingStore && op.scope != "mail.send" {
					continue
				}
				t.Run(fmt.Sprintf("missing_store=%t", missingStore), func(t *testing.T) {
					a, backend, store := newGroupedApp()
					args := op.args
					if op.name == "send" {
						args = groupedSeedSend(t, store)
					}
					if missingStore {
						a.Store = nil
					} else if op.scope == "mail.write" {
						a.EnableWrites = false
					} else {
						a.EnableSend = false
					}
					status, out := f.call(t, a, "mail.read mail.write mail.send", op.tool, args)
					groupedExpectError(t, status, out)
					if len(backend.calls) != 0 || store.puts+store.claims+store.completes != 0 {
						t.Fatalf("disabled action reached backend/store: calls=%v store=%#v", backend.calls, store)
					}
				})
			}
		})
	}
	t.Run("independent permanent delete gate", func(t *testing.T) {
		a, backend, store := newGroupedApp()
		a.EnableDelete = false
		status, out := f.call(t, a, "mail.read mail.write", "mail_delete_permanently", groupedReferenceJSON)
		groupedExpectError(t, status, out)
		if len(backend.calls) != 0 || store.puts+store.claims+store.completes != 0 {
			t.Fatal("permanent-delete gate bypassed")
		}
	})
	t.Run("read survives all mutation gates disabled", func(t *testing.T) {
		a, backend, _ := newGroupedApp()
		a.EnableDelete, a.EnableWrites, a.EnableSend, a.Store = false, false, false, nil
		status, out := f.call(t, a, "mail.read", "mail_query", `{"action":"read","reference":`+groupedReferenceJSON+`}`)
		groupedResult(t, status, out)
		if !reflect.DeepEqual(backend.calls, []string{"read"}) {
			t.Fatal(backend.calls)
		}
	})
}

func TestGroupedProtocolSentFilingRequiresWriteAuthority(t *testing.T) {
	f := newGroupedAuthFixture(t)
	for _, tc := range []struct {
		name, scope     string
		writes, success bool
	}{
		{"missing write scope", "mail.read mail.send", true, false},
		{"disabled writes", "mail.read mail.write mail.send", false, false},
		{"approved filing", "mail.read mail.write mail.send", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, backend, store := newGroupedApp()
			a.EnableWrites = tc.writes
			args := strings.Replace(groupedSeedSend(t, store), `"append_sent":false`, `"append_sent":true`, 1)
			status, out := f.call(t, a, tc.scope, "mail_send_confirmed", args)
			if tc.success {
				groupedResult(t, status, out)
				if !reflect.DeepEqual(backend.calls, []string{"send", "append_sent"}) || store.claims != 1 {
					t.Fatalf("filing calls=%v claims=%d", backend.calls, store.claims)
				}
			} else {
				groupedExpectError(t, status, out)
				if len(backend.calls) != 0 || store.claims != 0 {
					t.Fatal("missing filing authority allowed sending")
				}
			}
		})
	}
}

func TestGroupedProtocolOptionalDefaultsAndRecipientlessDraft(t *testing.T) {
	f := newGroupedAuthFixture(t)
	t.Run("search omitted", func(t *testing.T) {
		a, backend, _ := newGroupedApp()
		status, out := f.call(t, a, "mail.read", "mail_query", `{"action":"search"}`)
		groupedResult(t, status, out)
		if !reflect.DeepEqual(backend.search, mail.SearchRequest{}) || !reflect.DeepEqual(backend.calls, []string{"search"}) {
			t.Fatal("omitted search no longer reaches backend defaults")
		}
	})
	t.Run("recipientless draft and implicit folder", func(t *testing.T) {
		a, backend, _ := newGroupedApp()
		status, out := f.call(t, a, "mail.read mail.write", "mail_create", `{"action":"draft","message":{"to":[],"subject":"","text":""}}`)
		groupedResult(t, status, out)
		if backend.name != "" || !reflect.DeepEqual(backend.calls, []string{"draft"}) {
			t.Fatal("recipientless/implicit-folder draft changed")
		}
	})
}

func TestGroupedProtocolPresentationClippingDoesNotBlockPreparation(t *testing.T) {
	f := newGroupedAuthFixture(t)
	for _, detail := range []string{"summary", "full"} {
		t.Run(detail, func(t *testing.T) {
			a, backend, store := newGroupedApp()
			backend.message.Text = strings.Repeat("é", 3000)
			backend.message.Warnings = []string{"Fixture safety warning"}
			args := `{"action":"read","reference":` + groupedReferenceJSON + `,"detail":"` + detail + `"}`
			status, out := f.call(t, a, "mail.read", "mail_query", args)
			r := groupedResult(t, status, out)
			body, ok := r["structuredContent"].(map[string]any)
			if !ok {
				t.Fatalf("missing structured read result: %#v", r)
			}
			if body["truncated"] != false {
				t.Fatal("presentation clipping changed backend truncation")
			}
			for _, field := range []string{"reference", "headers", "flags", "modseq", "warnings", "attachments"} {
				if body[field] == nil {
					t.Fatalf("read omitted safety field %s", field)
				}
			}
			if detail == "full" && body["text"] != backend.message.Text {
				t.Fatal("full read lost text")
			}
			status, out = f.call(t, a, "mail.read mail.send", "mail_prepare", `{"action":"forward","reference":`+groupedReferenceJSON+`,"message":`+groupedMessageJSON+`}`)
			preparedResult := groupedResult(t, status, out)
			preparedBody, ok := preparedResult["structuredContent"].(map[string]any)
			if !ok || preparedBody["text"] != store.record.Message.Text {
				t.Fatal("long preparation preview was clipped")
			}
			if store.puts != 1 || !strings.Contains(store.record.Message.Text, backend.message.Text) {
				t.Fatal("presentation-clipped source lost full forward content")
			}
		})
	}
	for _, action := range []string{"reply", "forward"} {
		t.Run("truncated "+action, func(t *testing.T) {
			a, backend, store := newGroupedApp()
			backend.message.Truncated = true
			status, out := f.call(t, a, "mail.read mail.send", "mail_prepare", `{"action":"`+action+`","reference":`+groupedReferenceJSON+`,"message":`+groupedMessageJSON+`}`)
			groupedExpectError(t, status, out)
			if store.puts != 0 {
				t.Fatal("incomplete source prepared")
			}
		})
	}
}

func TestGroupedProtocolConsumedSendDoesNotRepeatSMTP(t *testing.T) {
	f := newGroupedAuthFixture(t)
	a, backend, store := newGroupedApp()
	args := groupedSeedSend(t, store)
	for i := 0; i < 2; i++ {
		status, out := f.call(t, a, "mail.read mail.send", "mail_send_confirmed", args)
		r := groupedResult(t, status, out)
		body, ok := r["structuredContent"].(map[string]any)
		if !ok || body["status"] != "accepted" {
			t.Fatalf("unexpected send outcome: %#v", r)
		}
		if i == 1 && body["resent"] != false {
			t.Fatal("consumed ID did not explicitly prevent resend")
		}
	}
	if !reflect.DeepEqual(backend.calls, []string{"send"}) || store.claims != 2 || store.completes != 1 {
		t.Fatalf("duplicate send: calls=%v claims=%d completes=%d", backend.calls, store.claims, store.completes)
	}
}

package mail

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/amxv/angelos/internal/compose"
	"github.com/amxv/angelos/internal/config"
)

func graphAPITestBackend(t *testing.T, handler http.HandlerFunc, profile ...string) *GraphBackend {
	t.Helper()
	values := map[string]string{"MAIL_PROVIDER": "microsoft", "MAIL_USERNAME": "person@example.com", "MICROSOFT_CLIENT_ID": "11111111-1111-1111-1111-111111111111", "MICROSOFT_CLIENT_SECRET": "fake-secret", "MICROSOFT_TOKEN_ENCRYPTION_KEY": strings.Repeat("12", 32), "MICROSOFT_REFRESH_TOKEN": "fake-refresh", "MICROSOFT_TENANT_ID": "consumers", "MICROSOFT_ACCOUNT_ID": "account-id", "MAIL_TIMEOUT": "2s"}
	c, e := config.Load(func(k string) string { return values[k] })
	if e != nil {
		t.Fatal(e)
	}
	b, e := NewGraph(c)
	if e != nil {
		t.Fatal(e)
	}
	cert, roots := microsoftOAuthTestCertificate(t)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "login.microsoftonline.com" {
			if r.Method != "POST" {
				t.Error("invalid token method")
			}
			io.WriteString(w, `{"access_token":"test-token","token_type":"Bearer","expires_in":3600,"scope":"User.Read Mail.ReadWrite Mail.Send"}`)
			return
		}
		if r.Host != "graph.microsoft.com" || r.Header.Get("Authorization") != "Bearer test-token" || r.Header.Get("Prefer") != `IdType="ImmutableId"` {
			t.Error("untrusted request")
		}
		if r.URL.Path == "/v1.0/me" {
			if len(profile) > 0 {
				io.WriteString(w, profile[0])
			} else {
				io.WriteString(w, `{"id":"account-id","mail":"person@example.com"}`)
			}
			return
		}
		handler(w, r)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	server.StartTLS()
	t.Cleanup(server.Close)
	if e := b.ConfigureTokenStore(newMicrosoftMemoryTokenStore()); e != nil {
		t.Fatal(e)
	}
	b.transport.roots = roots
	b.transport.dialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "graph.microsoft.com:443" && address != "login.microsoftonline.com:443" {
			t.Error("bad dial target")
			return nil, ErrUnavailable
		}
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	return b
}
func graphFixture() string {
	return `{"id":"message-id","parentFolderId":"folder-id","subject":"Hello","receivedDateTime":"2026-10-01T12:00:00Z","from":{"emailAddress":{"name":"Sender","address":"sender@example.com"}},"toRecipients":[{"emailAddress":{"address":"person@example.com"}}],"isRead":false,"isDraft":true,"flag":{"flagStatus":"flagged"}}`
}
func graphRef() Reference {
	return Reference{Provider: "microsoft_graph", Account: "account-id", ID: "message-id", Folder: "folder-id"}
}
func TestGraphReadDraftAttachmentAndSearch(t *testing.T) {
	p, e := compose.BuildDraft("person@example.com", compose.Input{To: []string{"to@example.com"}, Bcc: []string{"blind@example.com"}, Subject: "Hello", Text: "plain", HTML: "<p>html</p>", Attachments: []compose.Attachment{{Filename: "tiny.txt", ContentType: "text/plain", DataBase64: base64.StdEncoding.EncodeToString([]byte("payload"))}}}, strings.Repeat("a", 32), time.Now())
	if e != nil {
		t.Fatal(e)
	}
	raw, e := compose.DraftBytes(p)
	if e != nil {
		t.Fatal(e)
	}
	b := graphAPITestBackend(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1.0/me/mailFolders/folder-id/messages/message-id":
			io.WriteString(w, graphFixture())
		case "/v1.0/me/mailFolders/folder-id/messages/message-id/$value":
			w.Write(raw)
		case "/v1.0/me/mailFolders/folder-id/messages":
			io.WriteString(w, `{"value":[`+graphFixture()+`]}`)
		default:
			t.Error("unexpected path", r.URL.Path)
			w.WriteHeader(404)
		}
	})
	m, e := b.Read(context.Background(), graphRef())
	if e != nil || m.Reference != graphRef() || m.Text != "plain" || len(m.Attachments) != 1 {
		t.Fatalf("read %v %#v", e, m)
	}
	d, e := b.ReadDraft(context.Background(), graphRef())
	if e != nil || len(d.Message.Bcc) != 1 || d.Message.HTML != "<p>html</p>" || d.SourceDigest == "" {
		t.Fatalf("draft %v %#v", e, d)
	}
	a, e := b.GetAttachment(context.Background(), graphRef(), 1)
	if e != nil || a.DataBase64 != base64.StdEncoding.EncodeToString([]byte("payload")) {
		t.Fatalf("attachment %v %#v", e, a)
	}
	page, e := b.Search(context.Background(), SearchRequest{Folder: "folder-id", Query: "plain", Subject: "hello", Attention: true})
	if e != nil || len(page.Messages) != 1 || page.Provider != "microsoft_graph" || page.UIDValidity != 0 {
		t.Fatalf("search %v %#v", e, page)
	}
}
func TestGraphSendBccExactBytesAndUnknownNoRetry(t *testing.T) {
	for _, lost := range []bool{false, true} {
		t.Run(map[bool]string{false: "accepted", true: "lost-response"}[lost], func(t *testing.T) {
			original, e := compose.Build("person@example.com", compose.Input{To: []string{"to@example.com"}, Cc: []string{"cc@example.com"}, Bcc: []string{"blind@example.com"}, Subject: "hello", Text: "body"}, strings.Repeat("b", 32), time.Now())
			if e != nil {
				t.Fatal(e)
			}
			p, e := compose.ForMicrosoftGraph(original)
			if e != nil {
				t.Fatal(e)
			}
			var writes atomic.Int32
			b := graphAPITestBackend(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "POST" || r.URL.Path != "/v1.0/me/sendMail" {
					t.Error("wrong send")
				}
				writes.Add(1)
				body, _ := io.ReadAll(r.Body)
				raw, e := base64.StdEncoding.DecodeString(string(body))
				if e != nil || string(raw) != string(p.Raw) || !strings.Contains(string(raw), "blind@example.com") || r.Header.Get("Content-Type") != "text/plain" {
					t.Error("wire bytes/Bcc changed")
				}
				if lost {
					conn, _, e := w.(http.Hijacker).Hijack()
					if e == nil {
						conn.Close()
					}
					return
				}
				w.WriteHeader(202)
			})
			result, e := b.Send(context.Background(), Envelope{From: p.From, To: p.Recipients}, p.Raw)
			if writes.Load() != 1 {
				t.Fatal("write repeated")
			}
			if lost {
				if !errors.Is(e, ErrOutcomeUnknown) || result.Status != "unknown" {
					t.Fatal(result, e)
				}
			} else if e != nil || result.Status != "accepted" {
				t.Fatal(result, e)
			}
			if p.Digest == original.Digest || p.Digest != compose.PreparedDigest(p) {
				t.Fatal("provider wire digest not bound")
			}
			p.Raw[0] ^= 1
			if p.Digest == compose.PreparedDigest(p) {
				t.Fatal("tampering accepted")
			}
		})
	}
}
func TestGraphRejectsMissingBccAndUnsupportedBeforeIO(t *testing.T) {
	calls := 0
	b := graphAPITestBackend(t, func(http.ResponseWriter, *http.Request) { calls++ })
	original, e := compose.Build("person@example.com", compose.Input{To: []string{"to@example.com"}, Bcc: []string{"blind@example.com"}, Text: "body"}, strings.Repeat("c", 32), time.Now())
	if e != nil {
		t.Fatal(e)
	}
	if _, e = b.Send(context.Background(), Envelope{From: original.From, To: original.Recipients}, original.Raw); !errors.Is(e, ErrInvalidInput) {
		t.Fatal(e)
	}
	if _, e = b.SetFlags(context.Background(), FlagRequest{Reference: graphRef(), Operation: "add", Flags: []string{`\Answered`}}); !errors.Is(e, ErrUnsupported) {
		t.Fatal(e)
	}
	if _, e = b.SetFlags(context.Background(), FlagRequest{Reference: graphRef(), Operation: "add", Flags: []string{`\Seen`}, UnchangedSince: 1}); !errors.Is(e, ErrUnsupported) {
		t.Fatal(e)
	}
	if _, e = b.Delete(context.Background(), graphRef()); !errors.Is(e, ErrUnsupported) {
		t.Fatal(e)
	}
	if _, e = b.Conversation(context.Background(), graphRef(), SearchRequest{}); !errors.Is(e, ErrUnsupported) {
		t.Fatal(e)
	}
	wrong := graphRef()
	wrong.Account = "wrong-account"
	if _, e = b.Read(context.Background(), wrong); !errors.Is(e, ErrInvalidInput) {
		t.Fatal(e)
	}
	if calls != 0 {
		t.Fatal("unsupported reached mail provider")
	}
}
func TestGraphPaginationIntegrityAndOrigin(t *testing.T) {
	for _, next := range []string{"https://evil.example/v1.0/me/mailFolders/folder-id/messages", "https://graph.microsoft.com/v1.0/users/other/messages", "https://graph.microsoft.com/v1.0/me/messages", "https://graph.microsoft.com:443/v1.0/me/mailFolders/folder-id/messages"} {
		t.Run(next, func(t *testing.T) {
			b := graphAPITestBackend(t, func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(map[string]any{"value": []any{}, "@odata.nextLink": next})
			})
			if _, e := b.Search(context.Background(), SearchRequest{Folder: "folder-id"}); e == nil {
				t.Fatal("unsafe next accepted")
			}
		})
	}
	b := graphAPITestBackend(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("$skiptoken") == "opaque" {
			io.WriteString(w, `{"value":[`+graphFixture()+`]}`)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"value": []any{}, "@odata.nextLink": graphRoot + "/me/mailFolders/folder-id/messages?$skiptoken=opaque"})
	})
	first, e := b.Search(context.Background(), SearchRequest{Folder: "folder-id"})
	if e != nil || first.NextCursor == "" {
		t.Fatal(first, e)
	}
	second, e := b.Search(context.Background(), SearchRequest{Folder: "folder-id", Cursor: first.NextCursor})
	if e != nil || len(second.Messages) != 1 {
		t.Fatal(second, e)
	}
	if _, e = b.Search(context.Background(), SearchRequest{Folder: "folder-id", Subject: "changed", Cursor: first.NextCursor}); !errors.Is(e, ErrInvalidInput) {
		t.Fatal("scope change", e)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(first.NextCursor)
	var cursor graphCursor
	json.Unmarshal(raw, &cursor)
	cursor.URL = graphRoot + "/me/mailFolders/folder-id/messages?$skip=999"
	tampered := base64.RawURLEncoding.EncodeToString(graphJSON(cursor))
	if _, e = b.Search(context.Background(), SearchRequest{Folder: "folder-id", Cursor: tampered}); !errors.Is(e, ErrInvalidInput) {
		t.Fatal("tamper", e)
	}
}
func TestGraphWritesAndRedirect(t *testing.T) {
	calls := 0
	b := graphAPITestBackend(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		switch {
		case r.Method == "PATCH":
			var patch map[string]any
			json.NewDecoder(r.Body).Decode(&patch)
			if len(patch) != 1 || patch["isRead"] != true {
				t.Error("unexpected patch")
			}
			io.WriteString(w, strings.Replace(graphFixture(), `"isRead":false`, `"isRead":true`, 1))
		case strings.HasSuffix(r.URL.Path, "/move"):
			w.WriteHeader(201)
			io.WriteString(w, strings.Replace(graphFixture(), "folder-id", "destination-id", 1))
		default:
			w.Header().Set("Location", "https://evil.example/steal")
			w.WriteHeader(307)
		}
	})
	f, e := b.SetFlags(context.Background(), FlagRequest{Reference: graphRef(), Operation: "add", Flags: []string{`\Seen`}})
	if e != nil || !strings.Contains(strings.Join(f.Flags, ","), `\Seen`) {
		t.Fatal(f, e)
	}
	m, e := b.Move(context.Background(), graphRef(), "destination-id")
	if e != nil || m.Destination.Folder != "destination-id" {
		t.Fatal(m, e)
	}
	if e = b.CreateFolder(context.Background(), "new folder"); e == nil {
		t.Fatal("redirect followed")
	}
	if calls != 3 {
		t.Fatal(calls)
	}
}

func TestGraphFolderTreeAndDraftMutation(t *testing.T) {
	p, e := compose.BuildDraft("person@example.com", compose.Input{To: []string{"to@example.com"}, Bcc: []string{"blind@example.com"}, Text: "draft"}, strings.Repeat("d", 32), time.Now())
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := compose.DraftBytes(p)
	var creates, renames, drafts int
	b := graphAPITestBackend(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/v1.0/me/mailFolders":
			io.WriteString(w, `{"value":[{"id":"folder-id","displayName":"Inbox","childFolderCount":1}]}`)
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/childFolders"):
			io.WriteString(w, `{"value":[{"id":"child-id","displayName":"Child"}]}`)
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/messages"):
			drafts++
			body, _ := io.ReadAll(r.Body)
			decoded, e := base64.StdEncoding.DecodeString(string(body))
			if e != nil || string(decoded) != string(raw) {
				t.Error("draft bytes changed")
			}
			w.WriteHeader(201)
			io.WriteString(w, graphFixture())
		case r.Method == "POST":
			creates++
			w.WriteHeader(201)
			io.WriteString(w, `{"id":"new-folder"}`)
		case r.Method == "PATCH":
			renames++
			io.WriteString(w, `{"id":"new-folder"}`)
		default:
			t.Error("unexpected folder request", r.Method, r.URL.Path)
			w.WriteHeader(404)
		}
	})
	folders, e := b.ListFolders(context.Background())
	if e != nil || len(folders) != 2 || folders[0].Name != "folder-id" || folders[0].DisplayName != "Inbox" {
		t.Fatal(folders, e)
	}
	if e = b.CreateFolder(context.Background(), "A new folder"); e != nil {
		t.Fatal(e)
	}
	if e = b.RenameFolder(context.Background(), "new-folder", "New name"); e != nil {
		t.Fatal(e)
	}
	m, e := b.AppendDraft(context.Background(), "drafts", raw)
	if e != nil || m.Destination == nil || m.Destination.ID != "message-id" {
		t.Fatal(m, e)
	}
	if creates != 1 || renames != 1 || drafts != 1 {
		t.Fatal("unexpected mutation counts")
	}
}
func TestGraphIdentityMismatchStopsBeforeMailbox(t *testing.T) {
	for _, profile := range []string{`{"id":"another-account","mail":"person@example.com"}`, `{"id":"account-id","mail":"other@example.com"}`, `{"id":"account-id","mail":null,"userPrincipalName":"person@example.com"}`} {
		calls := 0
		b := graphAPITestBackend(t, func(http.ResponseWriter, *http.Request) { calls++ }, profile)
		if _, e := b.Read(context.Background(), graphRef()); !errors.Is(e, ErrUnavailable) {
			t.Fatal(e)
		}
		if calls != 0 {
			t.Fatal("mailbox touched before identity verified")
		}
	}
}

func TestGraphDraftExchangeMetadataRetainsRawDigestAndStrictSemantics(t *testing.T) {
	p, e := compose.BuildDraft("person@example.com", compose.Input{To: []string{"to@example.com"}, Text: "draft", HTML: "<p>draft</p>"}, strings.Repeat("e", 32), time.Now())
	if e != nil {
		t.Fatal(e)
	}
	raw := append([]byte("Received: from exchange.example\r\n\tby outlook.example; Thu, 8 Oct 2026 00:00:00 +0000\r\nThread-Topic: draft\r\nThread-Index: synthetic\r\nX-MS-Exchange-Organization-AuthAs: Internal\r\nContent-Language: en-US\r\n"), p.Raw...)
	cleaned, e := graphStructuredDraftSource(raw)
	if e != nil {
		t.Fatal(e)
	}
	source := Message{raw: raw, Summary: Summary{Size: int64(len(raw)), Flags: []string{`\Draft`}}}
	d, e := draftFromSource(source, cleaned)
	if e != nil || d.Message.HTML != "<p>draft</p>" {
		t.Fatal(d, e)
	}
	originalSum := sha256.Sum256(raw)
	if d.SourceDigest != hex.EncodeToString(originalSum[:]) {
		t.Fatal("digest lost original provider bytes")
	}
	for _, header := range []string{"Sensitivity: confidential", "MSIP_Labels: protected", "X-Unknown-Policy: retain", "Sender: other@example.com", "X-MS-TNEF-Correlator: semantic"} {
		candidate := append([]byte(header+"\r\n"), raw...)
		cleaned, e := graphStructuredDraftSource(candidate)
		if e != nil {
			continue
		}
		if _, e = compose.ParseDraft(cleaned); e == nil {
			t.Fatal("discarded semantic header", header)
		}
	}
}

func TestGraphLargeDraftUsesCompleteRawNotDisplayBudget(t *testing.T) {
	body := strings.Repeat("text ", 60000)
	p, e := compose.BuildDraft("person@example.com", compose.Input{To: []string{"to@example.com"}, Text: body}, strings.Repeat("f", 32), time.Now())
	if e != nil {
		t.Fatal(e)
	}
	b := graphAPITestBackend(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/$value") {
			w.Write(p.Raw)
		} else {
			io.WriteString(w, graphFixture())
		}
	})
	d, e := b.ReadDraft(context.Background(), graphRef())
	if e != nil || strings.TrimSuffix(d.Message.Text, "\r\n") != body {
		t.Fatal("display truncation affected full draft", e, len(d.Message.Text))
	}
}
func TestGraphSummaryBoundsUntrustedAddresses(t *testing.T) {
	b := &GraphBackend{config: config.Config{MicrosoftAccountID: "account-id"}}
	m := graphMessage{ID: "message-id", ParentFolderID: "folder-id", From: graphAddress{EmailAddress: Address{Name: "name\u202e\x00\r\n", Address: strings.Repeat("x", 2000)}}, ToRecipients: []graphAddress{{EmailAddress: Address{Name: "target\u202e", Address: "to@example.com\x00"}}}}
	s, e := b.summary(m)
	if e != nil || len(s.From[0].Address) > 1024 || strings.ContainsAny(s.From[0].Name, "\r\n\x00\u202e") || strings.ContainsRune(s.To[0].Address, 0) {
		t.Fatal(s, e)
	}
	m.ToRecipients = make([]graphAddress, 101)
	if _, e = b.summary(m); e == nil {
		t.Fatal("unbounded recipient count")
	}
}

package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/amxv/angelos/internal/compose"
	"github.com/amxv/angelos/internal/mail"
	gomail "github.com/emersion/go-message/mail"
)

func naturalSource(b *groupedBackend) {
	b.message.Headers = map[string]string{
		"From":     "Sender <Sender@Example.com>",
		"Reply-To": "First Reply <First@Example.com>, Second <Second@Example.com>",
		"To":       "Owner <owner@example.com>, Alias <alias@example.com>, Login <login@example.com>, Peer <Peer@Example.com>",
		"Cc":       "Peer Duplicate <peer@example.com>, Cc Person <Copy@Example.com>",
		"Bcc":      "secret-original-bcc@example.com", "Resent-Bcc": "secret-resent@example.com",
		"Message-ID": "(parent) <CaseSensitive@Example.COM>", "References": "<Root@Example.COM> <root@Example.COM>",
		"Date": "Fri, 2 Jan 2026 03:04:05 +0530", "Subject": "Re: RE: café",
	}
}

func prepareProtocol(t *testing.T, f *groupedAuthFixture, a *App, arguments string) map[string]any {
	t.Helper()
	status, out := f.call(t, a, "mail.read mail.send", "mail_prepare", arguments)
	r := groupedResult(t, status, out)
	return r["structuredContent"].(map[string]any)
}

func TestNaturalRepliesThroughOAuthMCP(t *testing.T) {
	f := newGroupedAuthFixture(t)
	for _, tc := range []struct {
		name, action, message string
		wantTo, wantCc        []string
	}{
		{"reply omitted", "reply", `{"text":"Thanks"}`, []string{"First@Example.com", "Second@Example.com"}, nil},
		{"reply-all omitted", "reply_all", `{"text":"Thanks"}`, []string{"First@Example.com", "Second@Example.com"}, []string{"Peer@Example.com", "Copy@Example.com"}},
		{"explicit replacement", "reply_all", `{"to":["owner@example.com"],"cc":[],"text":"Thanks"}`, []string{"owner@example.com"}, nil},
		{"explicit cc", "reply_all", `{"cc":["alias@example.com"],"text":"Thanks"}`, []string{"First@Example.com", "Second@Example.com"}, []string{"alias@example.com"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, backend, store := newGroupedApp()
			naturalSource(backend)
			a.Config.Username, a.Config.Aliases = "login@example.com", []string{"alias@example.com"}
			var firstID string
			for i := 0; i < 2; i++ {
				body := prepareProtocol(t, f, a, `{"action":"`+tc.action+`","reference":`+groupedReferenceJSON+`,"message":`+tc.message+`}`)
				p := store.record.Message
				mailboxes := func(values []string) []string {
					var result []string
					for _, value := range values {
						h := gomail.HeaderFromMap(map[string][]string{"To": {value}})
						addresses, err := h.AddressList("To")
						if err != nil {
							t.Fatal(err)
						}
						result = append(result, addresses[0].Address)
					}
					return result
				}
				if !reflect.DeepEqual(mailboxes(p.To), tc.wantTo) || !reflect.DeepEqual(mailboxes(p.Cc), tc.wantCc) {
					t.Fatalf("recipients: To %v Cc %v", p.To, p.Cc)
				}
				if p.Subject != "Re: café" || !strings.Contains(p.Text, "Thanks\n\nOn Fri, 2 Jan 2026 at 03:04 +0530, Sender <Sender@Example.com> wrote:\n> Original body") {
					t.Fatalf("unexpected reply: %q %q", p.Subject, p.Text)
				}
				if body["in_reply_to"] != "<CaseSensitive@Example.COM>" || !reflect.DeepEqual(body["references"], []any{"<Root@Example.COM>", "<root@Example.COM>", "<CaseSensitive@Example.COM>"}) {
					t.Fatalf("threading changed: %#v", body)
				}
				payload, _ := json.Marshal(body)
				if bytes.Contains(payload, []byte("secret-original")) || bytes.Contains(payload, []byte("secret-resent")) || bytes.Contains(p.Raw, []byte("Bcc:")) {
					t.Fatal("source BCC leaked")
				}
				if len(p.Attachments) != 0 || body["quote_original"] != true || body["original_mode"] != "quoted" || !reflect.DeepEqual(body["attachment_indexes"], []any{}) {
					t.Fatalf("bad preparation metadata: %#v", body)
				}
				if i == 0 {
					firstID = p.ID
				} else if p.ID == firstID {
					t.Fatal("repeated prepare reused ID")
				}
			}
			if !reflect.DeepEqual(backend.calls, []string{"read", "read"}) || store.puts != 2 || store.claims != 0 {
				t.Fatalf("prepare caused side effect: %v %#v", backend.calls, store)
			}
		})
	}
}

func TestNaturalReplyHTMLFullPreviewAndHash(t *testing.T) {
	f := newGroupedAuthFixture(t)
	for _, action := range []string{"reply", "reply_all", "forward"} {
		t.Run(action, func(t *testing.T) {
			a, backend, store := newGroupedApp()
			naturalSource(backend)
			authored := "<p>Authored &amp; exact</p>" + strings.Repeat("<p>long HTML</p>", 500)
			msg, _ := json.Marshal(map[string]any{"to": []string{"to@example.com"}, "html": authored})
			body := prepareProtocol(t, f, a, `{"action":"`+action+`","reference":`+groupedReferenceJSON+`,"message":`+string(msg)+`}`)
			p := store.record.Message
			if body["html"] != p.HTML || body["text"] != p.Text || !strings.HasPrefix(p.HTML, authored) || !strings.Contains(p.Text, "Authored & exact") || !strings.Contains(p.Text, "Original body") {
				t.Fatal("exact full alternatives omitted from preview")
			}
			reader, err := gomail.CreateReader(bytes.NewReader(p.Raw))
			if err != nil {
				t.Fatal(err)
			}
			seen := map[string]string{}
			for {
				part, err := reader.NextPart()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				data, err := io.ReadAll(part.Body)
				if err != nil {
					t.Fatal(err)
				}
				h, ok := part.Header.(*gomail.InlineHeader)
				if !ok {
					continue
				}
				ct, _, _ := h.ContentType()
				seen[ct] = string(data)
			}
			for _, ct := range []string{"text/plain", "text/html"} {
				if !strings.Contains(seen[ct], "Authored") || !strings.Contains(seen[ct], "Original body") {
					t.Fatalf("missing commentary/quote in %s: %.100q", ct, seen[ct])
				}
			}
			if p.Digest != compose.WireDigest(p.From, p.Recipients, p.Raw) {
				t.Fatal("incorrect immutable digest")
			}
			changed := bytes.Replace(p.Raw, []byte("Authored"), []byte("Altered"), 1)
			if p.Digest == compose.WireDigest(p.From, p.Recipients, changed) {
				t.Fatal("HTML mutation not bound by digest")
			}
		})
	}
}

func TestForwardModesAndSelectionThroughMCP(t *testing.T) {
	f := newGroupedAuthFixture(t)
	for _, tc := range []struct {
		name, options    string
		quoted, selected bool
	}{
		{"default", "", true, false}, {"empty default", `,"original_mode":""`, true, false}, {"quoted", `,"original_mode":"quoted"`, true, false},
		{"none", `,"original_mode":"none"`, false, false}, {"quote false", `,"quote_original":false`, false, false},
		{"selected", `,"attachment_indexes":[1]`, true, true}, {"none selected", `,"original_mode":"none","attachment_indexes":[1]`, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, backend, store := newGroupedApp()
			naturalSource(backend)
			backend.message.Attachments[0].Filename = "../ unsafe\\name\x00.txt"
			body := prepareProtocol(t, f, a, `{"action":"forward","reference":`+groupedReferenceJSON+`,"message":{"to":["to@example.com"],"text":"Comment"}`+tc.options+`}`)
			p := store.record.Message
			if strings.Contains(p.Text, "Original body") != tc.quoted || body["quote_original"] != tc.quoted {
				t.Fatal("wrong quote mode")
			}
			if bytes.Contains(p.Raw, []byte("In-Reply-To:")) || bytes.Contains(p.Raw, []byte("References:")) || p.Subject != "Fwd: Re: RE: café" {
				t.Fatal("forward retained source thread")
			}
			if tc.selected {
				sum := sha256.Sum256([]byte("hi"))
				if len(p.Attachments) != 1 || p.Attachments[0].Filename != "_ unsafe_name.txt" || p.Attachments[0].SHA256 != hex.EncodeToString(sum[:]) {
					t.Fatalf("selected payload changed: %#v", p.Attachments)
				}
				if !reflect.DeepEqual(backend.calls, []string{"read", "attachment"}) || backend.reference != groupedReference {
					t.Fatal("wrong exact attachment source")
				}
			} else if len(p.Attachments) != 0 || !reflect.DeepEqual(backend.calls, []string{"read"}) {
				t.Fatal("unselected attachments fetched/included")
			}
		})
	}
}

func TestPrepareRejectsInvalidOptionsWithoutSending(t *testing.T) {
	f := newGroupedAuthFixture(t)
	cases := []string{
		`{"action":"new","message":{"to":["to@example.com"],"text":"x"},"quote_original":true}`,
		`{"action":"reply","reference":` + groupedReferenceJSON + `,"message":{"text":"x"},"original_mode":"none"}`,
		`{"action":"reply_all","reference":` + groupedReferenceJSON + `,"message":{"text":"x"},"attachment_indexes":[]}`,
	}
	for _, options := range []string{`"original_mode":"unknown"`, `"original_mode":"eml","quote_original":true`, `"original_mode":"none","quote_original":false`, `"attachment_indexes":[0]`, `"attachment_indexes":[101]`, `"attachment_indexes":[1,1]`, `"attachment_indexes":[1.2]`, `"attachment_indexes":null`, `"quote_original":null`, `"original_mode":null`} {
		cases = append(cases, `{"action":"forward","reference":`+groupedReferenceJSON+`,"message":{"to":["to@example.com"],"text":"x"},`+options+`}`)
	}
	for i, args := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			a, b, s := newGroupedApp()
			status, out := f.call(t, a, "mail.read mail.send", "mail_prepare", args)
			groupedExpectError(t, status, out)
			if len(b.calls) != 0 || s.puts+s.claims != 0 {
				t.Fatalf("invalid options reached backend: %v", b.calls)
			}
		})
	}
	for _, options := range []string{`"original_mode":"eml"`, `"attachment_indexes":[2]`} {
		a, b, s := newGroupedApp()
		status, out := f.call(t, a, "mail.read mail.send", "mail_prepare", `{"action":"forward","reference":`+groupedReferenceJSON+`,"message":{"to":["to@example.com"],"text":"x"},`+options+`}`)
		groupedExpectError(t, status, out)
		if !reflect.DeepEqual(b.calls, []string{"read"}) || s.puts+s.claims != 0 {
			t.Fatal("missing raw/attachment prepared or sent")
		}
	}
}

func TestSourceAddressAndThreadingFailuresThroughMCP(t *testing.T) {
	f := newGroupedAuthFixture(t)
	for _, tc := range []struct {
		name, key, value, message string
		action                    string
		succeeds                  bool
	}{
		{"bad reply-to", "Reply-To", "valid@example.com, invalid", `{"text":"x"}`, "reply", false},
		{"empty reply-to", "Reply-To", "", `{"text":"x"}`, "reply", false},
		{"override bad reply-to", "Reply-To", "invalid", `{"to":["to@example.com"],"text":"x"}`, "reply", true},
		{"bad cc", "Cc", "valid@example.com, invalid", `{"text":"x"}`, "reply_all", false},
		{"replace bad cc", "Cc", "invalid", `{"cc":[],"text":"x"}`, "reply_all", true},
		{"missing parent", "Message-ID", "", `{"text":"x"}`, "reply", false},
		{"parent garbage", "Message-ID", "<Parent@example.com> junk", `{"text":"x"}`, "reply", false},
		{"two parents", "Message-ID", "<Parent@example.com> <Other@example.com>", `{"text":"x"}`, "reply", false},
		{"bad references", "References", "<Good@example.com> junk", `{"text":"x"}`, "reply", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b, s := newGroupedApp()
			naturalSource(b)
			b.message.Headers[tc.key] = tc.value
			status, out := f.call(t, a, "mail.read mail.send", "mail_prepare", `{"action":"`+tc.action+`","reference":`+groupedReferenceJSON+`,"message":`+tc.message+`}`)
			if tc.succeeds {
				groupedResult(t, status, out)
				if s.puts != 1 {
					t.Fatal("not prepared")
				}
			} else {
				groupedExpectError(t, status, out)
				if s.puts != 0 {
					t.Fatal("invalid source prepared")
				}
			}
		})
	}
}

func TestSourceHeaderCompletenessAndThreadFallbackThroughMCP(t *testing.T) {
	f := newGroupedAuthFixture(t)
	a, b, s := newGroupedApp()
	naturalSource(b)
	delete(b.message.Headers, "Reply-To")
	var addresses []string
	for i := 0; i < 35; i++ {
		addresses = append(addresses, strings.Repeat("Person ", 20)+fmt.Sprintf("<person%d@example.com>", i))
	}
	b.message.Headers["To"] = strings.Join(addresses, ", ")
	delete(b.message.Headers, "Cc")
	if len(b.message.Headers["To"]) <= 4096 {
		t.Fatal("fixture too short")
	}
	b.message.Headers["References"] = strings.Repeat("<Root@Example.com> ", 250) + "<UniqueTail@Example.com>"
	body := prepareProtocol(t, f, a, `{"action":"reply_all","reference":`+groupedReferenceJSON+`,"message":{"text":"Thanks"}}`)
	if len(s.record.Message.Cc) != 35 || !strings.Contains(strings.Join(s.record.Message.Cc, ","), "person34@example.com") {
		t.Fatal("long source participant list clipped")
	}
	if !reflect.DeepEqual(body["references"], []any{"<Root@Example.com>", "<UniqueTail@Example.com>", "<CaseSensitive@Example.COM>"}) {
		t.Fatal("long source references clipped")
	}
	for _, irt := range []string{"<PriorCASE@example.com>", "<PriorCASE@example.com> <ambiguous@example.com>", "broken"} {
		a, b, _ := newGroupedApp()
		naturalSource(b)
		delete(b.message.Headers, "References")
		b.message.Headers["In-Reply-To"] = irt
		b.message.Headers["Date"] = "bad date"
		body := prepareProtocol(t, f, a, `{"action":"reply","reference":`+groupedReferenceJSON+`,"message":{"text":"Thanks"}}`)
		refs := body["references"].([]any)
		want := 1
		if irt == "<PriorCASE@example.com>" {
			want = 2
			if refs[0] != irt {
				t.Fatal("fallback ID changed")
			}
		}
		if len(refs) != want || strings.Contains(body["text"].(string), "On ") || len(body["warnings"].([]any)) == 0 {
			t.Fatal("bad date/thread fallback")
		}
	}
}

func TestSevenBitEMLAndSafeSourceFilename(t *testing.T) {
	for _, tc := range []struct {
		raw   string
		valid bool
	}{{"From: a@example.com\r\n\r\ntext\r\n", true}, {"From: a@example.com\n\ntext\n", false}, {"X: café\r\n\r\nx\r\n", false}, {"X: a\r\n\r\n" + strings.Repeat("x", 999) + "\r\n", false}, {"X: a\r\n\r\nunterminated", false}, {"X: a\r\n\r\n\x00\r\n", false}} {
		if sevenBitEML([]byte(tc.raw)) != tc.valid {
			t.Errorf("wrong transport classification: %q", tc.raw)
		}
	}
	for _, name := range []string{"", "..", "../a\\b\x00.txt", strings.Repeat("é", 200), "\u202efile.txt"} {
		got := forwardAttachmentFilename(mail.Attachment{Index: 2, Filename: name})
		if got == "" || len(got) > 200 || !utf8.ValidString(got) || strings.ContainsAny(got, "/\\\x00") || strings.Contains(got, "\u202e") {
			t.Fatalf("unsafe filename: %q", got)
		}
	}
}

type mismatchedAttachmentBackend struct{ *groupedBackend }

func (b mismatchedAttachmentBackend) GetAttachment(context.Context, mail.Reference, int) (mail.AttachmentResult, error) {
	return mail.AttachmentResult{Reference: mail.Reference{Folder: "Other", UID: 17, UIDValidity: 9}}, nil
}

type staleCompositionBackend struct{ *groupedBackend }

func (b staleCompositionBackend) Read(context.Context, mail.Reference) (mail.Message, error) {
	return mail.Message{}, mail.ErrStaleReference
}
func TestSourceSelectionFailsClosedOnChangedReference(t *testing.T) {
	f := newGroupedAuthFixture(t)
	for _, mode := range []string{"attachment", "message", "stale"} {
		t.Run(mode, func(t *testing.T) {
			a, b, s := newGroupedApp()
			switch mode {
			case "attachment":
				a.Mail = mismatchedAttachmentBackend{b}
			case "message":
				b.message.Reference.UIDValidity++
			case "stale":
				a.Mail = staleCompositionBackend{b}
			}
			status, out := f.call(t, a, "mail.read mail.send", "mail_prepare", `{"action":"forward","reference":`+groupedReferenceJSON+`,"attachment_indexes":[1],"message":{"to":["to@example.com"],"text":"x"}}`)
			groupedExpectError(t, status, out)
			if s.puts+s.claims != 0 {
				t.Fatal("changed source reached durable store")
			}
		})
	}
}

func TestSourceDateRequiresKnownZone(t *testing.T) {
	for _, tc := range []struct{ date, formatted string }{
		{"Fri, 2 Jan 2026 03:04:05 +0530", "03:04 +0530"},
		{"Fri, 2 Jan 2026 03:04:05 EST", "03:04 -0500"},
		{"Fri, 2 Jan 2026 03:04:05 PDT", "03:04 -0700"},
		{"Fri, 2 Jan 2026 03:04:05 GMT", "03:04 +0000"},
		{"Fri, 2 Jan 2026 03:04:05 XYZ", ""},
		{"Fri, 2 Jan 2026 03:04:05 +2500", ""},
	} {
		date := sourceDate(tc.date)
		if tc.formatted == "" {
			if !date.IsZero() {
				t.Errorf("invented time zone: %s", date)
			}
		} else if date.Format("15:04 -0700") != tc.formatted {
			t.Errorf("wrong date: %s", date)
		}
	}
}

type attachmentPayloadBackend struct {
	*groupedBackend
	payload []byte
}

func (b attachmentPayloadBackend) GetAttachment(_ context.Context, ref mail.Reference, index int) (mail.AttachmentResult, error) {
	b.called("attachment")
	return mail.AttachmentResult{Reference: ref, Attachment: b.message.Attachments[index-1], DataBase64: base64.StdEncoding.EncodeToString(b.payload)}, nil
}
func TestSelectedContainerAttachmentsUseSafeTransport(t *testing.T) {
	f := newGroupedAuthFixture(t)
	for _, tc := range []struct {
		contentType string
		payload     []byte
		fallback    bool
	}{
		{"multipart/mixed; boundary=inner", []byte("--inner\r\nContent-Type: text/plain\r\n\r\nx\r\n--inner--\r\n"), true},
		{"message/rfc822", []byte("Subject: café\r\n\r\nbody\r\n"), true},
		{"message/rfc822", []byte("Subject: ascii\r\n\r\nbody\r\n"), false},
	} {
		t.Run(tc.contentType+fmt.Sprint(tc.fallback), func(t *testing.T) {
			a, b, s := newGroupedApp()
			b.message.Attachments[0] = mail.Attachment{Index: 1, Filename: "original.eml", ContentType: tc.contentType, Size: int64(len(tc.payload))}
			a.Mail = attachmentPayloadBackend{b, tc.payload}
			body := prepareProtocol(t, f, a, `{"action":"forward","reference":`+groupedReferenceJSON+`,"attachment_indexes":[1],"message":{"to":["to@example.com"],"text":"Comment"}}`)
			p := s.record.Message
			sum := sha256.Sum256(tc.payload)
			if p.Attachments[0].SHA256 != hex.EncodeToString(sum[:]) {
				t.Fatal("container bytes changed")
			}
			want := "message/rfc822"
			if tc.fallback {
				want = "application/octet-stream"
				if !strings.Contains(strings.Join(p.Warnings, " "), "container/message bytes safely") {
					t.Fatal("fallback disclosure missing")
				}
			}
			if p.Attachments[0].ContentType != want || body["warnings"] == nil {
				t.Fatalf("unsafe container type: %s", p.Attachments[0].ContentType)
			}
			reader, err := gomail.CreateReader(bytes.NewReader(p.Raw))
			if err != nil {
				t.Fatal(err)
			}
			for {
				part, err := reader.NextPart()
				if err == io.EOF {
					t.Fatal("no attachment")
				}
				if err != nil {
					t.Fatal(err)
				}
				data, err := io.ReadAll(part.Body)
				if err != nil {
					t.Fatal(err)
				}
				if _, ok := part.Header.(*gomail.AttachmentHeader); ok {
					if !bytes.Equal(data, tc.payload) {
						t.Fatal("container payload not exact")
					}
					break
				}
			}
		})
	}
}

func TestPrepareRejectsNullRecipientOverrides(t *testing.T) {
	f := newGroupedAuthFixture(t)
	for _, field := range []string{"to", "cc", "bcc", "subject", "text", "html", "attachments"} {
		a, b, s := newGroupedApp()
		naturalSource(b)
		status, out := f.call(t, a, "mail.read mail.send", "mail_prepare", `{"action":"reply_all","reference":`+groupedReferenceJSON+`,"message":{"`+field+`":null}}`)
		groupedExpectError(t, status, out)
		if len(b.calls) != 0 || s.puts != 0 {
			t.Fatalf("null %s reached backend", field)
		}
	}
}

func TestSourceAttachmentBoundsBeforeFetch(t *testing.T) {
	f := newGroupedAuthFixture(t)
	for _, test := range []string{"too many selected", "oversized selected", "aggregate selected", "with authored"} {
		t.Run(test, func(t *testing.T) {
			a, b, s := newGroupedApp()
			indexes := []int{1}
			message := map[string]any{"to": []string{"to@example.com"}, "text": "x"}
			switch test {
			case "too many selected":
				for i := 2; i <= 21; i++ {
					indexes = append(indexes, i)
				}
			case "oversized selected":
				b.message.Attachments[0].Size = (2 << 20) + 1
			case "aggregate selected":
				indexes = []int{1, 2}
				b.message.Attachments = []mail.Attachment{{Index: 1, Filename: "a", ContentType: "application/octet-stream", Size: 2 << 20}, {Index: 2, Filename: "b", ContentType: "application/octet-stream", Size: 2 << 20}}
			case "with authored":
				b.message.Attachments[0].Size = 2 << 20
				message["attachments"] = []compose.Attachment{{Filename: "new.bin", ContentType: "application/octet-stream", DataBase64: base64.StdEncoding.EncodeToString(make([]byte, (1<<20)+1))}}
			}
			args, _ := json.Marshal(map[string]any{"action": "forward", "reference": groupedReference, "message": message, "attachment_indexes": indexes})
			status, out := f.call(t, a, "mail.read mail.send", "mail_prepare", string(args))
			groupedExpectError(t, status, out)
			if strings.Contains(strings.Join(b.calls, ","), "attachment") || s.puts+s.claims != 0 {
				t.Fatalf("oversize fetched/prepared: %v", b.calls)
			}
		})
	}
}

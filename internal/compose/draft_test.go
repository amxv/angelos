package compose

import (
	"bytes"
	"encoding/base64"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func builtDraft(t *testing.T, in Input) []byte {
	t.Helper()
	p, err := BuildDraft("Owner <owner@example.com>", in, strings.Repeat("a", 32), time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := DraftBytes(p)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestParseDraftPreservesSupportedContent(t *testing.T) {
	in := Input{To: []string{"First <to@example.com>"}, Cc: []string{"cc@example.com"}, Bcc: []string{"Private <hidden@example.com>"}, Subject: "café", Text: "Plain\nbody", HTML: "<p>Exact <b>HTML</b></p><img src=\"https://example.invalid/image\">", InReplyTo: "<Parent@Example.COM>", References: []string{"<Root@Example.COM>", "<root@Example.COM>"}, Attachments: []Attachment{{Filename: "café.txt", ContentType: "text/plain; charset=iso-8859-1", DataBase64: base64.StdEncoding.EncodeToString([]byte{0x68, 0xe9, 0x00, 0xff})}, {Filename: "empty.bin", ContentType: "application/octet-stream", DataBase64: ""}}}
	raw := builtDraft(t, in)
	got, err := ParseDraft(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.From != `"Owner" <owner@example.com>` || got.MessageID != "<"+strings.Repeat("a", 32)+"@example.com>" {
		t.Fatalf("metadata: %+v", got)
	}
	if got.Message.Subject != in.Subject || normalizeBody(got.Message.Text) != in.Text || got.Message.HTML != in.HTML || got.Message.InReplyTo != in.InReplyTo || !reflect.DeepEqual(got.Message.References, in.References) || !reflect.DeepEqual(got.Message.Attachments, in.Attachments) {
		t.Fatalf("source changed: %+v", got.Message)
	}
	for _, recipients := range [][]string{got.Message.To, got.Message.Cc, got.Message.Bcc} {
		if len(recipients) != 1 {
			t.Fatalf("recipient loss: %+v", got)
		}
	}
	if !strings.Contains(got.Message.Bcc[0], "hidden@example.com") {
		t.Fatal("BCC lost")
	}
	rebuilt := builtDraft(t, got.Message)
	if _, err := ParseDraft(rebuilt); err != nil {
		t.Fatal(err)
	}
}

func TestParseDraftBeyondDisplayLimit(t *testing.T) {
	text := strings.Repeat("body ", 70000)
	got, err := ParseDraft(builtDraft(t, Input{Text: text}))
	if err != nil || normalizeBody(got.Message.Text) != text+"\n" {
		t.Fatalf("body truncated: %d %v", len(got.Message.Text), err)
	}
}

func TestParseDraftRecipientlessAndHTMLOnly(t *testing.T) {
	for _, raw := range []string{
		"From: owner@example.com\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n",
		"From: owner@example.com\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>Only HTML</p>",
	} {
		d, err := ParseDraft([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		if d.Message.HTML != "" && d.Message.Text != "" {
			t.Fatal("retrieval must not derive a text field")
		}
	}
}

func TestParseDraftRejectsUnrepresentableMIME(t *testing.T) {
	base := "From: owner@example.com\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nbody"
	cases := map[string]string{}
	for _, header := range []string{"Reply-To: alternate@example.com", "Sender: sender@example.com", "Resent-To: hidden@example.com", "X-Draft-Metadata: keep me", "Content-ID: <inline>", "Content-Language: fr", "To: first@example.com\r\nTo: second@example.com", "From: other@example.com", "Content-Type: text/html", "Content-Transfer-Encoding: base64\r\nContent-Transfer-Encoding: 7bit", "References: <valid@example.com> junk"} {
		cases[header] = header + "\r\n" + base
	}
	for _, ct := range []string{"text/enriched", "text/plain; charset=iso-8859-1", "text/plain; charset=utf-8; format=flowed", "multipart/related; boundary=b", "multipart/signed; boundary=b", "application/pkcs7-mime"} {
		cases[ct] = strings.Replace(base, "text/plain; charset=utf-8", ct, 1)
	}
	for _, cte := range []string{"unknown", "base64", "quoted-printable"} {
		body := "body!"
		if cte == "quoted-printable" {
			body = "bad=Z9"
		}
		cases[cte] = strings.Replace(base, "\r\n\r\nbody", "\r\nContent-Transfer-Encoding: "+cte+"\r\n\r\n"+body, 1)
	}
	cases["missing From"] = strings.TrimPrefix(base, "From: owner@example.com\r\n")
	cases["bare LF"] = strings.ReplaceAll(base, "\r\n", "\n")
	cases["invalid UTF8"] = base + "\xff"
	cases["body over limit"] = base + strings.Repeat("x", MaxTextBytes)
	cases["header over limit"] = "Subject: " + strings.Repeat("a", maxDraftHeaderBytes) + "\r\n" + base
	plain := "Content-Type: text/plain; charset=utf-8\r\n\r\nplain"
	html := "Content-Type: text/html; charset=utf-8\r\n\r\n<p>html</p>"
	multi := func(ct string, parts ...string) string {
		return "From: owner@example.com\r\nContent-Type: " + ct + "; boundary=b\r\n\r\n--b\r\n" + strings.Join(parts, "\r\n--b\r\n") + "\r\n--b--\r\n"
	}
	for _, boundary := range []string{"nonasciié", "trailing ", "bad@punctuation", "bad\"quote"} {
		cases["invalid boundary "+boundary] = "From: owner@example.com\r\nContent-Type: multipart/alternative; boundary=\"" + boundary + "\"\r\n\r\n--" + boundary + "\r\n" + plain + "\r\n--" + boundary + "\r\n" + html + "\r\n--" + boundary + "--\r\n"
	}
	cases["reversed alternatives"] = multi("multipart/alternative", html, plain)
	cases["extra alternative"] = multi("multipart/alternative", plain, html, plain)
	cases["mixed bodies"] = multi("multipart/mixed", plain, html)
	cases["inline attachment"] = multi("multipart/mixed", plain, "Content-Type: image/png\r\nContent-Disposition: inline; filename=image.png\r\n\r\nx")
	cases["CID attachment"] = multi("multipart/mixed", plain, "Content-Type: image/png\r\nContent-ID: <x>\r\nContent-Disposition: attachment; filename=image.png\r\n\r\nx")
	cases["preamble"] = strings.Replace(multi("multipart/alternative", plain, html), "\r\n\r\n--b", "\r\n\r\npreamble\r\n--b", 1)
	cases["epilogue"] = multi("multipart/alternative", plain, html) + "hidden data"
	cases["unterminated"] = strings.TrimSuffix(multi("multipart/alternative", plain, html), "--b--\r\n")
	cases["nested alternative"] = multi("multipart/alternative", plain, strings.TrimPrefix(multi("multipart/alternative", plain, html), "From: owner@example.com\r\n"))
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseDraft([]byte(raw)); !errors.Is(err, ErrUnsupportedDraft) {
				t.Fatalf("accepted unsupported MIME or wrong error: %v", err)
			}
		})
	}
}

func TestDraftChangesPreserveAndClear(t *testing.T) {
	in := Input{To: []string{"to@example.com"}, Bcc: []string{"hidden@example.com"}, Subject: "old", Text: "old text", HTML: "<p>old</p>", Attachments: []Attachment{{Filename: "a"}}, InReplyTo: "<parent@example.com>", References: []string{"<root@example.com>"}}
	replacement := "new"
	got := (Changes{Subject: &replacement}).Apply(in)
	want := in
	want.Subject = replacement
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("omitted fields changed: %+v", got)
	}
	empty := ""
	got = (Changes{To: []string{}, Bcc: []string{}, HTML: &empty, Attachments: []Attachment{}, InReplyTo: &empty, References: []string{}}).Apply(in)
	if len(got.To)+len(got.Bcc)+len(got.Attachments)+len(got.References) != 0 || got.HTML != "" || got.InReplyTo != "" || got.Text != in.Text {
		t.Fatalf("clear failed: %+v", got)
	}
}

func FuzzParseDraft(f *testing.F) {
	// Valid seeds reach each supported structural branch instead of requiring
	// mutations to discover a complete MIME tree from an incomplete delimiter.
	for _, in := range []Input{
		{Text: "plain", HTML: "<p>HTML</p>", Attachments: []Attachment{{Filename: "a.bin", ContentType: "application/octet-stream", DataBase64: "AP8="}}},
		{HTML: "<p>HTML</p>", PreserveEmptyText: true},
	} {
		p, err := BuildDraft("owner@example.com", in, strings.Repeat("a", 32), time.Unix(0, 0))
		if err != nil {
			f.Fatal(err)
		}
		raw, err := DraftBytes(p)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(raw)
	}
	f.Add([]byte("From: owner@example.com\r\nContent-Type: text/html\r\n\r\n"))
	f.Add([]byte("From: owner@example.com\r\nContent-Type: text/html\r\n\r\n\r")) // CR normalizes to CRLF on the MIME wire.
	f.Add([]byte("From: owner@example.com\r\nContent-Type: text/plain\r\n\r\nbody"))
	f.Add([]byte("From: owner@example.com\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > MaxMessageBytes+1 {
			return
		}
		d, err := ParseDraft(raw)
		if err != nil {
			return
		}
		p, err := BuildDraft(d.From, d.Message, strings.Repeat("f", 32), time.Unix(0, 0))
		if err != nil {
			t.Fatal(err)
		}
		headerEnd := bytes.Index(p.Raw, []byte("\r\n\r\n"))
		if headerEnd < 0 {
			t.Fatal("missing outer header terminator")
		}
		if bytes.Contains(p.Raw[:headerEnd], []byte("\r\nBcc:")) {
			t.Fatal("outbound BCC header")
		}
		if len(p.Raw) > MaxMessageBytes || len(d.Message.Attachments) > 20 {
			t.Fatal("unbounded draft")
		}
		draft, err := DraftBytes(p)
		if err != nil {
			t.Fatal(err)
		}
		again, err := ParseDraft(draft)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(again.Message.Attachments, d.Message.Attachments) || normalizeBody(again.Message.HTML) != normalizeBody(d.Message.HTML) {
			t.Fatal("rebuild changed attachments or HTML")
		}
		wantText := p.Text
		if p.HTML == "" && wantText != "" && !strings.HasSuffix(wantText, "\n") {
			wantText += "\n"
		}
		// A mixed container has no final SMTP newline inside its text body.
		if len(p.Attachments) > 0 {
			wantText = p.Text
		}
		if normalizeBody(again.Message.Text) != wantText {
			t.Fatal("rebuild changed the prepared plain-text alternative")
		}
	})
}

func TestDraftEmptyTextAlternativeIsNotGenerated(t *testing.T) {
	in := Input{HTML: "<p>HTML only visible here</p>", PreserveEmptyText: true}
	got, err := ParseDraft(builtDraft(t, in))
	if err != nil {
		t.Fatal(err)
	}
	if got.Message.Text != "" || !got.Message.PreserveEmptyText {
		t.Fatalf("empty alternative lost: %+v", got.Message)
	}
	p, err := BuildDraft(got.From, got.Message, strings.Repeat("b", 32), time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if p.Text != "" {
		t.Fatal("existing empty alternative was generated")
	}
	empty := ""
	patched := (Changes{Text: &empty}).Apply(Input{Text: "old text", HTML: "<p>HTML preserved</p>"})
	p, err = BuildDraft("owner@example.com", patched, strings.Repeat("b", 32), time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if p.Text != "" || p.HTML != patched.HTML {
		t.Fatal("clear text changed retained HTML or generated text")
	}
}

func TestParseDraftRejectsEmptyHTMLAlternative(t *testing.T) {
	for _, raw := range []string{
		"From: owner@example.com\r\nContent-Type: text/html; charset=utf-8\r\n\r\n",
		"From: owner@example.com\r\nContent-Type: multipart/alternative; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nvisible plain\r\n--b\r\nContent-Type: text/html\r\n\r\n\r\n--b--\r\n",
	} {
		if _, err := ParseDraft([]byte(raw)); !errors.Is(err, ErrUnsupportedDraft) {
			t.Fatalf("silently removed empty HTML alternative: %v", err)
		}
	}
}

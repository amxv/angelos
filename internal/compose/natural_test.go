package compose

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"reflect"
	"strings"
	"testing"
	"time"
)

func buildNatural(t *testing.T, in Input) Prepared {
	t.Helper()
	p, err := Build("Owner <owner@example.com>", in, strings.Repeat("a", 32), time.Date(2026, 10, 6, 18, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func readNatural(t *testing.T, raw []byte) *mail.Message {
	t.Helper()
	m, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	return m
}
func mediaNatural(t *testing.T, value string) (string, map[string]string) {
	t.Helper()
	mt, params, err := mime.ParseMediaType(value)
	if err != nil {
		t.Fatal(err)
	}
	return mt, params
}
func readAllNatural(t *testing.T, r io.Reader) string {
	t.Helper()
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
func testSource() Source {
	return Source{
		From: []string{"Original Sender <sender@example.com>"}, ReplyTo: []string{"Replies <reply@example.com>"},
		To: []string{"Me <owner@example.com>", "Other <other@example.com>"}, Cc: []string{"Alias <alias@example.com>", "Copy <copy@example.com>"},
		Subject: "Re: Re: 日本語 status", Text: "Original one\n\n> Prior quote\n>> Older quote", MessageID: "<Parent@Example.COM>",
		References: []string{"<Root@Example.com>", "<root@Example.com>"}, Date: time.Date(2026, 10, 6, 17, 0, 0, 0, time.UTC),
	}
}
func TestNaturalMIMEPlainAndAlternative(t *testing.T) {
	for _, htmlBody := range []string{"", "<p>こんにちは &amp; hello</p>"} {
		in := Input{To: []string{"Recipient <to@example.com>"}, Subject: "こんにちは ✉️", Text: "héllo\nsecond line", HTML: htmlBody}
		p := buildNatural(t, in)
		m := readNatural(t, p.Raw)
		if strings.Contains(string(p.Raw), "angelos") || m.Header.Get("X-Mailer") != "" || m.Header.Get("X-Apple-Content-Length") != "" {
			t.Fatal("branded or spoofed client header")
		}
		if p.HTML != htmlBody || p.Text != in.Text || p.Digest != WireDigest(p.From, p.Recipients, p.Raw) || !bytes.HasSuffix(p.Raw, []byte("\r\n")) {
			t.Fatal("preview or wire binding mismatch")
		}
		mt, params := mediaNatural(t, m.Header.Get("Content-Type"))
		if htmlBody == "" {
			if mt != "text/plain" || params["charset"] != "utf-8" || m.Header.Get("Content-Transfer-Encoding") != "quoted-printable" {
				t.Fatalf("not a plain message: %v", m.Header)
			}
			if got := readAllNatural(t, quotedprintable.NewReader(m.Body)); got != "héllo\r\nsecond line\r\n" {
				t.Fatalf("plain body = %q", got)
			}
			continue
		}
		if mt != "multipart/alternative" {
			t.Fatalf("root type = %s", mt)
		}
		parts := multipart.NewReader(m.Body, params["boundary"])
		for _, expected := range []struct{ mt, text string }{{"text/plain", "héllo\r\nsecond line"}, {"text/html", htmlBody}} {
			part, err := parts.NextPart()
			if err != nil {
				t.Fatal(err)
			}
			mt, _ = mediaNatural(t, part.Header.Get("Content-Type"))
			if mt != expected.mt || readAllNatural(t, part) != expected.text {
				t.Fatalf("unexpected alternative: %s", mt)
			}
		}
		if _, err := parts.NextPart(); err != io.EOF {
			t.Fatalf("extra part: %v", err)
		}
	}
}
func TestNaturalMixedBodyFirstAndAttachmentParameters(t *testing.T) {
	for _, htmlBody := range []string{"", "<p>body</p>"} {
		p := buildNatural(t, Input{To: []string{"to@example.com"}, Text: "body", HTML: htmlBody, Attachments: []Attachment{{"note.txt", "text/plain; charset=iso-8859-1", "Y2Fm6Q=="}}})
		m := readNatural(t, p.Raw)
		mt, params := mediaNatural(t, m.Header.Get("Content-Type"))
		if mt != "multipart/mixed" {
			t.Fatal(mt)
		}
		parts := multipart.NewReader(m.Body, params["boundary"])
		body, err := parts.NextPart()
		if err != nil {
			t.Fatal(err)
		}
		mt, _ = mediaNatural(t, body.Header.Get("Content-Type"))
		if (htmlBody == "" && mt != "text/plain") || (htmlBody != "" && mt != "multipart/alternative") {
			t.Fatalf("body part type %s", mt)
		}
		att, err := parts.NextPart()
		if err != nil {
			t.Fatal(err)
		}
		mt, params = mediaNatural(t, att.Header.Get("Content-Type"))
		if mt != "text/plain" || params["charset"] != "iso-8859-1" || att.FileName() != "note.txt" {
			t.Fatalf("attachment metadata: %v", att.Header)
		}
		data := readAllNatural(t, base64.NewDecoder(base64.StdEncoding, att))
		if data != "caf\xe9" {
			t.Fatalf("attachment bytes: %q", data)
		}
		hash := sha256.Sum256([]byte(data))
		if p.Attachments[0].SHA256 != hex.EncodeToString(hash[:]) || p.Attachments[0].ContentType != "text/plain; charset=iso-8859-1" {
			t.Fatal("hash/type not reviewed exactly")
		}
	}
}
func TestNaturalDedupDisplayNamesAndBCCPrivacy(t *testing.T) {
	p := buildNatural(t, Input{
		To:  []string{"First name <first@example.com>", "Duplicate <FIRST@example.com>", "Owner <owner@example.com>"},
		Cc:  []string{"Duplicate <first@example.com>", "Visible copy <copy@example.com>"},
		Bcc: []string{"COPY@example.com", "Private name <hidden@example.com>", "HIDDEN@example.com"}, Text: "hello",
	})
	if len(p.To) != 2 || len(p.Cc) != 1 || len(p.Bcc) != 1 || len(p.Recipients) != 4 || !strings.Contains(p.To[0], "First name") || !strings.Contains(p.Cc[0], "Visible copy") {
		t.Fatalf("unexpected recipients: %+v", p)
	}
	if strings.Contains(string(p.Raw), "hidden@example.com") || strings.Contains(string(p.Raw), "Bcc:") || !strings.Contains(string(p.Raw), "owner@example.com") {
		t.Fatal("Bcc leaked or explicit self removed")
	}
}
func TestNaturalReplyDerivationAndQuoting(t *testing.T) {
	source := testSource()
	in, err := ReplyPlan(source, []string{"owner@example.com", "alias@example.com"}, Input{Text: "Thank you."}, ReplyOptions{ReplyAll: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(in.To) != 1 || !strings.Contains(in.To[0], "reply@example.com") || len(in.Cc) != 2 || !strings.Contains(in.Cc[0], "other@example.com") || !strings.Contains(in.Cc[1], "copy@example.com") || len(in.Bcc) != 0 {
		t.Fatalf("reply recipients: %+v", in)
	}
	if in.Subject != "Re: 日本語 status" || in.InReplyTo != "<Parent@Example.COM>" || !reflect.DeepEqual(in.References, []string{"<Root@Example.com>", "<root@Example.com>", "<Parent@Example.COM>"}) {
		t.Fatalf("reply threading: %+v", in)
	}
	for _, want := range []string{"Thank you.\n\nOn Tue, 6 Oct 2026 at 17:00 +0000, Original Sender <sender@example.com> wrote:", "> Original one\n>\n> > Prior quote\n> >> Older quote"} {
		if !strings.Contains(in.Text, want) {
			t.Fatalf("missing normal quote %q in %q", want, in.Text)
		}
	}
	p := buildNatural(t, in)
	m := readNatural(t, p.Raw)
	if m.Header.Get("In-Reply-To") != in.InReplyTo || m.Header.Get("References") != strings.Join(in.References, " ") {
		t.Fatalf("header case changed: %v", m.Header)
	}
}
func TestNaturalReplyExplicitOverridesAndSentFallback(t *testing.T) {
	source := testSource()
	noQuote := false
	in, err := ReplyPlan(source, []string{"owner@example.com", "alias@example.com"}, Input{To: []string{}, Cc: []string{"Me <owner@example.com>"}, Bcc: []string{"Alias <alias@example.com>"}, Text: "exact", HTML: "<p>exact</p>"}, ReplyOptions{ReplyAll: true, QuoteOriginal: &noQuote})
	if err != nil || len(in.To) != 0 || len(in.Cc) != 1 || len(in.Bcc) != 1 || in.Text != "exact" || in.HTML != "<p>exact</p>" {
		t.Fatalf("explicit overrides/omit = %+v, %v", in, err)
	}
	source.From, source.ReplyTo = []string{"Me <owner@example.com>"}, nil
	for _, replyAll := range []bool{false, true} {
		in, err = ReplyPlan(source, []string{"owner@example.com", "alias@example.com"}, Input{Text: "follow-up"}, ReplyOptions{ReplyAll: replyAll})
		if err != nil || len(in.To) != 1 || !strings.Contains(in.To[0], "other@example.com") || (replyAll && len(in.Cc) != 1) || (!replyAll && len(in.Cc) != 0) {
			t.Fatalf("sent fallback = %+v, %v", in, err)
		}
	}
}
func TestNaturalReplyMalformedSourceFailsClosedWhenNeeded(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Source)
		all    bool
	}{
		{"reply-to", func(s *Source) { s.ReplyTo = []string{"broken"} }, false},
		{"source-to", func(s *Source) { s.To = []string{"bad\r\nBcc: victim@example.com"} }, true},
		{"source-cc", func(s *Source) { s.Cc = []string{"broken"} }, true},
		{"message-id", func(s *Source) { s.MessageID = "<bad@id>\r\nBcc: victim@example.com" }, false},
		{"references", func(s *Source) { s.References = []string{"bad"} }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			source := testSource()
			tc.mutate(&source)
			if _, err := ReplyPlan(source, []string{"owner@example.com"}, Input{Text: "reply"}, ReplyOptions{ReplyAll: tc.all}); err == nil {
				t.Fatal("accepted malformed needed source field")
			}
		})
	}
	source := testSource()
	source.From, source.ReplyTo, source.To, source.Cc = []string{"bad"}, []string{"bad"}, []string{"bad"}, []string{"bad"}
	if _, err := ReplyPlan(source, nil, Input{To: []string{"chosen@example.com"}, Cc: []string{}, Text: "reply"}, ReplyOptions{ReplyAll: true}); err != nil {
		t.Fatalf("unused malformed recipients blocked explicit choice: %v", err)
	}
}
func TestNaturalReferencesFallbackBoundsAndFolding(t *testing.T) {
	source := testSource()
	source.References = nil
	source.InReplyTo = "<Earlier@Example.COM>"
	in, err := ReplyPlan(source, nil, Input{Text: "reply"}, ReplyOptions{})
	if err != nil || !reflect.DeepEqual(in.References, []string{"<Earlier@Example.COM>", "<Parent@Example.COM>"}) {
		t.Fatalf("fallback = %v, %v", in.References, err)
	}
	source.References = []string{"<Root@Example.COM>"}
	for i := 0; i < 300; i++ {
		source.References = append(source.References, fmt.Sprintf("<Node-%03d-%s@Example.COM>", i, strings.Repeat("x", 90)))
	}
	in, err = ReplyPlan(source, nil, Input{Text: "reply"}, ReplyOptions{})
	if err != nil || len(in.References) > MaxReferences || len(strings.Join(in.References, " ")) > MaxReferencesBytes || in.References[0] != "<Root@Example.COM>" || in.References[len(in.References)-1] != source.MessageID || len(in.Warnings) != 1 {
		t.Fatalf("bounded references: %v, %v", in.References, err)
	}
	p := buildNatural(t, in)
	m := readNatural(t, p.Raw)
	if m.Header.Get("References") != strings.Join(in.References, " ") {
		t.Fatalf("folding changed references: %q", m.Header.Get("References"))
	}
	for _, line := range bytes.Split(p.Raw, []byte("\r\n")) {
		if len(line) > 998 {
			t.Fatal("long wire line")
		}
	}
}
func TestNaturalSubjectsUnicodeAndPrefixes(t *testing.T) {
	for _, tc := range []struct{ input, reply, forward string }{
		{"  re: RE: 日本語 👩‍💻", "Re: 日本語 👩‍💻", "Fwd: re: RE: 日本語 👩‍💻"},
		{"Fw: FWD: Café", "Re: Fw: FWD: Café", "Fwd: Café"},
		{"İstanbul", "Re: İstanbul", "Fwd: İstanbul"},
		{"", "Re:", "Fwd:"},
		{"Re:", "Re:", "Fwd: Re:"},
		{"主题", "Re: 主题", "Fwd: 主题"},
	} {
		if got := ReplySubject(tc.input); got != tc.reply {
			t.Errorf("ReplySubject(%q) = %q", tc.input, got)
		}
		if got := ForwardSubject(tc.input); got != tc.forward {
			t.Errorf("ForwardSubject(%q) = %q", tc.input, got)
		}
	}
}
func TestNaturalForwardSafeQuotedHTMLAndNewThread(t *testing.T) {
	source := testSource()
	source.Subject = "FW: Fwd: <img src='https://track.example/pixel'> & news"
	source.Text = "<script>alert(1)</script>\n& original"
	in, err := ForwardPlan(source, Input{To: []string{"target@example.com"}, Text: "Look here", HTML: "<p>Look here</p>", InReplyTo: "<wrong@id>", References: []string{"<wrong@id>"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if in.InReplyTo != "" || len(in.References) != 0 || len(in.Attachments) != 0 || len(in.Bcc) != 0 || in.Subject != "Fwd: <img src='https://track.example/pixel'> & news" {
		t.Fatalf("forward inherited unintended data: %+v", in)
	}
	for _, want := range []string{"---------- Forwarded message ----------", "From: Original Sender <sender@example.com>", "Date: Tue, 06 Oct 2026 17:00:00 +0000", "To: Me <owner@example.com>, Other <other@example.com>", "Cc: Alias <alias@example.com>, Copy <copy@example.com>", "<script>alert(1)</script>"} {
		if !strings.Contains(in.Text, want) {
			t.Fatalf("missing forward metadata/body: %q", want)
		}
	}
	if strings.Contains(in.HTML, "<script>") || strings.Contains(in.HTML, "<img") || !strings.Contains(in.HTML, "&lt;script&gt;") || !strings.Contains(in.HTML, "&amp; original") {
		t.Fatalf("source became active HTML: %q", in.HTML)
	}
	p := buildNatural(t, in)
	m := readNatural(t, p.Raw)
	if m.Header.Get("In-Reply-To") != "" || m.Header.Get("References") != "" {
		t.Fatal("forward threading headers leaked")
	}
}
func TestNaturalHTMLOnlyPlainFallbackAndDigest(t *testing.T) {
	htmlBody := "<html><head><style>.tracking{}</style></head><body><p>Hello &amp; 你好</p><div>Next<br>line</div><script>doNotRun()</script></body></html>"
	p := buildNatural(t, Input{To: []string{"to@example.com"}, HTML: htmlBody})
	if p.Text != "Hello & 你好\nNext\nline" || p.HTML != htmlBody || strings.Contains(p.Text, "doNotRun") {
		t.Fatalf("plain fallback %q", p.Text)
	}
	other := buildNatural(t, Input{To: []string{"to@example.com"}, Text: p.Text, HTML: htmlBody + " "})
	if p.Digest == other.Digest {
		t.Fatal("HTML omitted from exact wire digest")
	}
	in, err := ReplyPlan(testSource(), nil, Input{HTML: "<p>My answer &amp; text</p>"}, ReplyOptions{})
	if err != nil || !strings.HasPrefix(in.Text, "My answer & text\n\n") || !strings.Contains(in.HTML, "&lt;sender@example.com&gt;") {
		t.Fatalf("HTML-only reply = %+v, %v", in, err)
	}
}
func TestNaturalHeaderUTF8AndSizeValidation(t *testing.T) {
	for _, mutate := range []func(*Input){
		func(in *Input) { in.Subject = "bad\x01header" },
		func(in *Input) { in.Subject = "bad\xff" },
		func(in *Input) { in.Text = "bad\xff" },
		func(in *Input) { in.HTML = "bad\x00" },
		func(in *Input) { in.HTML = strings.Repeat("x", MaxTextBytes+1) },
		func(in *Input) { in.Text = strings.Repeat("x", MaxTextBytes+1) },
		func(in *Input) { in.To = []string{"=?utf-8?q?bad=0Aname?= <to@example.com>"} },
		func(in *Input) { in.InReplyTo = "<left right@example.com>" },
		func(in *Input) { in.InReplyTo = "<parent@@example.com>" },
		func(in *Input) { in.Attachments = []Attachment{{"x\xff", "text/plain", "aA=="}} },
		func(in *Input) { in.Attachments = []Attachment{{"x", "text/plain\r\nX-Evil: 1", "aA=="}} },
	} {
		in := Input{To: []string{"to@example.com"}, Text: "body"}
		mutate(&in)
		if _, err := Build("owner@example.com", in, strings.Repeat("a", 32), time.Now()); err == nil {
			t.Fatal("invalid input accepted")
		}
	}
	if got, ok := NormalizeMessageID("<Foo@EXAMPLE.com>"); !ok || got != "<Foo@EXAMPLE.com>" {
		t.Fatalf("case lost: %q", got)
	}
}
func TestNaturalEMLIdentityEncodingAndExactBytes(t *testing.T) {
	eml := "From: a@example.com\r\nTo: b@example.com\r\nSubject: Original\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\ncaf=C3=A9\r\n"
	p := buildNatural(t, Input{To: []string{"to@example.com"}, Text: "See attached", Attachments: []Attachment{{"original.eml", "message/rfc822", base64.StdEncoding.EncodeToString([]byte(eml))}}})
	m := readNatural(t, p.Raw)
	_, params := mediaNatural(t, m.Header.Get("Content-Type"))
	parts := multipart.NewReader(m.Body, params["boundary"])
	if _, err := parts.NextPart(); err != nil {
		t.Fatal(err)
	}
	part, err := parts.NextRawPart()
	if err != nil {
		t.Fatal(err)
	}
	if part.Header.Get("Content-Transfer-Encoding") != "7bit" || readAllNatural(t, part) != eml {
		t.Fatal("embedded EML encoding or bytes changed")
	}
	for _, raw := range []string{strings.ReplaceAll(eml, "\r\n", "\n"), eml + "é", eml + strings.Repeat("x", 999), "not a message"} {
		in := Input{To: []string{"to@example.com"}, Attachments: []Attachment{{"original.eml", "message/rfc822", base64.StdEncoding.EncodeToString([]byte(raw))}}}
		if _, err := Build("owner@example.com", in, strings.Repeat("a", 32), time.Now()); err == nil {
			t.Fatal("invalid 7bit EML accepted")
		}
		in.Attachments[0].ContentType = "application/octet-stream"
		buildNatural(t, in)
	}
}
func TestNaturalPreparedIsIndependentOfInputSlices(t *testing.T) {
	in := Input{To: []string{"to@example.com"}, Bcc: []string{"hidden@example.com"}, Text: "original", Attachments: []Attachment{{"note.txt", "text/plain", "aGVsbG8="}}}
	p := buildNatural(t, in)
	raw, digest := append([]byte(nil), p.Raw...), p.Digest
	in.To[0], in.Bcc[0], in.Attachments[0].Filename = "evil@example.com", "evil@example.com", "evil.txt"
	if strings.Contains(strings.Join(p.To, ","), "evil") || strings.Contains(strings.Join(p.Bcc, ","), "evil") || p.Attachments[0].Filename != "note.txt" || p.Digest != digest || !bytes.Equal(p.Raw, raw) {
		t.Fatal("prepared payload aliases mutable inputs")
	}
}

func TestNaturalFoldedLongUnicodeRecipientsAndDomainLiteralID(t *testing.T) {
	name := strings.Repeat("名", 130)
	in := Input{To: []string{(&mail.Address{Name: name, Address: "to@example.com"}).String()}, Text: "hello", InReplyTo: "<Case@[IPv6:2001:db8::1]>"}
	// Input limits bound user spelling, not the expanded RFC 2047 encoding.
	in.To[0] = name + " <to@example.com>"
	p := buildNatural(t, in)
	m := readNatural(t, p.Raw)
	// Re-planning already formatted recipients and creating a private Bcc
	// draft must accept the same decoded display name.
	planned, err := ReplyPlan(testSource(), nil, in, ReplyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	buildNatural(t, planned)
	p.Bcc = append([]string(nil), p.To...)
	if _, err := DraftBytes(p); err != nil {
		t.Fatal(err)
	}
	to, err := m.Header.AddressList("To")
	if err != nil || len(to) != 1 || to[0].Name != name || m.Header.Get("In-Reply-To") != in.InReplyTo {
		t.Fatalf("Unicode/header folding: %v, %v", to, err)
	}
}

func TestNaturalLimitsRemainBounded(t *testing.T) {
	id, now := strings.Repeat("a", 32), time.Now()
	to := make([]string, MaxRecipients)
	for i := range to {
		to[i] = fmt.Sprintf("recipient-%02d@example.com", i)
	}
	if _, err := Build("owner@example.com", Input{To: to, Text: "hello"}, id, now); err != nil {
		t.Fatal(err)
	}
	if _, err := Build("owner@example.com", Input{To: append(to, "extra@example.com")}, id, now); err == nil {
		t.Fatal("accepted >50 recipients")
	}
	payload := bytes.Repeat([]byte("x"), MaxAttachmentBytes)
	attachment := Attachment{"data.bin", "application/octet-stream", base64.StdEncoding.EncodeToString(payload)}
	if _, err := Build("owner@example.com", Input{To: []string{"to@example.com"}, Attachments: []Attachment{attachment}}, id, now); err != nil {
		t.Fatal(err)
	}
	if _, err := Build("owner@example.com", Input{To: []string{"to@example.com"}, Attachments: []Attachment{attachment, {"extra.txt", "text/plain", "eA=="}}}, id, now); err == nil {
		t.Fatal("accepted aggregate attachments >3MiB")
	}
	if _, err := Build("owner@example.com", Input{To: []string{"to@example.com"}, Text: strings.Repeat("x", MaxTextBytes), HTML: strings.Repeat("y", MaxTextBytes), Attachments: []Attachment{attachment}}, id, now); err == nil {
		t.Fatal("accepted encoded wire >5MiB")
	}
}

func TestNaturalHTMLFallbackFailsClosedForParseErrorsAndDecodedControls(t *testing.T) {
	noQuote := false
	for _, tc := range []struct{ name, body, errorText string }{
		{"excessive nesting", strings.Repeat("<div>", 513) + "Important commentary" + strings.Repeat("</div>", 513), "complete plain-text alternative"},
		{"decoded SOH", "<p>hello&#x01;world</p>", "derived HTML text is invalid"},
		{"decoded vertical tab", "<p>hello&#x0b;world</p>", "derived HTML text is invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := Input{To: []string{"to@example.com"}, HTML: tc.body}
			for name, prepare := range map[string]func() error{
				"new": func() error {
					_, err := Build("owner@example.com", in, strings.Repeat("a", 32), time.Now())
					return err
				},
				"draft": func() error {
					_, err := BuildDraft("owner@example.com", in, strings.Repeat("a", 32), time.Now())
					return err
				},
				"reply quoted": func() error { _, err := ReplyPlan(testSource(), nil, in, ReplyOptions{}); return err },
				"reply unquoted": func() error {
					_, err := ReplyPlan(testSource(), nil, in, ReplyOptions{QuoteOriginal: &noQuote})
					return err
				},
				"forward quoted":   func() error { _, err := ForwardPlan(testSource(), in, nil); return err },
				"forward unquoted": func() error { _, err := ForwardPlan(testSource(), in, &noQuote); return err },
			} {
				t.Run(name, func(t *testing.T) {
					if err := prepare(); err == nil || !strings.Contains(err.Error(), tc.errorText) {
						t.Fatalf("did not fail closed for incomplete/invalid fallback: %v", err)
					}
				})
			}
		})
	}
	// An explicit reviewed plain body needs no HTML-to-text conversion.
	in := Input{To: []string{"to@example.com"}, Text: "Important commentary", HTML: strings.Repeat("<div>", 513) + "Important commentary" + strings.Repeat("</div>", 513)}
	p := buildNatural(t, in)
	if p.Text != in.Text || p.HTML != in.HTML {
		t.Fatal("explicit reviewed alternatives changed")
	}
}

func TestNaturalHTMLQuotationsInheritFontAndPreserveSafeLines(t *testing.T) {
	source := testSource()
	source.Text = "First <img src='https://track.example/pixel'> & line\n\n> Prior quote\n>> Older quote"
	for _, forwarding := range []bool{false, true} {
		name := "reply"
		if forwarding {
			name = "forward"
		}
		t.Run(name, func(t *testing.T) {
			in := Input{To: []string{"target@example.com"}, Text: "My commentary", HTML: "<p>My commentary</p>"}
			var rich, plain Input
			var err error
			if forwarding {
				rich, err = ForwardPlan(source, in, nil)
				in.HTML = ""
				plain, _ = ForwardPlan(source, in, nil)
			} else {
				rich, err = ReplyPlan(source, nil, in, ReplyOptions{})
				in.HTML = ""
				plain, _ = ReplyPlan(source, nil, in, ReplyOptions{})
			}
			if err != nil {
				t.Fatal(err)
			}
			if rich.Text != plain.Text {
				t.Fatal("HTML presentation changed plain alternative")
			}
			for _, forbidden := range []string{"<pre", "monospace", "class=", "<img"} {
				if strings.Contains(rich.HTML, forbidden) {
					t.Fatalf("forced font, branding, or active source markup: %q", rich.HTML)
				}
			}
			if !strings.Contains(rich.HTML, "First &lt;img src=&#39;https://track.example/pixel&#39;&gt; &amp; line<br>\n<br>\n&gt; Prior quote<br>\n&gt;&gt; Older quote") {
				t.Fatalf("source line breaks/escaping/nested quotes changed: %q", rich.HTML)
			}
			if !forwarding && !strings.Contains(rich.HTML, "<blockquote type=\"cite\">") {
				t.Fatalf("reply missing standard citation container: %q", rich.HTML)
			}
			if forwarding && !strings.Contains(rich.HTML, "From: Original Sender &lt;sender@example.com&gt;<br>\nDate:") {
				t.Fatalf("forward metadata not readable: %q", rich.HTML)
			}
		})
	}
}

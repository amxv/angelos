package mail

import (
	"bytes"
	"strings"
	"testing"
)

func sourceMessage(raw string) Message {
	m := Message{raw: []byte(raw), Summary: Summary{Size: int64(len(raw))}}
	parseMessage(m.raw, &m)
	return m
}

func TestCompositionHeadersPreserveStructuredFieldsAndLongReferences(t *testing.T) {
	refs := strings.Repeat("<Long.Reference.ID@EXAMPLE.com> ", 160)
	from := "=?UTF-8?Q?Name=2C_Still_One?= <Sender@Example.com>, Other <other@example.com>"
	raw := "From: " + from + "\r\nReply-To: reply1@example.com,\r\n reply2@example.com\r\nMessage-ID: <CaseSensitive@Example.COM>\r\nReferences: " + refs + "\r\nSubject: =?UTF-8?Q?caf=C3=A9?=\r\n\r\nOriginal\r\n"
	m := sourceMessage(raw)
	if len(m.Headers["References"]) > 4096 {
		t.Fatal("fixture no longer exercises clipped public headers")
	}
	h, err := m.CompositionHeaders()
	if err != nil {
		t.Fatal(err)
	}
	if h["From"] != from || h["Reply-To"] != "reply1@example.com, reply2@example.com" || h["Message-Id"] != "<CaseSensitive@Example.COM>" || h["Subject"] != "café" || h["References"] != strings.TrimSpace(refs) {
		t.Fatalf("source metadata altered: %#v", h)
	}
	if len(h["References"]) <= 4096 {
		t.Fatal("source references were clipped")
	}
}

func TestCompositionHeadersRejectDuplicateMalformedAndOversized(t *testing.T) {
	for _, raw := range []string{
		"From: a@example.com\r\nfrom: b@example.com\r\n\r\nx",
		"Message-ID: <A@example.com>\r\nMessage-Id: <B@example.com>\r\n\r\nx",
		"Subject: =?UTF-8?Q?hello=0D=0ABcc:_private@example.com?=\r\n\r\nx",
		"From: a@example.com\r\nSubject: " + strings.Repeat("x", 64<<10) + "\r\n\r\nx",
		"Malformed\r\n\r\nx",
	} {
		m := sourceMessage(raw)
		if _, err := m.CompositionHeaders(); err == nil {
			t.Errorf("accepted invalid source header, prefix %.80q", raw)
		}
	}
	m := Message{Headers: map[string]string{"From": "a@example.com", "from": "b@example.com"}}
	if _, err := m.CompositionHeaders(); err == nil {
		t.Fatal("fallback map accepted ambiguous field capitalization")
	}
	m = Message{Headers: map[string]string{"References": strings.Repeat("x", 64<<10)}}
	if _, err := m.CompositionHeaders(); err == nil {
		t.Fatal("unbounded fallback headers")
	}
}

func TestSanitizedEMLPreservesEveryOtherByte(t *testing.T) {
	for _, newline := range []string{"\r\n", "\n"} {
		headers := "From: a@example.com" + newline + "BCC : private@example.com," + newline + " other@example.com" + newline + "Subject: Keep bytes" + newline + "Resent-Bcc: resent@example.com" + newline + "\tand-more@example.com" + newline + "Received: private trace remains" + newline + "bCc: third@example.com" + newline
		body := "Nested body Bcc: keep-body@example.com" + newline + "\x00\xff"
		m := sourceMessage(headers + newline + body)
		got, err := m.SanitizedEML()
		if err != nil {
			t.Fatal(err)
		}
		want := "From: a@example.com" + newline + "Subject: Keep bytes" + newline + "Received: private trace remains" + newline + newline + body
		if !bytes.Equal(got, []byte(want)) {
			t.Fatalf("sanitizer changed other bytes: %q", got)
		}
		if bytes.Contains(got, []byte("private@example.com")) || bytes.Contains(got, []byte("resent@example.com")) {
			t.Fatal("outer BCC leaked")
		}
	}
}

func TestSanitizedEMLRequiresCompleteRawSource(t *testing.T) {
	for _, m := range []Message{
		{}, {raw: []byte("From: a@example.com\r\n")},
		{raw: []byte("From: a@example.com\r\n\r\npartial body"), Truncated: true},
		{raw: []byte("From: a@example.com\r\n\r\nx"), Summary: Summary{Size: 1000}},
		{raw: append([]byte("From: a@example.com\r\n\r\n"), bytes.Repeat([]byte("x"), maxMessageBytes)...)},
	} {
		if _, err := m.SanitizedEML(); err == nil {
			t.Fatal("incomplete raw source accepted")
		}
	}
}

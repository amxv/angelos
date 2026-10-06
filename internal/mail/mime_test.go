package mail

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"testing/iotest"
)

func TestParseMIME(t *testing.T) {
	raw := "From: Sender <sender@example.com>\r\nSubject: =?UTF-8?Q?caf=C3=A9?=\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nhello=20world\r\n--x\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=example.txt\r\nContent-Transfer-Encoding: base64\r\n\r\naGVsbG8=\r\n--x--\r\n"
	out := Message{Headers: map[string]string{}}
	parseMessage([]byte(raw), &out)
	if out.Headers["Subject"] != "café" || !strings.Contains(out.Text, "hello world") || len(out.Attachments) != 1 || out.Attachments[0].Size != 5 {
		t.Fatalf("unexpected parse: %+v", out)
	}
}
func TestHTMLNeverReturned(t *testing.T) {
	out := Message{Headers: map[string]string{}}
	parseMessage([]byte("Content-Type: text/html\r\n\r\n<script>bad()</script><img src=\"https://example.com/track\">"), &out)
	if out.Text != "" {
		t.Fatalf("HTML leaked: %+v", out)
	}
}
func TestMIMEBounded(t *testing.T) {
	out := Message{Headers: map[string]string{}}
	parseMessage([]byte("Content-Type: text/plain\r\n\r\n"+strings.Repeat("x", maxTextBytes+10)), &out)
	if !out.Truncated || len(out.Text) > maxTextBytes {
		t.Fatal("unbounded text")
	}
}
func TestNestedMIMEDepthBound(t *testing.T) {
	body := "Content-Type: text/plain\r\n\r\nhello"
	for i := 0; i < 20; i++ {
		body = fmt.Sprintf("Content-Type: multipart/mixed; boundary=b%d\r\n\r\n--b%d\r\n%s\r\n--b%d--\r\n", i, i, body, i)
	}
	out := Message{Headers: map[string]string{}}
	parseMessage([]byte(body), &out)
	if !out.Truncated {
		t.Fatal("depth not bounded")
	}
}
func TestSanitizeControls(t *testing.T) {
	if got := cleanHeader("a\x1b[31m\r\n b\u202ec", 100); got != "a[31m bc" {
		t.Fatalf("got %q", got)
	}
}
func TestCursorScope(t *testing.T) {
	scope := searchScope("INBOX", "term")
	c := encodeCursor(cursor{Version: 9, Before: 20, Scope: scope})
	if _, e := decodeCursor(c, scope); e != nil {
		t.Fatal(e)
	}
	if _, e := decodeCursor(c, searchScope("Sent", "term")); e == nil {
		t.Fatal("cross-folder cursor accepted")
	}
	if _, e := decodeCursor(strings.Repeat("A", 513), scope); e == nil {
		t.Fatal("oversized cursor accepted")
	}
}

func TestHTMLTextExtraction(t *testing.T) {
	raw := "Content-Type: text/html; charset=utf-8\r\n\r\n<html><head><title>hidden</title><style>.x { color: red }</style></head><body><p>Hello &amp; welcome.</p><script>secret()</script><p>Next <b>part</b>.</p><img src=\"https://example.com/tracker\"></body></html>"
	out := Message{Headers: map[string]string{}}
	parseMessage([]byte(raw), &out)
	if !strings.Contains(out.Text, "Hello & welcome.") || !strings.Contains(out.Text, "Next part.") || strings.Contains(out.Text, "secret") || strings.Contains(out.Text, "tracker") || strings.Contains(out.Text, "hidden") {
		t.Fatalf("bad HTML text %q", out.Text)
	}
}
func TestHTMLBounded(t *testing.T) {
	for _, raw := range []string{strings.Repeat("<div>", 150) + "hello", strings.Repeat("<p>x</p>", 10000), "<p>" + strings.Repeat("x", 70<<10) + "</p>"} {
		_, truncated := htmlText(strings.NewReader(raw))
		if !truncated {
			t.Fatal("HTML bound not enforced")
		}
	}
}
func TestPlainPreferredToHTML(t *testing.T) {
	raw := "Content-Type: multipart/alternative; boundary=x\r\n\r\n--x\r\nContent-Type: text/plain\r\n\r\nplain\r\n--x\r\nContent-Type: text/html\r\n\r\n<p>html</p>\r\n--x--\r\n"
	out := Message{Headers: map[string]string{}}
	parseMessage([]byte(raw), &out)
	if strings.TrimSpace(out.Text) != "plain" {
		t.Fatalf("wrong alternative %q", out.Text)
	}
}

// wrapMIMEPart covers both standalone attachment messages and multipart children.
func wrapMIMEPart(part string, nested bool) string {
	if !nested {
		return part
	}
	return "Content-Type: multipart/mixed; boundary=outer\r\n\r\n--outer\r\n" + part + "\r\n--outer--\r\n"
}

func TestAttachmentPreservesCharsetBytes(t *testing.T) {
	for _, fixture := range []struct {
		name, charset string
		data          []byte
	}{
		{"latin1", "iso-8859-1", []byte{'c', 'a', 'f', 0xe9}},
		{"utf16", "utf-16le", []byte{'h', 0, 'i', 0}},
		{"unknown_charset", "x-unknown", []byte{0xff, 0xfe, 0x00}},
	} {
		for _, nested := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/nested=%v", fixture.name, nested), func(t *testing.T) {
				raw := "Content-Type: text/plain; charset=" + fixture.charset + "\r\nContent-Disposition: attachment; filename=note.txt\r\nContent-Transfer-Encoding: base64\r\n\r\n" + base64.StdEncoding.EncodeToString(fixture.data)
				out := Message{Headers: map[string]string{}}
				got, err := parseMessageAttachment([]byte(wrapMIMEPart(raw, nested)), &out, 1)
				if err != nil || !bytes.Equal(got, fixture.data) {
					t.Fatalf("got %x, err %v; want original %x", got, err, fixture.data)
				}
				if len(out.Attachments) != 1 || out.Attachments[0].Size != int64(len(fixture.data)) || out.Text != "" || out.Truncated {
					t.Fatalf("unexpected metadata: %+v", out)
				}
			})
		}
	}
}

func TestAttachmentRejectsUndecodablePayload(t *testing.T) {
	for _, fixture := range []struct{ name, encoding, body string }{
		{"unknown", "x-unsupported", "ENCODED_CONTENT"},
		{"malformed_base64", "base64", "aGVsbG8=!!!!"},
		{"truncated_base64", "base64", "aGVsbG8"},
	} {
		for _, nested := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/nested=%v", fixture.name, nested), func(t *testing.T) {
				raw := "Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=file.bin\r\nContent-Transfer-Encoding: " + fixture.encoding + "\r\n\r\n" + fixture.body
				out := Message{Headers: map[string]string{}}
				got, err := parseMessageAttachment([]byte(wrapMIMEPart(raw, nested)), &out, 1)
				if !errors.Is(err, ErrInvalidInput) || len(got) != 0 {
					t.Fatalf("got %q, err %v; want no payload and ErrInvalidInput", got, err)
				}
				if !out.Truncated || len(out.Warnings) == 0 {
					t.Fatalf("missing incomplete-data warning: %+v", out)
				}
			})
		}
	}
}

func TestMultipartAttachmentIsOpaque(t *testing.T) {
	body := "--inner\r\nContent-Type: text/plain\r\n\r\nPRIVATE ATTACHMENT BODY\r\n--inner--\r\n"
	attached := "Content-Type: multipart/mixed; boundary=inner\r\nContent-Disposition: attachment; filename=private.mime\r\n\r\n" + body
	raw := "Content-Type: multipart/mixed; boundary=outer\r\n\r\n--outer\r\nContent-Type: text/plain\r\n\r\nPUBLIC BODY\r\n--outer\r\n" + attached + "\r\n--outer--\r\n"
	out := Message{Headers: map[string]string{}}
	got, err := parseMessageAttachment([]byte(raw), &out, 1)
	if err != nil || !bytes.Equal(got, []byte(body)) {
		t.Fatalf("got %q, err %v; want opaque multipart body", got, err)
	}
	if out.Text != "PUBLIC BODY" || len(out.Attachments) != 1 || out.Attachments[0].Filename != "private.mime" || out.Truncated {
		t.Fatalf("attachment entered inline text: %+v", out)
	}
}

func TestInlineCharsetDecodingAndRFC2231Filename(t *testing.T) {
	raw := "Content-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\nContent-Type: text/plain; charset=iso-8859-1\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\ncaf=E9\r\n--x\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename*0*=utf-8''caf%C3; filename*1*=%A9.txt\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\na=00=FF\r\n--x--\r\n"
	out := Message{Headers: map[string]string{}}
	got, err := parseMessageAttachment([]byte(raw), &out, 1)
	if err != nil || !bytes.Equal(got, []byte{'a', 0, 0xff}) || out.Text != "café" || len(out.Attachments) != 1 || out.Attachments[0].Filename != "café.txt" || out.Truncated {
		t.Fatalf("got %x err %v message %+v", got, err, out)
	}
}

func TestAttachmentDecodedLimitUsesOriginalBytes(t *testing.T) {
	for _, size := range []int{2 << 20, (2 << 20) + 1} {
		data := bytes.Repeat([]byte{0xe9}, size)
		raw := "Content-Type: text/plain; charset=iso-8859-1\r\nContent-Disposition: attachment; filename=large.txt\r\nContent-Transfer-Encoding: base64\r\n\r\n" + base64.StdEncoding.EncodeToString(data)
		out := Message{Headers: map[string]string{}}
		got, err := parseMessageAttachment([]byte(raw), &out, 1)
		if size == 2<<20 {
			if err != nil || !bytes.Equal(got, data) {
				t.Fatalf("within-limit attachment changed or rejected: bytes=%d err=%v", len(got), err)
			}
		} else if !errors.Is(err, ErrLimit) || len(got) != 0 {
			t.Fatalf("oversized attachment: bytes=%d err=%v", len(got), err)
		}
	}
}

func TestUnknownInlineEncodingIsIncomplete(t *testing.T) {
	for _, encoding := range []string{"Content-Transfer-Encoding: x-unsupported", "Content-Type: text/plain; charset=x-unknown"} {
		for _, nested := range []bool{false, true} {
			raw := wrapMIMEPart(encoding+"\r\n\r\nENCODED_CONTENT", nested)
			out := Message{Headers: map[string]string{}}
			parseMessage([]byte(raw), &out)
			if !out.Truncated || len(out.Warnings) == 0 || strings.Contains(out.Text, "ENCODED_CONTENT") {
				t.Fatalf("unsafe inline decoding: %+v", out)
			}
		}
	}
}

func TestMIMEHeaderBoundsDoNotClipBody(t *testing.T) {
	body := strings.Repeat("z", 100<<10)
	for _, size := range []int{maxMIMEHeaderBytes - 1, maxMIMEHeaderBytes, maxMIMEHeaderBytes + 1} {
		header := "X-Padding: " + strings.Repeat("x", size-len("X-Padding: \r\n\r\n")) + "\r\n\r\n"
		out := Message{Headers: map[string]string{}}
		parseMessage([]byte(header+body), &out)
		if size <= maxMIMEHeaderBytes {
			if out.Text != body || out.Truncated {
				t.Fatalf("header %d rejected or body clipped: body=%d truncated=%v", size, len(out.Text), out.Truncated)
			}
		} else if !out.Truncated || out.Text != "" {
			t.Fatalf("oversized header accepted: %+v", out)
		}
	}
}

func TestMIMELimitsAreNotMissingAttachments(t *testing.T) {
	tooMany := "Content-Type: multipart/mixed; boundary=x\r\n\r\n" + strings.Repeat("--x\r\nContent-Type: text/plain\r\n\r\nhi\r\n", 101) + "--x--\r\n"
	deep := "Content-Type: text/plain\r\n\r\nhi"
	for i := 0; i < 14; i++ {
		deep = fmt.Sprintf("Content-Type: multipart/mixed; boundary=b%d\r\n\r\n--b%d\r\n%s\r\n--b%d--\r\n", i, i, deep, i)
	}
	header := "X-Padding: " + strings.Repeat("x", maxMIMEHeaderBytes) + "\r\n\r\nhi"
	for name, raw := range map[string]string{"parts": tooMany, "depth": deep, "root_header": header, "part_header": wrapMIMEPart(header, true)} {
		t.Run(name, func(t *testing.T) {
			out := Message{Headers: map[string]string{}}
			got, err := parseMessageAttachment([]byte(raw), &out, 1)
			if !errors.Is(err, ErrLimit) || len(got) != 0 || !out.Truncated || len(out.Warnings) == 0 {
				t.Fatalf("limit presented as absent/success: bytes=%d err=%v truncated=%v warnings=%v", len(got), err, out.Truncated, out.Warnings)
			}
		})
	}
	out := Message{Headers: map[string]string{}}
	if _, err := parseMessageAttachment([]byte("Content-Type: text/plain\r\n\r\nhi"), &out, 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("genuinely missing attachment: %v", err)
	}
}

func TestAttachmentTransferEncodingsAndStableIndexes(t *testing.T) {
	for _, encoding := range []string{"", "7bit", "8bit", "binary", "base64", "quoted-printable"} {
		t.Run(encoding, func(t *testing.T) {
			want := []byte{'h', 'i', 0, 0xff}
			payload := string(want)
			switch encoding {
			case "base64":
				payload = "aGkA\r\n  /w=="
			case "quoted-printable":
				payload = "hi=00=FF"
			}
			raw := "Content-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=first.bin\r\nContent-Transfer-Encoding: x-unknown\r\n\r\nBAD\r\n--x\r\nContent-Type: application/octet-stream; name=second.bin\r\nContent-Transfer-Encoding: " + encoding + "\r\n\r\n" + payload + "\r\n--x--\r\n"
			out := Message{Headers: map[string]string{}}
			got, err := parseMessageAttachment([]byte(raw), &out, 2)
			if err != nil || !bytes.Equal(got, want) || len(out.Attachments) != 2 || out.Attachments[1].Filename != "second.bin" || !out.Truncated {
				t.Fatalf("bytes=%x err=%v attachments=%+v truncated=%v", got, err, out.Attachments, out.Truncated)
			}
		})
	}
}

func FuzzParseMessageAttachment(f *testing.F) {
	for _, raw := range []string{
		"Content-Type: text/plain\r\n\r\nhello",
		"Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=a.bin\r\nContent-Transfer-Encoding: base64\r\n\r\naGk=",
		wrapMIMEPart("Content-Type: text/plain; charset=iso-8859-1\r\nContent-Disposition: attachment; filename=a.txt\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\ncaf=E9", true),
		wrapMIMEPart("Content-Type: multipart/mixed; boundary=inner\r\nContent-Disposition: attachment; filename=private.mime\r\n\r\n--inner\r\n\r\nprivate\r\n--inner--\r\n", true),
		wrapMIMEPart("Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: x-unknown\r\n\r\nencoded", true),
	} {
		f.Add([]byte(raw), uint8(1))
	}
	f.Fuzz(func(t *testing.T, raw []byte, index uint8) {
		if len(raw) > maxMessageBytes {
			t.Skip()
		}
		target := int(index % 101)
		out := Message{Headers: map[string]string{}}
		payload, err := parseMessageAttachment(raw, &out, target)
		if len(out.Text) > maxTextBytes || len(out.Attachments) > 100 || len(payload) > 2<<20 {
			t.Fatal("MIME result exceeds limits")
		}
		if err != nil && len(payload) > 0 {
			t.Fatal("attachment payload returned with an error")
		}
		if err == nil && target > 0 {
			if len(out.Attachments) < target || int64(len(payload)) != out.Attachments[target-1].Size {
				t.Fatal("successful download does not match attachment inventory")
			}
		}
		for i, a := range out.Attachments {
			if a.Index != i+1 {
				t.Fatal("unstable attachment indexes")
			}
		}
	})
}

func TestDiscardedChildHeadersRespectRawLimit(t *testing.T) {
	for _, newline := range []string{"\r\n", "\n"} {
		for _, size := range []int{maxMIMEHeaderBytes - 1, maxMIMEHeaderBytes, maxMIMEHeaderBytes + 1} {
			prefix := "Content-Type: application/octet-stream" + newline
			discarded := ": discarded" + newline
			n := (size - len(prefix) - len(newline) - len("X-Padding: "+newline)) / len(discarded)
			header := prefix + strings.Repeat(discarded, n) + "X-Padding: "
			header += strings.Repeat("x", size-len(header)-2*len(newline)) + newline + newline
			raw := "Content-Type: multipart/mixed; boundary=outer" + newline + newline + "--outer" + newline + header + "PAYLOAD" + newline + "--outer--" + newline
			out := Message{}
			got, err := parseMessageAttachment([]byte(raw), &out, 1)
			if size <= maxMIMEHeaderBytes {
				if err != nil || string(got) != "PAYLOAD" || out.Truncated {
					t.Fatalf("raw child header %d newline=%q rejected: payload=%q err=%v truncated=%v", size, newline, got, err, out.Truncated)
				}
			} else if !errors.Is(err, ErrLimit) || len(got) != 0 || !out.Truncated {
				t.Fatalf("oversized discarded child headers succeeded: payload=%q err=%v truncated=%v", got, err, out.Truncated)
			}
		}
	}
}

func TestInlineMultipartRejectsNonidentityEncoding(t *testing.T) {
	decoded := "--outer\r\nContent-Type: application/octet-stream\r\n\r\nPAYLOAD\r\n--outer--\r\n"
	for _, encoding := range []string{"base64", "quoted-printable", "x-unknown"} {
		body := decoded
		if encoding == "base64" {
			body = base64.StdEncoding.EncodeToString([]byte(decoded)) + "!!!!"
		}
		raw := "Content-Type: multipart/mixed; boundary=outer\r\nContent-Transfer-Encoding: " + encoding + "\r\n\r\n" + body
		out := Message{}
		got, err := parseMessageAttachment([]byte(raw), &out, 1)
		if !errors.Is(err, ErrInvalidInput) || len(got) != 0 || !out.Truncated {
			t.Fatalf("inline multipart %s succeeded: payload=%q err=%v truncated=%v", encoding, got, err, out.Truncated)
		}
	}
}

func TestMIMEHeaderGuardPreservesFraming(t *testing.T) {
	for _, newline := range []string{"\r\n", "\n"} {
		// Long body lines and boundary lookalikes must not start header accounting.
		body := strings.Repeat("x", 5000) + "--outer" + newline + "--outer-extra" + newline + strings.Repeat(": body data"+newline, 7000)
		raw := "preamble" + newline + "--outer \t" + newline + "Content-Type: text/plain" + newline + "X-Folded: first" + newline + " second" + newline + newline + body + newline + "--outer" + newline + newline + "second part" + newline + "--outer-- \t" + newline + strings.Repeat(": epilogue"+newline, 7000)
		for _, split := range []bool{false, true} {
			var reader io.Reader = strings.NewReader(raw)
			if split {
				reader = iotest.OneByteReader(reader)
			}
			guarded := guardMIMEHeaders(reader, "outer")
			got, err := io.ReadAll(guarded)
			if err != nil || string(got) != raw || guarded.limitExceeded {
				t.Fatalf("guard altered MIME bytes: newline=%q split=%v len=%d err=%v", newline, split, len(got), err)
			}
		}
	}
	raw := "--outer\r\n" + strings.Repeat(": ignored\r\n", 7000) + "\r\nbody\r\n--outer--\r\n"
	guarded := guardMIMEHeaders(iotest.OneByteReader(strings.NewReader(raw)), "outer")
	got, err := io.ReadAll(guarded)
	if !errors.Is(err, ErrLimit) || !guarded.limitExceeded || len(got) > len("--outer\r\n")+maxMIMEHeaderBytes {
		t.Fatalf("raw budget leaked bytes: len=%d err=%v", len(got), err)
	}
}

func TestBinaryBareLFBoundaryLookalike(t *testing.T) {
	for _, offset := range []int{6, 4094, 4095, 4096, 4097, 8191} {
		payload := strings.Repeat("x", offset) + "\n--outer\r\n" + strings.Repeat("not-a-header\r\n", 6000)
		raw := "Content-Type: multipart/mixed; boundary=outer\r\n\r\n--outer\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: binary\r\n\r\n" + payload + "\r\n--outer--\r\n"
		out := Message{}
		got, err := parseMessageAttachment([]byte(raw), &out, 1)
		if err != nil || string(got) != payload || out.Truncated {
			t.Fatalf("offset=%d bytes=%d want=%d err=%v truncated=%v", offset, len(got), len(payload), err, out.Truncated)
		}
	}
}

func TestBareLFFinalBoundaryDoesNotDisableHeaderLimit(t *testing.T) {
	raw := "Content-Type: multipart/mixed; boundary=outer\r\n\r\n--outer\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: binary\r\n\r\nPREFIX\n--outer--\r\nrest\r\n--outer\r\n" + strings.Repeat(": discarded\r\n", 6000) + "Content-Type: application/octet-stream\r\n\r\nPAYLOAD\r\n--outer--\r\n"
	out := Message{}
	got, err := parseMessageAttachment([]byte(raw), &out, 2)
	if !errors.Is(err, ErrLimit) || len(got) != 0 || !out.Truncated {
		t.Fatalf("false close bypassed header limit: payload=%q err=%v truncated=%v", got, err, out.Truncated)
	}
}

func TestMIMEHeaderGuardBoundaryNewlineAndBodyStart(t *testing.T) {
	for _, newline := range []string{"\r\n", "\n"} {
		for _, headerNewline := range []string{"\r\n", "\n"} {
			for _, offset := range []int{0, 1, 4094, 4095, 4096, 4097, 8191} {
				body := ""
				if offset > 0 {
					body = strings.Repeat("x", offset) + newline
				}
				// At offset zero the next boundary begins at part-body byte zero. At
				// other offsets, its preceding CRLF may span ReadSlice buffer chunks.
				raw := "--outer" + newline + "Content-Type: application/octet-stream" + headerNewline + headerNewline + body + "--outer" + newline + strings.Repeat(": discarded"+newline, 7000) + newline + "PAYLOAD" + newline + "--outer--" + newline
				for _, split := range []bool{false, true} {
					var reader io.Reader = strings.NewReader(raw)
					if split {
						reader = iotest.OneByteReader(reader)
					}
					guarded := guardMIMEHeaders(reader, "outer")
					_, err := io.ReadAll(guarded)
					if !errors.Is(err, ErrLimit) || !guarded.limitExceeded {
						t.Fatalf("boundary missed: newline=%q header=%q offset=%d split=%v err=%v", newline, headerNewline, offset, split, err)
					}
				}
			}
		}
	}
}

func FuzzBinaryAttachmentRoundTrip(f *testing.F) {
	for _, payload := range [][]byte{
		[]byte("hello"),
		[]byte("PREFIX\n--outer\r\n" + strings.Repeat("not-a-header\r\n", 6000)),
		[]byte("PREFIX\n--outer--\r\nrest"),
		[]byte(strings.Repeat("x", 4095) + "\r\ncontinuation"),
	} {
		f.Add(payload)
	}
	f.Fuzz(func(t *testing.T, payload []byte) {
		if len(payload) > 2<<20 || bytes.HasPrefix(payload, []byte("--outer")) || bytes.Contains(payload, []byte("\r\n--outer")) {
			t.Skip()
		}
		raw := append([]byte("Content-Type: multipart/mixed; boundary=outer\r\n\r\n--outer\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: binary\r\n\r\n"), payload...)
		raw = append(raw, []byte("\r\n--outer--\r\n")...)
		out := Message{}
		got, err := parseMessageAttachment(raw, &out, 1)
		if err != nil || !bytes.Equal(got, payload) || out.Truncated {
			t.Fatalf("binary roundtrip: got=%d want=%d err=%v truncated=%v", len(got), len(payload), err, out.Truncated)
		}
	})
}

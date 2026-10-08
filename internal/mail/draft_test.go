package mail

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestDraftChangedErrorRetainsConflictIdentity(t *testing.T) {
	const want = "draft source changed; read the draft again before revising or preparing"
	if ErrDraftChanged.Error() != want {
		t.Fatalf("draft guidance = %q, want %q", ErrDraftChanged.Error(), want)
	}
	wrapped := fmt.Errorf("wrapped: %w", ErrDraftChanged)
	if !errors.Is(wrapped, ErrDraftChanged) || !errors.Is(wrapped, ErrConflict) {
		t.Fatal("draft conflict identity was lost")
	}
}

func draftFixture(raw, flags, extra string, trace *imapTrace) func(net.Conn) {
	return func(c net.Conn) {
		fmt.Fprint(c, "* OK [CAPABILITY IMAP4rev1] draft fixture\r\n")
		r := bufio.NewReader(c)
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimSpace(line)
			trace.add(line)
			fields := strings.SplitN(line, " ", 2)
			if len(fields) != 2 {
				return
			}
			tag, cmd := fields[0], strings.ToUpper(fields[1])
			switch {
			case strings.HasPrefix(cmd, "LOGIN "):
				fmt.Fprintf(c, "%s OK [CAPABILITY IMAP4rev1] login\r\n", tag)
			case cmd == "CAPABILITY":
				fmt.Fprintf(c, "* CAPABILITY IMAP4rev1\r\n%s OK capabilities\r\n", tag)
			case strings.HasPrefix(cmd, "EXAMINE "):
				fmt.Fprintf(c, "* FLAGS (\\Draft \\Seen \\Deleted)\r\n* 1 EXISTS\r\n* OK [UIDVALIDITY 7] validity\r\n* OK [UIDNEXT 2501] next\r\n%s OK [READ-ONLY] examined\r\n", tag)
			case strings.HasPrefix(cmd, "UID FETCH "):
				sizeField := fmt.Sprintf("RFC822.SIZE %d", len(raw))
				flagsField := "FLAGS (" + flags + ")"
				more := extra
				switch extra {
				case "$omit_size":
					sizeField, more = "", ""
				case "$omit_flags":
					flagsField, more = "", ""
				case "$size_larger":
					sizeField, more = fmt.Sprintf("RFC822.SIZE %d", len(raw)+1), ""
				case "$size_smaller":
					sizeField, more = fmt.Sprintf("RFC822.SIZE %d", len(raw)-1), ""
				case "$duplicate_body":
					more = fmt.Sprintf("BODY[]<0> {%d}\r\n%s", len(raw), raw)
				}
				metadata := []string{"UID 2500"}
				for _, field := range []string{flagsField, sizeField, more} {
					if field != "" {
						metadata = append(metadata, field)
					}
				}
				fmt.Fprintf(c, "* 1 FETCH (%s BODY[]<0> {%d}\r\n%s)\r\n%s OK fetched\r\n", strings.Join(metadata, " "), len(raw), raw, tag)
			default:
				fmt.Fprintf(c, "%s BAD unexpected command\r\n", tag)
			}
		}
	}
}

func TestReadDraftRawPeekDigestAndCompleteAlternatives(t *testing.T) {
	raw := "From: owner@example.com\r\nTo: to@example.com\r\nCc: cc@example.com\r\nBcc: hidden@example.com\r\nSubject: Draft\r\nContent-Type: multipart/alternative; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" + strings.Repeat("x", 300000) + "\r\n--b\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>exact HTML</p>\r\n--b--\r\n"
	bodyStart := strings.Index(raw, "Content-Type: multipart/alternative")
	raw = raw[:bodyStart] + "Content-Type: multipart/mixed; boundary=m\r\n\r\n--m\r\n" + raw[bodyStart:] + "\r\n--m\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=exact.bin\r\nContent-Transfer-Encoding: base64\r\n\r\nAP+A\r\n--m--\r\n"
	trace := &imapTrace{}
	backend := backendForTest(t, draftFixture(raw, `\dRaFt`, "", trace), true)
	backend.config.Timeout = 10 * time.Second // Large TLS literals under race/load, not a production limit change.
	ref := Reference{Folder: "Drafts", UIDValidity: 7, UID: 2500}
	d, err := backend.ReadDraft(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(raw))
	if d.Reference != ref || d.SourceDigest != hex.EncodeToString(sum[:]) || len(d.Message.Text) != 300000 || d.Message.HTML != "<p>exact HTML</p>" || len(d.Message.Bcc) != 1 || !strings.Contains(d.Message.Bcc[0], "hidden@example.com") {
		t.Fatalf("incomplete draft: %d %+v", len(d.Message.Text), d.Reference)
	}
	if len(d.Message.Attachments) != 1 || d.Message.Attachments[0].DataBase64 != "AP+A" {
		t.Fatal("binary attachment bytes changed")
	}
	commands := trace.String()
	if !strings.Contains(commands, "EXAMINE ") || !strings.Contains(commands, "BODY.PEEK[]<0.5242881>") || strings.Contains(commands, "SELECT ") || strings.Contains(commands, "STORE ") {
		t.Fatalf("mutating/unbounded read: %s", commands)
	}
}

func TestReadDraftRejectsMissingFlagsUnsafeMIMEAndStaleRefs(t *testing.T) {
	raw := "From: owner@example.com\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nbody"
	for _, tc := range []struct {
		name, flags, raw, extra string
		validity                uint32
		want                    error
	}{
		{"no Draft", `\Seen`, raw, "", 7, ErrInvalidInput},
		{"deleted draft", `\Draft \Deleted`, raw, "", 7, ErrInvalidInput},
		{"stale", `\Draft`, raw, "", 8, ErrStaleReference},
		{"duplicate UID", `\Draft`, raw, "UID 2500", 7, ErrUnavailable},
		{"duplicate flags", `\Draft`, raw, `FLAGS (\Seen)`, 7, ErrUnavailable},
		{"duplicate size", `\Draft`, raw, "RFC822.SIZE 1", 7, ErrUnavailable},
		{"missing size", `\Draft`, raw, "$omit_size", 7, ErrUnavailable},
		{"missing flags", `\Draft`, raw, "$omit_flags", 7, ErrUnavailable},
		{"size larger", `\Draft`, raw, "$size_larger", 7, ErrLimit},
		{"size smaller", `\Draft`, raw, "$size_smaller", 7, ErrLimit},
		{"duplicate body", `\Draft`, raw, "$duplicate_body", 7, ErrUnavailable},
		{"duplicate MIME header", `\Draft`, "Bcc: first@example.com\r\nBcc: second@example.com\r\n" + raw, "", 7, ErrUnsupported},
		{"unknown routing header", `\Draft`, "Reply-To: alternate@example.com\r\n" + raw, "", 7, ErrUnsupported},
		{"oversized raw", `\Draft`, raw + strings.Repeat("x", maxMessageBytes), "", 7, ErrLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			trace := &imapTrace{}
			backend := backendForTest(t, draftFixture(tc.raw, tc.flags, tc.extra, trace), true)
			backend.config.Timeout = 10 * time.Second // Oversized-literal test must reach the byte limit under -race.
			d, err := backend.ReadDraft(context.Background(), Reference{Folder: "Drafts", UIDValidity: tc.validity, UID: 2500})
			if !errors.Is(err, tc.want) || d.SourceDigest != "" {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			if tc.name == "stale" && strings.Contains(trace.String(), "FETCH") {
				t.Fatal("stale ref reached fetch")
			}
		})
	}
}

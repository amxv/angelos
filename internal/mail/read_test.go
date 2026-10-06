package mail

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
)

type imapTrace struct {
	mu    sync.Mutex
	lines []string
}

func (r *imapTrace) add(s string) { r.mu.Lock(); defer r.mu.Unlock(); r.lines = append(r.lines, s) }
func (r *imapTrace) String() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return strings.Join(r.lines, "\n")
}
func imapFixture(raw string, search string, trace *imapTrace) func(net.Conn) {
	return func(c net.Conn) {
		fmt.Fprint(c, "* OK [CAPABILITY IMAP4rev1 SPECIAL-USE] test server\r\n")
		r := bufio.NewReader(c)
		for {
			line, e := r.ReadString('\n')
			if e != nil {
				return
			}
			line = strings.TrimSpace(line)
			trace.add(line)
			parts := strings.SplitN(line, " ", 2)
			if len(parts) != 2 {
				return
			}
			tag, cmd := parts[0], strings.ToUpper(parts[1])
			switch {
			case strings.HasPrefix(cmd, "LOGIN "):
				fmt.Fprintf(c, "%s OK [CAPABILITY IMAP4rev1 SPECIAL-USE] login\r\n", tag)
			case cmd == "CAPABILITY":
				fmt.Fprintf(c, "* CAPABILITY IMAP4rev1 SPECIAL-USE\r\n%s OK capabilities\r\n", tag)
			case strings.HasPrefix(cmd, "LIST "):
				fmt.Fprintf(c, "* LIST (\\HasNoChildren) \"/\" \"INBOX\"\r\n* LIST (\\Sent) \"/\" \"Sent Mail\"\r\n%s OK listed\r\n", tag)
			case strings.HasPrefix(cmd, "EXAMINE "):
				fmt.Fprintf(c, "* FLAGS (\\Seen \\Flagged)\r\n* 2 EXISTS\r\n* OK [UIDVALIDITY 7] validity\r\n* OK [UIDNEXT 2501] next\r\n%s OK [READ-ONLY] examined\r\n", tag)
			case strings.HasPrefix(cmd, "UID SEARCH "):
				fmt.Fprintf(c, "* SEARCH%s\r\n%s OK searched\r\n", search, tag)
			case strings.HasPrefix(cmd, "UID FETCH "):
				if strings.Contains(cmd, "BODY.PEEK") {
					fmt.Fprintf(c, "* 2 FETCH (UID 2500 FLAGS () RFC822.SIZE %d BODY[]<0> {%d}\r\n%s)\r\n%s OK fetched\r\n", len(raw), len(raw), raw, tag)
				} else {
					fmt.Fprintf(c, "* 1 FETCH (UID 2499 FLAGS (\\Seen) RFC822.SIZE 100)\r\n* 2 FETCH (UID 2500 FLAGS () RFC822.SIZE 100)\r\n%s OK fetched\r\n", tag)
				}
			default:
				fmt.Fprintf(c, "%s BAD unexpected test command\r\n", tag)
			}
		}
	}
}
func TestListFoldersSpecialUse(t *testing.T) {
	trace := &imapTrace{}
	b := backendForTest(t, imapFixture("", "", trace), true)
	folders, e := b.ListFolders(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if len(folders) != 2 || folders[1].Name != "Sent Mail" || folders[1].Attributes[0] != `\Sent` {
		t.Fatalf("folders %+v", folders)
	}
	if !strings.Contains(trace.String(), "SPECIAL-USE") {
		t.Fatal("SPECIAL-USE not requested")
	}
}
func TestSearchBoundedUIDWindow(t *testing.T) {
	trace := &imapTrace{}
	b := backendForTest(t, imapFixture("", " 2499 2500", trace), true)
	out, e := b.Search(context.Background(), SearchRequest{Folder: "INBOX", Query: "hello", Limit: 2})
	if e != nil {
		t.Fatal(e)
	}
	if len(out.Messages) != 2 || out.Messages[0].Reference.UID != 2500 || out.ScannedUIDs != 1000 || out.NextCursor == "" {
		t.Fatalf("bad search %+v", out)
	}
	if !strings.Contains(trace.String(), "UID 1501:2500") {
		t.Fatalf("unbounded search: %s", trace.String())
	}
	if strings.Contains(trace.String(), "SELECT ") {
		t.Fatal("read search selected writable mailbox")
	}
}
func TestSparseSearchCursorAdvances(t *testing.T) {
	trace := &imapTrace{}
	b := backendForTest(t, imapFixture("", "", trace), true)
	out, e := b.Search(context.Background(), SearchRequest{Folder: "INBOX"})
	if e != nil {
		t.Fatal(e)
	}
	if len(out.Messages) != 0 || out.NextCursor == "" {
		t.Fatal("sparse page incorrectly complete")
	}
	out, e = b.Search(context.Background(), SearchRequest{Folder: "INBOX", Cursor: out.NextCursor})
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(trace.String(), "UID 501:1500") {
		t.Fatalf("cursor did not advance: %s", trace.String())
	}
	out, e = b.Search(context.Background(), SearchRequest{Folder: "INBOX", Cursor: out.NextCursor})
	if e != nil {
		t.Fatal(e)
	}
	if out.NextCursor != "" {
		t.Fatal("last page has cursor")
	}
}
func TestReadUsesPeekAndUIDValidity(t *testing.T) {
	trace := &imapTrace{}
	raw := "From: sender@example.net\r\nSubject: Test\r\nContent-Type: text/plain\r\n\r\nhello"
	b := backendForTest(t, imapFixture(raw, "", trace), true)
	out, e := b.Read(context.Background(), Reference{Folder: "INBOX", UIDValidity: 7, UID: 2500})
	if e != nil {
		t.Fatal(e)
	}
	if out.Text != "hello" || out.Headers["Subject"] != "Test" {
		t.Fatalf("bad read %+v", out)
	}
	if !strings.Contains(trace.String(), "BODY.PEEK[]<0.5242881>") || !strings.Contains(trace.String(), "EXAMINE ") {
		t.Fatalf("unsafe read %s", trace.String())
	}
	trace = &imapTrace{}
	b = backendForTest(t, imapFixture(raw, "", trace), true)
	if _, e := b.Read(context.Background(), Reference{Folder: "INBOX", UIDValidity: 8, UID: 2500}); e != ErrStaleReference {
		t.Fatalf("stale reference error %v", e)
	}
	if strings.Contains(trace.String(), "FETCH") {
		t.Fatal("fetched stale UID")
	}
}
func TestSearchStructuredFilters(t *testing.T) {
	trace := &imapTrace{}
	b := backendForTest(t, imapFixture("", "", trace), true)
	unread := true
	_, e := b.Search(context.Background(), SearchRequest{From: "sender@example.net", To: "person@example.com", Subject: "invoice", Since: "2026-01-01", Before: "2026-02-01", Unread: &unread})
	if e != nil {
		t.Fatal(e)
	}
	for _, want := range []string{"FROM", "TO", "SUBJECT", "SINCE", "BEFORE", "SEEN"} {
		if !strings.Contains(strings.ToUpper(trace.String()), want) {
			t.Errorf("missing %s", want)
		}
	}
}
func TestAttachmentDecode(t *testing.T) {
	raw := "Content-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\nContent-Type: text/plain\r\n\r\nhello\r\n--x\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=file.txt\r\nContent-Transfer-Encoding: base64\r\n\r\naGVsbG8=\r\n--x--\r\n"
	b := backendForTest(t, imapFixture(raw, "", &imapTrace{}), true)
	out, e := b.GetAttachment(context.Background(), Reference{Folder: "INBOX", UIDValidity: 7, UID: 2500}, 1)
	if e != nil {
		t.Fatal(e)
	}
	if out.DataBase64 != "aGVsbG8=" || out.Attachment.Index != 1 || out.Attachment.Size != 5 {
		t.Fatalf("attachment %+v", out)
	}
}
func TestOldestUIDPagination(t *testing.T) {
	trace := &imapTrace{}
	b := backendForTest(t, imapFixture("", "", trace), true)
	out, e := b.Search(context.Background(), SearchRequest{Order: "oldest"})
	if e != nil {
		t.Fatal(e)
	}
	if out.NextCursor == "" || out.Order != "oldest" || !strings.Contains(trace.String(), "UID 1:1000") {
		t.Fatalf("bad oldest page %+v trace %s", out, trace.String())
	}
	out, e = b.Search(context.Background(), SearchRequest{Order: "oldest", Cursor: out.NextCursor})
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(trace.String(), "UID 1001:2000") {
		t.Fatal("oldest cursor did not advance")
	}
	out, e = b.Search(context.Background(), SearchRequest{Order: "oldest", Cursor: out.NextCursor})
	if e != nil {
		t.Fatal(e)
	}
	if out.NextCursor != "" {
		t.Fatal("oldest pagination did not stop")
	}
}

func TestAttachmentByteIntegrityPublicBoundary(t *testing.T) {
	for _, fixture := range []struct {
		name, part string
		want       []byte
		wantErr    error
	}{
		{"charset", "Content-Type: text/plain; charset=iso-8859-1\r\nContent-Disposition: attachment; filename=cafe.txt\r\nContent-Transfer-Encoding: base64\r\n\r\nY2Fm6Q==", []byte{'c', 'a', 'f', 0xe9}, nil},
		{"unknown_transfer_encoding", "Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=file.bin\r\nContent-Transfer-Encoding: x-unsupported\r\n\r\nENCODED_CONTENT", nil, ErrInvalidInput},
		{"malformed_base64", "Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=file.bin\r\nContent-Transfer-Encoding: base64\r\n\r\naGVsbG8=!!!!", nil, ErrInvalidInput},
	} {
		for _, nested := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/nested=%v", fixture.name, nested), func(t *testing.T) {
				raw := wrapMIMEPart(fixture.part, nested)
				b := backendForTest(t, imapFixture(raw, "", &imapTrace{}), true)
				ref := Reference{Folder: "INBOX", UIDValidity: 7, UID: 2500}
				msg, err := b.Read(context.Background(), ref)
				if err != nil {
					t.Fatal(err)
				}
				out, err := b.GetAttachment(context.Background(), ref, 1)
				if !errors.Is(err, fixture.wantErr) {
					t.Fatalf("attachment error %v; want %v", err, fixture.wantErr)
				}
				if fixture.wantErr != nil {
					if out.DataBase64 != "" || !msg.Truncated {
						t.Fatalf("incorrect success or missing warning: result=%+v read=%+v", out, msg)
					}
					return
				}
				if out.DataBase64 != base64.StdEncoding.EncodeToString(fixture.want) || out.Attachment.Size != int64(len(fixture.want)) || len(msg.Attachments) != 1 || msg.Attachments[0].Size != out.Attachment.Size {
					t.Fatalf("incorrect bytes or inventory: result=%+v read=%+v", out, msg)
				}
			})
		}
	}
}

func TestMultipartAttachmentPublicBoundary(t *testing.T) {
	body := "--inner\r\nContent-Type: text/plain\r\n\r\nPRIVATE ATTACHMENT BODY\r\n--inner--\r\n"
	raw := wrapMIMEPart("Content-Type: multipart/mixed; boundary=inner\r\nContent-Disposition: attachment; filename=private.mime\r\n\r\n"+body, true)
	b := backendForTest(t, imapFixture(raw, "", &imapTrace{}), true)
	ref := Reference{Folder: "INBOX", UIDValidity: 7, UID: 2500}
	msg, err := b.Read(context.Background(), ref)
	if err != nil || msg.Text != "" || len(msg.Attachments) != 1 || msg.Truncated {
		t.Fatalf("multipart attachment privacy/inventory: text=%q attachments=%+v truncated=%v err=%v", msg.Text, msg.Attachments, msg.Truncated, err)
	}
	out, err := b.GetAttachment(context.Background(), ref, 1)
	if err != nil || out.DataBase64 != base64.StdEncoding.EncodeToString([]byte(body)) || out.Attachment.Size != int64(len(body)) {
		t.Fatalf("opaque multipart download: result=%+v err=%v", out, err)
	}
}

func TestInvalidMultipartPublicBoundary(t *testing.T) {
	decoded := "--outer\r\nContent-Type: application/octet-stream\r\n\r\nPAYLOAD\r\n--outer--\r\n"
	for _, fixture := range []struct {
		name, raw string
		wantErr   error
	}{
		{"discarded_headers", "Content-Type: multipart/mixed; boundary=outer\r\n\r\n--outer\r\n" + strings.Repeat(": discarded\r\n", 6000) + "Content-Type: application/octet-stream\r\n\r\nPAYLOAD\r\n--outer--\r\n", ErrLimit},
		{"encoded_container", "Content-Type: multipart/mixed; boundary=outer\r\nContent-Transfer-Encoding: base64\r\n\r\n" + base64.StdEncoding.EncodeToString([]byte(decoded)) + "!!!!", ErrInvalidInput},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			b := backendForTest(t, imapFixture(fixture.raw, "", &imapTrace{}), true)
			ref := Reference{Folder: "INBOX", UIDValidity: 7, UID: 2500}
			msg, err := b.Read(context.Background(), ref)
			if err != nil || !msg.Truncated {
				t.Fatalf("missing incomplete warning: truncated=%v err=%v", msg.Truncated, err)
			}
			out, err := b.GetAttachment(context.Background(), ref, 1)
			if !errors.Is(err, fixture.wantErr) || out.DataBase64 != "" {
				t.Fatalf("invalid multipart returned payload: result=%+v err=%v", out, err)
			}
		})
	}
}

func TestBinaryBoundaryLookalikePublicBoundary(t *testing.T) {
	payload := "PREFIX\n--outer\r\n" + strings.Repeat("not-a-header\r\n", 6000)
	raw := "Content-Type: multipart/mixed; boundary=outer\r\n\r\n--outer\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: binary\r\n\r\n" + payload + "\r\n--outer--\r\n"
	b := backendForTest(t, imapFixture(raw, "", &imapTrace{}), true)
	ref := Reference{Folder: "INBOX", UIDValidity: 7, UID: 2500}
	msg, err := b.Read(context.Background(), ref)
	if err != nil || msg.Truncated || len(msg.Attachments) != 1 || msg.Attachments[0].Size != int64(len(payload)) {
		t.Fatalf("valid binary attachment rejected: count=%d truncated=%v err=%v", len(msg.Attachments), msg.Truncated, err)
	}
	out, err := b.GetAttachment(context.Background(), ref, 1)
	if err != nil || out.DataBase64 != base64.StdEncoding.EncodeToString([]byte(payload)) {
		t.Fatalf("binary attachment bytes changed: size=%d err=%v", out.Attachment.Size, err)
	}
}

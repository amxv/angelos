package mail

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-imap/v2/imapserver/imapmemserver"
)

// Run a real IMAP parser/search engine over the test backend's TLS connection.
// No TCP listener or external mailbox is involved.
type searchOneConnListener struct {
	conn net.Conn
	done chan struct{}
	once sync.Once
	sent bool
}

func (l *searchOneConnListener) Accept() (net.Conn, error) {
	if !l.sent {
		l.sent = true
		return &searchCloseNotifyConn{Conn: l.conn, listener: l}, nil
	}
	<-l.done
	return nil, net.ErrClosed
}
func (l *searchOneConnListener) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *searchOneConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

type searchCloseNotifyConn struct {
	net.Conn
	listener *searchOneConnListener
}

func (c *searchCloseNotifyConn) Close() error {
	err := c.Conn.Close()
	c.listener.Close()
	return err
}

type searchStringLiteral struct{ *strings.Reader }

func TestParticipantSearchRealTLSIMAP(t *testing.T) {
	mem := imapmemserver.New()
	user := imapmemserver.NewUser("person@example.com", "test-only")
	mem.AddUser(user)
	if err := user.Create("INBOX", nil); err != nil {
		t.Fatal(err)
	}
	date := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	for _, tt := range []struct {
		field, value, subject string
		flags                 []imap.Flag
		date                  time.Time
	}{
		{"From", `"PERSON@EXAMPLE contact" <sender@example>`, "invoice", []imap.Flag{imap.FlagFlagged}, date},
		{"Reply-To", "Person@Example", "invoice", []imap.Flag{imap.FlagFlagged}, date},
		{"To", `"PERSON@EXAMPLE contact" <recipient@example>`, "invoice", []imap.Flag{imap.FlagFlagged}, date},
		{"Cc", "Person@Example", "invoice", []imap.Flag{imap.FlagFlagged}, date},
		{"Cc", "prefixPerson@Example.suffix", "invoice", []imap.Flag{imap.FlagFlagged}, date},
		{"Bcc", "Person@Example", "invoice", []imap.Flag{imap.FlagFlagged}, date},
		{"Cc", "Person@Example", "wrong-subject", []imap.Flag{imap.FlagFlagged}, date},
		{"Cc", "Person@Example", "invoice", []imap.Flag{imap.FlagFlagged, imap.FlagSeen}, date},
		{"Cc", "Person@Example", "invoice", nil, date},
		{"Cc", "Person@Example", "invoice", []imap.Flag{imap.FlagFlagged}, date.AddDate(-1, 0, 0)},
		{"X-Unrelated", "Person@Example", "invoice", []imap.Flag{imap.FlagFlagged}, date},
	} {
		from, to, extra := "sender@example", "recipient@example", ""
		if tt.field == "From" {
			from = tt.value
		} else if tt.field == "To" {
			to = tt.value
		} else {
			extra = tt.field + ": " + tt.value + "\r\n"
		}
		raw := fmt.Sprintf("From: %s\r\nTo: %s\r\n%sSubject: %s\r\nMessage-ID: <%s>\r\n\r\nbody-marker Person@Example", from, to, extra, tt.subject, exactTestID)
		if _, err := user.Append("INBOX", searchStringLiteral{strings.NewReader(raw)}, &imap.AppendOptions{Time: tt.date, Flags: tt.flags}); err != nil {
			t.Fatal(err)
		}
	}
	b := backendForTest(t, func(c net.Conn) {
		listener := &searchOneConnListener{conn: c, done: make(chan struct{})}
		srv := imapserver.New(&imapserver.Options{
			// TLS is already active underneath our close-notification wrapper.
			InsecureAuth: true,
			NewSession: func(*imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
				return mem.NewSession(), nil, nil
			},
		})
		defer srv.Close()
		srv.Serve(listener)
	}, true)
	unread, flagged := true, true
	for _, order := range []string{"newest", "oldest"} {
		// Including an exact-ID request exercises a standards-compliant server's
		// selected-header serialization as well as AND/OR search evaluation.
		out, err := b.Search(context.Background(), SearchRequest{MessageID: exactTestID, Participant: "person@example", From: "sender@example", To: "recipient@example", Subject: "invoice", Query: "body-marker", Since: "2026-01-01", Before: "2026-02-01", Unread: &unread, Flagged: &flagged, Order: order})
		if err != nil {
			t.Fatal(err)
		}
		var uids []uint32
		for _, m := range out.Messages {
			uids = append(uids, m.Reference.UID)
			for _, flag := range m.Flags {
				if flag == string(imap.FlagSeen) {
					t.Fatal("read-only search marked a match Seen")
				}
			}
		}
		want := "[5 4 3 2 1]"
		if order == "oldest" {
			want = "[1 2 3 4 5]"
		}
		if fmt.Sprint(uids) != want || out.NextCursor != "" {
			t.Fatalf("participant header OR/other AND filters: got %v want %s, cursor=%q", uids, want, out.NextCursor)
		}
	}
}

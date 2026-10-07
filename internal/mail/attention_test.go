package mail

import (
	"context"
	"fmt"
	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-imap/v2/imapserver/imapmemserver"
	"net"
	"reflect"
	"strings"
	"testing"
)

type attentionTraceConn struct {
	net.Conn
	trace *imapTrace
}

func (c *attentionTraceConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.trace.add(string(p[:n]))
	return n, err
}

// BackendForTriageTesting is a synthetic local TLS fixture only, not a production bypass.
func BackendForTriageTesting(t *testing.T) (*Backend, func() string) {
	t.Helper()
	mem := imapmemserver.New()
	user := imapmemserver.NewUser("person@example.com", "test-only")
	mem.AddUser(user)
	if err := user.Create("INBOX", nil); err != nil {
		t.Fatal(err)
	}
	for i, flags := range [][]imap.Flag{nil, {imap.FlagSeen, imap.FlagFlagged}, {imap.FlagFlagged}, {imap.FlagSeen}, nil} {
		subject := "Due"
		if i == 4 {
			subject = "Other"
		}
		raw := fmt.Sprintf("From: sender@example.com\r\nTo: owner@example.com\r\nBcc: private@example.com\r\nSubject: %s\r\nMessage-ID: <id%d@example.com>\r\n\r\nprivate body", subject, i)
		if _, err := user.Append("INBOX", searchStringLiteral{strings.NewReader(raw)}, &imap.AppendOptions{Flags: flags}); err != nil {
			t.Fatal(err)
		}
	}
	trace := &imapTrace{}
	b := backendForTest(t, func(c net.Conn) {
		listener := &searchOneConnListener{conn: &attentionTraceConn{Conn: c, trace: trace}, done: make(chan struct{})}
		srv := imapserver.New(&imapserver.Options{InsecureAuth: true, NewSession: func(*imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			return mem.NewSession(), nil, nil
		}})
		defer srv.Close()
		srv.Serve(listener)
	}, true)
	return b, trace.String
}

func TestAttentionSearchRealTLSIMAP(t *testing.T) {
	b, trace := BackendForTriageTesting(t)
	for _, order := range []string{"newest", "oldest"} {
		req := SearchRequest{Attention: true, Subject: "Due", Order: order, Limit: 2}
		var got []uint32
		for {
			out, err := b.Search(context.Background(), req)
			if err != nil {
				t.Fatal(err)
			}
			for _, m := range out.Messages {
				got = append(got, m.Reference.UID)
				if m.Reference.Folder != "INBOX" || m.Reference.UIDValidity != out.UIDValidity {
					t.Fatal("inexact reference", m)
				}
			}
			if out.NextCursor == "" {
				break
			}
			req.Cursor = out.NextCursor
		}
		want := []uint32{3, 2, 1}
		if order == "oldest" {
			want = []uint32{1, 2, 3}
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatal("attention OR/AND, overlap or pagination changed", got, want)
		}
	}
	seen := false
	out, err := b.Search(context.Background(), SearchRequest{Attention: true, Unread: &seen, Subject: "Due"})
	if err != nil || len(out.Messages) != 1 || out.Messages[0].Reference.UID != 2 {
		t.Fatal("attention did not AND explicit unread filter", out, err)
	}
	wire := strings.ToUpper(trace())
	for _, bad := range []string{"BODY", "STORE ", "SELECT ", "APPEND ", "EXPUNGE", "BCC"} {
		if strings.Contains(wire, bad) {
			t.Fatal("triage fetched body/private fields or wrote mailbox", bad, wire)
		}
	}
	if !strings.Contains(wire, "EXAMINE ") || !strings.Contains(wire, "OR (UNSEEN) (FLAGGED)") {
		t.Fatal("missing read-only server-side filter", wire)
	}
}

func TestAttentionCursorCannotBecomeUnfiltered(t *testing.T) {
	b, _ := BackendForTriageTesting(t)
	req := SearchRequest{Attention: true, Limit: 1}
	out, err := b.Search(context.Background(), req)
	if err != nil || out.NextCursor == "" {
		t.Fatal(out, err)
	}
	req.Cursor, req.Attention = out.NextCursor, false
	if _, err := b.Search(context.Background(), req); err != ErrInvalidInput {
		t.Fatal("attention cursor reused for other filter", err)
	}
}

func TestSummaryRetainsLateSystemFlags(t *testing.T) {
	standard := []imap.Flag{imap.FlagSeen, imap.FlagFlagged, imap.FlagAnswered, imap.FlagDraft, imap.FlagDeleted, imap.Flag(`\Recent`)}
	for _, prefix := range []imap.Flag{"keyword", imap.FlagSeen} {
		flags := make([]imap.Flag, 110)
		for i := range flags {
			flags[i] = prefix
		}
		flags = append(flags, standard...)
		out := summaryFromBuffer(&imapclient.FetchMessageBuffer{Flags: flags}, "INBOX", 7)
		if len(out.Flags) != 100 {
			t.Fatal("flag bound changed", len(out.Flags))
		}
		for _, want := range standard {
			found := false
			for _, got := range out.Flags {
				found = found || strings.EqualFold(got, string(want))
			}
			if !found {
				t.Fatal("standard flag dropped", want, out.Flags)
			}
		}
	}
}

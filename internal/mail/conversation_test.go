package mail

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-imap/v2/imapserver/imapmemserver"
)

const conversationTestAnchorID = "Anchor@Example.NET"

var conversationTestRef = Reference{Folder: "INBOX", UIDValidity: 7, UID: 25}

type conversationFixture struct {
	headers     map[uint32]string
	candidates  []uint32
	uidNext     uint32
	validity    uint32
	trace       *imapTrace
	fault       string
	faultFetch  int
	unrequested string
	envelopeID  string
}

func (f conversationFixture) handler(c net.Conn) {
	if f.uidNext == 0 {
		f.uidNext = 51
	}
	if f.validity == 0 {
		f.validity = 7
	}
	fmt.Fprint(c, "* OK [CAPABILITY IMAP4rev1 CONDSTORE] conversation fixture\r\n")
	r := bufio.NewReader(c)
	fetchCount := 0
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)
		f.trace.add(line)
		parts := strings.SplitN(line, " ", 2)
		if len(parts) != 2 {
			return
		}
		tag, command := parts[0], parts[1]
		upper := strings.ToUpper(command)
		switch {
		case strings.HasPrefix(upper, "LOGIN "):
			fmt.Fprintf(c, "%s OK [CAPABILITY IMAP4rev1 CONDSTORE] login\r\n", tag)
		case upper == "CAPABILITY":
			fmt.Fprintf(c, "* CAPABILITY IMAP4rev1 CONDSTORE\r\n%s OK capabilities\r\n", tag)
		case strings.HasPrefix(upper, "EXAMINE "):
			fmt.Fprintf(c, "* FLAGS (\\Seen \\Flagged)\r\n* %d EXISTS\r\n* OK [UIDVALIDITY %d] validity\r\n* OK [UIDNEXT %d] next\r\n* OK [HIGHESTMODSEQ %d] modseq\r\n%s OK [READ-ONLY] examined\r\n", max(len(f.headers), 1), f.validity, f.uidNext, exactTestModSeq, tag)
		case strings.HasPrefix(upper, "UID SEARCH "):
			fmt.Fprint(c, "* SEARCH")
			for _, uid := range f.candidates {
				fmt.Fprintf(c, " %d", uid)
			}
			fmt.Fprintf(c, "\r\n%s OK searched\r\n", tag)
		case strings.HasPrefix(upper, "UID FETCH "):
			fetchCount++
			fault := ""
			if fetchCount == f.faultFetch {
				fault = f.fault
			}
			set := fixtureUIDSet(strings.Fields(command)[2])
			var uids []uint32
			for uid := range f.headers {
				if set.Contains(imap.UID(uid)) {
					uids = append(uids, uid)
				}
			}
			// Ignore requested order; summaries must retain UID identity.
			sort.Slice(uids, func(i, j int) bool { return uids[i] < uids[j] })
			for _, uid := range uids {
				fmt.Fprintf(c, "* 1 FETCH (UID %d FLAGS (\\Flagged) RFC822.SIZE 1234 MODSEQ (%d) ENVELOPE (NIL \"Shared subject\" NIL NIL NIL NIL NIL NIL NIL %q)", uid, exactTestModSeq, f.envelopeID)
				if fault == "duplicate_uid" {
					fmt.Fprintf(c, " UID %d", uid)
				}
				if f.unrequested != "" {
					fmt.Fprintf(c, " BODY[TEXT] {%d}\r\n%s BINARY[1] {%d}\r\n%s", len(f.unrequested), f.unrequested, len(f.unrequested), f.unrequested)
				}
				section := "BODY[HEADER.FIELDS (MESSAGE-ID REFERENCES IN-REPLY-TO)]<0>"
				if fault == "offset" {
					section = "BODY[HEADER.FIELDS (MESSAGE-ID REFERENCES IN-REPLY-TO)]<1>"
				}
				if fault == "wrong_fields" {
					section = "BODY[HEADER.FIELDS (MESSAGE-ID)]<0>"
				}
				if fault == "nil" {
					fmt.Fprintf(c, " %s NIL", section)
				} else if fault != "omit" {
					raw := f.headers[uid]
					if fault == "short_literal" {
						fmt.Fprintf(c, " %s {%d}\r\n%s", section, len(raw)+10, raw)
						return
					}
					fmt.Fprintf(c, " %s {%d}\r\n%s", section, len(raw), raw)
					if fault == "duplicate_section" {
						fmt.Fprintf(c, " %s {%d}\r\n%s", section, len(raw), raw)
					}
				}
				fmt.Fprint(c, ")\r\n")
			}
			if fault == "tagged_failure" {
				fmt.Fprintf(c, "%s NO provider-private-detail\r\n", tag)
			} else {
				fmt.Fprintf(c, "%s OK fetched\r\n", tag)
			}
		default:
			fmt.Fprintf(c, "%s BAD unexpected command\r\n", tag)
		}
	}
}

func conversationHeaderText(id, references, reply string) string {
	var b strings.Builder
	for _, h := range []struct{ name, value string }{{"Message-ID", id}, {"References", references}, {"In-Reply-To", reply}} {
		if h.value != "" {
			fmt.Fprintf(&b, "%s: %s\r\n", h.name, h.value)
		}
	}
	b.WriteString("\r\n")
	return b.String()
}

func conversationTestFixture() conversationFixture {
	return conversationFixture{
		headers: map[uint32]string{
			25: conversationHeaderText("<"+conversationTestAnchorID+">", "<Root@Example.NET> <Parent@Example.NET>", ""),
			24: conversationHeaderText("<Sibling@example>", "<Root@Example.NET>", ""),
			23: conversationHeaderText("<child@example>", "", "<"+conversationTestAnchorID+">"),
			22: conversationHeaderText("<indirect@example>", "", "<Sibling@example>"),
			21: searchIDHeader("root@example.net"),
			20: searchIDHeader("prefixRoot@Example.NET"),
			19: searchIDHeader("Root@Example.NET.suffix"),
			18: searchIDHeader("unrelated@example"),
			17: conversationHeaderText("<unrelated@example>", "(comment <Root@Example.NET>) <other@example>", ""),
			16: conversationHeaderText("<Root@Example.NET> <spoof@example>", "", ""),
			15: conversationHeaderText("<Root@Example.NET>", "<broken>", ""),
			14: searchIDHeader("Root@Example.NET"),
			13: conversationHeaderText("", "", "(note) <Parent@Example.NET>"),
		},
		candidates: []uint32{13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25},
		trace:      &imapTrace{},
		envelopeID: "<Root@Example.NET>",
	}
}

// BackendForConversationTesting exposes only a local synthetic TLS fixture to
// external signed-OAuth/MCP integration tests; it adds no production API.
func BackendForConversationTesting(t *testing.T) (*Backend, Reference, func() string) {
	t.Helper()
	f := conversationTestFixture()
	return backendForTest(t, f.handler, true), conversationTestRef, f.trace.String
}

func TestConversationFixedSeedExactCaseAndReadOnly(t *testing.T) {
	for _, order := range []string{"newest", "oldest"} {
		t.Run(order, func(t *testing.T) {
			f := conversationTestFixture()
			b := backendForTest(t, f.handler, true)
			out, err := b.Conversation(context.Background(), conversationTestRef, SearchRequest{Order: order})
			var got []uint32
			for _, m := range out.Messages {
				got = append(got, m.Reference.UID)
				if m.Reference.Folder != "INBOX" || m.Reference.UIDValidity != 7 || m.ModSeq != exactTestModSeq {
					t.Fatalf("identity/modseq lost: %+v", m)
				}
			}
			want := "[25 24 23 14 13]"
			if order == "oldest" {
				want = "[13 14 23 24 25]"
			}
			if err != nil || fmt.Sprint(got) != want || out.NextCursor != "" || out.Order != order || out.ScannedUIDs != 50 {
				t.Fatalf("fixed-seed result %+v, %v; want %s; trace %s", out, err, want, f.trace.String())
			}
			wire := f.trace.String()
			for _, forbidden := range []string{" SELECT ", " STORE ", " APPEND ", " COPY ", " MOVE ", " EXPUNGE", "BODY.PEEK[]", "SUBJECT"} {
				if strings.Contains(wire, forbidden) {
					t.Fatalf("unsafe/unrelated fetch: %s", wire)
				}
			}
			if !strings.Contains(wire, " EXAMINE INBOX") || !strings.Contains(wire, "BODY.PEEK[HEADER.FIELDS (\"Message-ID\" \"References\" \"In-Reply-To\")]<0.65537>") {
				t.Fatalf("missing bounded selected-header PEEK: %s", wire)
			}
			encoded, _ := json.Marshal(out)
			if strings.Contains(string(encoded), "Root@Example.NET") || strings.Contains(string(encoded), "references") || strings.Contains(string(encoded), "body") {
				t.Fatalf("selected headers leaked through summary index: %s", encoded)
			}
		})
	}
}

func TestConversationRejectsInputsBeforeConnection(t *testing.T) {
	b := &Backend{dialContext: func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("invalid conversation connected")
		return nil, ErrUnavailable
	}}
	v := false
	for _, req := range []SearchRequest{
		{Folder: "Other"}, {Folder: "inbox"}, {Order: "date"}, {Limit: -1}, {Limit: 101},
		{Query: "q"}, {From: "x"}, {To: "x"}, {Subject: "x"}, {Since: "2026-01-01"}, {Before: "2026-02-01"},
		{Unread: &v}, {Flagged: &v}, {MessageID: "x@example"}, {Participant: "x"}, {Attention: true},
		{Cursor: "garbage"}, {Cursor: strings.Repeat("a", 513)},
	} {
		if _, err := b.Conversation(context.Background(), conversationTestRef, req); err != ErrInvalidInput {
			t.Fatalf("invalid request %+v: %v", req, err)
		}
	}
	for _, ref := range []Reference{{}, {Folder: "INBOX", UID: 1}, {Folder: "INBOX", UIDValidity: 7}, {Folder: "bad\nname", UIDValidity: 7, UID: 1}} {
		if _, err := b.Conversation(context.Background(), ref, SearchRequest{}); err != ErrInvalidInput {
			t.Fatalf("invalid ref %+v: %v", ref, err)
		}
	}
}

func TestConversationIdentifierParser(t *testing.T) {
	for _, tt := range []struct {
		name, raw string
		valid     bool
		err       error
	}{
		{"folded_comments", "Message-ID: (nested (comment) \\))\r\n\t<" + conversationTestAnchorID + "> (tail)\r\nReferences: <root@example>\r\n\t<root@[IPv6:2001:db8::1]>\r\nIn-Reply-To: <a@example><b@example>\r\n\r\n", true, nil},
		{"no_message_id", "References: <root@example>\r\n\r\n", true, nil},
		{"absent", "\r\n", false, nil},
		{"empty_id", "Message-ID: \r\n\r\n", false, nil},
		{"empty_references", "Message-ID: <a@example>\r\nReferences: \r\n\r\n", false, nil},
		{"duplicate_id", "Message-ID: <a@example>\r\nmessage-id: <a@example>\r\n\r\n", false, nil},
		{"duplicate_references", "References: <a@example>\r\nReferences: <a@example>\r\n\r\n", false, nil},
		{"duplicate_reply", "In-Reply-To: <a@example>\r\nIn-Reply-To: <a@example>\r\n\r\n", false, nil},
		{"two_message_ids", "Message-ID: <a@example> <b@example>\r\n\r\n", false, nil},
		{"malformed_field_name", "Message-ID : <a@example>\r\nReferences: <b@example>\r\n\r\n", false, nil},
		{"bare_id", "Message-ID: a@example\r\n\r\n", false, nil},
		{"quoted_id", "Message-ID: <\"a\"@example>\r\n\r\n", false, nil},
		{"trailing_junk", "References: <a@example> junk\r\n\r\n", false, nil},
		{"malformed_comment", "In-Reply-To: <a@example> (unterminated\r\n\r\n", false, nil},
		{"comment_only", "In-Reply-To: (comment <a@example>)\r\n\r\n", false, nil},
		{"invalid_utf8", "References: <a@example> (\xff)\r\n\r\n", false, nil},
		{"control", "References: <a@example> (\x00)\r\n\r\n", false, nil},
		{"bare_lf", "Message-ID: <a@example>\nReferences: <b@example>\r\n\r\n", false, nil},
		{"too_many_ids", "References: " + strings.Repeat("<a@example> ", maxConversationIDs+1) + "\r\n\r\n", false, ErrLimit},
		{"too_long_id", "Message-ID: <" + strings.Repeat("a", maxConversationIDBytes) + "@example>\r\n\r\n", false, ErrLimit},
		{"too_long_headers", strings.Repeat("a", maxSearchIDHeaderBytes+1), false, ErrLimit},
		{"empty_literal", "", false, ErrUnavailable},
		{"incomplete", "Message-ID: <a@example>\r\n", false, ErrUnavailable},
		{"extra_suffix", "Message-ID: <a@example>\r\n\r\nReferences: <b@example>\r\n\r\n", false, ErrUnavailable},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ids, valid, err := parseConversationIDs([]byte(tt.raw))
			if valid != tt.valid || !errors.Is(err, tt.err) {
				t.Fatalf("parsed %+v valid=%v err=%v, want valid=%v err=%v", ids, valid, err, tt.valid, tt.err)
			}
		})
	}
	// Bounds are inclusive and a digest is deterministic across header order,
	// repeated IDs, and formatting, without weakening identifier case.
	raw := "References: " + strings.Repeat("<a@example> ", maxConversationIDs) + "\r\n\r\n"
	ids, valid, err := parseConversationIDs([]byte(raw))
	if err != nil || !valid {
		t.Fatalf("exact ID-count bound rejected: %v", err)
	}
	seed, digest := conversationSeed(ids)
	_, equivalent := conversationSeed(conversationIDs{message: "a@example"})
	_, different := conversationSeed(conversationIDs{message: "A@example"})
	if len(seed) != 1 || digest != equivalent || digest == different {
		t.Fatal("unstable/case-insensitive seed digest")
	}
	id := strings.Repeat("a", maxConversationIDBytes-len("@example")) + "@example"
	if _, valid, err := parseConversationIDs([]byte(searchIDHeader(id))); !valid || err != nil {
		t.Fatalf("exact ID-length bound rejected: %v", err)
	}
}

func TestConversationAnchorFailsExplicitly(t *testing.T) {
	for _, tt := range []struct {
		name, raw string
		missing   bool
		err       error
	}{
		{"missing", "", true, ErrNotFound},
		{"no_identifiers", "\r\n", false, ErrInvalidInput},
		{"malformed", "Message-ID: <a@example> <b@example>\r\n\r\n", false, ErrInvalidInput},
		{"too_many", "References: " + strings.Repeat("<a@example> ", maxConversationIDs+1) + "\r\n\r\n", false, ErrLimit},
		{"only_references", "References: <Root@Example.NET>\r\n\r\n", false, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := conversationTestFixture()
			f.headers[25] = tt.raw
			if tt.missing {
				delete(f.headers, 25)
			}
			b := backendForTest(t, f.handler, true)
			_, err := b.Conversation(context.Background(), conversationTestRef, SearchRequest{})
			if !errors.Is(err, tt.err) || tt.err != nil && strings.Contains(f.trace.String(), "UID SEARCH") {
				t.Fatalf("anchor error=%v want=%v trace=%s", err, tt.err, f.trace.String())
			}
		})
	}
}

func TestConversationTransportFailures(t *testing.T) {
	for _, stage := range []int{1, 2} {
		for _, fault := range []string{"omit", "nil", "offset", "wrong_fields", "duplicate_section", "duplicate_uid", "short_literal", "tagged_failure"} {
			t.Run(fmt.Sprintf("fetch_%d/%s", stage, fault), func(t *testing.T) {
				f := conversationFixture{headers: map[uint32]string{25: searchIDHeader(conversationTestAnchorID)}, candidates: []uint32{25}, trace: &imapTrace{}, fault: fault, faultFetch: stage}
				b := backendForTest(t, f.handler, true)
				out, err := b.Conversation(context.Background(), conversationTestRef, SearchRequest{})
				if !errors.Is(err, ErrUnavailable) || len(out.Messages) != 0 {
					t.Fatalf("transport accepted: %+v %v trace=%s", out, err, f.trace.String())
				}
			})
		}
	}
	for _, raw := range []string{"", "Message-ID: <a@example>\r\n", searchIDHeader("a@example") + "hidden\r\n\r\n", strings.Repeat("x", maxSearchIDHeaderBytes+1)} {
		f := conversationFixture{headers: map[uint32]string{25: searchIDHeader(conversationTestAnchorID), 26: raw}, candidates: []uint32{26}, trace: &imapTrace{}}
		b := backendForTest(t, f.handler, true)
		out, err := b.Conversation(context.Background(), conversationTestRef, SearchRequest{})
		want := ErrUnavailable
		if len(raw) > maxSearchIDHeaderBytes {
			want = ErrLimit
		}
		if err != want || len(out.Messages) != 0 {
			t.Fatalf("incomplete/oversized candidate accepted: %+v %v", out, err)
		}
	}
}

func TestConversationVerifiedQuotaAndBatchContinuation(t *testing.T) {
	for _, order := range []string{"newest", "oldest"} {
		t.Run(order, func(t *testing.T) {
			f := conversationFixture{headers: map[uint32]string{}, uidNext: 61, trace: &imapTrace{}}
			for uid := uint32(1); uid <= 60; uid++ {
				f.candidates = append(f.candidates, uid)
				f.headers[uid] = searchIDHeader(strings.ToLower(conversationTestAnchorID))
			}
			for _, uid := range []uint32{2, 25, 49} {
				f.headers[uid] = searchIDHeader(conversationTestAnchorID)
			}
			delete(f.headers, 1) // Concurrent expunge does not consume quota.
			delete(f.headers, 60)
			b := backendForTest(t, f.handler, true)
			var got []uint32
			cursor := ""
			for page := 0; ; page++ {
				if page > 3 {
					t.Fatal("pagination failed to finish")
				}
				out, err := b.Conversation(context.Background(), conversationTestRef, SearchRequest{Order: order, Limit: 1, Cursor: cursor})
				if err != nil || len(out.Messages) > 1 {
					t.Fatalf("page %+v: %v", out, err)
				}
				for _, m := range out.Messages {
					got = append(got, m.Reference.UID)
				}
				cursor = out.NextCursor
				if cursor == "" {
					break
				}
			}
			want := "[49 25 2]"
			if order == "oldest" {
				want = "[2 25 49]"
			}
			if fmt.Sprint(got) != want {
				t.Fatalf("hidden/repeated/out-of-order matches: %v want %s", got, want)
			}
			for _, line := range strings.Split(f.trace.String(), "\n") {
				if strings.Contains(line, " UID FETCH ") {
					uids, _ := fixtureUIDSet(strings.Fields(line)[3]).Nums()
					if len(uids) > searchFetchBatch {
						t.Fatalf("unbounded batch: %s", line)
					}
				}
			}
		})
	}
}

func TestConversationSparseFrozenWindow(t *testing.T) {
	for _, order := range []string{"newest", "oldest"} {
		t.Run(order, func(t *testing.T) {
			f := conversationFixture{headers: map[uint32]string{25: searchIDHeader(conversationTestAnchorID), 1250: searchIDHeader(conversationTestAnchorID), 2501: searchIDHeader(conversationTestAnchorID)}, candidates: []uint32{1250, 2501, 4000000000}, uidNext: 2501, trace: &imapTrace{}}
			b := backendForTest(t, f.handler, true)
			out, err := b.Conversation(context.Background(), conversationTestRef, SearchRequest{Order: order})
			if err != nil || len(out.Messages) != 0 || out.NextCursor == "" || out.ScannedUIDs != 1000 {
				t.Fatalf("first sparse page: %+v %v", out, err)
			}
			f.uidNext = 2600
			b = backendForTest(t, f.handler, true)
			out, err = b.Conversation(context.Background(), conversationTestRef, SearchRequest{Order: order, Cursor: out.NextCursor})
			if err != nil || len(out.Messages) != 1 || out.Messages[0].Reference.UID != 1250 || out.NextCursor == "" || out.ScannedUIDs != 1000 {
				t.Fatalf("second sparse page: %+v %v", out, err)
			}
			out, err = b.Conversation(context.Background(), conversationTestRef, SearchRequest{Order: order, Cursor: out.NextCursor})
			if err != nil || len(out.Messages) != 0 || out.NextCursor != "" || out.ScannedUIDs != 500 {
				t.Fatalf("last sparse page: %+v %v", out, err)
			}
			if strings.Contains(f.trace.String(), "UID 2001:2599") {
				t.Fatal("new arrival escaped frozen snapshot")
			}
		})
	}
}

func TestConversationCursorScopeAnchorAndValidity(t *testing.T) {
	f := conversationTestFixture()
	b := backendForTest(t, f.handler, true)
	out, err := b.Conversation(context.Background(), conversationTestRef, SearchRequest{Limit: 1})
	if err != nil || out.NextCursor == "" {
		t.Fatalf("first page: %+v %v", out, err)
	}
	original := out.NextCursor
	b.dialContext = func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("invalid scoped cursor connected")
		return nil, ErrUnavailable
	}
	for _, ref := range []Reference{{Folder: "Other", UIDValidity: 7, UID: 25}, {Folder: "INBOX", UIDValidity: 7, UID: 24}, {Folder: "INBOX", UIDValidity: 8, UID: 25}} {
		if _, err := b.Conversation(context.Background(), ref, SearchRequest{Cursor: original}); err != ErrInvalidInput {
			t.Fatalf("cross-anchor cursor accepted: %+v %v", ref, err)
		}
	}
	if _, err := b.Conversation(context.Background(), conversationTestRef, SearchRequest{Order: "oldest", Cursor: original}); err != ErrInvalidInput {
		t.Fatalf("cross-order cursor accepted: %v", err)
	}
	if _, err := b.Search(context.Background(), SearchRequest{Cursor: original}); err != ErrInvalidInput {
		t.Fatalf("conversation cursor accepted by Search: %v", err)
	}
	if _, err := b.Conversation(context.Background(), conversationTestRef, SearchRequest{Cursor: encodeCursor(cursor{Version: 7, Before: 25, Upper: 50, Scope: "search"})}); err != ErrInvalidInput {
		t.Fatalf("search cursor accepted by Conversation: %v", err)
	}
	// Explicit same folder and changed page size do not change scope.
	b = backendForTest(t, f.handler, true)
	if _, err := b.Conversation(context.Background(), conversationTestRef, SearchRequest{Folder: "INBOX", Limit: 2, Cursor: original}); err != nil {
		t.Fatalf("equivalent request rejected: %v", err)
	}
	f.trace = &imapTrace{}
	f.headers[25] = searchIDHeader(conversationTestAnchorID)
	b = backendForTest(t, f.handler, true)
	if _, err := b.Conversation(context.Background(), conversationTestRef, SearchRequest{Cursor: original}); err != ErrInvalidInput || strings.Contains(f.trace.String(), "UID SEARCH") {
		t.Fatalf("changed seed accepted: %v trace=%s", err, f.trace.String())
	}
	f.validity, f.trace = 8, &imapTrace{}
	b = backendForTest(t, f.handler, true)
	if _, err := b.Conversation(context.Background(), conversationTestRef, SearchRequest{Cursor: original}); err != ErrStaleReference || strings.Contains(f.trace.String(), "UID FETCH") {
		t.Fatalf("changed UIDVALIDITY read anchor: %v trace=%s", err, f.trace.String())
	}
}

func TestConversationLargeCompleteSectionAndUnrequestedLiterals(t *testing.T) {
	padding := maxSearchIDHeaderBytes - len("Message-ID: <"+conversationTestAnchorID+"> ()\r\n\r\n")
	f := conversationFixture{headers: map[uint32]string{25: "Message-ID: <" + conversationTestAnchorID + "> (" + strings.Repeat("x", padding) + ")\r\n\r\n"}, candidates: []uint32{25}, trace: &imapTrace{}, unrequested: strings.Repeat("unrequested-private", 65536)}
	b := backendForTest(t, f.handler, true)
	// Race instrumentation scans several MiB through a synthetic TLS pipe.
	b.config.Timeout = 10 * time.Second
	out, err := b.Conversation(context.Background(), conversationTestRef, SearchRequest{})
	if err != nil || len(out.Messages) != 1 {
		t.Fatalf("valid bounded header or streaming failed: %+v %v", out, err)
	}
	encoded, _ := json.Marshal(out)
	if len(encoded) > 2000 || strings.Contains(string(encoded), "unrequested-private") {
		t.Fatal("unrequested literal leaked")
	}
}

func FuzzParseConversationIDs(f *testing.F) {
	for _, seed := range []string{searchIDHeader(conversationTestAnchorID), "\r\n", "References: <a@example> (nested (comment)) <b@example>\r\n\r\n", "Message-ID: <x@[a@b<>]>\r\n\r\n"} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		ids, valid, err := parseConversationIDs(raw)
		if !valid || err != nil {
			return
		}
		seed, _ := conversationSeed(ids)
		if len(seed) < 1 || len(seed) > maxConversationIDs || len(raw) > maxSearchIDHeaderBytes {
			t.Fatal("successful parse outside bounds")
		}
		for id := range seed {
			if len(id) > maxConversationIDBytes {
				t.Fatal("unbounded identifier")
			}
		}
	})
}

func TestConversationRealTLSIMAP(t *testing.T) {
	mem := imapmemserver.New()
	user := imapmemserver.NewUser("person@example.com", "test-only")
	mem.AddUser(user)
	for _, folder := range []string{"INBOX", "Other"} {
		if err := user.Create(folder, nil); err != nil {
			t.Fatal(err)
		}
	}
	var ref Reference
	for i, headers := range []string{
		conversationHeaderText("<"+conversationTestAnchorID+">", "<Root@Example.NET> <parent@example>", ""),
		searchIDHeader("Root@Example.NET"),
		conversationHeaderText("<sibling@example>", "<parent@example>", ""),
		conversationHeaderText("<child@example>", "", "<"+conversationTestAnchorID+">"),
		searchIDHeader(strings.ToLower(conversationTestAnchorID)),
		conversationHeaderText("<indirect@example>", "", "<child@example>"),
		conversationHeaderText("<unrelated@example>", "(comment <Root@Example.NET>) <other@example>", ""),
		searchIDHeader("unrelated@example"),
	} {
		raw := "Subject: Identical subject\r\nFrom: sender@example\r\nTo: person@example.com\r\nBcc: hidden@example\r\n" + headers + "body includes Root@Example.NET"
		data, err := user.Append("INBOX", searchStringLiteral{strings.NewReader(raw)}, &imap.AppendOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			ref = Reference{Folder: "INBOX", UIDValidity: data.UIDValidity, UID: uint32(data.UID)}
			if _, err := user.Append("Other", searchStringLiteral{strings.NewReader(raw)}, &imap.AppendOptions{}); err != nil {
				t.Fatal(err)
			}
		}
	}
	b := backendForTest(t, func(c net.Conn) {
		listener := &searchOneConnListener{conn: c, done: make(chan struct{})}
		srv := imapserver.New(&imapserver.Options{InsecureAuth: true, NewSession: func(*imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			return mem.NewSession(), nil, nil
		}})
		defer srv.Close()
		srv.Serve(listener)
	}, true)
	for _, order := range []string{"newest", "oldest"} {
		out, err := b.Conversation(context.Background(), ref, SearchRequest{Order: order})
		if err != nil {
			t.Fatal(err)
		}
		var got []uint32
		for _, m := range out.Messages {
			got = append(got, m.Reference.UID)
			if m.Reference.Folder != "INBOX" {
				t.Fatal("cross-mailbox result")
			}
		}
		want := "[4 3 2 1]"
		if order == "oldest" {
			want = "[1 2 3 4]"
		}
		if fmt.Sprint(got) != want || out.NextCursor != "" {
			t.Fatalf("real IMAP OR/exact matching failed: got %v want %s cursor=%s", got, want, out.NextCursor)
		}
	}
	unread := true
	out, err := b.Search(context.Background(), SearchRequest{Unread: &unread})
	if err != nil || len(out.Messages) != 8 {
		t.Fatalf("conversation marked messages Seen: %+v %v", out, err)
	}
}

func TestConversationPrefilterIncludesEverySeedAndBoundsQuery(t *testing.T) {
	f := conversationTestFixture()
	b := backendForTest(t, f.handler, true)
	if _, err := b.Conversation(context.Background(), conversationTestRef, SearchRequest{}); err != nil {
		t.Fatal(err)
	}
	wire := f.trace.String()
	for _, id := range []string{conversationTestAnchorID, "Root@Example.NET", "Parent@Example.NET"} {
		for _, header := range []string{"Message-ID", "References", "In-Reply-To"} {
			if !strings.Contains(wire, fmt.Sprintf("HEADER %q %q", header, id)) {
				t.Fatalf("omitted prefilter seed/field %s %s: %s", id, header, wire)
			}
		}
	}
	// All 100 ordinary seed IDs fit and are represented; no silent cap at a
	// smaller thread size. Exceptionally long lists fail before UID SEARCH.
	seed := map[string]bool{}
	for i := 0; i < maxConversationIDs; i++ {
		seed[fmt.Sprintf("id%d@example", i)] = true
	}
	criteria, err := conversationCriteria(seed, 1, 1000)
	if err != nil {
		t.Fatal(err)
	}
	count, depth := 0, 0
	var walk func(imap.SearchCriteria, int)
	walk = func(c imap.SearchCriteria, d int) {
		depth = max(depth, d)
		count += len(c.Header)
		for _, pair := range c.Or {
			walk(pair[0], d+1)
			walk(pair[1], d+1)
		}
	}
	walk(*criteria, 0)
	if count != 3*maxConversationIDs || depth > 9 {
		t.Fatalf("query dropped identifiers or is too deeply nested: leaves=%d depth=%d", count, depth)
	}
	var ids []string
	for i := 0; i < 60; i++ {
		ids = append(ids, fmt.Sprintf("<id%d%s@example>", i, strings.Repeat("x", 1000)))
	}
	f = conversationFixture{headers: map[uint32]string{25: "References: " + strings.Join(ids, " ") + "\r\n\r\n"}, trace: &imapTrace{}}
	b = backendForTest(t, f.handler, true)
	if _, err := b.Conversation(context.Background(), conversationTestRef, SearchRequest{}); err != ErrLimit || strings.Contains(f.trace.String(), "UID SEARCH") {
		t.Fatalf("oversized search command accepted: %v trace=%s", err, f.trace.String())
	}
}

func TestConversationCursorBoundaries(t *testing.T) {
	const maxUID = ^uint32(0)
	for _, tt := range []struct {
		name, order       string
		upper, before     uint32
		uidNext, wantHigh uint32
		wantErr           error
	}{
		{"newest_exclusive_boundary", "newest", 50, 51, 100, 50, nil},
		{"newest_exceeded", "newest", 50, 52, 100, 0, ErrInvalidInput},
		{"newest_exhausted", "newest", 50, 1, 100, 0, nil},
		{"newest_max_boundary", "newest", maxUID - 1, maxUID, maxUID, maxUID - 1, nil},
		{"newest_max_exceeded", "newest", maxUID - 2, maxUID, maxUID, 0, ErrInvalidInput},
		{"upper_exceeds_current", "newest", 100, 50, 100, 0, ErrInvalidInput},
		{"oldest_boundary", "oldest", 50, 50, 100, 50, nil},
		{"oldest_exceeded", "oldest", 50, 51, 100, 0, ErrInvalidInput},
		{"oldest_max_boundary", "oldest", maxUID - 1, maxUID - 1, maxUID, maxUID - 1, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, digest := conversationSeed(conversationIDs{message: conversationTestAnchorID})
			cur := conversationCursor{cursor: cursor{Version: 7, Upper: tt.upper, Before: tt.before, Scope: conversationScope(conversationTestRef, tt.order, digest)}, Seed: digest}
			f := conversationFixture{headers: map[uint32]string{25: searchIDHeader(conversationTestAnchorID)}, uidNext: tt.uidNext, trace: &imapTrace{}}
			if tt.wantHigh != 0 {
				f.headers[tt.wantHigh] = searchIDHeader(conversationTestAnchorID)
				f.candidates = append(f.candidates, tt.wantHigh)
			}
			b := backendForTest(t, f.handler, true)
			out, err := b.Conversation(context.Background(), conversationTestRef, SearchRequest{Order: tt.order, Cursor: encodeConversationCursor(cur)})
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("result=%+v err=%v want=%v", out, err, tt.wantErr)
			}
			if tt.wantHigh == 0 {
				if len(out.Messages) != 0 || strings.Contains(f.trace.String(), "UID SEARCH") {
					t.Fatalf("invalid/exhausted cursor searched: %+v trace=%s", out, f.trace.String())
				}
			} else if len(out.Messages) != 1 || out.Messages[0].Reference.UID != tt.wantHigh || out.ScannedUIDs > searchWindow {
				t.Fatalf("boundary/window changed: %+v wantUID=%d trace=%s", out, tt.wantHigh, f.trace.String())
			}
		})
	}
	b := &Backend{dialContext: func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("malformed cursor connected")
		return nil, ErrUnavailable
	}}
	_, digest := conversationSeed(conversationIDs{message: conversationTestAnchorID})
	valid, _ := json.Marshal(conversationCursor{cursor: cursor{Version: 7, Upper: 50, Before: 25, Scope: conversationScope(conversationTestRef, "newest", digest)}, Seed: digest})
	for _, raw := range []string{"null", string(valid) + "{}", strings.Replace(string(valid), `"d":`, `"unknown":1,"d":`, 1), strings.Replace(string(valid), `"u":50`, `"u":0`, 1), strings.Replace(string(valid), `"b":25`, `"b":0`, 1), strings.Replace(string(valid), `"d":"`+digest+`"`, `"d":"bad"`, 1)} {
		if _, err := b.Conversation(context.Background(), conversationTestRef, SearchRequest{Cursor: base64.RawURLEncoding.EncodeToString([]byte(raw))}); err != ErrInvalidInput {
			t.Fatalf("malformed cursor accepted: %s: %v", raw, err)
		}
	}
}

func TestConversationDefaultAndMaximumPageSizes(t *testing.T) {
	f := conversationFixture{headers: map[uint32]string{}, uidNext: 120, trace: &imapTrace{}}
	for uid := uint32(1); uid < 120; uid++ {
		f.headers[uid] = searchIDHeader(conversationTestAnchorID)
		f.candidates = append(f.candidates, uid)
	}
	b := backendForTest(t, f.handler, true)
	for _, size := range []int{0, 100} {
		out, err := b.Conversation(context.Background(), conversationTestRef, SearchRequest{Limit: size})
		want := size
		if want == 0 {
			want = 25
		}
		if err != nil || len(out.Messages) != want || out.NextCursor == "" || out.Order != "newest" {
			t.Fatalf("size=%d: %+v %v", size, out, err)
		}
	}
}

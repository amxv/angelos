package mail

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/emersion/go-imap/v2"
)

const exactTestID = "Case.Preserved+tag@Example.NET"
const exactTestModSeq = uint64(9007199254740993)

type exactSearchFixture struct {
	headers          map[uint32]string
	candidates       []uint32
	uidNext          uint32
	validity         uint32
	trace            *imapTrace
	omitHeader       bool
	nilHeader        bool
	wrongSection     bool
	duplicateSection bool
	unrequested      string
	envelopeID       string
}

func (f exactSearchFixture) handler(c net.Conn) {
	if f.uidNext == 0 {
		f.uidNext = 2501
	}
	if f.validity == 0 {
		f.validity = 7
	}
	fmt.Fprint(c, "* OK [CAPABILITY IMAP4rev1 CONDSTORE] exact search test\r\n")
	r := bufio.NewReader(c)
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
			// Return even out-of-window candidates to verify that the client
			// enforces its UID window rather than trusting server ranges.
			fmt.Fprint(c, "* SEARCH")
			for _, uid := range f.candidates {
				fmt.Fprintf(c, " %d", uid)
			}
			fmt.Fprintf(c, "\r\n%s OK searched\r\n", tag)
		case strings.HasPrefix(upper, "UID FETCH "):
			set := fixtureUIDSet(strings.Fields(command)[2])
			var uids []uint32
			for uid := range f.headers {
				if set.Contains(imap.UID(uid)) {
					uids = append(uids, uid)
				}
			}
			// Ascending wire order and shifting sequence numbers deliberately
			// differ from newest-first UID identity/order.
			sort.Slice(uids, func(i, j int) bool { return uids[i] < uids[j] })
			for _, uid := range uids {
				fmt.Fprintf(c, "* 1 FETCH (UID %d FLAGS (\\Flagged) RFC822.SIZE 1234 MODSEQ (%d)", uid, exactTestModSeq)
				if f.envelopeID != "" {
					fmt.Fprintf(c, " ENVELOPE (NIL \"Envelope subject\" NIL NIL NIL NIL NIL NIL NIL %q)", f.envelopeID)
				}
				if f.unrequested != "" {
					fmt.Fprintf(c, " BODY[TEXT] {%d}\r\n%s", len(f.unrequested), f.unrequested)
					fmt.Fprintf(c, " BINARY[1] {%d}\r\n%s", len(f.unrequested), f.unrequested)
				}
				if strings.Contains(upper, "HEADER.FIELDS") && !f.omitHeader {
					section := "BODY[HEADER.FIELDS (MESSAGE-ID)]<0>"
					if f.wrongSection {
						section = "BODY[HEADER.FIELDS (MESSAGE-ID)]<1>"
					}
					if f.nilHeader {
						fmt.Fprintf(c, " %s NIL", section)
					} else {
						raw := f.headers[uid]
						fmt.Fprintf(c, " %s {%d}\r\n%s", section, len(raw), raw)
						if f.duplicateSection {
							fmt.Fprintf(c, " %s {%d}\r\n%s", section, len(raw), raw)
						}
					}
				}
				fmt.Fprint(c, ")\r\n")
			}
			fmt.Fprintf(c, "%s OK fetched\r\n", tag)
		default:
			fmt.Fprintf(c, "%s BAD unexpected command\r\n", tag)
		}
	}
}

func fixtureUIDSet(s string) imap.UIDSet {
	var out imap.UIDSet
	for _, group := range strings.Split(s, ",") {
		rangeParts := strings.Split(group, ":")
		start, _ := strconv.ParseUint(rangeParts[0], 10, 32)
		end := start
		if len(rangeParts) == 2 {
			end, _ = strconv.ParseUint(rangeParts[1], 10, 32)
		}
		out.AddRange(imap.UID(start), imap.UID(end))
	}
	return out
}

func searchIDHeader(id string) string { return "Message-ID: <" + id + ">\r\n\r\n" }

func TestNormalizeSearchMessageID(t *testing.T) {
	for _, raw := range []string{exactTestID, "<" + exactTestID + ">", "  <" + exactTestID + ">  ", "  " + exactTestID + "  ", "id@[IPv6:2001:db8::1]", "id@[a@b<>]"} {
		id, err := normalizeSearchMessageID(raw)
		if err != nil || id != strings.Trim(strings.Trim(raw, " "), "<>") {
			t.Fatalf("normalize %q = %q, %v", raw, id, err)
		}
	}
	for _, raw := range []string{"", " ", "<>", "x", "@example", "x@", "x..y@example", ".x@example", "x.@example", "x@.example", "x@ex..ample", "x@example.", "<x@example", "x@example>", "<<x@example>>", "<x@example><y@example>", "<x@example> garbage", "(comment) <x@example>", "x (comment)@example", "\"x\"@example", "x@exa mple", "x@ex\x00ample", "x@ex\nample", "x@ex\rample", "x@ex\tample", "x@éxample", "x@ex\u202eample", "x@[bad\\literal]", "x@[unterminated", "\t<x@example>", strings.Repeat("x", 1025) + "@example"} {
		if id, err := normalizeSearchMessageID(raw); err != ErrInvalidInput {
			t.Errorf("accepted %q = %q, %v", raw, id, err)
		}
	}
}

func TestExactSearchRejectsInvalidInputBeforeConnection(t *testing.T) {
	b := &Backend{dialContext: func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("invalid request connected")
		return nil, ErrUnavailable
	}}
	for _, req := range []SearchRequest{
		{MessageID: "<first@example> <second@example>"}, {MessageID: "first@example\r\nUID SEARCH ALL"}, {MessageID: " "},
		{Participant: "person\x00@example"}, {Participant: "person\n@example"}, {Participant: "person\x1b@example"}, {Participant: "person\u200b@example"}, {Participant: strings.Repeat("a", 1025)}, {Participant: string([]byte{0xff})},
	} {
		if _, err := b.Search(context.Background(), req); err != ErrInvalidInput {
			t.Errorf("invalid request %#v: %v", req, err)
		}
	}
}

func TestExactSearchCompleteUniqueHeaderID(t *testing.T) {
	tests := []struct {
		name, raw string
		match     bool
	}{
		{"exact", searchIDHeader(exactTestID), true},
		{"case", searchIDHeader(strings.ToLower(exactTestID)), false},
		{"local_prefix", searchIDHeader("prefix" + exactTestID), false},
		{"domain_suffix", searchIDHeader(exactTestID + ".suffix"), false},
		{"two_ids", "Message-ID: <" + exactTestID + "> <other@example>\r\n\r\n", false},
		{"duplicate_identical", "Message-ID: <" + exactTestID + ">\r\nmessage-id: <" + exactTestID + ">\r\n\r\n", false},
		{"duplicate_other", "Message-ID: <" + exactTestID + ">\r\nMessage-ID: <other@example>\r\n\r\n", false},
		{"duplicate_empty", "Message-ID: <" + exactTestID + ">\r\nMessage-ID:\r\n\r\n", false},
		{"garbage_suffix", "Message-ID: <" + exactTestID + "> garbage\r\n\r\n", false},
		{"malformed_suffix", "Message-ID: <" + exactTestID + "> (unclosed\r\n\r\n", false},
		{"bare_header", "Message-ID: " + exactTestID + "\r\n\r\n", false},
		{"empty", "Message-ID:\r\n\r\n", false},
		{"missing", "\r\n", false},
		{"comment_only_id", "Message-ID: (the <" + exactTestID + ">) <other@example>\r\n\r\n", false},
		{"comments_folded", "mEsSaGe-Id: (outer (nested) \\) comment)\r\n\t<" + exactTestID + ">\r\n\t(tail <not-an-id>)\r\n\r\n", true},
		{"folded_multi_id", "Message-ID: <" + exactTestID + ">\r\n\t<other@example>\r\n\r\n", false},
		{"folded_inside_id", "Message-ID: <Case.Preserved+tag@\r\n\tExample.NET>\r\n\r\n", false},
		{"invalid_field_name", "Message-ID : <" + exactTestID + ">\r\n\r\n", false},
		{"control", "Message-ID: <" + exactTestID + "> (bad\x00)\r\n\r\n", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trace := &imapTrace{}
			f := exactSearchFixture{headers: map[uint32]string{2500: tt.raw}, candidates: []uint32{2500}, trace: trace, envelopeID: "<" + exactTestID + ">"}
			b := backendForTest(t, f.handler, true)
			out, err := b.Search(context.Background(), SearchRequest{MessageID: "<" + exactTestID + ">", Limit: 1})
			if err != nil || (len(out.Messages) == 1) != tt.match {
				t.Fatalf("match=%v result=%+v err=%v trace=%s", tt.match, out, err, trace.String())
			}
			wire := trace.String()
			if !strings.Contains(wire, `HEADER "Message-ID" "`+exactTestID+`"`) || !strings.Contains(wire, "BODY.PEEK[HEADER.FIELDS (\"Message-ID\")]<0.65537>") || !strings.Contains(wire, "EXAMINE ") || strings.Contains(wire, "BODY.PEEK[]") || strings.Contains(wire, "SELECT ") || strings.Contains(wire, "STORE ") {
				t.Fatalf("unsafe/inexact wire: %s", wire)
			}
			if tt.match && (out.Messages[0].Reference.UID != 2500 || out.Messages[0].Reference.UIDValidity != 7 || out.Messages[0].ModSeq != exactTestModSeq) {
				t.Fatalf("identity/modseq lost: %+v", out)
			}
		})
	}
}

func TestExactSearchHeaderSafetyBounds(t *testing.T) {
	for _, tt := range []struct {
		name string
		f    exactSearchFixture
		err  error
	}{
		{"missing_section", exactSearchFixture{omitHeader: true}, ErrUnavailable},
		{"nil_section", exactSearchFixture{nilHeader: true}, ErrUnavailable},
		{"wrong_partial_offset", exactSearchFixture{wrongSection: true}, ErrUnavailable},
		{"duplicate_section", exactSearchFixture{duplicateSection: true}, ErrUnavailable},
		{"incomplete_header", exactSearchFixture{headers: map[uint32]string{2500: "Message-ID: <" + exactTestID + ">\r\n"}}, ErrUnavailable},
		{"empty_literal", exactSearchFixture{headers: map[uint32]string{2500: ""}}, ErrUnavailable},
		{"extra_after_terminator", exactSearchFixture{headers: map[uint32]string{2500: searchIDHeader(exactTestID) + "Message-ID: <other@example>\r\n\r\n"}}, ErrUnavailable},
		{"oversized_ignored_partial", exactSearchFixture{headers: map[uint32]string{2500: "Message-ID: <" + exactTestID + "> (" + strings.Repeat("x", maxSearchIDHeaderBytes) + ")\r\n\r\n"}}, ErrLimit},
		{"max_partial_prefix", exactSearchFixture{headers: map[uint32]string{2500: searchIDHeader(exactTestID) + strings.Repeat("x", maxSearchIDHeaderBytes+1-len(searchIDHeader(exactTestID)))}}, ErrLimit},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := tt.f
			if f.headers == nil {
				f.headers = map[uint32]string{2500: searchIDHeader(exactTestID)}
			}
			f.candidates, f.trace = []uint32{2500}, &imapTrace{}
			b := backendForTest(t, f.handler, true)
			out, err := b.Search(context.Background(), SearchRequest{MessageID: exactTestID})
			if !errors.Is(err, tt.err) || len(out.Messages) != 0 {
				t.Fatalf("result=%+v err=%v want=%v", out, err, tt.err)
			}
		})
	}
}

func TestExactSearchLargeCompleteHeaderAndUnrequestedLiterals(t *testing.T) {
	padding := maxSearchIDHeaderBytes - len("Message-ID: <"+exactTestID+"> ()\r\n\r\n")
	trace := &imapTrace{}
	f := exactSearchFixture{headers: map[uint32]string{2500: "Message-ID: <" + exactTestID + "> (" + strings.Repeat("x", padding) + ")\r\n\r\n"}, candidates: []uint32{2500}, trace: trace, unrequested: strings.Repeat("unrequested-data", 65536)}
	b := backendForTest(t, f.handler, true)
	for _, req := range []SearchRequest{{MessageID: exactTestID}, {}} {
		out, err := b.Search(context.Background(), req)
		if err != nil || len(out.Messages) != 1 || out.Messages[0].ModSeq != exactTestModSeq {
			t.Fatalf("large valid header or streamed unrequested literal rejected: %+v %v", out, err)
		}
		encoded, _ := json.Marshal(out)
		if strings.Contains(string(encoded), "unrequested-data") || len(encoded) > 2000 {
			t.Fatal("unrequested literal leaked")
		}
	}
}

func TestExactSearchFiltersBeforeQuotaAndContinuesBothOrders(t *testing.T) {
	for _, order := range []string{"newest", "oldest"} {
		t.Run(order, func(t *testing.T) {
			trace := &imapTrace{}
			f := exactSearchFixture{headers: map[uint32]string{}, trace: trace, uidNext: 100}
			for uid := uint32(1); uid <= 50; uid++ {
				f.candidates = append(f.candidates, uid)
				f.headers[uid] = searchIDHeader(strings.ToLower(exactTestID))
			}
			for _, uid := range []uint32{2, 25, 49} {
				f.headers[uid] = searchIDHeader(exactTestID)
			}
			// SEARCH saw these UIDs; FETCH omits them after concurrent expunge.
			delete(f.headers, 1)
			delete(f.headers, 50)
			b := backendForTest(t, f.handler, true)
			var got []uint32
			cursor := ""
			for page := 0; ; page++ {
				if page > 3 {
					t.Fatal("pagination did not terminate")
				}
				out, err := b.Search(context.Background(), SearchRequest{MessageID: exactTestID, Order: order, Limit: 1, Cursor: cursor})
				if err != nil || len(out.Messages) > 1 {
					t.Fatalf("page=%d result=%+v err=%v", page, out, err)
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
				t.Fatalf("results hidden, repeated or out of order: got %v want %s", got, want)
			}
			for _, line := range strings.Split(trace.String(), "\n") {
				if strings.Contains(line, " UID FETCH ") {
					uids, _ := fixtureUIDSet(strings.Fields(line)[3]).Nums()
					if len(uids) > searchFetchBatch {
						t.Fatalf("unbounded fetch batch: %s", line)
					}
				}
			}
		})
	}
}

func TestExactSearchSparseContinuationAndStableCeiling(t *testing.T) {
	for _, order := range []string{"newest", "oldest"} {
		t.Run(order, func(t *testing.T) {
			trace := &imapTrace{}
			f := exactSearchFixture{headers: map[uint32]string{1250: searchIDHeader(exactTestID), 2501: searchIDHeader(exactTestID)}, candidates: []uint32{1250, 2501, 4000000000}, trace: trace}
			b := backendForTest(t, f.handler, true)
			out, err := b.Search(context.Background(), SearchRequest{MessageID: exactTestID, Order: order})
			if err != nil || len(out.Messages) != 0 || out.NextCursor == "" || out.ScannedUIDs != 1000 {
				t.Fatalf("first sparse page %+v %v", out, err)
			}
			// A new arrival increases UIDNEXT, but must not expand the cursor's snapshot.
			f.uidNext = 2600
			b = backendForTest(t, f.handler, true)
			out, err = b.Search(context.Background(), SearchRequest{MessageID: exactTestID, Order: order, Cursor: out.NextCursor})
			if err != nil || len(out.Messages) != 1 || out.Messages[0].Reference.UID != 1250 || out.NextCursor == "" {
				t.Fatalf("second sparse page %+v %v", out, err)
			}
			out, err = b.Search(context.Background(), SearchRequest{MessageID: exactTestID, Order: order, Cursor: out.NextCursor})
			if err != nil || len(out.Messages) != 0 || out.NextCursor != "" || out.ScannedUIDs != 500 {
				t.Fatalf("last sparse page %+v %v", out, err)
			}
			if strings.Contains(trace.String(), "UID 2001:2599") {
				t.Fatal("oldest snapshot expanded to include arrivals")
			}
		})
	}
}

func TestExactSearchCursorScopeAndUIDValidity(t *testing.T) {
	trace := &imapTrace{}
	f := exactSearchFixture{headers: map[uint32]string{}, trace: trace}
	b := backendForTest(t, f.handler, true)
	req := SearchRequest{MessageID: "<" + exactTestID + ">", Participant: "person@example"}
	out, err := b.Search(context.Background(), req)
	if err != nil || out.NextCursor == "" {
		t.Fatalf("first page %+v %v", out, err)
	}
	req.Cursor = out.NextCursor
	var connects atomic.Int32
	b.dialContext = func(context.Context, string, string) (net.Conn, error) {
		connects.Add(1)
		return nil, ErrUnavailable
	}
	for _, change := range []func(*SearchRequest){
		func(r *SearchRequest) { r.MessageID = strings.ToLower(exactTestID) },
		func(r *SearchRequest) { r.MessageID = "" },
		func(r *SearchRequest) { r.Participant = "other@example" },
		func(r *SearchRequest) { r.Participant = "" },
		func(r *SearchRequest) { r.Order = "oldest" },
	} {
		other := req
		change(&other)
		if _, err := b.Search(context.Background(), other); err != ErrInvalidInput {
			t.Fatalf("cross-filter cursor accepted: %+v %v", other, err)
		}
	}
	if connects.Load() != 0 {
		t.Fatal("cross-filter cursor made network call")
	}
	// Equivalent bare/bracketed IDs and a changed page size share the scope.
	b = backendForTest(t, f.handler, true)
	req.MessageID, req.Limit = exactTestID, 1
	if _, err := b.Search(context.Background(), req); err != nil {
		t.Fatalf("equivalent ID normalization or page size changed scope: %v", err)
	}
	f.validity, f.trace = 8, &imapTrace{}
	b = backendForTest(t, f.handler, true)
	if _, err := b.Search(context.Background(), req); err != ErrStaleReference || strings.Contains(f.trace.String(), "UID SEARCH") {
		t.Fatalf("changed UIDVALIDITY did not stop search: %v %s", err, f.trace.String())
	}
}

func TestSearchDefaultCursorJSONUnchanged(t *testing.T) {
	encoded, err := json.Marshal(SearchRequest{Folder: "INBOX", Query: "hello", Order: "newest"})
	if err != nil || string(encoded) != `{"folder":"INBOX","query":"hello","order":"newest"}` {
		t.Fatalf("empty optional filters changed legacy cursor scope: %s %v", encoded, err)
	}
}

func TestParticipantSearchORAndExistingFilters(t *testing.T) {
	trace := &imapTrace{}
	f := exactSearchFixture{headers: map[uint32]string{}, trace: trace}
	b := backendForTest(t, f.handler, true)
	unread, flagged := true, false
	_, err := b.Search(context.Background(), SearchRequest{Participant: "Person@Example", MessageID: exactTestID, From: "sender@example", To: "recipient@example", Subject: "invoice", Query: "body term", Since: "2026-01-01", Before: "2026-02-01", Unread: &unread, Flagged: &flagged})
	if err != nil {
		t.Fatal(err)
	}
	wire := trace.String()
	for _, want := range []string{`UID 1501:2500`, `SINCE "1-Jan-2026"`, `BEFORE "1-Feb-2026"`, `FROM "sender@example"`, `TO "recipient@example"`, `SUBJECT "invoice"`, `TEXT "body term"`, `UNSEEN`, `UNFLAGGED`, `OR (OR (FROM "Person@Example") (HEADER "Reply-To" "Person@Example")) (OR (TO "Person@Example") (CC "Person@Example"))`} {
		if !strings.Contains(wire, want) {
			t.Errorf("missing AND/OR criterion %s: %s", want, wire)
		}
	}
	if strings.Contains(strings.ToUpper(wire), "BCC") {
		t.Fatal("participant search included private Bcc")
	}
}

func TestNewestSearchCursorCannotEscapeFrozenCeiling(t *testing.T) {
	const maxUID = ^uint32(0)
	for _, filter := range []struct {
		name string
		req  SearchRequest
	}{
		{"default", SearchRequest{}},
		{"message_id", SearchRequest{MessageID: exactTestID}},
		{"participant", SearchRequest{Participant: "person@example"}},
		{"combined", SearchRequest{MessageID: exactTestID, Participant: "person@example"}},
	} {
		for _, tt := range []struct {
			name                   string
			upper, before, uidNext uint32
			wantUID                uint32
			wantErr                error
		}{
			{"above_snapshot", 2500, 2600, 2600, 0, ErrInvalidInput},
			{"one_above_exclusive_bound", 2500, 2502, 2600, 0, ErrInvalidInput},
			{"exclusive_ceiling_plus_one", 2500, 2501, 2600, 2500, nil},
			{"exclusive_ceiling", 2500, 2500, 2600, 2499, nil},
			{"first_uid_boundary", 1, 2, 3, 1, nil},
			{"first_uid_exceeded", 1, 3, 3, 0, ErrInvalidInput},
			{"exhausted_boundary", 1, 1, 3, 0, nil},
			{"max_exclusive_bound", maxUID - 1, maxUID, maxUID, maxUID - 1, nil},
			{"max_exceeds_snapshot", maxUID - 2, maxUID, maxUID, 0, ErrInvalidInput},
			{"upper_exceeds_current_uidnext", maxUID, maxUID, maxUID, 0, ErrInvalidInput},
			{"legacy_without_upper", 0, 2600, 2600, 2599, nil},
		} {
			t.Run(filter.name+"/"+tt.name, func(t *testing.T) {
				trace := &imapTrace{}
				f := exactSearchFixture{headers: map[uint32]string{}, trace: trace, uidNext: tt.uidNext}
				if tt.wantUID != 0 {
					f.headers[tt.wantUID] = searchIDHeader(exactTestID)
					f.candidates = append(f.candidates, tt.wantUID)
				}
				// Include an arrival above the snapshot as a candidate, even
				// for the accepted exclusive-bound cases. It must not be fetched.
				if tt.upper != 0 && tt.upper < maxUID-1 && tt.upper+1 < tt.uidNext {
					f.headers[tt.upper+1] = searchIDHeader(exactTestID)
					f.candidates = append(f.candidates, tt.upper+1)
				}
				req := filter.req
				req.Folder, req.Order = "INBOX", "newest"
				scopeData, err := json.Marshal(req)
				if err != nil {
					t.Fatal(err)
				}
				req.Cursor = encodeCursor(cursor{Version: 7, Upper: tt.upper, Before: tt.before, Scope: searchScope(req.Folder, string(scopeData))})
				b := backendForTest(t, f.handler, true)
				out, err := b.Search(context.Background(), req)
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("result=%+v err=%v want=%v trace=%s", out, err, tt.wantErr, trace.String())
				}
				if tt.wantUID == 0 {
					if len(out.Messages) != 0 || strings.Contains(trace.String(), "UID SEARCH") || strings.Contains(trace.String(), "UID FETCH") {
						t.Fatalf("invalid/exhausted cursor searched: result=%+v trace=%s", out, trace.String())
					}
				} else if len(out.Messages) != 1 || out.Messages[0].Reference.UID != tt.wantUID || out.ScannedUIDs > searchWindow {
					t.Fatalf("exclusive boundary or window changed: result=%+v wantUID=%d trace=%s", out, tt.wantUID, trace.String())
				}
			})
		}
	}
}

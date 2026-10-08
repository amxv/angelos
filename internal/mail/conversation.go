package mail

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/textproto"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
)

const (
	maxConversationIDs        = 100
	maxConversationIDBytes    = 1024
	maxConversationQueryBytes = 64 << 10
)

type conversationIDs struct {
	message string
	links   []string
}

// parseConversationIDs accepts only complete selected-header sections. Invalid
// identifier syntax is a non-match; incomplete provider responses and exceeded
// bounds are errors, never successful parses of a prefix.
func parseConversationIDs(raw []byte) (conversationIDs, bool, error) {
	var out conversationIDs
	if len(raw) > maxSearchIDHeaderBytes {
		return out, false, ErrLimit
	}
	if !bytes.Equal(raw, []byte("\r\n")) && (len(raw) < 4 || bytes.Index(raw, []byte("\r\n\r\n")) != len(raw)-4) {
		return out, false, ErrUnavailable
	}
	if !utf8.Valid(raw) {
		return out, false, nil
	}
	for i, c := range raw {
		if c == '\n' && (i == 0 || raw[i-1] != '\r') || c == '\r' && (i+1 == len(raw) || raw[i+1] != '\n') || c < 32 && c != '\r' && c != '\n' && c != '\t' || c == 127 {
			return out, false, nil
		}
	}
	h, err := textproto.NewReader(bufio.NewReader(bytes.NewReader(raw))).ReadMIMEHeader()
	if err != nil {
		return out, false, nil
	}
	// A selected section must not smuggle malformed field names past the
	// identifier parser (for example "Message-ID " with a space).
	for name := range h {
		if name != "Message-Id" && name != "References" && name != "In-Reply-To" {
			return out, false, nil
		}
	}
	count := 0
	for _, name := range []string{"Message-ID", "References", "In-Reply-To"} {
		values := h.Values(name)
		if len(values) > 1 {
			return conversationIDs{}, false, nil
		}
		if len(values) == 0 {
			continue
		}
		value, valid := skipSearchIDCFWS(values[0])
		if !valid || value == "" {
			return conversationIDs{}, false, nil
		}
		fieldCount := 0
		for value != "" {
			id, n, valid := parseSearchMessageID(value)
			if !valid {
				return conversationIDs{}, false, nil
			}
			count++
			fieldCount++
			if count > maxConversationIDs || len(id) > maxConversationIDBytes {
				return conversationIDs{}, false, ErrLimit
			}
			if name == "Message-ID" {
				if fieldCount != 1 {
					return conversationIDs{}, false, nil
				}
				out.message = id
			} else {
				out.links = append(out.links, id)
			}
			value, valid = skipSearchIDCFWS(value[n:])
			if !valid {
				return conversationIDs{}, false, nil
			}
		}
	}
	return out, count != 0, nil
}

func conversationSeed(ids conversationIDs) (map[string]bool, string) {
	seed := make(map[string]bool, len(ids.links)+1)
	if ids.message != "" {
		seed[ids.message] = true
	}
	for _, id := range ids.links {
		seed[id] = true
	}
	ordered := make([]string, 0, len(seed))
	for id := range seed {
		ordered = append(ordered, id)
	}
	sort.Strings(ordered)
	data, _ := json.Marshal(ordered)
	digest := sha256.Sum256(data)
	return seed, base64.RawURLEncoding.EncodeToString(digest[:])
}

func (ids conversationIDs) matches(seed map[string]bool) bool {
	if seed[ids.message] {
		return true
	}
	for _, id := range ids.links {
		if seed[id] {
			return true
		}
	}
	return false
}

// conversationCriteria uses substring search only as a coarse server-side
// prefilter. Every candidate is still checked against exact case-sensitive IDs.
// A balanced OR tree avoids a deeply nested query for ordinary long threads.
func conversationCriteria(seed map[string]bool, low, high uint32) (*imap.SearchCriteria, error) {
	ordered := make([]string, 0, len(seed))
	for id := range seed {
		ordered = append(ordered, id)
	}
	sort.Strings(ordered)
	leaves := make([]imap.SearchCriteria, 0, 3*len(ordered))
	// Include ample space for tag, UID criterion, delimiters and quoting. IDs
	// are validated ASCII with no backslashes; quotes in domain literals need
	// one additional escape byte. This bounds encoded command size from above.
	queryBytes := 512
	for _, id := range ordered {
		for _, name := range []string{"Message-ID", "References", "In-Reply-To"} {
			queryBytes += len(name) + len(id) + strings.Count(id, "\"") + 32
			if queryBytes > maxConversationQueryBytes {
				return nil, ErrLimit
			}
			leaves = append(leaves, imap.SearchCriteria{Header: []imap.SearchCriteriaHeaderField{{Key: name, Value: id}}})
		}
	}
	if len(leaves) == 0 {
		return nil, ErrInvalidInput
	}
	var combine func([]imap.SearchCriteria) imap.SearchCriteria
	combine = func(parts []imap.SearchCriteria) imap.SearchCriteria {
		if len(parts) == 1 {
			return parts[0]
		}
		mid := len(parts) / 2
		return imap.SearchCriteria{Or: [][2]imap.SearchCriteria{{combine(parts[:mid]), combine(parts[mid:])}}}
	}
	criteria := combine(leaves)
	criteria.UID = []imap.UIDSet{{{Start: imap.UID(low), Stop: imap.UID(high)}}}
	return &criteria, nil
}

type conversationCursor struct {
	cursor
	Seed string `json:"d"`
}

func conversationScope(ref Reference, order, seed string) string {
	data, _ := json.Marshal(struct {
		Operation string    `json:"operation"`
		Anchor    Reference `json:"anchor"`
		Order     string    `json:"order"`
		Seed      string    `json:"seed"`
	}{"conversation-v1", ref, order, seed})
	return searchScope(ref.Folder, string(data))
}

func encodeConversationCursor(c conversationCursor) string {
	data, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(data)
}

func decodeConversationCursor(raw string, ref Reference, order string) (conversationCursor, error) {
	var c conversationCursor
	if len(raw) > 512 {
		return c, ErrInvalidInput
	}
	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return c, ErrInvalidInput
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil || d.Decode(new(any)) != io.EOF {
		return c, ErrInvalidInput
	}
	digest, err := base64.RawURLEncoding.DecodeString(c.Seed)
	if err != nil || len(digest) != sha256.Size || c.Version != ref.UIDValidity || c.Before == 0 || c.Upper == 0 || c.Scope != conversationScope(ref, order, c.Seed) {
		return c, ErrInvalidInput
	}
	maxBefore := uint64(c.Upper)
	if order == "newest" {
		maxBefore++
	}
	if uint64(c.Before) > maxBefore {
		return c, ErrInvalidInput
	}
	return c, nil
}

// Conversation returns a bounded, mailbox-scoped summary index tied to an exact
// anchor. It matches only the anchor's fixed identifier seed, never subjects or
// a recursively expanded graph. Read each returned Reference for message content.
func (b *Backend) Conversation(ctx context.Context, ref Reference, req SearchRequest) (SearchResult, error) {
	out := SearchResult{Messages: []Summary{}}
	// Whitelist fields before any network activity, including future filters.
	if req != (SearchRequest{Folder: req.Folder, Order: req.Order, Cursor: req.Cursor, Limit: req.Limit}) || !validWriteReference(ref) || req.Folder != "" && req.Folder != ref.Folder {
		return out, ErrInvalidInput
	}
	if req.Limit == 0 {
		req.Limit = 25
	}
	if req.Order == "" {
		req.Order = "newest"
	}
	if req.Limit < 1 || req.Limit > 100 || req.Order != "newest" && req.Order != "oldest" {
		return out, ErrInvalidInput
	}
	out.Order = req.Order
	var cur conversationCursor
	var err error
	if req.Cursor != "" {
		cur, err = decodeConversationCursor(req.Cursor, ref, req.Order)
		if err != nil {
			return out, err
		}
	}
	s, err := b.connectIMAP(ctx)
	if err != nil {
		return out, err
	}
	defer s.close()
	selected, err := s.selectMailbox(ref.Folder, ref.UIDValidity)
	if err != nil {
		return out, err
	}
	out.UIDValidity = selected.UIDValidity
	if selected.NumMessages == 0 || ref.UID >= uint32(selected.UIDNext) {
		return out, ErrNotFound
	}
	ceiling := uint32(selected.UIDNext) - 1
	if cur.Upper != 0 {
		if cur.Upper > ceiling {
			return out, ErrInvalidInput
		}
		ceiling = cur.Upper
	}
	anchors, err := fetchConversationHeaders(s, ref.Folder, selected.UIDValidity, []imap.UID{imap.UID(ref.UID)}, false)
	if err != nil {
		return out, err
	}
	anchor, ok := anchors[imap.UID(ref.UID)]
	if !ok {
		return out, ErrNotFound
	}
	if !anchor.valid {
		return out, ErrInvalidInput
	}
	seed, digest := conversationSeed(anchor.ids)
	if cur.Seed != "" && cur.Seed != digest {
		return out, ErrInvalidInput
	}
	scope := conversationScope(ref, req.Order, digest)
	low, high := uint32(1), ceiling
	if req.Order == "oldest" {
		if cur.Before != 0 {
			low = cur.Before
		}
		if uint64(low)+searchWindow-1 < uint64(ceiling) {
			high = low + searchWindow - 1
		}
	} else {
		if cur.Before != 0 {
			high = cur.Before - 1
		}
		if high == 0 {
			return out, nil
		}
		if high >= searchWindow {
			low = high - searchWindow + 1
		}
	}
	criteria, err := conversationCriteria(seed, low, high)
	if err != nil {
		return out, err
	}
	data, err := s.client.UIDSearch(criteria, nil).Wait()
	if err != nil {
		return out, safeError(err)
	}
	set, ok := data.All.(imap.UIDSet)
	if !ok || set.Dynamic() {
		return out, ErrUnavailable
	}
	// Iterate only the bounded local range, never expand untrusted server sets.
	matches := make([]imap.UID, 0)
	for uid := low; ; uid++ {
		if set.Contains(imap.UID(uid)) {
			matches = append(matches, imap.UID(uid))
		}
		if uid == high {
			break
		}
	}
	if req.Order == "newest" {
		for i, j := 0, len(matches)-1; i < j; i, j = i+1, j-1 {
			matches[i], matches[j] = matches[j], matches[i]
		}
	}
	out.ScannedUIDs = int(high - low + 1)
	messages, last, exhausted, err := fetchConversationPage(s, ref.Folder, selected.UIDValidity, matches, seed, req.Limit)
	if err != nil {
		return out, err
	}
	out.Messages = messages
	next := uint64(low)
	if req.Order == "oldest" {
		next = uint64(high) + 1
		if !exhausted {
			next = uint64(last) + 1
		}
		if next > uint64(ceiling) {
			return out, nil
		}
	} else {
		if !exhausted {
			next = uint64(last)
		}
		if next <= 1 {
			return out, nil
		}
	}
	out.NextCursor = encodeConversationCursor(conversationCursor{cursor: cursor{Version: selected.UIDValidity, Before: uint32(next), Scope: scope, Upper: ceiling}, Seed: digest})
	return out, nil
}

type conversationHeader struct {
	ids     conversationIDs
	valid   bool
	summary Summary
}

func fetchConversationPage(s *imapSession, folder string, validity uint32, uids []imap.UID, seed map[string]bool, limit int) ([]Summary, imap.UID, bool, error) {
	out := make([]Summary, 0, limit)
	for start := 0; start < len(uids); start += searchFetchBatch {
		end := min(start+searchFetchBatch, len(uids))
		headers, err := fetchConversationHeaders(s, folder, validity, uids[start:end], true)
		if err != nil {
			return nil, 0, false, err
		}
		for i := start; i < end; i++ {
			header, ok := headers[uids[i]]
			if ok && header.valid && header.ids.matches(seed) {
				out = append(out, header.summary)
				if len(out) == limit {
					return out, uids[i], i == len(uids)-1, nil
				}
			}
		}
	}
	return out, 0, true, nil
}

func fetchConversationHeaders(s *imapSession, folder string, validity uint32, uids []imap.UID, summaries bool) (map[imap.UID]conversationHeader, error) {
	part := &imap.FetchItemBodySection{Peek: true, Specifier: imap.PartSpecifierHeader, HeaderFields: []string{"Message-ID", "References", "In-Reply-To"}, Partial: &imap.SectionPartial{Size: maxSearchIDHeaderBytes + 1}}
	opts := &imap.FetchOptions{UID: true, BodySection: []*imap.FetchItemBodySection{part}}
	if summaries {
		opts.Envelope, opts.Flags, opts.InternalDate, opts.RFC822Size, opts.ModSeq = true, true, true, true, s.modseq
	}
	requested := imap.UIDSetNum(uids...)
	cmd := s.client.Fetch(requested, opts)
	fail := func(err error) (map[imap.UID]conversationHeader, error) {
		s.cleanup()
		cmd.Close()
		return nil, safeError(err)
	}
	// Premature EOF releases go-imap's decoder while the literal still has a
	// positive advertised remainder. Do not let Close discard/read that same
	// literal concurrently with the decoder. Abort and join the decoder first;
	// closing the entire client also releases this failed fetch command.
	failLiteral := func(err error) (map[imap.UID]conversationHeader, error) {
		s.cleanup()
		s.client.Close()
		return nil, safeError(err)
	}
	out := make(map[imap.UID]conversationHeader, len(uids))
	for data := cmd.Next(); data != nil; data = cmd.Next() {
		if len(out) >= len(uids) {
			return fail(ErrLimit)
		}
		buf := &imapclient.FetchMessageBuffer{}
		var header conversationHeader
		gotHeader := false
		for item := data.Next(); item != nil; item = data.Next() {
			switch v := item.(type) {
			case imapclient.FetchItemDataUID:
				if buf.UID != 0 {
					return fail(ErrUnavailable)
				}
				buf.UID = v.UID
			case imapclient.FetchItemDataEnvelope:
				buf.Envelope = v.Envelope
			case imapclient.FetchItemDataFlags:
				buf.Flags = v.Flags
			case imapclient.FetchItemDataRFC822Size:
				buf.RFC822Size = v.Size
			case imapclient.FetchItemDataInternalDate:
				buf.InternalDate = v.Time
			case imapclient.FetchItemDataModSeq:
				buf.ModSeq = v.ModSeq
			case imapclient.FetchItemDataBodySection:
				if !v.MatchCommand(part) {
					// Stream/discard unrequested literals through Next; never Collect.
					continue
				}
				if gotHeader || v.Literal == nil {
					return fail(ErrUnavailable)
				}
				gotHeader = true
				if v.Literal.Size() > maxSearchIDHeaderBytes {
					return fail(ErrLimit)
				}
				raw, err := io.ReadAll(io.LimitReader(v.Literal, maxSearchIDHeaderBytes+1))
				if err != nil {
					return failLiteral(err)
				}
				if int64(len(raw)) != v.Literal.Size() {
					return failLiteral(ErrUnavailable)
				}
				header.ids, header.valid, err = parseConversationIDs(raw)
				if err != nil {
					return fail(err)
				}
			}
		}
		if _, seen := out[buf.UID]; buf.UID == 0 || !requested.Contains(buf.UID) || seen || !gotHeader {
			return fail(ErrUnavailable)
		}
		header.summary = summaryFromBuffer(buf, folder, validity)
		out[buf.UID] = header
	}
	if err := cmd.Close(); err != nil {
		return nil, safeError(err)
	}
	// Concurrently expunged candidates can be omitted. Missing anchor identity
	// and returned messages lacking the requested section fail at their callers.
	return out, nil
}

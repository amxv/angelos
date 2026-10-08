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
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
)

const (
	maxFolders             = 1000
	searchWindow           = 1000
	maxMessageBytes        = 5 << 20
	maxTextBytes           = 256 << 10
	searchFetchBatch       = 16
	maxSearchIDHeaderBytes = 64 << 10
)

func validFolder(s string) bool {
	if len(s) == 0 || len(s) > 1024 || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}
func clean(s string, max int) string {
	s = strings.ToValidUTF8(s, "�")
	s = strings.Map(func(r rune) rune {
		if (unicode.IsControl(r) && r != '\n' && r != '\t') || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, s)
	if len(s) > max {
		s = s[:max]
		for !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	return s
}
func cleanHeader(s string, max int) string { return strings.Join(strings.Fields(clean(s, max)), " ") }
func (b *Backend) ListFolders(ctx context.Context) ([]Folder, error) {
	s, err := b.connectIMAP(ctx)
	if err != nil {
		return nil, err
	}
	defer s.close()
	opts := &imap.ListOptions{}
	if s.client.Caps().Has(imap.CapSpecialUse) {
		opts.ReturnSpecialUse = true
	}
	cmd := s.client.List("", "*", opts)
	out := make([]Folder, 0)
	for data := cmd.Next(); data != nil; data = cmd.Next() {
		if len(out) >= maxFolders {
			s.cleanup()
			cmd.Close()
			return nil, ErrLimit
		}
		attrs := make([]string, 0, len(data.Attrs))
		for _, a := range data.Attrs {
			attrs = append(attrs, cleanHeader(string(a), 256))
		}
		if !validFolder(data.Mailbox) {
			s.cleanup()
			cmd.Close()
			return nil, ErrLimit
		}
		delim := ""
		if data.Delim != 0 {
			delim = string(data.Delim)
		}
		out = append(out, Folder{Name: data.Mailbox, Delimiter: delim, Attributes: attrs})
	}
	if err := cmd.Close(); err != nil {
		return nil, safeError(err)
	}
	return out, nil
}

type cursor struct {
	Version uint32 `json:"v"`
	Before  uint32 `json:"b"`
	Scope   string `json:"s"`
	Upper   uint32 `json:"u,omitempty"`
}

func searchScope(folder, query string) string {
	h := sha256.Sum256([]byte(folder + "\x00" + query))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
func encodeCursor(c cursor) string {
	data, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(data)
}
func decodeCursor(raw, scope string) (cursor, error) {
	var c cursor
	if len(raw) > 512 {
		return c, ErrInvalidInput
	}
	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return c, ErrInvalidInput
	}
	if json.Unmarshal(data, &c) != nil || c.Version == 0 || c.Before == 0 || c.Scope != scope {
		return c, ErrInvalidInput
	}
	return c, nil
}
func (b *Backend) Search(ctx context.Context, req SearchRequest) (SearchResult, error) {
	out := SearchResult{Messages: []Summary{}}
	if req.Folder == "" {
		req.Folder = "INBOX"
	}
	if req.Limit == 0 {
		req.Limit = 25
	}
	if req.Order == "" {
		req.Order = "newest"
	}
	if req.Order != "newest" && req.Order != "oldest" {
		return out, ErrInvalidInput
	}
	out.Order = req.Order
	if !validFolder(req.Folder) || req.Limit < 1 || req.Limit > 100 || len(req.Query) > 1024 || strings.ContainsAny(req.Query, "\r\n\x00") || !utf8.ValidString(req.Query) {
		return out, ErrInvalidInput
	}
	for _, v := range []string{req.From, req.To, req.Subject} {
		if len(v) > 1024 || !utf8.ValidString(v) || strings.ContainsAny(v, "\r\n\x00") {
			return out, ErrInvalidInput
		}
	}
	if len(req.Participant) > 1024 || !utf8.ValidString(req.Participant) || strings.IndexFunc(req.Participant, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) }) >= 0 {
		return out, ErrInvalidInput
	}
	var err error
	if req.MessageID != "" {
		req.MessageID, err = normalizeSearchMessageID(req.MessageID)
		if err != nil {
			return out, err
		}
	}
	var since, before time.Time
	if req.Since != "" {
		since, err = time.Parse("2006-01-02", req.Since)
		if err != nil {
			return out, ErrInvalidInput
		}
	}
	if req.Before != "" {
		before, err = time.Parse("2006-01-02", req.Before)
		if err != nil {
			return out, ErrInvalidInput
		}
	}
	if !since.IsZero() && !before.IsZero() && !since.Before(before) {
		return out, ErrInvalidInput
	}
	scopeReq := req
	scopeReq.Cursor = ""
	scopeReq.Limit = 0
	scopeData, _ := json.Marshal(scopeReq)
	scope := searchScope(req.Folder, string(scopeData))
	var cur cursor
	if req.Cursor != "" {
		cur, err = decodeCursor(req.Cursor, scope)
		if err != nil {
			return out, err
		}
	}
	s, err := b.connectIMAP(ctx)
	if err != nil {
		return out, err
	}
	defer s.close()
	selected, err := s.selectMailbox(req.Folder, cur.Version)
	if err != nil {
		return out, err
	}
	out.UIDValidity = selected.UIDValidity
	if selected.NumMessages == 0 {
		return out, nil
	}
	ceiling := uint32(selected.UIDNext) - 1
	if cur.Upper != 0 {
		if cur.Upper > ceiling {
			return out, ErrInvalidInput
		}
		ceiling = cur.Upper
	}
	if ceiling == 0 {
		return out, nil
	}
	high := ceiling
	low := uint32(1)
	if req.Order == "oldest" {
		if cur.Before != 0 {
			low = cur.Before
		}
		if low > ceiling {
			return out, ErrInvalidInput
		}
		if uint64(low)+searchWindow-1 < uint64(ceiling) {
			high = low + searchWindow - 1
		}
	} else {
		if cur.Before != 0 {
			// The exclusive continuation bound must stay inside the frozen
			// snapshot, even if newer arrivals increased the current UIDNEXT.
			if uint64(cur.Before) > uint64(ceiling)+1 {
				return out, ErrInvalidInput
			}
			high = cur.Before - 1
		}
		if high == 0 {
			return out, nil
		}
		if high >= searchWindow {
			low = high - searchWindow + 1
		}
	}
	criteria := &imap.SearchCriteria{UID: []imap.UIDSet{{{Start: imap.UID(low), Stop: imap.UID(high)}}}}
	if req.Query != "" {
		criteria.Text = []string{req.Query}
	}
	criteria.Since = since
	criteria.Before = before
	for _, h := range []struct{ k, v string }{{"From", req.From}, {"To", req.To}, {"Subject", req.Subject}, {"Message-ID", req.MessageID}} {
		if h.v != "" {
			criteria.Header = append(criteria.Header, imap.SearchCriteriaHeaderField{Key: h.k, Value: h.v})
		}
	}
	if req.Participant != "" {
		header := func(key string) imap.SearchCriteria {
			return imap.SearchCriteria{Header: []imap.SearchCriteriaHeaderField{{Key: key, Value: req.Participant}}}
		}
		// Nested binary OR stays one term in the surrounding AND criteria.
		criteria.Or = append(criteria.Or, [2]imap.SearchCriteria{
			{Or: [][2]imap.SearchCriteria{{header("From"), header("Reply-To")}}},
			{Or: [][2]imap.SearchCriteria{{header("To"), header("Cc")}}},
		})
	}
	if req.Attention {
		criteria.Or = append(criteria.Or, [2]imap.SearchCriteria{
			{NotFlag: []imap.Flag{imap.FlagSeen}},
			{Flag: []imap.Flag{imap.FlagFlagged}},
		})
	}
	if req.Unread != nil {
		if *req.Unread {
			criteria.NotFlag = append(criteria.NotFlag, imap.FlagSeen)
		} else {
			criteria.Flag = append(criteria.Flag, imap.FlagSeen)
		}
	}
	if req.Flagged != nil {
		if *req.Flagged {
			criteria.Flag = append(criteria.Flag, imap.FlagFlagged)
		} else {
			criteria.NotFlag = append(criteria.NotFlag, imap.FlagFlagged)
		}
	}
	data, err := s.client.UIDSearch(criteria, nil).Wait()
	if err != nil {
		return out, safeError(err)
	}
	// Never expand an untrusted server range. Iterate only our bounded window.
	set, ok := data.All.(imap.UIDSet)
	if !ok || set.Dynamic() {
		return out, ErrUnavailable
	}
	matches := make([]imap.UID, 0)
	if req.Order == "oldest" {
		for uid := low; ; uid++ {
			if set.Contains(imap.UID(uid)) {
				matches = append(matches, imap.UID(uid))
			}
			if uid == high {
				break
			}
		}
	} else {
		for uid := high; ; uid-- {
			if set.Contains(imap.UID(uid)) {
				matches = append(matches, imap.UID(uid))
			}
			if uid == low {
				break
			}
		}
	}
	out.ScannedUIDs = int(high - low + 1)
	if req.MessageID != "" {
		// HEADER SEARCH is case-insensitive substring matching. Verify before
		// consuming the result quota, including candidates lost to expunge.
		summaries, last, exhausted, err := fetchExactSearchPage(s, req.Folder, selected.UIDValidity, matches, req.MessageID, req.Limit)
		if err != nil {
			return out, err
		}
		out.Messages = summaries
		if req.Order == "oldest" {
			next := uint64(high) + 1
			if !exhausted {
				next = uint64(last) + 1
			}
			if next <= uint64(ceiling) {
				out.NextCursor = encodeCursor(cursor{Version: selected.UIDValidity, Before: uint32(next), Scope: scope, Upper: ceiling})
			}
		} else {
			next := low
			if !exhausted {
				next = uint32(last)
			}
			if next > 1 {
				out.NextCursor = encodeCursor(cursor{Version: selected.UIDValidity, Before: next, Scope: scope, Upper: ceiling})
			}
		}
		return out, nil
	}
	if req.Order == "oldest" {
		next := uint64(high) + 1
		if len(matches) > req.Limit {
			matches = matches[:req.Limit]
			next = uint64(matches[len(matches)-1]) + 1
		}
		if next <= uint64(ceiling) {
			out.NextCursor = encodeCursor(cursor{Version: selected.UIDValidity, Before: uint32(next), Scope: scope, Upper: ceiling})
		}
	} else {
		next := low
		if len(matches) > req.Limit {
			matches = matches[:req.Limit]
			next = uint32(matches[len(matches)-1])
		}
		if next > 1 {
			out.NextCursor = encodeCursor(cursor{Version: selected.UIDValidity, Before: next, Scope: scope, Upper: ceiling})
		}
	}
	if len(matches) == 0 {
		return out, nil
	}
	summaries, err := fetchSummaries(s, req.Folder, selected.UIDValidity, matches)
	if err != nil {
		return out, err
	}
	if req.Order == "oldest" {
		sort.Slice(summaries, func(i, j int) bool { return summaries[i].Reference.UID < summaries[j].Reference.UID })
	}
	out.Messages = summaries
	return out, nil
}
func summaryFromBuffer(buf *imapclient.FetchMessageBuffer, folder string, validity uint32) Summary {
	out := Summary{Reference: Reference{Folder: folder, UIDValidity: validity, UID: uint32(buf.UID)}, From: []Address{}, To: []Address{}, Flags: []string{}, Size: buf.RFC822Size, Date: buf.InternalDate, ModSeq: buf.ModSeq}
	out.Flags = summaryFlags(buf.Flags)
	if e := buf.Envelope; e != nil {
		out.Subject = cleanHeader(e.Subject, 4096)
		out.From = addresses(e.From)
		out.To = addresses(e.To)
		if !e.Date.IsZero() {
			out.Date = e.Date
		}
	}
	return out
}

// Keep bounded keyword output without dropping standard read/triage flags.
func summaryFlags(flags []imap.Flag) []string {
	out := make([]string, 0, min(len(flags), 100))
	counts := make(map[string]int, 6)
	system := func(flag string) bool {
		switch flag {
		case `\seen`, `\flagged`, `\answered`, `\draft`, `\deleted`, `\recent`:
			return true
		}
		return false
	}
	for _, flag := range flags {
		value := cleanHeader(string(flag), 256)
		key := strings.ToLower(value)
		if len(out) < 100 {
			out = append(out, value)
			if system(key) {
				counts[key]++
			}
			continue
		}
		if !system(key) || counts[key] > 0 {
			continue
		}
		for i := len(out) - 1; i >= 0; i-- {
			old := strings.ToLower(out[i])
			if !system(old) || counts[old] > 1 {
				if system(old) {
					counts[old]--
				}
				out[i] = value
				counts[key]++
				break
			}
		}
	}
	return out
}

func addresses(in []imap.Address) []Address {
	out := make([]Address, 0)
	for i, a := range in {
		if i >= 100 {
			break
		}
		if addr := a.Addr(); addr != "" {
			out = append(out, Address{Name: cleanHeader(a.Name, 1024), Address: cleanHeader(addr, 1024)})
		}
	}
	return out
}

// normalizeSearchMessageID accepts modern ASCII dot-atom IDs (including a
// no-fold domain literal), with optional angle brackets and outer spaces.
// Obsolete quoted/CFWS-inside-ID forms are rejected, never rewritten.
func normalizeSearchMessageID(raw string) (string, error) {
	if len(raw) > 1024 {
		return "", ErrInvalidInput
	}
	raw = strings.Trim(raw, " ")
	if raw == "" {
		return "", ErrInvalidInput
	}
	if raw[0] != '<' {
		raw = "<" + raw + ">"
	}
	id, n, ok := parseSearchMessageID(raw)
	if !ok || n != len(raw) {
		return "", ErrInvalidInput
	}
	return id, nil
}

func searchIDDotAtom(s string) bool {
	if s == "" || s[0] == '.' || s[len(s)-1] == '.' || strings.Contains(s, "..") {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-/=?^_`{|}~.", rune(c))) {
			return false
		}
	}
	return true
}

// parseSearchMessageID consumes exactly one bracketed ID, retaining its octets.
func parseSearchMessageID(s string) (string, int, bool) {
	if len(s) < 5 || s[0] != '<' {
		return "", 0, false
	}
	at := strings.IndexByte(s, '@')
	if at < 2 || !searchIDDotAtom(s[1:at]) {
		return "", 0, false
	}
	right := at + 1
	if right >= len(s) {
		return "", 0, false
	}
	var end int
	if s[right] == '[' {
		end = right + 1
		for end < len(s) && s[end] != ']' {
			c := s[end]
			if !(c >= 33 && c <= 90 || c >= 94 && c <= 126) {
				return "", 0, false
			}
			end++
		}
		end++ // closing domain-literal bracket
	} else {
		closing := strings.IndexByte(s[right:], '>')
		if closing < 0 {
			return "", 0, false
		}
		end = right + closing
		if !searchIDDotAtom(s[right:end]) {
			return "", 0, false
		}
	}
	if end >= len(s) || s[end] != '>' {
		return "", 0, false
	}
	return s[1:end], end + 1, true
}

// skipSearchIDCFWS accepts unfolded RFC 5322 whitespace and nested comments.
// It allocates nothing and rejects malformed comments and control characters.
func skipSearchIDCFWS(s string) (string, bool) {
	for {
		s = strings.TrimLeft(s, " \t")
		if s == "" || s[0] != '(' {
			return s, true
		}
		depth, i := 1, 1
		for i < len(s) && depth > 0 {
			c := s[i]
			if c == '\\' {
				i++
				if i == len(s) || s[i] < 32 && s[i] != '\t' || s[i] == 127 {
					return "", false
				}
			} else if c == '(' {
				depth++
			} else if c == ')' {
				depth--
			} else if c < 32 && c != '\t' || c == 127 {
				return "", false
			}
			i++
		}
		if depth != 0 {
			return "", false
		}
		s = s[i:]
	}
}

// exactSearchMessageID requires a complete selected-header section. An absent
// or malformed/duplicate Message-ID is not a match; an incomplete provider
// response is an error, since accepting a prefix could conceal another ID.
func exactSearchMessageID(raw []byte, wanted string) (bool, error) {
	if len(raw) > maxSearchIDHeaderBytes {
		return false, ErrLimit
	}
	if !bytes.Equal(raw, []byte("\r\n")) && (bytes.Index(raw, []byte("\r\n\r\n")) != len(raw)-4 || len(raw) < 4) {
		return false, ErrUnavailable
	}
	if !utf8.Valid(raw) {
		return false, nil
	}
	// net/textproto accepts bare LF. Here only complete CRLF framing counts.
	for i, c := range raw {
		if c == '\n' && (i == 0 || raw[i-1] != '\r') || c == '\r' && (i+1 == len(raw) || raw[i+1] != '\n') || c < 32 && c != '\r' && c != '\n' && c != '\t' || c == 127 {
			return false, nil
		}
	}
	h, err := textproto.NewReader(bufio.NewReader(bytes.NewReader(raw))).ReadMIMEHeader()
	if err != nil || len(h.Values("Message-ID")) != 1 {
		return false, nil
	}
	value, ok := skipSearchIDCFWS(h.Get("Message-ID"))
	if !ok {
		return false, nil
	}
	id, n, ok := parseSearchMessageID(value)
	if !ok {
		return false, nil
	}
	rest, ok := skipSearchIDCFWS(value[n:])
	return ok && rest == "" && id == wanted, nil
}

// fetchExactSearchPage consumes candidates in the requested UID order, while
// fetching at most one small batch at a time. If the quota fills inside a batch,
// its unreturned candidates remain eligible on the next page.
func fetchExactSearchPage(s *imapSession, folder string, validity uint32, uids []imap.UID, messageID string, limit int) ([]Summary, imap.UID, bool, error) {
	out := make([]Summary, 0, limit)
	for start := 0; start < len(uids); start += searchFetchBatch {
		end := min(start+searchFetchBatch, len(uids))
		summaries, err := fetchSearchSummaries(s, folder, validity, uids[start:end], messageID)
		if err != nil {
			return nil, 0, false, err
		}
		byUID := make(map[imap.UID]Summary, len(summaries))
		for _, summary := range summaries {
			byUID[imap.UID(summary.Reference.UID)] = summary
		}
		for i := start; i < end; i++ {
			if summary, ok := byUID[uids[i]]; ok {
				out = append(out, summary)
				if len(out) == limit {
					return out, uids[i], i == len(uids)-1, nil
				}
			}
		}
	}
	return out, 0, true, nil
}

func fetchSummaries(s *imapSession, folder string, validity uint32, uids []imap.UID) ([]Summary, error) {
	out, err := fetchSearchSummaries(s, folder, validity, uids, "")
	sort.Slice(out, func(i, j int) bool { return out[i].Reference.UID > out[j].Reference.UID })
	return out, err
}

func fetchSearchSummaries(s *imapSession, folder string, validity uint32, uids []imap.UID, messageID string) ([]Summary, error) {
	opts := &imap.FetchOptions{UID: true, Envelope: true, Flags: true, InternalDate: true, RFC822Size: true, ModSeq: s.modseq}
	var part *imap.FetchItemBodySection
	if messageID != "" {
		part = &imap.FetchItemBodySection{Peek: true, Specifier: imap.PartSpecifierHeader, HeaderFields: []string{"Message-ID"}, Partial: &imap.SectionPartial{Size: maxSearchIDHeaderBytes + 1}}
		opts.BodySection = []*imap.FetchItemBodySection{part}
	}
	requested := imap.UIDSetNum(uids...)
	cmd := s.client.Fetch(requested, opts)
	fail := func(err error) ([]Summary, error) {
		s.cleanup()
		cmd.Close()
		return nil, safeError(err)
	}
	// A failed/short literal has released the decoder. Join it without asking
	// command Close to re-read the exhausted literal concurrently.
	failLiteral := func(err error) ([]Summary, error) {
		s.cleanup()
		s.client.Close()
		return nil, safeError(err)
	}
	out := make([]Summary, 0, len(uids))
	seen := make(map[imap.UID]bool, len(uids))
	for data := cmd.Next(); data != nil; data = cmd.Next() {
		if len(seen) >= len(uids) {
			return fail(ErrLimit)
		}
		buf := &imapclient.FetchMessageBuffer{}
		gotHeader, exact := false, false
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
				if part == nil || !v.MatchCommand(part) {
					// Next streams/discards unrequested literals; never Collect.
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
				exact, err = exactSearchMessageID(raw, messageID)
				if err != nil {
					return fail(err)
				}
			}
		}
		if buf.UID == 0 || !requested.Contains(buf.UID) || seen[buf.UID] || part != nil && !gotHeader {
			return fail(ErrUnavailable)
		}
		seen[buf.UID] = true
		if part == nil || exact {
			out = append(out, summaryFromBuffer(buf, folder, validity))
		}
	}
	if err := cmd.Close(); err != nil {
		return nil, safeError(err)
	}
	// Missing UIDs are skipped: IMAP omits messages concurrently expunged after
	// SEARCH. A returned message missing the requested header fails above.
	return out, nil
}
func (b *Backend) Read(ctx context.Context, ref Reference) (Message, error) {
	out, err := b.readRaw(ctx, ref)
	if err == nil {
		parseMessage(out.raw, &out)
	}
	return out, err
}

// readRaw keeps complete source bytes separate from the bounded display parser.
func (b *Backend) readRaw(ctx context.Context, ref Reference) (Message, error) {
	out := Message{Headers: map[string]string{}, Attachments: []Attachment{}}
	if !validFolder(ref.Folder) || ref.UID == 0 || ref.UIDValidity == 0 {
		return out, ErrInvalidInput
	}
	s, err := b.connectIMAP(ctx)
	if err != nil {
		return out, err
	}
	defer s.close()
	if _, err := s.selectMailbox(ref.Folder, ref.UIDValidity); err != nil {
		return out, err
	}
	part := &imap.FetchItemBodySection{Peek: true, Partial: &imap.SectionPartial{Offset: 0, Size: maxMessageBytes + 1}}
	cmd := s.client.Fetch(imap.UIDSetNum(imap.UID(ref.UID)), &imap.FetchOptions{UID: true, Envelope: true, Flags: true, InternalDate: true, RFC822Size: true, ModSeq: s.modseq, BodySection: []*imap.FetchItemBodySection{part}})
	found := false
	gotBody, gotUID, gotFlags, gotSize := false, false, false, false
	fail := func() (Message, error) { s.cleanup(); cmd.Close(); return out, ErrUnavailable }
	var raw []byte
	buf := &imapclient.FetchMessageBuffer{}
	for data := cmd.Next(); data != nil; data = cmd.Next() {
		if found {
			s.cleanup()
			cmd.Close()
			return out, ErrLimit
		}
		found = true
		for item := data.Next(); item != nil; item = data.Next() {
			switch v := item.(type) {
			case imapclient.FetchItemDataUID:
				if gotUID {
					return fail()
				}
				gotUID = true
				buf.UID = v.UID
			case imapclient.FetchItemDataEnvelope:
				buf.Envelope = v.Envelope
			case imapclient.FetchItemDataFlags:
				if gotFlags {
					return fail()
				}
				gotFlags = true
				buf.Flags = v.Flags
			case imapclient.FetchItemDataRFC822Size:
				if gotSize {
					return fail()
				}
				gotSize = true
				buf.RFC822Size = v.Size
			case imapclient.FetchItemDataInternalDate:
				buf.InternalDate = v.Time
			case imapclient.FetchItemDataModSeq:
				buf.ModSeq = v.ModSeq
			case imapclient.FetchItemDataBodySection:
				if !v.MatchCommand(part) {
					continue
				}
				if gotBody || v.Literal == nil {
					return fail()
				}
				gotBody = true
				if v.Literal != nil {
					raw, err = io.ReadAll(io.LimitReader(v.Literal, maxMessageBytes+1))
					if err != nil || len(raw) <= maxMessageBytes && int64(len(raw)) != v.Literal.Size() {
						// Premature EOF/error has released the protocol decoder.
						// Join it instead of re-discarding the failed literal.
						s.cleanup()
						s.client.Close()
						if err == nil {
							err = ErrUnavailable
						}
						return out, safeError(err)
					}
					if len(raw) > maxMessageBytes {
						out.Truncated = true
						raw = raw[:maxMessageBytes]
						s.cleanup()
					}
				}
			}
		}
	}
	if err := cmd.Close(); err != nil && !out.Truncated {
		return out, safeError(err)
	}
	if !found || uint32(buf.UID) != ref.UID {
		return out, ErrNotFound
	}
	if !gotBody || !gotUID || !gotFlags || !gotSize {
		return out, ErrUnavailable
	}
	out.Summary = summaryFromBuffer(buf, ref.Folder, ref.UIDValidity)
	if buf.RFC822Size > int64(len(raw)) {
		out.Truncated = true
	}
	out.raw = raw
	return out, nil
}

package mail

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
)

const (
	maxFolders      = 1000
	searchWindow    = 1000
	maxMessageBytes = 5 << 20
	maxTextBytes    = 256 << 10
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
	var since, before time.Time
	var err error
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
			if cur.Before > uint32(selected.UIDNext) {
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
	for _, h := range []struct{ k, v string }{{"From", req.From}, {"To", req.To}, {"Subject", req.Subject}} {
		if h.v != "" {
			criteria.Header = append(criteria.Header, imap.SearchCriteriaHeaderField{Key: h.k, Value: h.v})
		}
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
	for i, f := range buf.Flags {
		if i >= 100 {
			break
		}
		out.Flags = append(out.Flags, cleanHeader(string(f), 256))
	}
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
func fetchSummaries(s *imapSession, folder string, validity uint32, uids []imap.UID) ([]Summary, error) {
	cmd := s.client.Fetch(imap.UIDSetNum(uids...), &imap.FetchOptions{UID: true, Envelope: true, Flags: true, InternalDate: true, RFC822Size: true, ModSeq: s.modseq})
	out := make([]Summary, 0, len(uids))
	for data := cmd.Next(); data != nil; data = cmd.Next() {
		if len(out) >= len(uids) {
			s.cleanup()
			cmd.Close()
			return nil, ErrLimit
		}
		buf, err := data.Collect()
		if err != nil {
			s.cleanup()
			cmd.Close()
			return nil, safeError(err)
		}
		out = append(out, summaryFromBuffer(buf, folder, validity))
	}
	if err := cmd.Close(); err != nil {
		return nil, safeError(err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Reference.UID > out[j].Reference.UID })
	return out, nil
}
func (b *Backend) Read(ctx context.Context, ref Reference) (Message, error) {
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
	gotBody := false
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
					continue
				}
				gotBody = true
				if v.Literal != nil {
					raw, err = io.ReadAll(io.LimitReader(v.Literal, maxMessageBytes+1))
					if err != nil {
						s.cleanup()
						cmd.Close()
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
	if !gotBody {
		return out, ErrUnavailable
	}
	out.Summary = summaryFromBuffer(buf, ref.Folder, ref.UIDValidity)
	if buf.RFC822Size > int64(len(raw)) {
		out.Truncated = true
	}
	out.raw = raw
	parseMessage(raw, &out)
	return out, nil
}

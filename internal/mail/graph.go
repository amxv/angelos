package mail

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/amxv/angelos/internal/config"
)

const graphRoot = "https://graph.microsoft.com/v1.0"

// GraphBackend operates only on /me with delegated Graph permissions. It never
// falls back to IMAP, SMTP, application permissions, or a shared mailbox.
type GraphBackend struct {
	config     config.Config
	transport  *Backend
	tokens     microsoftTokenCache
	tokenStore *microsoftTokenStore
}

func NewGraph(c config.Config) (*GraphBackend, error) {
	if !c.IsMicrosoft() {
		return nil, ErrInvalidInput
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &GraphBackend{config: c, transport: &Backend{config: c}}, nil
}
func graphID(id string) bool {
	if len(id) == 0 || len(id) > 1024 {
		return false
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_=", r)) {
			return false
		}
	}
	return true
}

// ValidGraphReference checks shape only; each operation additionally binds the
// reference to this configured account and verifies the native parent folder.
func ValidGraphReference(r Reference) bool {
	return r.Provider == "microsoft_graph" && graphID(r.ID) && graphID(r.Folder) && graphID(r.Account) && r.UID == 0 && r.UIDValidity == 0
}
func (b *GraphBackend) refOK(r Reference) bool {
	return ValidGraphReference(r) && r.Account == b.config.MicrosoftAccountID
}
func (b *GraphBackend) ref(id, folder string) Reference {
	return Reference{Provider: "microsoft_graph", Account: b.config.MicrosoftAccountID, ID: id, Folder: folder}
}
func graphURL(raw string) bool {
	u, e := url.Parse(raw)
	return e == nil && u.Scheme == "https" && u.Host == "graph.microsoft.com" && u.User == nil && u.Fragment == "" && u.Opaque == "" && strings.HasPrefix(u.Path, "/v1.0/me") && (u.Path == "/v1.0/me" || strings.HasPrefix(u.Path, "/v1.0/me/"))
}

// One HTTP attempt only. In particular writes never retry after HTTP failures,
// redirects, expired tokens, or lost responses. A write failure is conservative.
func (b *GraphBackend) request(ctx context.Context, token, method, target, contentType string, body []byte, limit int) ([]byte, int, error) {
	if !graphURL(target) {
		return nil, 0, ErrInvalidInput
	}
	ctx, cancel := context.WithTimeout(ctx, b.config.Timeout)
	defer cancel()
	req, e := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if e != nil {
		return nil, 0, ErrInvalidInput
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Prefer", `IdType="ImmutableId"`)
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	tr := &http.Transport{Proxy: nil, DisableKeepAlives: true, DisableCompression: true, MaxResponseHeaderBytes: 16 << 10, TLSHandshakeTimeout: b.config.Timeout, ResponseHeaderTimeout: b.config.Timeout, TLSClientConfig: b.transport.tlsConfig("graph.microsoft.com"), DialContext: func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "graph.microsoft.com:443" {
			return nil, ErrUnavailable
		}
		conn, done, e := b.transport.openConn(ctx, config.Endpoint{Host: "graph.microsoft.com", Port: 443, TLSMode: "tls"})
		if e != nil {
			return nil, e
		}
		return &googleRefreshConn{Conn: conn, cleanup: done}, nil
	}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: b.config.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, e := client.Do(req)
	if e != nil {
		if method != http.MethodGet {
			return nil, 0, ErrOutcomeUnknown
		}
		return nil, 0, ErrUnavailable
	}
	defer resp.Body.Close()
	if resp.StatusCode == 401 {
		b.graphInvalidateToken(token)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if method != http.MethodGet && resp.StatusCode >= 500 {
			return nil, resp.StatusCode, ErrOutcomeUnknown
		}
		if resp.StatusCode == 404 {
			return nil, resp.StatusCode, ErrNotFound
		}
		return nil, resp.StatusCode, ErrUnavailable
	}
	data, e := io.ReadAll(io.LimitReader(resp.Body, int64(limit)+1))
	if e != nil || len(data) > limit {
		if method != http.MethodGet {
			return nil, resp.StatusCode, ErrOutcomeUnknown
		}
		return nil, resp.StatusCode, ErrLimit
	}
	return data, resp.StatusCode, nil
}
func (b *GraphBackend) identity(ctx context.Context) (string, error) {
	token, e := b.graphToken(ctx)
	if e != nil {
		return "", e
	}
	data, _, e := b.request(ctx, token, "GET", graphRoot+"/me?$select=id,mail,userPrincipalName", "", nil, 64<<10)
	if e != nil {
		return "", e
	}
	var me struct{ ID, Mail, UserPrincipalName string }
	if json.Unmarshal(data, &me) != nil || me.ID != b.config.MicrosoftAccountID || !strings.EqualFold(me.Mail, b.config.From) {
		return "", ErrUnavailable
	}
	return token, nil
}
func graphJSON(v any) []byte { data, _ := json.Marshal(v); return data }

type graphFolder struct {
	ID, DisplayName  string
	ChildFolderCount int
}

func (b *GraphBackend) ListFolders(ctx context.Context) ([]Folder, error) {
	ctx, cancel := context.WithTimeout(ctx, b.config.Timeout)
	defer cancel()
	token, e := b.identity(ctx)
	if e != nil {
		return nil, e
	}
	out := []Folder{}
	queue := []string{graphRoot + "/me/mailFolders?$top=100&includeHiddenFolders=false"}
	seen := map[string]bool{}
	for len(queue) > 0 {
		target := queue[0]
		queue = queue[1:]
		if seen[target] || len(seen) >= maxFolders {
			return nil, ErrLimit
		}
		seen[target] = true
		data, _, e := b.request(ctx, token, "GET", target, "", nil, 1<<20)
		if e != nil {
			return nil, e
		}
		var page struct {
			Value []graphFolder
			Next  string `json:"@odata.nextLink"`
		}
		if json.Unmarshal(data, &page) != nil {
			return nil, ErrUnavailable
		}
		for _, f := range page.Value {
			if !graphID(f.ID) || len(out) >= maxFolders {
				return nil, ErrLimit
			}
			out = append(out, Folder{Name: f.ID, DisplayName: cleanHeader(f.DisplayName, 1024), Attributes: []string{}})
			if f.ChildFolderCount > 0 {
				queue = append(queue, graphRoot+"/me/mailFolders/"+f.ID+"/childFolders?$top=100&includeHiddenFolders=false")
			}
		}
		if page.Next != "" {
			if !graphSameCollection(target, page.Next) {
				return nil, ErrUnavailable
			}
			queue = append(queue, page.Next)
		}
	}
	return out, nil
}
func graphSameCollection(a, b string) bool {
	if !graphURL(a) || !graphURL(b) {
		return false
	}
	ua, _ := url.Parse(a)
	ub, _ := url.Parse(b)
	return ua.EscapedPath() == ub.EscapedPath()
}
func (b *GraphBackend) Capabilities(ctx context.Context) (Capabilities, error) {
	out := Capabilities{IMAP: []string{}, Move: true, SpecialUse: true, SMTPStoresSent: true, SpecialFolders: map[string][]string{}, Provider: "microsoft_graph", SupportedFlags: []string{`\Seen`, `\Flagged`}, Warnings: []string{"Graph uses account-bound opaque references and native folder IDs, not UID snapshots or MODSEQ. Conversation traversal and permanent deletion are unsupported. Sent filing is automatic."}}
	token, e := b.identity(ctx)
	if e != nil {
		return out, e
	}
	for name, role := range map[string]string{"inbox": `\Inbox`, "drafts": `\Drafts`, "sentitems": `\Sent`, "deleteditems": `\Trash`, "archive": `\Archive`} {
		data, _, e := b.request(ctx, token, "GET", graphRoot+"/me/mailFolders/"+name+"?$select=id", "", nil, 64<<10)
		if e != nil {
			return out, e
		}
		var f graphFolder
		if json.Unmarshal(data, &f) != nil || !graphID(f.ID) {
			return out, ErrUnavailable
		}
		out.SpecialFolders[role] = []string{f.ID}
	}
	return out, nil
}

type graphAddress struct{ EmailAddress Address }
type graphMessage struct {
	ID, ParentFolderID, Subject, InternetMessageID string
	ReceivedDateTime                               time.Time
	From                                           graphAddress
	ToRecipients, CcRecipients, ReplyTo            []graphAddress
	IsRead, IsDraft                                bool
	Flag                                           struct{ FlagStatus string }
}

const graphSelect = "id,parentFolderId,subject,internetMessageId,receivedDateTime,from,toRecipients,ccRecipients,replyTo,isRead,isDraft,flag"

func (b *GraphBackend) summary(m graphMessage) (Summary, error) {
	if !graphID(m.ID) || !graphID(m.ParentFolderID) || len(m.ToRecipients) > 100 || len(m.CcRecipients) > 100 || len(m.ReplyTo) > 100 {
		return Summary{}, ErrUnavailable
	}
	s := Summary{Reference: b.ref(m.ID, m.ParentFolderID), Subject: cleanHeader(m.Subject, 4096), From: []Address{graphCleanAddress(m.From.EmailAddress)}, To: []Address{}, Date: m.ReceivedDateTime, Flags: []string{}}
	for _, a := range m.ToRecipients {
		s.To = append(s.To, graphCleanAddress(a.EmailAddress))
	}
	if m.IsRead {
		s.Flags = append(s.Flags, `\Seen`)
	}
	if m.IsDraft {
		s.Flags = append(s.Flags, `\Draft`)
	}
	if m.Flag.FlagStatus == "flagged" {
		s.Flags = append(s.Flags, `\Flagged`)
	}
	return s, nil
}
func (b *GraphBackend) metadata(ctx context.Context, token string, ref Reference) (graphMessage, error) {
	var m graphMessage
	if !b.refOK(ref) {
		return m, ErrInvalidInput
	}
	data, _, e := b.request(ctx, token, "GET", graphMessagePath(ref)+"?$select="+graphSelect, "", nil, 256<<10)
	if e != nil {
		return m, e
	}
	if json.Unmarshal(data, &m) != nil || m.ID != ref.ID || m.ParentFolderID != ref.Folder {
		return m, graphStaleReference{}
	}
	return m, nil
}
func (b *GraphBackend) readRaw(ctx context.Context, token string, ref Reference) (Message, error) {
	out := Message{Headers: map[string]string{}, Attachments: []Attachment{}}
	m, e := b.metadata(ctx, token, ref)
	if e != nil {
		return out, e
	}
	out.Summary, e = b.summary(m)
	if e != nil {
		return out, e
	}
	raw, _, e := b.request(ctx, token, "GET", graphMessagePath(ref)+"/$value", "", nil, maxMessageBytes)
	if e != nil {
		return out, e
	}
	out.raw = raw
	out.Size = int64(len(raw))
	return out, nil
}
func (b *GraphBackend) read(ctx context.Context, token string, ref Reference) (Message, error) {
	m, e := b.readRaw(ctx, token, ref)
	if e == nil {
		parseMessage(m.raw, &m)
	}
	return m, e
}

func (b *GraphBackend) Read(ctx context.Context, ref Reference) (Message, error) {
	if !b.refOK(ref) {
		return Message{}, ErrInvalidInput
	}
	token, e := b.identity(ctx)
	if e != nil {
		return Message{}, e
	}
	return b.read(ctx, token, ref)
}
func (b *GraphBackend) GetAttachment(ctx context.Context, ref Reference, index int) (AttachmentResult, error) {
	out := AttachmentResult{Reference: ref}
	if index < 1 || index > 100 {
		return out, ErrInvalidInput
	}
	m, e := b.Read(ctx, ref)
	if e != nil {
		return out, e
	}
	parsed := Message{Headers: map[string]string{}, Attachments: []Attachment{}}
	payload, e := parseMessageAttachment(m.raw, &parsed, index)
	if e != nil {
		return out, e
	}
	if len(parsed.Attachments) < index {
		return out, ErrNotFound
	}
	out.Attachment = parsed.Attachments[index-1]
	out.DataBase64 = base64.StdEncoding.EncodeToString(payload)
	return out, nil
}
func (b *GraphBackend) ReadDraft(ctx context.Context, ref Reference) (Draft, error) {
	if !b.refOK(ref) {
		return Draft{}, ErrInvalidInput
	}
	token, e := b.identity(ctx)
	if e != nil {
		return Draft{}, e
	}
	m, e := b.readRaw(ctx, token, ref)
	if e != nil {
		return Draft{}, e
	}
	raw, e := graphStructuredDraftSource(m.raw)
	if e != nil {
		return Draft{}, e
	}
	d, e := draftFromSource(m, raw)
	if e == nil {
		d.Warnings = append(d.Warnings, "Exchange transport-only metadata is omitted when rebuilding; the source digest binds the complete original MIME.")
	}
	return d, e
}
func (b *GraphBackend) Conversation(context.Context, Reference, SearchRequest) (SearchResult, error) {
	return SearchResult{}, ErrUnsupported
}

type graphCursor struct{ URL, Scope, MAC string }

func (b *GraphBackend) cursorMAC(c graphCursor) string {
	h := hmac.New(sha256.New, []byte(b.config.MicrosoftClientSecret))
	h.Write([]byte(c.Scope + "\x00" + c.URL))
	return hex.EncodeToString(h.Sum(nil))
}
func (b *GraphBackend) Search(ctx context.Context, req SearchRequest) (SearchResult, error) {
	out := SearchResult{Provider: "microsoft_graph", Messages: []Summary{}, Warnings: []string{"Graph pages follow received-date order, not UID snapshots. Concurrent changes can affect pagination. Filters are literal, case-insensitive (Message-ID exact); query matches decoded visible text and headers, not attachment bytes. Empty pages may have a next cursor. Message size is unknown until read."}}
	ctx, cancel := context.WithTimeout(ctx, b.config.Timeout)
	defer cancel()
	if req.Folder == "" || req.Folder == "INBOX" {
		req.Folder = "inbox"
	}
	if !graphID(req.Folder) {
		return out, ErrInvalidInput
	}
	if req.Limit == 0 {
		req.Limit = 25
	}
	if req.Limit < 1 || req.Limit > 100 || req.Order != "" && req.Order != "newest" && req.Order != "oldest" {
		return out, ErrInvalidInput
	}
	if req.Order == "" {
		req.Order = "newest"
	}
	out.Order = req.Order
	for _, v := range []string{req.Query, req.From, req.To, req.Subject, req.Participant, req.MessageID} {
		if len(v) > 4096 || strings.ContainsAny(v, "\r\n\x00") {
			return out, ErrInvalidInput
		}
	}
	var since, before time.Time
	var e error
	if req.Since != "" {
		since, e = time.Parse("2006-01-02", req.Since)
		if e != nil {
			return out, ErrInvalidInput
		}
	}
	if req.Before != "" {
		before, e = time.Parse("2006-01-02", req.Before)
		if e != nil {
			return out, ErrInvalidInput
		}
	}
	cursor := req.Cursor
	req.Cursor = ""
	scope := searchScope(b.config.MicrosoftAccountID, string(graphJSON(req)))
	order := "desc"
	if req.Order == "oldest" {
		order = "asc"
	}
	target := graphRoot + "/me/mailFolders/" + req.Folder + "/messages?" + url.Values{"$top": {strconv.Itoa(min(req.Limit, 25))}, "$select": {graphSelect}, "$orderby": {"receivedDateTime " + order}}.Encode()
	if cursor != "" {
		if len(cursor) > 24<<10 {
			return out, ErrInvalidInput
		}
		data, e := base64.RawURLEncoding.DecodeString(cursor)
		var c graphCursor
		if e != nil || json.Unmarshal(data, &c) != nil || c.Scope != scope || !hmac.Equal([]byte(c.MAC), []byte(b.cursorMAC(c))) || !graphSameCollection(target, c.URL) {
			return out, ErrInvalidInput
		}
		target = c.URL
	}
	token, e := b.identity(ctx)
	if e != nil {
		return out, e
	}
	data, _, e := b.request(ctx, token, "GET", target, "", nil, 2<<20)
	if e != nil {
		return out, e
	}
	var page struct {
		Value []graphMessage
		Next  string `json:"@odata.nextLink"`
	}
	if json.Unmarshal(data, &page) != nil || len(page.Value) > 25 {
		return out, ErrLimit
	}
	// A page scans at most min(limit,25) messages, preventing hidden truncation.
	// $top is request-bound and should equal that bound, including subsequent pages.
	if len(page.Value) > req.Limit {
		return out, ErrLimit
	}
	bytesRead := int64(0)
	for _, m := range page.Value {
		if !since.IsZero() && m.ReceivedDateTime.Before(since) || !before.IsZero() && !m.ReceivedDateTime.Before(before) {
			continue
		}
		flagged := m.Flag.FlagStatus == "flagged"
		if req.Unread != nil && *req.Unread == m.IsRead || req.Flagged != nil && *req.Flagged != flagged || req.Attention && m.IsRead && !flagged {
			continue
		}
		if !graphContains(m.Subject, req.Subject) || !graphContains(m.From.EmailAddress.Name+" "+m.From.EmailAddress.Address, req.From) || !graphContains(graphAddresses(m.ToRecipients), req.To) {
			continue
		}
		if req.MessageID != "" && strings.Trim(m.InternetMessageID, "<>") != strings.Trim(req.MessageID, "<>") {
			continue
		}
		if req.Participant != "" && !graphContains(m.From.EmailAddress.Name+" "+m.From.EmailAddress.Address+" "+graphAddresses(m.ToRecipients)+" "+graphAddresses(m.CcRecipients)+" "+graphAddresses(m.ReplyTo), req.Participant) {
			continue
		}
		s, e := b.summary(m)
		if e != nil {
			return out, e
		}
		if req.Query != "" {
			msg, e := b.read(ctx, token, s.Reference)
			if e != nil {
				return out, e
			}
			bytesRead += int64(len(msg.raw))
			if bytesRead > maxWireBytes {
				return out, ErrLimit
			}
			if msg.Truncated {
				return out, ErrLimit
			}
			queryText := msg.Text
			for _, value := range msg.Headers {
				queryText += " " + value
			}
			if !graphContains(queryText, req.Query) {
				continue
			}
			s = msg.Summary
		}
		out.Messages = append(out.Messages, s)
	}
	if page.Next != "" {
		if len(page.Next) > 16<<10 || !graphSameCollection(target, page.Next) {
			return out, ErrUnavailable
		}
		c := graphCursor{URL: page.Next, Scope: scope}
		c.MAC = b.cursorMAC(c)
		out.NextCursor = base64.RawURLEncoding.EncodeToString(graphJSON(c))
	}
	return out, nil
}
func graphContains(text, query string) bool {
	return query == "" || strings.Contains(strings.ToLower(text), strings.ToLower(query))
}
func graphAddresses(a []graphAddress) string {
	v := ""
	for _, x := range a {
		v += " " + x.EmailAddress.Name + " " + x.EmailAddress.Address
	}
	return v
}

func graphCleanAddress(a Address) Address {
	return Address{Name: cleanHeader(a.Name, 1024), Address: cleanHeader(a.Address, 1024)}
}

type graphStaleReference struct{}

func (graphStaleReference) Error() string {
	return "Graph message moved or reference changed; search again"
}
func (graphStaleReference) Unwrap() error { return ErrStaleReference }

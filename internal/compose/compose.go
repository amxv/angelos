// Package compose creates bounded immutable MIME messages. It never sends mail.
package compose

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/textproto"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const MaxMessageBytes = 5 << 20
const MaxAttachmentBytes = 3 << 20
const MaxTextBytes = 1 << 20
const MaxRecipients = 50
const MaxReferences = 100
const MaxReferencesBytes = 8 << 10

type Attachment struct {
	Filename    string `json:"filename" jsonschema:"Attachment filename; no paths"`
	ContentType string `json:"content_type" jsonschema:"MIME type and optional parameters such as application/pdf"`
	DataBase64  string `json:"data_base64" jsonschema:"Base64 bytes; maximum total decoded attachments 3 MiB"`
}
type Input struct {
	To                []string     `json:"to,omitempty"`
	Cc                []string     `json:"cc,omitempty"`
	Bcc               []string     `json:"bcc,omitempty"`
	Subject           string       `json:"subject"`
	Text              string       `json:"text"`
	HTML              string       `json:"html,omitempty" jsonschema:"Optional authored HTML alternative; reviewed in full before sending"`
	Attachments       []Attachment `json:"attachments,omitempty"`
	InReplyTo         string       `json:"in_reply_to,omitempty"`
	References        []string     `json:"references,omitempty"`
	Warnings          []string     `json:"-"` // Planner notices; never accepted as tool input.
	PreserveEmptyText bool         `json:"-"` // An existing or explicitly cleared draft alternative, not HTML-only authorship.
}
type Prepared struct {
	ID          string              `json:"id"`
	Digest      string              `json:"digest"`
	From        string              `json:"from"`
	To          []string            `json:"to"`
	Cc          []string            `json:"cc,omitempty"`
	Bcc         []string            `json:"bcc,omitempty"`
	Subject     string              `json:"subject"`
	Text        string              `json:"text"`
	HTML        string              `json:"html,omitempty"`
	Attachments []AttachmentSummary `json:"attachments,omitempty"`
	MessageID   string              `json:"message_id"`
	ExpiresAt   time.Time           `json:"expires_at"`
	Raw         []byte              `json:"raw"`
	Recipients  []string            `json:"recipients"`
	Warnings    []string            `json:"warnings,omitempty"`
}
type AttachmentSummary struct {
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	Bytes       int    `json:"bytes"`
	SHA256      string `json:"sha256"`
}

func invalid(s string) bool {
	return !utf8.ValidString(s) || strings.IndexFunc(s, unicode.IsControl) >= 0
}
func addresses(in []string) ([]string, []string, error) {
	formatted, envelope := []string{}, []string{}
	for _, s := range in {
		if len(s) > 2048 || invalid(s) {
			return nil, nil, errors.New("invalid recipient")
		}
		a, e := mail.ParseAddress(s)
		if e != nil || len(a.Name)+len(a.Address) > 512 || invalid(a.Name) || !strings.Contains(a.Address, "@") || !ascii(a.Address) || invalid(a.Address) || strings.ContainsAny(a.Address, " <>\t") {
			return nil, nil, errors.New("invalid recipient; SMTPUTF8 addresses are not supported")
		}
		formatted = append(formatted, a.String())
		envelope = append(envelope, a.Address)
	}
	return formatted, envelope, nil
}
func ascii(s string) bool {
	for _, r := range s {
		if r > 127 {
			return false
		}
	}
	return true
}

// NormalizeMessageID preserves the case of both halves of a message identifier.
// It accepts a bare stored identifier or one angle-bracketed RFC message-id.
// Deliberately unsupported obsolete/quoted forms must not become unsafe headers.
func NormalizeMessageID(value string) (string, bool) {
	if invalid(value) {
		return "", false
	}
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "<") && strings.HasSuffix(value, ">") {
		value = value[1 : len(value)-1]
	}
	if len(value) == 0 || len(value)+2 > 997 || !ascii(value) || strings.ContainsAny(value, "<> \t") {
		return "", false
	}
	left, right, ok := strings.Cut(value, "@")
	if !ok || !dotAtom(left) || !(dotAtom(right) || domainLiteral(right)) {
		return "", false
	}
	return "<" + value + ">", true
}
func dotAtom(s string) bool {
	if s == "" || strings.HasPrefix(s, ".") || strings.HasSuffix(s, ".") || strings.Contains(s, "..") {
		return false
	}
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strings.ContainsRune("!#$%&'*+-/=?^_`{|}~.", c) {
			continue
		}
		return false
	}
	return true
}
func domainLiteral(s string) bool {
	if len(s) < 3 || s[0] != '[' || s[len(s)-1] != ']' {
		return false
	}
	for _, c := range s[1 : len(s)-1] {
		if c < 33 || c > 126 || strings.ContainsRune("[]\\", c) {
			return false
		}
	}
	return true
}
func validMessageID(s string) bool {
	v, ok := NormalizeMessageID(s)
	return ok && v == s
}
func validBody(s string) bool {
	return len(s) <= MaxTextBytes && utf8.ValidString(s) && strings.IndexFunc(s, func(r rune) bool {
		return unicode.IsControl(r) && r != '\r' && r != '\n' && r != '\t'
	}) < 0
}
func normalizeBody(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\r", "\n")
}

// normalizeRecipients keeps the first spelling and display name, with To > Cc > Bcc.
// Self addresses are intentionally not special here: explicitly addressing oneself
// is legitimate and only reply derivation filters the account's identities.
func normalizeRecipients(in Input) (Input, []string, error) {
	seen := map[string]bool{}
	envelope := []string{}
	lists := []*[]string{&in.To, &in.Cc, &in.Bcc}
	for _, dst := range lists {
		formatted, emails, err := addresses(*dst)
		if err != nil {
			return Input{}, nil, err
		}
		out := []string{}
		for i, email := range emails {
			key := strings.ToLower(email)
			if !seen[key] {
				seen[key] = true
				out = append(out, formatted[i])
				envelope = append(envelope, email)
			}
		}
		*dst = out
	}
	return in, envelope, nil
}

// Build fixes Date, Message-ID, MIME boundaries, recipients and bytes before approval.
func Build(from string, in Input, id string, now time.Time) (Prepared, error) {
	return build(from, in, id, now, false)
}

// BuildDraft permits recipientless drafts while preserving all MIME safety checks.
func BuildDraft(from string, in Input, id string, now time.Time) (Prepared, error) {
	return build(from, in, id, now, true)
}
func build(from string, in Input, id string, now time.Time, draft bool) (Prepared, error) {
	var out Prepared
	if len(id) != 32 {
		return out, errors.New("invalid preparation id")
	}
	if _, e := hex.DecodeString(id); e != nil {
		return out, errors.New("invalid preparation id")
	}
	fromHeader, fromEnvelope, e := addresses([]string{from})
	if e != nil {
		return out, errors.New("invalid configured sender")
	}
	if len(in.To)+len(in.Cc)+len(in.Bcc) > MaxRecipients {
		return out, errors.New("recipient count must be 1 to 50")
	}
	in, recipients, e := normalizeRecipients(in)
	if e != nil {
		return out, e
	}
	if !draft && len(recipients) == 0 {
		return out, errors.New("recipient count must be 1 to 50")
	}
	if len(in.Subject) > 512 || invalid(in.Subject) || !validBody(in.Text) || !validBody(in.HTML) {
		return out, errors.New("invalid or oversized subject, text, or HTML; bodies must be valid UTF-8 and at most 1 MiB each")
	}
	in, e = textAlternative(in)
	if e != nil {
		return out, e
	}
	in.Text, in.HTML = normalizeBody(in.Text), normalizeBody(in.HTML)
	// Validate the final alternatives, including any text decoded from HTML.
	if !validBody(in.Text) || !validBody(in.HTML) {
		return out, errors.New("final text or HTML is invalid or exceeds 1 MiB")
	}
	if len(in.Attachments) > 20 {
		return out, errors.New("too many attachments")
	}
	if in.InReplyTo != "" {
		var ok bool
		in.InReplyTo, ok = NormalizeMessageID(in.InReplyTo)
		if !ok {
			return out, errors.New("invalid reply message id")
		}
	}
	refs, _, e := referenceChain(in.References, "", false)
	if e != nil {
		return out, e
	}
	in.References = refs
	bodyHeader, body, e := composeBody(in, id)
	if e != nil {
		return out, e
	}
	summaries := []AttachmentSummary{}
	if len(in.Attachments) > 0 {
		bodyHeader, body, summaries, e = composeMixed(bodyHeader, body, in.Attachments, id)
		if e != nil {
			return out, e
		}
	}
	domain := fromEnvelope[0][strings.LastIndexByte(fromEnvelope[0], '@')+1:]
	mid := "<" + id + "@" + domain + ">"
	if !validMessageID(mid) {
		return out, errors.New("configured sender cannot form a safe Message-ID")
	}
	var msg bytes.Buffer
	writeHeader(&msg, "From", fromHeader[0])
	if len(in.To) > 0 {
		writeHeader(&msg, "To", strings.Join(in.To, ", "))
	}
	if len(in.Cc) > 0 {
		writeHeader(&msg, "Cc", strings.Join(in.Cc, ", "))
	}
	writeHeader(&msg, "Subject", mime.QEncoding.Encode("utf-8", in.Subject))
	fmt.Fprintf(&msg, "Date: %s\r\nMessage-ID: %s\r\nMIME-Version: 1.0\r\n", now.UTC().Format(time.RFC1123Z), mid)
	if in.InReplyTo != "" {
		writeHeader(&msg, "In-Reply-To", in.InReplyTo)
	}
	if len(in.References) > 0 {
		writeHeader(&msg, "References", strings.Join(in.References, " "))
	}
	writeHeader(&msg, "Content-Type", bodyHeader.Get("Content-Type"))
	if cte := bodyHeader.Get("Content-Transfer-Encoding"); cte != "" {
		writeHeader(&msg, "Content-Transfer-Encoding", cte)
	}
	msg.WriteString("\r\n")
	msg.Write(body)
	// SMTP DATA closes with CRLF; include it in the immutable wire digest.
	if !bytes.HasSuffix(msg.Bytes(), []byte("\r\n")) {
		msg.WriteString("\r\n")
	}
	if msg.Len() > MaxMessageBytes {
		return out, errors.New("encoded message exceeds 5 MiB")
	}
	for _, line := range bytes.Split(msg.Bytes(), []byte("\r\n")) {
		if len(line) > 998 {
			return out, errors.New("MIME line exceeds SMTP limit; shorten headers")
		}
	}
	// Digest includes the SMTP envelope (including Bcc) and exact wire bytes.
	digest := WireDigest(fromEnvelope[0], recipients, msg.Bytes())
	out = Prepared{ID: id, Digest: digest, From: fromEnvelope[0], To: in.To, Cc: in.Cc, Bcc: in.Bcc, Subject: in.Subject, Text: in.Text, HTML: in.HTML, Attachments: summaries, MessageID: mid, ExpiresAt: now.Add(15 * time.Minute), Raw: msg.Bytes(), Recipients: recipients, Warnings: append([]string(nil), in.Warnings...)}
	return out, nil
}

// writeHeader folds only at existing spaces, preserving case and field contents.
// A long indivisible token is placed on a continuation line; the final wire check
// enforces the RFC 5322 hard limit rather than cutting a message-id or encoded word.
func writeHeader(w io.Writer, name, value string) {
	io.WriteString(w, name+":")
	line := len(name) + 1
	for _, token := range strings.Split(value, " ") {
		if line+1+len(token) > 78 {
			io.WriteString(w, "\r\n ")
			line = 1
		} else {
			io.WriteString(w, " ")
			line++
		}
		io.WriteString(w, token)
		line += len(token)
	}
	io.WriteString(w, "\r\n")
}

func quotedBody(value string) ([]byte, error) {
	var b bytes.Buffer
	qp := quotedprintable.NewWriter(&b)
	if _, err := io.WriteString(qp, value); err != nil {
		return nil, err
	}
	if err := qp.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
func textHeader(mediaType string) textproto.MIMEHeader {
	return textproto.MIMEHeader{"Content-Type": {mediaType + "; charset=utf-8"}, "Content-Transfer-Encoding": {"quoted-printable"}}
}
func composeBody(in Input, id string) (textproto.MIMEHeader, []byte, error) {
	text, err := quotedBody(in.Text)
	if err != nil || in.HTML == "" {
		return textHeader("text/plain"), text, err
	}
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	boundary := "=_alternative_" + id
	if err := w.SetBoundary(boundary); err != nil {
		return nil, nil, err
	}
	for _, item := range []struct{ mediaType, value string }{{"text/plain", in.Text}, {"text/html", in.HTML}} {
		part, err := w.CreatePart(textHeader(item.mediaType))
		if err != nil {
			return nil, nil, err
		}
		body, err := quotedBody(item.value)
		if err != nil {
			return nil, nil, err
		}
		if _, err := part.Write(body); err != nil {
			return nil, nil, err
		}
	}
	if err := w.Close(); err != nil {
		return nil, nil, err
	}
	return textproto.MIMEHeader{"Content-Type": {mime.FormatMediaType("multipart/alternative", map[string]string{"boundary": boundary})}}, b.Bytes(), nil
}
func composeMixed(bodyHeader textproto.MIMEHeader, body []byte, attachments []Attachment, id string) (textproto.MIMEHeader, []byte, []AttachmentSummary, error) {
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	boundary := "=_mixed_" + id
	if err := w.SetBoundary(boundary); err != nil {
		return nil, nil, nil, err
	}
	part, err := w.CreatePart(bodyHeader)
	if err != nil {
		return nil, nil, nil, err
	}
	if _, err := part.Write(body); err != nil {
		return nil, nil, nil, err
	}
	total := 0
	summaries := []AttachmentSummary{}
	for _, a := range attachments {
		if len(a.Filename) == 0 || len(a.Filename) > 200 || invalid(a.Filename) || strings.ContainsAny(a.Filename, "/\\") {
			return nil, nil, nil, errors.New("invalid attachment filename")
		}
		if len(a.DataBase64) > ((MaxAttachmentBytes+2)/3)*4 {
			return nil, nil, nil, errors.New("attachment too large")
		}
		data, err := base64.StdEncoding.Strict().DecodeString(a.DataBase64)
		if err != nil {
			return nil, nil, nil, errors.New("invalid attachment base64")
		}
		total += len(data)
		if total > MaxAttachmentBytes {
			return nil, nil, nil, errors.New("attachments exceed 3 MiB")
		}
		ct, params, err := mime.ParseMediaType(a.ContentType)
		if err != nil || invalid(a.ContentType) || !strings.Contains(ct, "/") || strings.HasPrefix(ct, "multipart/") {
			return nil, nil, nil, errors.New("invalid attachment content type; multipart entities must be supplied as a file")
		}
		ct = mime.FormatMediaType(ct, params)
		if ct == "" {
			return nil, nil, nil, errors.New("invalid attachment content type")
		}
		h := textproto.MIMEHeader{}
		h.Set("Content-Type", ct)
		h.Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": a.Filename}))
		mediaType, _, _ := mime.ParseMediaType(ct)
		if mediaType == "message/rfc822" {
			// RFC 2046 forbids base64/quoted-printable for message/rfc822. 7bit
			// needs no SMTPUTF8 or 8BITMIME negotiation and preserves exact bytes.
			if !safe7BitMessage(data) {
				return nil, nil, nil, errors.New("message/rfc822 requires a 7bit message with CRLF lines; use application/octet-stream for other exact EML bytes")
			}
			if bytes.Contains(data, []byte("--"+boundary)) {
				return nil, nil, nil, errors.New("embedded message conflicts with MIME boundary; prepare again")
			}
			h.Set("Content-Transfer-Encoding", "7bit")
		} else {
			h.Set("Content-Transfer-Encoding", "base64")
		}
		part, err := w.CreatePart(h)
		if err != nil {
			return nil, nil, nil, err
		}
		if mediaType == "message/rfc822" {
			if _, err := part.Write(data); err != nil {
				return nil, nil, nil, err
			}
		} else {
			enc := base64.StdEncoding.EncodeToString(data)
			for len(enc) > 0 {
				n := min(76, len(enc))
				fmt.Fprintf(part, "%s\r\n", enc[:n])
				enc = enc[n:]
			}
		}
		sum := sha256.Sum256(data)
		summaries = append(summaries, AttachmentSummary{a.Filename, ct, len(data), hex.EncodeToString(sum[:])})
	}
	if err := w.Close(); err != nil {
		return nil, nil, nil, err
	}
	return textproto.MIMEHeader{"Content-Type": {mime.FormatMediaType("multipart/mixed", map[string]string{"boundary": boundary})}}, b.Bytes(), summaries, nil
}
func safe7BitMessage(data []byte) bool {
	for i, c := range data {
		if c >= 127 || (c < 32 && c != '\r' && c != '\n' && c != '\t') || (c == '\r' && (i+1 == len(data) || data[i+1] != '\n')) || (c == '\n' && (i == 0 || data[i-1] != '\r')) {
			return false
		}
	}
	for _, line := range bytes.Split(data, []byte("\r\n")) {
		if len(line) > 998 {
			return false
		}
	}
	_, err := mail.ReadMessage(bytes.NewReader(data))
	return err == nil && bytes.Contains(data, []byte("\r\n\r\n"))
}

// DraftBytes preserves Bcc in the private IMAP draft, never in outbound SMTP.
func DraftBytes(p Prepared) ([]byte, error) {
	if len(p.Bcc) == 0 {
		return append([]byte(nil), p.Raw...), nil
	}
	bcc, _, err := addresses(p.Bcc)
	if err != nil {
		return nil, err
	}
	var header bytes.Buffer
	writeHeader(&header, "Bcc", strings.Join(bcc, ", "))
	raw := append(header.Bytes(), p.Raw...)
	if len(raw) > MaxMessageBytes {
		return nil, errors.New("draft too large")
	}
	return raw, nil
}

// WireDigest binds SMTP envelope (including Bcc) to the exact approved MIME bytes.
func WireDigest(from string, recipients []string, raw []byte) string {
	binding, _ := json.Marshal(struct {
		From       string
		Recipients []string
		Raw        []byte
	}{from, recipients, raw})
	sum := sha256.Sum256(binding)
	return hex.EncodeToString(sum[:])
}

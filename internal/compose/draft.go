package compose

import (
	"bufio"
	"bytes"
	"encoding/base64"
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
)

// ErrUnsupportedDraft refuses MIME that Input cannot faithfully represent. This
// is intentionally not a general raw-MIME editor or a permissive mail renderer.
var ErrUnsupportedDraft = errors.New("draft is outside the supported structured MIME subset")

const maxDraftHeaderBytes = 64 << 10

// DraftContent retains authored alternatives and every attachment's decoded
// bytes. From and MessageID describe the source; rebuilding uses the configured
// sender and a new Date/Message-ID. No HTML is rendered or remotely fetched.
type DraftContent struct {
	From      string `json:"from"`
	MessageID string `json:"message_id,omitempty"`
	Message   Input  `json:"message"`
}

func draftUnsupported(reason string) error {
	return fmt.Errorf("%w: %s", ErrUnsupportedDraft, reason)
}

// ParseDraft accepts text/plain, text/html, a plain-then-HTML alternative, and a
// mixed container whose first part is one of those bodies and whose remaining
// parts are named attachments. Everything else fails closed, including unknown
// headers, inline/CID resources, MIME preambles/epilogues, and signed containers.
func ParseDraft(raw []byte) (DraftContent, error) {
	var out DraftContent
	if len(raw) == 0 || len(raw) > MaxMessageBytes {
		return out, draftUnsupported("complete source must be at most 5 MiB")
	}
	h, body, err := draftHeader(raw, true)
	if err != nil {
		return out, err
	}
	for _, key := range []string{"From", "To", "Cc", "Bcc"} {
		value := h.Get(key)
		if value == "" {
			if key == "From" {
				return out, draftUnsupported("a single From address is required")
			}
			continue
		}
		parsed, err := mail.ParseAddressList(value)
		if err != nil || len(parsed) == 0 || key == "From" && len(parsed) != 1 {
			return out, draftUnsupported("invalid address header")
		}
		values := make([]string, 0, len(parsed))
		for _, a := range parsed {
			values = append(values, a.String())
		}
		if _, _, err := addresses(values); err != nil {
			return out, draftUnsupported("unsupported address header")
		}
		switch key {
		case "From":
			out.From = values[0]
		case "To":
			out.Message.To = values
		case "Cc":
			out.Message.Cc = values
		case "Bcc":
			out.Message.Bcc = values
		}
	}
	if out.Message.Subject, err = new(mime.WordDecoder).DecodeHeader(h.Get("Subject")); err != nil {
		return out, draftUnsupported("invalid subject encoding")
	}
	if value := h.Get("Date"); value != "" {
		if _, err := mail.ParseDate(value); err != nil {
			return out, draftUnsupported("invalid Date")
		}
	}
	if value := h.Get("Message-Id"); value != "" {
		var ok bool
		if out.MessageID, ok = NormalizeMessageID(value); !ok {
			return out, draftUnsupported("invalid Message-ID")
		}
	}
	if value := h.Get("In-Reply-To"); value != "" {
		var ok bool
		if out.Message.InReplyTo, ok = NormalizeMessageID(value); !ok {
			return out, draftUnsupported("unsupported In-Reply-To")
		}
	}
	if value := h.Get("References"); value != "" {
		for _, value := range strings.Fields(value) {
			id, ok := NormalizeMessageID(value)
			if !ok {
				return out, draftUnsupported("unsupported References")
			}
			out.Message.References = append(out.Message.References, id)
		}
	}
	if version := h.Get("Mime-Version"); version != "" && version != "1.0" {
		return out, draftUnsupported("unsupported MIME version")
	}
	ct, params, err := draftMediaType(h)
	if err != nil {
		return out, err
	}
	if ct == "multipart/mixed" {
		parts, err := draftMultipart(h, body, params, 21)
		if err != nil {
			return out, err
		}
		if len(parts) < 2 {
			return out, draftUnsupported("mixed container must contain a body and attachments")
		}
		first, content, err := draftHeader(parts[0], false)
		if err != nil {
			return out, err
		}
		if err := draftBody(first, content, &out.Message); err != nil {
			return out, err
		}
		total := 0
		for _, rawPart := range parts[1:] {
			ph, content, err := draftHeader(rawPart, false)
			if err != nil {
				return out, err
			}
			ct, params, err := draftMediaType(ph)
			if err != nil || strings.HasPrefix(ct, "multipart/") {
				return out, draftUnsupported("unsupported attachment content type")
			}
			disp, dparams, err := mime.ParseMediaType(ph.Get("Content-Disposition"))
			if err != nil || disp != "attachment" || len(dparams) != 1 || dparams["filename"] == "" {
				return out, draftUnsupported("attachments require only an explicit filename disposition; inline resources are unsupported")
			}
			data, err := draftDecode(ph, content, MaxAttachmentBytes-total)
			if err != nil {
				return out, err
			}
			total += len(data)
			out.Message.Attachments = append(out.Message.Attachments, Attachment{Filename: dparams["filename"], ContentType: mime.FormatMediaType(ct, params), DataBase64: base64.StdEncoding.EncodeToString(data)})
		}
	} else if err := draftBody(h, body, &out.Message); err != nil {
		return out, err
	}
	// Reuse the outbound validator without changing the retrieved source fields.
	// This verifies all lengths, UTF-8, filenames, threading and attachment types.
	prepared, err := BuildDraft(out.From, out.Message, strings.Repeat("0", 32), time.Unix(0, 0))
	if err == nil {
		_, err = DraftBytes(prepared)
	}
	if err != nil {
		return DraftContent{}, draftUnsupported("source cannot be rebuilt safely: " + err.Error())
	}
	return out, nil
}

func draftHeader(raw []byte, outer bool) (textproto.MIMEHeader, []byte, error) {
	end := bytes.Index(raw, []byte("\r\n\r\n"))
	if end < 0 || end+4 > maxDraftHeaderBytes {
		return nil, nil, draftUnsupported("missing or oversized CRLF header block")
	}
	header := raw[:end+4]
	for i, c := range header {
		if c == '\r' && (i+1 == len(header) || header[i+1] != '\n') || c == '\n' && (i == 0 || header[i-1] != '\r') || c < 32 && c != '\r' && c != '\n' && c != '\t' || c == 127 {
			return nil, nil, draftUnsupported("invalid header control or newline")
		}
	}
	h, err := textproto.NewReader(bufio.NewReader(bytes.NewReader(header))).ReadMIMEHeader()
	if err != nil {
		return nil, nil, draftUnsupported("malformed MIME header")
	}
	allowed := map[string]bool{"Content-Type": true, "Content-Transfer-Encoding": true, "Content-Disposition": true}
	if outer {
		for _, key := range []string{"From", "To", "Cc", "Bcc", "Subject", "Date", "Message-Id", "In-Reply-To", "References", "Mime-Version"} {
			allowed[key] = true
		}
	}
	for key, values := range h {
		if !allowed[key] || len(values) != 1 {
			return nil, nil, draftUnsupported("unknown or duplicate header " + key)
		}
	}
	return h, raw[end+4:], nil
}

func draftMediaType(h textproto.MIMEHeader) (string, map[string]string, error) {
	value := h.Get("Content-Type")
	if value == "" {
		value = "text/plain; charset=us-ascii"
	}
	ct, params, err := mime.ParseMediaType(value)
	if err != nil || !strings.Contains(ct, "/") {
		return "", nil, draftUnsupported("invalid Content-Type")
	}
	return ct, params, nil
}

func draftBody(h textproto.MIMEHeader, body []byte, out *Input) error {
	if h.Get("Content-Disposition") != "" {
		return draftUnsupported("body dispositions are unsupported")
	}
	ct, params, err := draftMediaType(h)
	if err != nil {
		return err
	}
	if ct == "multipart/alternative" {
		parts, err := draftMultipart(h, body, params, 2)
		if err != nil {
			return err
		}
		if len(parts) != 2 {
			return draftUnsupported("alternative requires exactly plain text then HTML")
		}
		for i, rawPart := range parts {
			ph, content, err := draftHeader(rawPart, false)
			if err != nil {
				return err
			}
			media, _, err := draftMediaType(ph)
			if err != nil || media != []string{"text/plain", "text/html"}[i] {
				return draftUnsupported("alternative requires exactly plain text then HTML")
			}
			if err := draftBody(ph, content, out); err != nil {
				return err
			}
		}
		return nil
	}
	if ct != "text/plain" && ct != "text/html" {
		return draftUnsupported("unsupported body MIME type")
	}
	for key, value := range params {
		if key != "charset" || !strings.EqualFold(value, "utf-8") && !strings.EqualFold(value, "us-ascii") {
			return draftUnsupported("only UTF-8 or US-ASCII body charsets without other parameters are supported")
		}
	}
	data, err := draftDecode(h, body, MaxTextBytes)
	if err != nil {
		return err
	}
	if params["charset"] == "" || strings.EqualFold(params["charset"], "us-ascii") {
		if !ascii(string(data)) {
			return draftUnsupported("non-ASCII body without UTF-8 charset")
		}
	}
	if !validBody(string(data)) {
		return draftUnsupported("invalid or oversized body")
	}
	if ct == "text/plain" {
		out.Text = string(data)
		out.PreserveEmptyText = true
	} else {
		if len(data) == 0 {
			return draftUnsupported("an empty HTML alternative cannot be represented safely")
		}
		out.HTML = string(data)
	}
	return nil
}

// Only exact CRLF boundary lines are accepted. Empty preambles/epilogues ensure
// no unrepresented data disappears during rebuilding. Multipart parsing cannot
// silently discard malformed child headers or stop before an extra body part.
func draftMultipart(h textproto.MIMEHeader, body []byte, params map[string]string, maxParts int) ([][]byte, error) {
	if h.Get("Content-Disposition") != "" || len(params) != 1 || params["boundary"] == "" || len(params["boundary"]) > 70 || invalid(params["boundary"]) {
		return nil, draftUnsupported("unsupported multipart parameters or disposition")
	}
	if cte := strings.ToLower(h.Get("Content-Transfer-Encoding")); cte != "" && cte != "7bit" && cte != "8bit" && cte != "binary" {
		return nil, draftUnsupported("encoded multipart is unsupported")
	}
	if err := multipart.NewWriter(io.Discard).SetBoundary(params["boundary"]); err != nil {
		return nil, draftUnsupported("invalid multipart boundary")
	}
	boundary := []byte("--" + params["boundary"])
	opening := append(append([]byte(nil), boundary...), '\r', '\n')
	if !bytes.HasPrefix(body, opening) {
		return nil, draftUnsupported("multipart preamble or opening boundary is unsupported")
	}
	remaining := body[len(opening):]
	delimiter := append([]byte("\r\n"), boundary...)
	parts := make([][]byte, 0, maxParts)
	for {
		at := -1
		for start := 0; start < len(remaining); {
			n := bytes.Index(remaining[start:], delimiter)
			if n < 0 {
				break
			}
			n += start
			tail := remaining[n+len(delimiter):]
			if bytes.HasPrefix(tail, []byte("\r\n")) || bytes.HasPrefix(tail, []byte("--")) {
				at = n
				break
			}
			start = n + len(delimiter)
		}
		if at < 0 || len(parts) == maxParts {
			return nil, draftUnsupported("incomplete multipart or too many parts")
		}
		parts = append(parts, remaining[:at])
		remaining = remaining[at+len(delimiter):]
		if bytes.HasPrefix(remaining, []byte("--")) {
			trailing := remaining[2:]
			if len(trailing) != 0 && !bytes.Equal(trailing, []byte("\r\n")) {
				return nil, draftUnsupported("multipart epilogue is unsupported")
			}
			return parts, nil
		}
		remaining = remaining[2:]
	}
}

func draftDecode(h textproto.MIMEHeader, body []byte, limit int) ([]byte, error) {
	var reader io.Reader = bytes.NewReader(body)
	switch strings.ToLower(h.Get("Content-Transfer-Encoding")) {
	case "", "7bit":
		if !ascii(string(body)) {
			return nil, draftUnsupported("non-ASCII 7bit content")
		}
	case "8bit", "binary":
	case "base64":
		reader = base64.NewDecoder(base64.StdEncoding.Strict(), reader)
	case "quoted-printable":
		hex := func(c byte) bool { return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' }
		for i := 0; i < len(body); i++ {
			if body[i] != '=' {
				continue
			}
			if i+2 >= len(body) || !(body[i+1] == '\r' && body[i+2] == '\n' || hex(body[i+1]) && hex(body[i+2])) {
				return nil, draftUnsupported("invalid quoted-printable content")
			}
			i += 2
		}
		reader = quotedprintable.NewReader(reader)
	default:
		return nil, draftUnsupported("unknown transfer encoding")
	}
	data, err := io.ReadAll(io.LimitReader(reader, int64(limit)+1))
	if err != nil || len(data) > limit {
		return nil, draftUnsupported("invalid or oversized decoded content")
	}
	return data, nil
}

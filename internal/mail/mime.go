package mail

import (
	"bufio"
	"bytes"
	"io"
	"mime"
	"strings"

	"github.com/emersion/go-message"
	_ "github.com/emersion/go-message/charset"
	"github.com/emersion/go-message/textproto"
)

const maxMIMEHeaderBytes = 64 << 10

// readMIMEHeader bounds only the header, keeping buffered and unread body bytes
// available without transfer or charset decoding. A sentinel byte distinguishes
// an exhausted header budget from a genuine header-only message.
func readMIMEHeader(raw []byte) (message.Header, io.Reader, error) {
	limited := &io.LimitedReader{R: bytes.NewReader(raw), N: maxMIMEHeaderBytes + 1}
	buffered := bufio.NewReader(limited)
	h, err := textproto.ReadHeader(buffered)
	consumed := maxMIMEHeaderBytes + 1 - limited.N - int64(buffered.Buffered())
	if consumed > maxMIMEHeaderBytes {
		return message.Header{}, nil, ErrLimit
	}
	if err != nil {
		return message.Header{}, nil, ErrInvalidInput
	}
	limited.N = int64(len(raw)) // The header limit must never clip the body.
	return message.Header{Header: h}, buffered, nil
}

// mimeHeaderGuard counts raw child-header bytes before the multipart parser can
// discard malformed fields or unfold whitespace. It recognizes only the current
// container's boundary lines; field and body parsing remain with textproto.
// ReadSlice caps its buffer, including when an attacker sends a giant line.
type mimeHeaderGuard struct {
	reader        *bufio.Reader
	boundary      []byte
	newline       []byte
	pending       []byte
	err           error
	inHeader      bool
	lineStart     bool // Header lines tolerate bare LF.
	boundaryStart bool // Body boundaries require the container newline.
	lastByte      byte
	seenBoundary  bool
	closed        bool
	headerBytes   int
	limitExceeded bool
}

func guardMIMEHeaders(body io.Reader, boundary string) *mimeHeaderGuard {
	return &mimeHeaderGuard{reader: bufio.NewReader(body), boundary: []byte("--" + boundary), newline: []byte("\r\n"), lineStart: true, boundaryStart: true}
}

func (g *mimeHeaderGuard) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(g.pending) == 0 {
		if g.err != nil {
			return 0, g.err
		}
		line, err := g.reader.ReadSlice('\n')
		if err != nil && err != bufio.ErrBufferFull {
			g.err = err
		}
		bodyStart := false
		if g.inHeader {
			g.headerBytes += len(line)
			if g.headerBytes > maxMIMEHeaderBytes {
				g.limitExceeded = true
				g.err = ErrLimit
				return 0, g.err
			}
			if g.lineStart && (bytes.Equal(line, []byte("\r\n")) || bytes.Equal(line, []byte("\n"))) {
				g.inHeader = false
				bodyStart = true
			}
		} else if (g.boundaryStart || (!g.seenBoundary && g.lineStart)) && !g.closed && err != bufio.ErrBufferFull && bytes.HasPrefix(line, g.boundary) {
			rest := line[len(g.boundary):]
			if bytes.HasPrefix(rest, []byte("--")) {
				rest = bytes.TrimLeft(rest[2:], " \t")
				if len(rest) == 0 || bytes.Equal(rest, g.newline) {
					g.closed = true
				}
			} else {
				rest = bytes.TrimLeft(rest, " \t")
				// Match the multipart parser's first-boundary LF compatibility behavior.
				if !g.seenBoundary && bytes.Equal(rest, []byte("\n")) {
					g.newline = []byte("\n")
				}
				if bytes.Equal(rest, g.newline) {
					g.seenBoundary = true
					g.inHeader = true
					g.headerBytes = 0
				}
			}
		}
		g.lineStart = bytes.HasSuffix(line, []byte("\n"))
		g.boundaryStart = bytes.HasSuffix(line, g.newline)
		if len(g.newline) == 2 && len(line) == 1 && line[0] == '\n' && g.lastByte == '\r' {
			// ReadSlice can split CRLF across its fixed-size buffer chunks.
			g.boundaryStart = true
		}
		if bodyStart {
			// textproto also recognizes a delimiter at byte zero of a part
			// body, even after a bare-LF header terminator in CRLF mode.
			g.boundaryStart = true
		}
		if len(line) > 0 {
			g.lastByte = line[len(line)-1]
		}
		g.pending = line
		if len(g.pending) == 0 {
			return 0, g.err
		}
	}
	n := copy(p, g.pending)
	g.pending = g.pending[n:]
	return n, nil
}

// attachmentBody decodes the transfer encoding, never the text charset. Using
// the original Content-Type with message.New would rewrite text attachments to
// UTF-8, and multipart types would skip transfer decoding altogether.
func attachmentBody(h message.Header, body io.Reader) (io.Reader, error) {
	var encodingHeader message.Header
	encodingHeader.Set("Content-Type", "application/octet-stream")
	encodingHeader.Set("Content-Transfer-Encoding", h.Get("Content-Transfer-Encoding"))
	e, err := message.New(encodingHeader, body)
	if err != nil {
		return nil, ErrInvalidInput
	}
	return e.Body, nil
}

func parseMessage(raw []byte, out *Message) { parseMessageAttachment(raw, out, 0) }
func parseMessageAttachment(raw []byte, out *Message, target int) ([]byte, error) {
	var attachmentData []byte
	var attachmentErr, incompleteErr error

	h, body, err := readMIMEHeader(raw)
	if err != nil {
		out.Warnings = append(out.Warnings, "Message headers could not be parsed within safety limits.")
		out.Truncated = true
		return nil, err
	}
	if out.Headers == nil {
		out.Headers = map[string]string{}
	}
	for _, key := range []string{"From", "To", "Cc", "Reply-To", "Subject", "Date", "Message-Id", "In-Reply-To", "References"} {
		v, _ := h.Text(key)
		if v != "" {
			out.Headers[key] = cleanHeader(v, 4096)
		}
	}
	incomplete := func(err error) {
		out.Truncated = true
		if incompleteErr == nil || err == ErrLimit {
			incompleteErr = err
		}
	}
	parts := 0
	var text, htmlFallback strings.Builder
	var walk func(message.Header, io.Reader, int)
	walk = func(h message.Header, body io.Reader, depth int) {
		parts++
		if depth > 12 || parts > 100 {
			incomplete(ErrLimit)
			return
		}
		ct, params, ctErr := h.ContentType()
		disp, dparams, dispErr := h.ContentDisposition()
		if ctErr != nil || (dispErr != nil && h.Get("Content-Disposition") != "") {
			incomplete(ErrInvalidInput)
			return
		}
		filename := dparams["filename"]
		if filename == "" {
			filename = params["name"]
		}
		isMultipart := strings.HasPrefix(ct, "multipart/")
		// An attached multipart is one opaque attachment. Descending first would
		// omit it from the inventory and leak its children into inline forwards.
		if strings.EqualFold(disp, "attachment") || filename != "" || (!isMultipart && !strings.HasPrefix(ct, "text/") && ct != "") {
			index := len(out.Attachments) + 1
			// Keep interpretive parameters with byte-exact downloads: losing a
			// text charset or multipart boundary breaks an explicit forward.
			contentType := mime.FormatMediaType(ct, params)
			if contentType == "" || len(contentType) > 4096 {
				incomplete(ErrLimit)
				return
			}
			decoded, err := attachmentBody(h, body)
			var n int64
			if err == nil {
				if index == target {
					attachmentData, err = io.ReadAll(io.LimitReader(decoded, (2<<20)+1))
					n = int64(len(attachmentData))
					if n > 2<<20 {
						attachmentErr = ErrLimit
						attachmentData = nil
					}
				} else {
					n, err = io.Copy(io.Discard, io.LimitReader(decoded, maxMessageBytes+1))
				}
			}
			if err != nil || n > maxMessageBytes {
				incomplete(ErrInvalidInput)
				if index == target {
					attachmentErr = ErrInvalidInput
					attachmentData = nil
				}
			}
			out.Attachments = append(out.Attachments, Attachment{Index: index, Filename: cleanHeader(filename, 1024), ContentType: contentType, Size: n})
			return
		}
		if isMultipart {
			// RFC 2045 permits only identity encodings on inline multipart.
			// Decoding a container could hide a transfer error after its closing
			// boundary, where multipart readers legitimately stop reading.
			switch strings.ToLower(h.Get("Content-Transfer-Encoding")) {
			case "", "7bit", "8bit", "binary":
			default:
				incomplete(ErrInvalidInput)
				return
			}
			guarded := guardMIMEHeaders(body, params["boundary"])
			mr := textproto.NewMultipartReader(guarded, params["boundary"])
			for parts < 100 {
				part, err := mr.NextPart()
				if err == io.EOF {
					return
				}
				if err != nil {
					if guarded.limitExceeded {
						incomplete(ErrLimit)
					} else {
						incomplete(ErrInvalidInput)
					}
					return
				}
				walk(message.Header{Header: part.Header}, part, depth+1)
				if depth >= 12 || parts >= 100 {
					incomplete(ErrLimit)
					return
				}
			}
			return
		}
		if ct != "text/plain" && ct != "text/html" && ct != "" {
			return
		}
		// Only displayed inline text gets charset conversion. Unknown transfer
		// encodings/charsets make it incomplete, blocking reply/forward use.
		e, err := message.New(h, body)
		if err != nil {
			incomplete(ErrInvalidInput)
			return
		}
		if ct == "text/html" {
			if htmlFallback.Len() < maxTextBytes {
				value, truncated := htmlText(e.Body)
				remaining := maxTextBytes - htmlFallback.Len()
				if len(value) > remaining {
					value = clean(value, remaining)
					truncated = true
				}
				htmlFallback.WriteString(value)
				if truncated {
					incomplete(ErrLimit)
				}
			} else {
				incomplete(ErrLimit)
			}
			return
		}
		remaining := maxTextBytes - text.Len()
		if text.Len() > 0 {
			remaining-- // Reserve the separator within the global text budget.
		}
		if remaining <= 0 {
			incomplete(ErrLimit)
			return
		}
		data, err := io.ReadAll(io.LimitReader(e.Body, int64(remaining+1)))
		if err != nil {
			incomplete(ErrInvalidInput)
		}
		if len(data) > remaining {
			data = data[:remaining]
			incomplete(ErrLimit)
		}
		if text.Len() > 0 {
			text.WriteByte('\n')
		}
		text.WriteString(clean(string(data), remaining))
	}
	walk(h, body, 0)
	out.Text = clean(text.String(), maxTextBytes)
	if out.Text == "" && htmlFallback.Len() > 0 {
		out.Text = clean(htmlFallback.String(), maxTextBytes)
		out.Warnings = append(out.Warnings, "Text extracted from HTML; styling, scripts, and remote images are omitted. Selected absolute HTTP(S)/mailto link destinations are included as untrusted text, not verified or fetched.")
	}
	if out.Truncated {
		out.Warnings = append(out.Warnings, "Message exceeds read limits or contains incomplete MIME data; returned content may be partial.")
	}
	if attachmentErr != nil {
		return nil, attachmentErr
	}
	if target > 0 && len(out.Attachments) < target {
		if incompleteErr != nil {
			return nil, incompleteErr
		}
		return nil, ErrNotFound
	}
	return attachmentData, nil
}

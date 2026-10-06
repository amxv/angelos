package mail

import (
	"bytes"
	"io"
	"strings"

	"github.com/emersion/go-message"
	_ "github.com/emersion/go-message/charset"
)

func parseMessage(raw []byte, out *Message) { parseMessageAttachment(raw, out, 0) }
func parseMessageAttachment(raw []byte, out *Message, target int) ([]byte, error) {
	var attachmentData []byte
	var attachmentErr error

	e, err := message.ReadWithOptions(bytes.NewReader(raw), &message.ReadOptions{MaxHeaderBytes: 64 << 10})
	if e == nil {
		out.Warnings = append(out.Warnings, "Message headers could not be parsed within safety limits.")
		out.Truncated = true
		return nil, ErrInvalidInput
	}
	if err != nil {
		out.Warnings = append(out.Warnings, "Some message encoding could not be decoded.")
	}
	for _, key := range []string{"From", "To", "Cc", "Reply-To", "Subject", "Date", "Message-Id", "In-Reply-To", "References"} {
		v, _ := e.Header.Text(key)
		if v != "" {
			out.Headers[key] = cleanHeader(v, 4096)
		}
	}
	parts := 0
	var text, htmlFallback strings.Builder
	var walk func(*message.Entity, int)
	walk = func(e *message.Entity, depth int) {
		parts++
		if depth > 12 || parts > 100 {
			out.Truncated = true
			return
		}
		if mr := e.MultipartReader(); mr != nil {
			for parts < 100 {
				part, err := mr.NextPart()
				if err == io.EOF {
					return
				}
				if part == nil {
					out.Truncated = true
					return
				}
				walk(part, depth+1)
				if depth >= 12 || parts >= 100 {
					out.Truncated = true
					return
				}
			}
			return
		}
		ct, params, _ := e.Header.ContentType()
		disp, dparams, _ := e.Header.ContentDisposition()
		filename := dparams["filename"]
		if filename == "" {
			filename = params["name"]
		}
		if strings.EqualFold(disp, "attachment") || filename != "" || (!strings.HasPrefix(ct, "text/") && ct != "") {
			// Count decoded attachment bytes, but never return payload or fetch a URL.
			index := len(out.Attachments) + 1
			var n int64
			var err error
			if index == target {
				attachmentData, err = io.ReadAll(io.LimitReader(e.Body, (2<<20)+1))
				n = int64(len(attachmentData))
				if n > 2<<20 {
					attachmentErr = ErrLimit
					attachmentData = nil
				}
			} else {
				n, err = io.Copy(io.Discard, io.LimitReader(e.Body, maxMessageBytes+1))
			}
			if err != nil || n > maxMessageBytes {
				out.Truncated = true
				if index == target {
					attachmentErr = ErrInvalidInput
				}
			}
			out.Attachments = append(out.Attachments, Attachment{Index: index, Filename: cleanHeader(filename, 1024), ContentType: cleanHeader(ct, 256), Size: n})
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
					out.Truncated = true
				}
			}
			return
		}
		if ct != "text/plain" && ct != "" {
			return
		}
		remaining := maxTextBytes - text.Len()
		if remaining <= 0 {
			out.Truncated = true
			return
		}
		body, err := io.ReadAll(io.LimitReader(e.Body, int64(remaining+1)))
		if err != nil {
			out.Truncated = true
		}
		if len(body) > remaining {
			body = body[:remaining]
			out.Truncated = true
		}
		if text.Len() > 0 {
			text.WriteByte('\n')
		}
		text.WriteString(clean(string(body), remaining))
	}
	walk(e, 0)
	out.Text = clean(text.String(), maxTextBytes)
	if out.Text == "" && htmlFallback.Len() > 0 {
		out.Text = clean(htmlFallback.String(), maxTextBytes)
		out.Warnings = append(out.Warnings, "Text extracted from HTML; styling, scripts, links, and remote images are omitted.")
	}
	if out.Truncated {
		out.Warnings = append(out.Warnings, "Message exceeds read limits or contains incomplete MIME data; returned content may be partial.")
	}
	if target > 0 && len(out.Attachments) < target {
		return nil, ErrNotFound
	}
	return attachmentData, attachmentErr
}

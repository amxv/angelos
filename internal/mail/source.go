package mail

import (
	"bytes"
	"errors"
	"strings"

	"github.com/emersion/go-message"
)

var compositionHeaderNames = []string{"From", "Reply-To", "To", "Cc", "Message-Id", "In-Reply-To", "References", "Date", "Subject"}

// CompositionHeaders exposes complete bounded source fields to composition.
// Address and identifier fields retain their structured syntax: decoding an
// entire address field as RFC 2047 text could turn a display-name comma into a
// new recipient. Only Subject is decoded. Duplicate fields fail closed.
// Headers is a compatibility fallback for test/custom Readers without raw data;
// production reads always use the original message bytes, never clipped output.
func (m Message) CompositionHeaders() (map[string]string, error) {
	var h message.Header
	if len(m.raw) > 0 {
		var err error
		h, _, err = readMIMEHeader(m.raw)
		if err != nil {
			return nil, err
		}
	} else {
		values := make(map[string][]string)
		total := 0
		for key, value := range m.Headers {
			for _, allowed := range compositionHeaderNames {
				if !strings.EqualFold(key, allowed) {
					continue
				}
				total += len(key) + len(value) + 4
				if total > maxMIMEHeaderBytes {
					return nil, ErrLimit
				}
				values[allowed] = append(values[allowed], value)
			}
		}
		h = message.HeaderFromMap(values)
	}
	out := make(map[string]string)
	for _, key := range compositionHeaderNames {
		fields := h.FieldsByKey(key)
		if !fields.Next() {
			continue
		}
		value := fields.Value()
		if fields.Next() {
			return nil, errors.New("source contains duplicate composition header fields")
		}
		if key == "Subject" {
			var err error
			value, err = h.Text(key)
			if err != nil {
				return nil, errors.New("source subject encoding is invalid")
			}
		}
		if len(value) > maxMIMEHeaderBytes || strings.ContainsAny(value, "\r\n\x00") {
			return nil, ErrInvalidInput
		}
		out[key] = value
	}
	return out, nil
}

// SanitizedEML returns the original bytes with outer Bcc and Resent-Bcc fields
// (including their continuations) removed. All other bytes, including embedded
// messages and attachments, are unchanged and may contain private information.
// It deliberately does not reconstruct a message from parsed/snippet fields.
func (m Message) SanitizedEML() ([]byte, error) {
	if len(m.raw) == 0 {
		return nil, errors.New("complete raw source is unavailable for attached-EML forwarding")
	}
	if m.Truncated || len(m.raw) > maxMessageBytes || m.Size > int64(len(m.raw)) {
		return nil, ErrLimit
	}
	if _, _, err := readMIMEHeader(m.raw); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	skip := false
	for start := 0; start < len(m.raw); {
		end := bytes.IndexByte(m.raw[start:], '\n')
		if end < 0 {
			return nil, ErrInvalidInput
		}
		end += start + 1
		line := m.raw[start:end]
		if bytes.Equal(line, []byte("\r\n")) || bytes.Equal(line, []byte("\n")) {
			out.Write(m.raw[start:])
			return out.Bytes(), nil
		}
		if line[0] != ' ' && line[0] != '\t' {
			colon := bytes.IndexByte(line, ':')
			if colon < 0 {
				return nil, ErrInvalidInput
			}
			key := string(bytes.Trim(line[:colon], " \t"))
			skip = strings.EqualFold(key, "Bcc") || strings.EqualFold(key, "Resent-Bcc")
		}
		if !skip {
			out.Write(line)
		}
		start = end
	}
	return nil, ErrInvalidInput
}

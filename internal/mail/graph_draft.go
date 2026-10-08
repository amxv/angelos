package mail

import (
	"bytes"
	"strings"
)

// Exchange adds transport-only metadata while materializing MIME. Only this
// explicit inert outer-header set may be discarded for structured draft editing.
// Authored/semantic headers (including sensitivity, rights-management, signatures,
// Resent-*, Sender and unknown X-* headers) still reach the strict parser and fail.
var graphInertDraftHeaders = map[string]bool{
	"received": true, "return-path": true,
	"thread-topic": true, "thread-index": true,
	"accept-language": true, "content-language": true,
	"x-ms-has-attach":                                   true,
	"x-ms-exchange-organization-authas":                 true,
	"x-ms-exchange-organization-authsource":             true,
	"x-ms-exchange-organization-network-message-id":     true,
	"x-ms-exchange-organization-messagedirectionality":  true,
	"x-ms-exchange-organization-scl":                    true,
	"x-ms-exchange-crosstenant-authas":                  true,
	"x-ms-exchange-crosstenant-authsource":              true,
	"x-ms-exchange-crosstenant-id":                      true,
	"x-ms-exchange-crosstenant-fromentityheader":        true,
	"x-ms-exchange-crosstenant-network-message-id":      true,
	"x-ms-exchange-crosstenant-originalarrivaltime":     true,
	"x-ms-exchange-transport-crosstenantheadersstamped": true,
	"x-ms-traffictypediagnostic":                        true,
	"x-ms-office365-filtering-correlation-id":           true,
}

func graphStructuredDraftSource(raw []byte) ([]byte, error) {
	end := bytes.Index(raw, []byte("\r\n\r\n"))
	if end < 0 || end > maxMIMEHeaderBytes {
		return nil, ErrUnsupported
	}
	header := raw[:end+2]
	for i, c := range header {
		if c == '\r' && (i+1 == len(header) || header[i+1] != '\n') || c == '\n' && (i == 0 || header[i-1] != '\r') || c < 32 && c != '\r' && c != '\n' && c != '\t' || c == 127 {
			return nil, ErrUnsupported
		}
	}
	h, _, e := readMIMEHeader(raw)
	if e != nil {
		return nil, ErrUnsupported
	}
	fields := h.FieldsByKey("X-MS-TNEF-Correlator")
	emptyCorrelator := false
	if fields.Next() {
		emptyCorrelator = strings.TrimSpace(fields.Value()) == ""
		if fields.Next() {
			emptyCorrelator = false
		}
	}
	var out bytes.Buffer
	skip := false
	for _, line := range bytes.Split(header, []byte("\r\n")) {
		if len(line) == 0 {
			continue
		}
		if line[0] != ' ' && line[0] != '\t' {
			colon := bytes.IndexByte(line, ':')
			if colon <= 0 {
				return nil, ErrUnsupported
			}
			name := strings.ToLower(string(line[:colon]))
			skip = graphInertDraftHeaders[name]
			// Empty TNEF correlators are Exchange bookkeeping. A nonempty one is not
			// silently discarded, even if its MIME structure superficially looks simple.
			if name == "x-ms-tnef-correlator" && emptyCorrelator {
				skip = true
			}
		}
		if !skip {
			out.Write(line)
			out.WriteString("\r\n")
		}
	}
	out.WriteString("\r\n")
	out.Write(raw[end+4:])
	return out.Bytes(), nil
}

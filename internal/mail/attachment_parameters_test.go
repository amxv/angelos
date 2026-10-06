package mail

import (
	"mime"
	"strings"
	"testing"
)

func TestAttachmentContentTypePreservesInterpretiveParameters(t *testing.T) {
	for _, contentType := range []string{"text/plain; charset=iso-8859-1", "multipart/mixed; boundary=original-boundary"} {
		raw := "Content-Type: " + contentType + "\r\nContent-Disposition: attachment; filename=original.bin\r\n\r\nORIGINAL BYTES"
		var message Message
		payload, err := parseMessageAttachment([]byte(raw), &message, 1)
		if err != nil || string(payload) != "ORIGINAL BYTES" || len(message.Attachments) != 1 {
			t.Fatalf("payload=%q error=%v inventory=%+v", payload, err, message.Attachments)
		}
		wantType, wantParams, _ := mime.ParseMediaType(contentType)
		gotType, gotParams, err := mime.ParseMediaType(message.Attachments[0].ContentType)
		if err != nil || gotType != wantType || len(gotParams) != len(wantParams) {
			t.Fatal("attachment content type changed")
		}
		for key, value := range wantParams {
			if gotParams[key] != value {
				t.Fatalf("lost %s parameter", key)
			}
		}
	}
}

func TestOversizedAttachmentContentTypeCannotBeSilentlyClipped(t *testing.T) {
	raw := "Content-Type: application/octet-stream; description=" + strings.Repeat("x", 4096) + "\r\nContent-Disposition: attachment; filename=a.bin\r\n\r\nPAYLOAD"
	var message Message
	payload, err := parseMessageAttachment([]byte(raw), &message, 1)
	if err != ErrLimit || len(payload) != 0 || !message.Truncated {
		t.Fatalf("payload=%q error=%v truncated=%v", payload, err, message.Truncated)
	}
}

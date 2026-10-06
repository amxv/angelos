package mail

import (
	"context"
	"encoding/base64"
)

// GetAttachment re-reads the immutable UID message and returns a MIME attachment
// by its one-based index from Read. Whole RFC822 message limit: 5 MiB; decoded
// attachment limit: 2 MiB. No attachment is opened, executed, or remotely fetched.
func (b *Backend) GetAttachment(ctx context.Context, ref Reference, index int) (AttachmentResult, error) {
	result := AttachmentResult{Reference: ref}
	if index < 1 || index > 100 {
		return result, ErrInvalidInput
	}
	msg, err := b.Read(ctx, ref)
	if err != nil {
		return result, err
	}
	if msg.Size > int64(len(msg.raw)) {
		return result, ErrLimit
	}
	parsed := Message{Headers: map[string]string{}, Attachments: []Attachment{}}
	payload, err := parseMessageAttachment(msg.raw, &parsed, index)
	if err != nil {
		return result, err
	}
	if len(parsed.Attachments) < index {
		return result, ErrNotFound
	}
	result.Attachment = parsed.Attachments[index-1]
	result.DataBase64 = base64.StdEncoding.EncodeToString(payload)
	return result, nil
}

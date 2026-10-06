package app

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"mime"
	stdmail "net/mail"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/amxv/angelos/internal/compose"
	"github.com/amxv/angelos/internal/mail"
	gomail "github.com/emersion/go-message/mail"
)

func compositionSource(message mail.Message, replying bool) (compose.Source, []string, error) {
	headers, err := message.CompositionHeaders()
	if err != nil {
		return compose.Source{}, nil, err
	}
	source := compose.Source{Text: message.Text, Subject: message.Subject}
	warnings := append([]string(nil), message.Warnings...)
	if value, present := headers["Subject"]; present {
		source.Subject = value
	}
	for _, field := range []struct {
		key      string
		target   *[]string
		fallback []mail.Address
	}{
		{"From", &source.From, message.From}, {"Reply-To", &source.ReplyTo, nil},
		{"To", &source.To, message.To}, {"Cc", &source.Cc, nil},
	} {
		value, present := headers[field.key]
		if !present {
			for _, address := range field.fallback {
				*field.target = append(*field.target, (&stdmail.Address{Name: address.Name, Address: address.Address}).String())
			}
			continue
		}
		addresses, parseErr := gomail.ParseAddressList(value)
		if parseErr != nil || ((field.key == "From" || field.key == "Reply-To") && len(addresses) == 0) {
			// Retain malformed present metadata as an invalid mailbox. The
			// planner rejects it if needed for derived routing, while explicit
			// recipient replacements can still make a safe reply possible.
			*field.target = []string{value}
			warnings = append(warnings, "Source "+field.key+" is malformed; it cannot be used to derive recipients.")
			continue
		}
		for _, address := range addresses {
			*field.target = append(*field.target, address.String())
		}
	}
	if value := headers["Date"]; value != "" {
		source.Date = sourceDate(value)
	}
	if source.Date.IsZero() {
		warnings = append(warnings, "Source Date is missing or invalid; the quotation omits the date.")
	}
	parseIDs := func(key string) ([]string, error) {
		value, present := headers[key]
		if !present {
			return nil, nil
		}
		if strings.TrimSpace(value) == "" {
			return nil, errors.New("empty source threading header")
		}
		h := gomail.HeaderFromMap(map[string][]string{key: {value}})
		ids, err := h.MsgIDList(key)
		if err != nil {
			return nil, errors.New("invalid source threading header")
		}
		for i, id := range ids {
			ids[i] = "<" + id + ">"
			if _, ok := compose.NormalizeMessageID(ids[i]); !ok {
				return nil, errors.New("invalid source threading identifier")
			}
		}
		return ids, nil
	}
	ids, err := parseIDs("Message-Id")
	if err != nil || len(ids) != 1 {
		if replying {
			return compose.Source{}, nil, errors.New("source has no unique valid Message-ID; prepare a standalone message instead")
		}
		warnings = append(warnings, "Source Message-ID is missing or invalid; this forward starts a new thread.")
	} else {
		source.MessageID = ids[0]
	}
	if replying {
		source.References, err = parseIDs("References")
		if err != nil {
			return compose.Source{}, nil, errors.New("source References is invalid; prepare a standalone message instead")
		}
		if _, present := headers["References"]; !present {
			ids, err = parseIDs("In-Reply-To")
			if err == nil && len(ids) == 1 {
				source.InReplyTo = ids[0]
			} else if _, present := headers["In-Reply-To"]; present {
				warnings = append(warnings, "Source In-Reply-To is ambiguous or invalid; threading uses only the parent Message-ID.")
			}
		}
	}
	return source, warnings, nil
}

// sourceDate refuses unknown alphabetic zones that net/mail may otherwise
// fabricate as UTC. RFC 5322's obsolete US zones have fixed explicit offsets.
func sourceDate(value string) time.Time {
	parsed, err := stdmail.ParseDate(value)
	if err != nil {
		return time.Time{}
	}
	name, offset := parsed.Zone()
	// time.Parse can label a numeric zone with the machine's local name
	// (for example +0530 becomes IST). Numeric source offsets remain exact.
	if at := strings.IndexAny(value, "+-"); at >= 0 && len(value) >= at+5 {
		if offset <= -24*3600 || offset >= 24*3600 {
			return time.Time{}
		}
		return parsed
	}
	zones := map[string]int{"UT": 0, "UTC": 0, "GMT": 0, "EST": -5 * 3600, "EDT": -4 * 3600, "CST": -6 * 3600, "CDT": -5 * 3600, "MST": -7 * 3600, "MDT": -6 * 3600, "PST": -8 * 3600, "PDT": -7 * 3600}
	offset, ok := zones[name]
	if !ok {
		return time.Time{}
	}
	return time.Date(parsed.Year(), parsed.Month(), parsed.Day(), parsed.Hour(), parsed.Minute(), parsed.Second(), parsed.Nanosecond(), time.FixedZone(name, offset))
}

func (a *App) prepareSource(ctx context.Context, in prepareInput) (any, error) {
	if len(in.AttachmentIndexes) > 20 {
		return nil, errors.New("select at most 20 source attachments")
	}
	selected := make(map[int]bool)
	for _, index := range in.AttachmentIndexes {
		if index < 1 || index > 100 || selected[index] {
			return nil, errors.New("source attachment indexes must be unique integers from 1 to 100")
		}
		selected[index] = true
	}
	mode := in.OriginalMode
	if mode == "" {
		mode = "quoted"
	}
	if mode != "quoted" && mode != "eml" && mode != "none" {
		return nil, errors.New("unsupported original_mode")
	}
	if mode != "quoted" && in.QuoteOriginal != nil {
		return nil, errors.New("quote_original applies only to quoted originals")
	}
	attachmentCount := len(in.Message.Attachments) + len(in.AttachmentIndexes)
	if mode == "eml" {
		attachmentCount++
	}
	if attachmentCount > 20 {
		return nil, errors.New("too many attachments; combined total must be at most 20")
	}
	attachmentBytes := 0
	for _, attachment := range in.Message.Attachments {
		if len(attachment.DataBase64) > ((compose.MaxAttachmentBytes+2)/3)*4 {
			return nil, errors.New("attachment too large")
		}
		data, err := base64.StdEncoding.Strict().DecodeString(attachment.DataBase64)
		if err != nil {
			return nil, errors.New("invalid attachment base64")
		}
		attachmentBytes += len(data)
		if attachmentBytes > compose.MaxAttachmentBytes {
			return nil, errors.New("attachments exceed 3 MiB")
		}
	}
	quote := mode == "quoted" && (in.QuoteOriginal == nil || *in.QuoteOriginal)
	if mode == "quoted" && !quote {
		mode = "none"
	}
	source, err := a.Mail.Read(ctx, in.Reference)
	if err != nil {
		return nil, err
	}
	if source.Reference != in.Reference {
		return nil, errors.New("source reference does not match requested message")
	}
	if source.Truncated {
		return nil, errors.New("source message is truncated; prepare manually to avoid an incomplete reply or forward")
	}
	planSource, warnings, err := compositionSource(source, in.Action != "forward")
	if err != nil {
		return nil, err
	}
	var message compose.Input
	if in.Action == "forward" {
		message, err = compose.ForwardPlan(planSource, in.Message, &quote)
	} else {
		message, err = compose.ReplyPlan(planSource, a.Config.SelfAddresses(), in.Message, compose.ReplyOptions{ReplyAll: in.Action == "reply_all", QuoteOriginal: &quote})
	}
	if err != nil {
		return nil, err
	}
	included := []mail.Attachment{}
	omitted := []mail.Attachment{}
	byIndex := make(map[int]mail.Attachment)
	for _, attachment := range source.Attachments {
		if attachment.Index < 1 || byIndex[attachment.Index].Index != 0 {
			return nil, errors.New("source attachment metadata is invalid")
		}
		byIndex[attachment.Index] = attachment
		if !selected[attachment.Index] && mode != "eml" {
			omitted = append(omitted, attachment)
		}
	}
	// Check aggregate metadata limits before fetching any selected payload.
	for _, index := range in.AttachmentIndexes {
		metadata, exists := byIndex[index]
		if !exists {
			return nil, errors.New("selected source attachment does not exist")
		}
		if metadata.Size < 0 || metadata.Size > 2<<20 {
			return nil, errors.New("source attachment exceeds 2 MiB")
		}
		attachmentBytes += int(metadata.Size)
		if attachmentBytes > compose.MaxAttachmentBytes {
			return nil, errors.New("attachments exceed 3 MiB")
		}
	}
	for _, index := range in.AttachmentIndexes {
		metadata := byIndex[index]
		attachment, err := a.Mail.GetAttachment(ctx, in.Reference, index)
		if err != nil {
			return nil, err
		}
		if attachment.Reference != in.Reference || attachment.Attachment != metadata {
			return nil, errors.New("source attachment changed or does not match the exact message reference")
		}
		if len(attachment.DataBase64) > ((2<<20)+2)/3*4 {
			return nil, errors.New("source attachment exceeds 2 MiB")
		}
		data, err := base64.StdEncoding.Strict().DecodeString(attachment.DataBase64)
		if err != nil || int64(len(data)) != metadata.Size || len(data) > 2<<20 {
			return nil, errors.New("source attachment bytes are incomplete or invalid")
		}
		contentType := metadata.ContentType
		mediaType, _, typeErr := mime.ParseMediaType(contentType)
		if typeErr != nil {
			return nil, errors.New("source attachment MIME type is invalid")
		}
		if strings.HasPrefix(mediaType, "multipart/") || (mediaType == "message/rfc822" && !sevenBitEML(data)) {
			contentType = "application/octet-stream"
			warnings = append(warnings, fmt.Sprintf("Source attachment %d uses application/octet-stream with base64 transport to preserve its container/message bytes safely; original type was %s.", index, mediaType))
		}
		message.Attachments = append(message.Attachments, compose.Attachment{Filename: forwardAttachmentFilename(metadata), ContentType: contentType, DataBase64: attachment.DataBase64})
		included = append(included, metadata)
	}
	if mode == "eml" {
		raw, err := source.SanitizedEML()
		if err != nil {
			return nil, err
		}
		if len(raw) > compose.MaxAttachmentBytes-attachmentBytes {
			return nil, errors.New("attachments exceed 3 MiB")
		}
		mediaType := "message/rfc822"
		if !sevenBitEML(raw) {
			mediaType = "application/octet-stream"
			warnings = append(warnings, "Original EML is not canonical 7-bit mail; forwarded-message.eml uses application/octet-stream with base64 transport to preserve its bytes safely.")
		}
		message.Attachments = append(message.Attachments, compose.Attachment{Filename: "forwarded-message.eml", ContentType: mediaType, DataBase64: base64.StdEncoding.EncodeToString(raw)})
		warnings = append(warnings, "Attached EML includes original headers and attachments. Outer Bcc/Resent-Bcc fields were removed; embedded attachments are unchanged and may contain private data.")
	}
	message.Warnings = append(message.Warnings, warnings...)
	prepared, err := a.compose(message)
	if err != nil {
		return nil, err
	}
	if err := a.Store.Put(ctx, prepared); err != nil {
		return nil, err
	}
	out := preview(prepared)
	out["source"] = in.Reference
	out["source_message_id"] = planSource.MessageID
	out["in_reply_to"] = message.InReplyTo
	out["references"] = message.References
	out["quote_original"] = quote
	out["original_mode"] = mode
	out["attachment_indexes"] = append([]int{}, in.AttachmentIndexes...)
	out["included_source_attachments"] = included
	out["omitted_source_attachments"] = omitted
	out["warnings"] = prepared.Warnings
	if mode == "eml" {
		out["source_attachments_in_eml"] = source.Attachments
	}
	return out, nil
}

func sevenBitEML(raw []byte) bool {
	line := 0
	for i, b := range raw {
		if b >= 127 || b == 0 || (b < 32 && b != '\r' && b != '\n' && b != '\t') {
			return false
		}
		switch b {
		case '\r':
			if i+1 == len(raw) || raw[i+1] != '\n' {
				return false
			}
		case '\n':
			if i == 0 || raw[i-1] != '\r' {
				return false
			}
			line = 0
		default:
			line++
			if line > 998 {
				return false
			}
		}
	}
	return len(raw) >= 2 && raw[len(raw)-2] == '\r' && raw[len(raw)-1] == '\n'
}

// Adapted from amxv/icloud-cli's Apache-2.0 forwardAttachmentFilename pattern:
// replace path punctuation, remove controls, and bound the UTF-8 byte length.
func forwardAttachmentFilename(attachment mail.Attachment) string {
	name := strings.Map(func(r rune) rune {
		switch {
		case strings.ContainsRune(`/\\:*?"<>|`, r):
			return '_'
		case unicode.IsControl(r) || unicode.Is(unicode.Cf, r):
			return -1
		default:
			return r
		}
	}, strings.ToValidUTF8(strings.TrimSpace(attachment.Filename), ""))
	name = strings.Trim(name, ". ")
	if name == "" {
		name = fmt.Sprintf("attachment-%d.bin", attachment.Index)
	}
	if len(name) > 200 {
		name = name[:200]
		for !utf8.ValidString(name) {
			name = name[:len(name)-1]
		}
	}
	return name
}

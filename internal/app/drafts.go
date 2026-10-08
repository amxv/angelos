package app

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	stdmail "net/mail"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/amxv/angelos/internal/compose"
	"github.com/amxv/angelos/internal/mail"
)

// Includes JSON escaping of alternatives and base64 files; no partial draft is
// ever returned. The protocol envelope contains text and structured copies.
const maxDraftResponseBytes = 1 << 20

func validSourceDigest(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func (a *App) readDraft(ctx context.Context, ref mail.Reference, digest string) (mail.Draft, error) {
	if !mail.ValidGraphReference(ref) && (ref.UID == 0 || ref.UIDValidity == 0 || len(ref.Folder) == 0 || len(ref.Folder) > 1024 || !utf8.ValidString(ref.Folder) || strings.IndexFunc(ref.Folder, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) }) >= 0) {
		return mail.Draft{}, mail.ErrInvalidInput
	}
	if digest != "" && !validSourceDigest(digest) {
		return mail.Draft{}, mail.ErrInvalidInput
	}
	backend, ok := a.Mail.(mail.DraftReader)
	if !ok {
		return mail.Draft{}, mail.ErrUnsupported
	}
	source, err := backend.ReadDraft(ctx, ref)
	if err != nil {
		return mail.Draft{}, err
	}
	if source.Reference != ref || !validSourceDigest(source.SourceDigest) {
		return mail.Draft{}, mail.ErrUnavailable
	}
	isDraft := false
	for _, flag := range source.Flags {
		if strings.EqualFold(flag, `\Deleted`) {
			return mail.Draft{}, mail.ErrInvalidInput
		}
		if strings.EqualFold(flag, `\Draft`) {
			isDraft = true
		}
	}
	if !isDraft {
		return mail.Draft{}, fmt.Errorf("%w: source must still have the Draft flag", mail.ErrInvalidInput)
	}
	if digest != "" && subtle.ConstantTimeCompare([]byte(digest), []byte(source.SourceDigest)) != 1 {
		return mail.Draft{}, mail.ErrDraftChanged
	}
	if err := boundedDraftPayload(source); err != nil {
		return mail.Draft{}, err
	}
	return source, nil
}

func boundedDraftPayload(value any) error {
	data, err := json.Marshal(value)
	if err != nil || len(data) > maxDraftResponseBytes {
		return fmt.Errorf("%w: complete structured draft or preview exceeds 1 MiB JSON; no partial content returned", mail.ErrLimit)
	}
	return nil
}

func (a *App) draftSender(source mail.Draft) error {
	from, err := stdmail.ParseAddress(source.From)
	configured, configErr := stdmail.ParseAddress(a.Config.From)
	if err != nil || configErr != nil || !strings.EqualFold(from.Address, configured.Address) {
		return fmt.Errorf("%w: draft From must match the configured sender; identity changes require an explicitly authored new draft", mail.ErrUnsupported)
	}
	return nil
}

func (a *App) reviseDraft(ctx context.Context, in createInput) (any, error) {
	if !validSourceDigest(in.SourceDigest) {
		return nil, mail.ErrInvalidInput
	}
	source, err := a.readDraft(ctx, in.Reference, in.SourceDigest)
	if err != nil {
		return nil, err
	}
	if err := a.draftSender(source); err != nil {
		return nil, err
	}
	if (in.Changes.Text != nil && in.Changes.HTML == nil && source.Message.HTML != "") ||
		(in.Changes.HTML != nil && in.Changes.Text == nil && (source.Message.Text != "" || source.Message.PreserveEmptyText)) {
		return nil, invalidArgumentsError(errors.New("body alternatives require an explicit choice: supply both changes.text and changes.html, updating or clearing each; omitted alternatives would preserve stale content"))
	}
	message := in.Changes.Apply(source.Message)
	p, err := a.composeDraft(message)
	if err != nil {
		return nil, err
	}
	raw, err := compose.DraftBytes(p)
	if err != nil {
		return nil, err
	}
	// Validate the exact new bytes before APPEND; no source flags are changed.
	parsed, err := compose.ParseDraft(raw)
	if err != nil {
		return nil, err
	}
	next := source
	next.DraftContent = parsed
	if err := boundedDraftPayload(next); err != nil {
		return nil, err
	}
	folder := in.Folder
	if folder == "" {
		folder = in.Reference.Folder
	}
	mutation, err := a.Mail.AppendDraft(ctx, folder, raw)
	mutation.Source = &in.Reference
	warnings := append([]string(nil), source.Warnings...)
	warnings = append(warnings, "The original draft was not changed or deleted. APPEND is not an atomic replacement or a lock on other mail clients; verify uncertain outcomes before retrying.")
	return result{"revision": mutation, "source_digest": source.SourceDigest, "original_retained": true, "message_id": p.MessageID, "warnings": warnings}, err
}

func (a *App) prepareDraft(ctx context.Context, in prepareInput) (any, error) {
	if !validSourceDigest(in.SourceDigest) {
		return nil, mail.ErrInvalidInput
	}
	source, err := a.readDraft(ctx, in.Reference, in.SourceDigest)
	if err != nil {
		return nil, err
	}
	if err := a.draftSender(source); err != nil {
		return nil, err
	}
	p, err := a.compose(source.Message)
	if err != nil {
		return nil, err
	}
	p.Warnings = append(p.Warnings, source.Warnings...)
	p.Warnings = append(p.Warnings, "Preparation freezes this reviewed snapshot; later edits to the draft do not change it. Sending does not delete or retire the original draft.")
	out := preview(p)
	out["source_reference"], out["source_digest"], out["original_retained"] = in.Reference, source.SourceDigest, true
	out["in_reply_to"], out["references"] = source.Message.InReplyTo, source.Message.References
	if err := boundedDraftPayload(out); err != nil {
		return nil, err
	}
	if err := a.storePreparation(ctx, p); err != nil {
		return nil, err
	}
	return out, nil
}

// Ensure nested nulls cannot masquerade as omitted patch keys. Empty objects
// aren't revisions, and changing only one alternative does not edit the other.
func validateDraftChanges(raw json.RawMessage) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || len(fields) == 0 {
		return errors.New("changes must contain at least one replacement field")
	}
	for key, value := range fields {
		if strings.TrimSpace(string(value)) == "null" {
			return fmt.Errorf("changes.%s must not be null; omit it to preserve or use an empty value to clear", key)
		}
	}
	return nil
}

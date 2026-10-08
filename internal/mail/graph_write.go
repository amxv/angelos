package mail

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	stdmail "net/mail"
	"sort"
	"strings"

	"github.com/amxv/angelos/internal/compose"
)

// Keep the base64 request below Graph's ordinary 4 MiB request limit.
const maxGraphMIMEBytes = (3 << 20) - 1024

func graphMessagePath(r Reference) string {
	return graphRoot + "/me/mailFolders/" + r.Folder + "/messages/" + r.ID
}
func (b *GraphBackend) SetFlags(ctx context.Context, in FlagRequest) (FlagResult, error) {
	out := FlagResult{Reference: in.Reference, Warnings: []string{"Graph updates only the requested properties; no MODSEQ or conditional concurrency guarantee."}}
	if in.UnchangedSince != 0 {
		return out, ErrUnsupported
	}
	if !b.refOK(in.Reference) || in.Operation != "add" && in.Operation != "remove" || len(in.Flags) == 0 || len(in.Flags) > 2 {
		return out, ErrInvalidInput
	}
	patch := map[string]any{}
	for _, flag := range in.Flags {
		switch flag {
		case `\Seen`:
			patch["isRead"] = in.Operation == "add"
		case `\Flagged`:
			status := "notFlagged"
			if in.Operation == "add" {
				status = "flagged"
			}
			patch["flag"] = map[string]string{"flagStatus": status}
		default:
			return out, ErrUnsupported
		}
	}
	token, e := b.identity(ctx)
	if e != nil {
		return out, e
	}
	data, status, e := b.request(ctx, token, "PATCH", graphMessagePath(in.Reference), "application/json", graphJSON(patch), 256<<10)
	if e != nil {
		return out, e
	}
	if status != 200 {
		return out, ErrOutcomeUnknown
	}
	var m graphMessage
	if json.Unmarshal(data, &m) != nil || m.ID != in.Reference.ID {
		return out, ErrOutcomeUnknown
	}
	s, e := b.summary(m)
	if e != nil {
		return out, ErrOutcomeUnknown
	}
	out.Reference = s.Reference
	out.Flags = s.Flags
	return out, nil
}
func (b *GraphBackend) CreateFolder(ctx context.Context, name string) error {
	if !validFolder(name) {
		return ErrInvalidInput
	}
	token, e := b.identity(ctx)
	if e != nil {
		return e
	}
	_, status, e := b.request(ctx, token, "POST", graphRoot+"/me/mailFolders", "application/json", graphJSON(map[string]string{"displayName": name}), 64<<10)
	if e == nil && status != 201 {
		return ErrOutcomeUnknown
	}
	return e
}
func (b *GraphBackend) RenameFolder(ctx context.Context, id, name string) error {
	if !graphID(id) || !validFolder(name) {
		return ErrInvalidInput
	}
	token, e := b.identity(ctx)
	if e != nil {
		return e
	}
	_, status, e := b.request(ctx, token, "PATCH", graphRoot+"/me/mailFolders/"+id, "application/json", graphJSON(map[string]string{"displayName": name}), 64<<10)
	if e == nil && status != 200 {
		return ErrOutcomeUnknown
	}
	return e
}
func (b *GraphBackend) transfer(ctx context.Context, ref Reference, destination, action string) (MutationResult, error) {
	out := MutationResult{Source: &ref, Status: "rejected"}
	if !b.refOK(ref) || !graphID(destination) {
		return out, ErrInvalidInput
	}
	token, e := b.identity(ctx)
	if e != nil {
		return out, e
	}
	data, status, e := b.request(ctx, token, "POST", graphMessagePath(ref)+"/"+action, "application/json", graphJSON(map[string]string{"destinationId": destination}), 256<<10)
	if e != nil {
		if errors.Is(e, ErrOutcomeUnknown) {
			out.Status = "unknown"
		}
		return out, e
	}
	if status != 201 {
		out.Status = "unknown"
		return out, ErrOutcomeUnknown
	}
	var m graphMessage
	if json.Unmarshal(data, &m) != nil || !graphID(m.ID) || !graphID(m.ParentFolderID) {
		out.Status = "unknown"
		return out, ErrOutcomeUnknown
	}
	r := b.ref(m.ID, m.ParentFolderID)
	out.Destination = &r
	out.Status = "completed"
	return out, nil
}
func (b *GraphBackend) Copy(ctx context.Context, ref Reference, destination string) (MutationResult, error) {
	return b.transfer(ctx, ref, destination, "copy")
}
func (b *GraphBackend) Move(ctx context.Context, ref Reference, destination string) (MutationResult, error) {
	return b.transfer(ctx, ref, destination, "move")
}
func (b *GraphBackend) Trash(ctx context.Context, ref Reference) (MutationResult, error) {
	return b.transfer(ctx, ref, "deleteditems", "move")
}
func (b *GraphBackend) Delete(context.Context, Reference) (MutationResult, error) {
	return MutationResult{}, ErrUnsupported
}
func (b *GraphBackend) AppendSent(context.Context, []byte) (MutationResult, error) {
	return MutationResult{}, ErrAutomaticSent
}
func (b *GraphBackend) AppendDraft(ctx context.Context, folder string, raw []byte) (MutationResult, error) {
	out := MutationResult{Status: "rejected"}
	if folder == "" {
		folder = "drafts"
	}
	if !graphID(folder) || len(raw) == 0 || len(raw) > maxGraphMIMEBytes {
		return out, ErrInvalidInput
	}
	if _, e := compose.ParseDraft(raw); e != nil {
		return out, ErrUnsupported
	}
	if e := b.validateMIME(raw, nil); e != nil {
		return out, e
	}
	token, e := b.identity(ctx)
	if e != nil {
		return out, e
	}
	data, status, e := b.request(ctx, token, "POST", graphRoot+"/me/mailFolders/"+folder+"/messages", "text/plain", []byte(base64.StdEncoding.EncodeToString(raw)), 256<<10)
	if e != nil {
		if errors.Is(e, ErrOutcomeUnknown) {
			out.Status = "unknown"
		}
		return out, e
	}
	if status != 201 {
		out.Status = "unknown"
		return out, ErrOutcomeUnknown
	}
	var m graphMessage
	if json.Unmarshal(data, &m) != nil || !m.IsDraft || !graphID(m.ID) || !graphID(m.ParentFolderID) {
		out.Status = "unknown"
		return out, ErrOutcomeUnknown
	}
	r := b.ref(m.ID, m.ParentFolderID)
	out.Destination = &r
	out.Status = "completed"
	return out, nil
}
func (b *GraphBackend) validateMIME(raw []byte, envelope *Envelope) error {
	if len(raw) == 0 || len(raw) > maxGraphMIMEBytes {
		return ErrInvalidInput
	}
	msg, e := stdmail.ReadMessage(bytes.NewReader(raw))
	if e != nil {
		return ErrInvalidInput
	}
	for _, key := range []string{"From", "To", "Cc", "Bcc"} {
		if len(msg.Header[key]) > 1 {
			return ErrInvalidInput
		}
	}
	from, e := stdmail.ParseAddress(msg.Header.Get("From"))
	if e != nil || from.Address != b.config.From {
		return ErrInvalidInput
	}
	for key := range msg.Header {
		if strings.HasPrefix(strings.ToLower(key), "resent-") || strings.EqualFold(key, "Sender") {
			return ErrInvalidInput
		}
	}
	if envelope == nil {
		return nil
	}
	if envelope.From != b.config.From || len(envelope.To) == 0 || len(envelope.To) > compose.MaxRecipients {
		return ErrInvalidInput
	}
	// Graph derives its recipients from MIME. Confirm equality with the complete
	// approved envelope, including blind recipients; never silently lose Bcc.
	recipients := []string{}
	for _, key := range []string{"To", "Cc", "Bcc"} {
		if msg.Header.Get(key) == "" {
			continue
		}
		addresses, e := msg.Header.AddressList(key)
		if e != nil {
			return ErrInvalidInput
		}
		for _, a := range addresses {
			if !bareAddress(a.Address) {
				return ErrInvalidInput
			}
			recipients = append(recipients, a.Address)
		}
	}
	want := append([]string(nil), envelope.To...)
	sort.Strings(want)
	sort.Strings(recipients)
	if len(want) != len(recipients) {
		return ErrInvalidInput
	}
	for i := range want {
		if want[i] != recipients[i] {
			return ErrInvalidInput
		}
	}
	return nil
}
func (b *GraphBackend) Send(ctx context.Context, envelope Envelope, raw []byte) (SendResult, error) {
	out := SendResult{Status: "rejected", Stage: "validation"}
	if e := b.validateMIME(raw, &envelope); e != nil {
		return out, e
	}
	out.Stage = "authentication"
	token, e := b.identity(ctx)
	if e != nil {
		return out, e
	}
	out.Stage = "graph_submission"
	_, status, e := b.request(ctx, token, "POST", graphRoot+"/me/sendMail", "text/plain", []byte(base64.StdEncoding.EncodeToString(raw)), 64<<10)
	if e != nil {
		if errors.Is(e, ErrOutcomeUnknown) {
			out.Status = "unknown"
		}
		return out, e
	}
	if status != 202 {
		out.Status = "unknown"
		return out, ErrOutcomeUnknown
	}
	out.Status = "accepted"
	return out, nil
}

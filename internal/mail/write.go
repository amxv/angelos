package mail

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	netmail "net/mail"
	"sort"
	"strings"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
)

func validWriteReference(ref Reference) bool {
	return validFolder(ref.Folder) && ref.UIDValidity != 0 && ref.UID != 0
}

// No CLOSE, ordinary EXPUNGE, or library MOVE fallback is used anywhere here.
// Each connection is closed at the transport level, which does not expunge.
func (s *imapSession) selectWritableMailbox(ref Reference) (*imap.SelectData,error) {
	if !validWriteReference(ref) { return nil,ErrInvalidInput }
	data,err := s.client.Select(ref.Folder,&imap.SelectOptions{CondStore:s.client.Caps().Has(imap.CapCondStore)}).Wait()
	if err != nil { return nil,safeError(err) }
	if data.UIDValidity == 0 { return nil,ErrUnavailable }
	if data.UIDValidity != ref.UIDValidity { return nil,ErrStaleReference }
	return data,nil
}

// commandMutationError never includes untrusted provider text. A negative
// protocol reply is definite rejection; a lost response has an unknown outcome.
func commandMutationError(err error) error {
	if err == nil { return nil }
	var status *imap.Error
	if errors.As(err,&status) { return ErrUnavailable }
	return ErrOutcomeUnknown
}

func (b *Backend) Capabilities(ctx context.Context) (Capabilities,error) {
	out := Capabilities{IMAP:[]string{},SpecialFolders:map[string][]string{}}
	s,err := b.connectIMAP(ctx); if err != nil { return out,err }; defer s.close()
	caps := s.client.Caps(); if caps == nil { return out,ErrUnavailable }
	if len(caps) > 1000 { return out,ErrLimit }
	for c := range caps { out.IMAP = append(out.IMAP,cleanHeader(string(c),256)) }; sort.Strings(out.IMAP)
	out.Move = caps.Has(imap.CapMove)
	out.UIDExpunge = caps.Has(imap.CapUIDPlus)
	out.CondStore = caps.Has(imap.CapCondStore)
	out.SpecialUse = caps.Has(imap.CapSpecialUse)
	out.SpecialFolders,err = discoverSpecialFolders(s)
	return out,err
}

func discoverSpecialFolders(s *imapSession) (map[string][]string,error) {
	out := map[string][]string{}
	opts := &imap.ListOptions{ReturnSpecialUse:s.client.Caps().Has(imap.CapSpecialUse)}
	cmd := s.client.List("","*",opts)
	n := 0
	for data := cmd.Next(); data != nil; data = cmd.Next() {
		n++; if n > maxFolders || !validFolder(data.Mailbox) { s.cleanup(); cmd.Close(); return nil,ErrLimit }
		selectable := true
		for _,a := range data.Attrs { if strings.EqualFold(string(a),`\Noselect`) { selectable = false } }
		if !selectable { continue }
		for _,a := range data.Attrs {
			var key string
			switch strings.ToLower(string(a)) {
			case `\all`: key = "all"
			case `\archive`: key = "archive"
			case `\drafts`: key = "drafts"
			case `\flagged`: key = "flagged"
			case `\junk`: key = "junk"
			case `\sent`: key = "sent"
			case `\trash`: key = "trash"
			default: continue
			}
			present := false; for _,name := range out[key] { if name == data.Mailbox { present = true } }
			if !present { out[key] = append(out[key],data.Mailbox) }
		}
	}
	if err := cmd.Close(); err != nil { return nil,safeError(err) }
	for _,names := range out { sort.Strings(names) }
	return out,nil
}

func resolveSpecialFolder(s *imapSession, role string) (string,error) {
	folders,err := discoverSpecialFolders(s); if err != nil { return "",err }
	if len(folders[role]) != 1 { return "",ErrUnsupported }
	return folders[role][0],nil
}

func parseFlagRequest(req FlagRequest) ([]imap.Flag,imap.StoreFlagsOp,error) {
	var op imap.StoreFlagsOp
	switch req.Operation { case "add": op = imap.StoreFlagsAdd; case "remove": op = imap.StoreFlagsDel; default: return nil,op,ErrInvalidInput }
	if !validWriteReference(req.Reference) || len(req.Flags) == 0 || len(req.Flags) > 32 { return nil,op,ErrInvalidInput }
	flags := make([]imap.Flag,0,len(req.Flags)); seen := map[string]bool{}
	for _,f := range req.Flags {
		if len(f) == 0 || len(f) > 128 { return nil,op,ErrInvalidInput }
		if f[0] == '\\' {
			switch strings.ToLower(f) { case `\seen`: f = `\Seen`; case `\answered`: f = `\Answered`; case `\flagged`: f = `\Flagged`; case `\draft`: f = `\Draft`; default: return nil,op,ErrInvalidInput }
		} else {
			// Keywords are IMAP atoms. A conservative ASCII subset prevents
			// protocol injection and leaves server-specific exotic flags read-only.
			for _,r := range f { if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("$._-",r)) { return nil,op,ErrInvalidInput } }
		}
		key := strings.ToLower(f); if !seen[key] { flags = append(flags,imap.Flag(f)); seen[key] = true }
	}
	return flags,op,nil
}

func flagsPermitted(flags, permanent []imap.Flag) bool {
	for _,want := range flags {
		allowed := false
		for _,have := range permanent {
			if strings.EqualFold(string(want),string(have)) || (have == imap.Flag(`\*`) && !strings.HasPrefix(string(want),`\`)) { allowed = true }
		}
		if !allowed { return false }
	}
	return true
}

type flagSnapshot struct { uid imap.UID; flags []imap.Flag; modSeq uint64; found bool; hasFlags bool }

// Fetch only the requested UID, and stream-discard anything else. Never expand
// provider ranges or buffer a message literal while inspecting flags.
func collectFlagSnapshot(cmd *imapclient.FetchCommand, uid uint32) (flagSnapshot,error) {
	var out flagSnapshot
	for data := cmd.Next(); data != nil; data = cmd.Next() {
		var current flagSnapshot
		for item := data.Next(); item != nil; item = data.Next() {
			switch v := item.(type) {
			case imapclient.FetchItemDataUID: current.uid = v.UID
			case imapclient.FetchItemDataFlags: current.flags = v.Flags; current.hasFlags = true
			case imapclient.FetchItemDataModSeq: current.modSeq = v.ModSeq
			}
		}
		if uint32(current.uid) == uid { if out.found { cmd.Close(); return out,ErrUnavailable }; current.found = true; out = current }
	}
	if err := cmd.Close(); err != nil { return out,err }
	return out,nil
}

func readFlagSnapshot(s *imapSession, uid uint32, condstore bool) (flagSnapshot,error) {
	out,err := collectFlagSnapshot(s.client.Fetch(imap.UIDSetNum(imap.UID(uid)),&imap.FetchOptions{UID:true,Flags:true,ModSeq:condstore}),uid)
	if err != nil { return out,safeError(err) }
	if !out.found { return out,ErrNotFound }
	if !out.hasFlags || len(out.flags) > 1000 { return out,ErrUnavailable }
	if condstore && out.modSeq == 0 { return out,ErrUnsupported }
	return out,nil
}

func flagPostcondition(current, requested []imap.Flag, op imap.StoreFlagsOp) bool {
	for _,want := range requested {
		has := false; for _,f := range current { if strings.EqualFold(string(f),string(want)) { has = true } }
		if (op == imap.StoreFlagsAdd && !has) || (op == imap.StoreFlagsDel && has) { return false }
	}
	return true
}

func (b *Backend) SetFlags(ctx context.Context, req FlagRequest) (FlagResult,error) {
	out := FlagResult{Reference:req.Reference,Flags:[]string{}}
	flags,op,err := parseFlagRequest(req); if err != nil { return out,err }
	s,err := b.connectIMAP(ctx); if err != nil { return out,err }; defer s.close()
	selected,err := s.selectWritableMailbox(req.Reference); if err != nil { return out,err }
	if !flagsPermitted(flags,selected.PermanentFlags) { return out,ErrUnsupported }
	conditional := s.client.Caps().Has(imap.CapCondStore) && selected.HighestModSeq != 0
	if req.UnchangedSince != 0 && !conditional { return out,ErrUnsupported }
	before,err := readFlagSnapshot(s,req.Reference.UID,conditional); if err != nil { return out,err }
	if req.UnchangedSince != 0 && before.modSeq > req.UnchangedSince { return out,ErrConflict }
	options := &imap.StoreOptions{}
	if conditional { options.UnchangedSince = before.modSeq; if req.UnchangedSince != 0 { options.UnchangedSince = req.UnchangedSince } }
	// Non-silent STORE is essential: go-imap beta.8 does not expose an OK
	// [MODIFIED] response. An omitted matching FETCH is therefore a conflict,
	// never silent success. Successful conditional STORE returns MODSEQ.
	after,err := collectFlagSnapshot(s.client.Store(imap.UIDSetNum(imap.UID(req.Reference.UID)),&imap.StoreFlags{Op:op,Flags:flags},options),req.Reference.UID)
	if err != nil { return out,commandMutationError(err) }
	if !after.found || !after.hasFlags || (conditional && after.modSeq == 0) || !flagPostcondition(after.flags,flags,op) { return out,ErrConflict }
	if len(after.flags) > 1000 { return out,ErrOutcomeUnknown }
	for _,f := range after.flags { out.Flags = append(out.Flags,cleanHeader(string(f),256)) }
	out.ModSeq = after.modSeq; out.Conditional = conditional
	if !conditional { out.Warnings = []string{"This mailbox lacks CONDSTORE; the flag delta was applied without a concurrency precondition."} }
	return out,nil
}

func (b *Backend) CreateFolder(ctx context.Context, name string) error {
	if !validFolder(name) { return ErrInvalidInput }
	s,err := b.connectIMAP(ctx); if err != nil { return err }; defer s.close()
	return commandMutationError(s.client.Create(name,nil).Wait())
}

func (b *Backend) RenameFolder(ctx context.Context, oldName,newName string) error {
	// RENAME INBOX has unusual message-moving semantics and is deliberately
	// excluded. There is no folder deletion or recursive deletion endpoint.
	if !validFolder(oldName) || !validFolder(newName) || oldName == newName || strings.EqualFold(oldName,"INBOX") || strings.EqualFold(newName,"INBOX") { return ErrInvalidInput }
	s,err := b.connectIMAP(ctx); if err != nil { return err }; defer s.close()
	return commandMutationError(s.client.Rename(oldName,newName,nil).Wait())
}

func singleUID(set imap.NumSet) (uint32,bool) {
	uids,ok := set.(imap.UIDSet)
	// Do not call Nums on server data: a single hostile range can expand to
	// billions of values. Only a single exact UID can represent this operation.
	if !ok || len(uids) != 1 || uids[0].Start == 0 || uids[0].Start != uids[0].Stop { return 0,false }
	return uint32(uids[0].Start),true
}

func transferredResult(ref Reference,destination,status string,validity uint32,source,dest imap.NumSet) MutationResult {
	out := MutationResult{Source:&ref,Status:status}
	src,okSrc := singleUID(source); dst,okDst := singleUID(dest)
	if validity != 0 && okSrc && src == ref.UID && okDst {
		out.Destination = &Reference{Folder:destination,UIDValidity:validity,UID:dst}
	} else {
		out.Warnings = []string{"The server confirmed the change but did not provide a valid new UID mapping. Search the destination before acting on the new message."}
	}
	return out
}

func transferMessage(s *imapSession, ref Reference, destination string, move bool) (MutationResult,error) {
	out := MutationResult{Source:&ref,Status:"not_applied"}
	if !validWriteReference(ref) || !validFolder(destination) || ref.Folder == destination || (strings.EqualFold(ref.Folder,"INBOX") && strings.EqualFold(destination,"INBOX")) { return out,ErrInvalidInput }
	if move && !s.client.Caps().Has(imap.CapMove) { return out,ErrUnsupported }
	if _,err := s.selectWritableMailbox(ref); err != nil { return out,err }
	if _,err := readFlagSnapshot(s,ref.UID,false); err != nil { return out,err }
	if move {
		// Guard before Client.Move: without MOVE the library may emulate this
		// using COPY, STORE and a mailbox-wide EXPUNGE. Never permit that path.
		data,err := s.client.Move(imap.UIDSetNum(imap.UID(ref.UID)),destination).Wait()
		if err != nil { out.Status = "unknown"; return out,commandMutationError(err) }
		return transferredResult(ref,destination,"moved",data.UIDValidity,data.SourceUIDs,data.DestUIDs),nil
	}
	data,err := s.client.Copy(imap.UIDSetNum(imap.UID(ref.UID)),destination).Wait()
	if err != nil { out.Status = "unknown"; return out,commandMutationError(err) }
	return transferredResult(ref,destination,"copied",data.UIDValidity,data.SourceUIDs,data.DestUIDs),nil
}

func (b *Backend) Copy(ctx context.Context, ref Reference, destination string) (MutationResult,error) {
	if !validWriteReference(ref) || !validFolder(destination) { return MutationResult{},ErrInvalidInput }
	s,err := b.connectIMAP(ctx); if err != nil { return MutationResult{},err }; defer s.close()
	return transferMessage(s,ref,destination,false)
}

func (b *Backend) Move(ctx context.Context, ref Reference, destination string) (MutationResult,error) {
	if !validWriteReference(ref) || !validFolder(destination) { return MutationResult{},ErrInvalidInput }
	s,err := b.connectIMAP(ctx); if err != nil { return MutationResult{},err }; defer s.close()
	return transferMessage(s,ref,destination,true)
}

func (b *Backend) Trash(ctx context.Context, ref Reference) (MutationResult,error) {
	if !validWriteReference(ref) { return MutationResult{},ErrInvalidInput }
	s,err := b.connectIMAP(ctx); if err != nil { return MutationResult{},err }; defer s.close()
	if !s.client.Caps().Has(imap.CapMove) { return MutationResult{},ErrUnsupported }
	folder,err := resolveSpecialFolder(s,"trash"); if err != nil { return MutationResult{},err }
	return transferMessage(s,ref,folder,true)
}

// AppendDraft creates a new draft; it does not replace or delete an old draft.
// An empty folder means the unique server-advertised SPECIAL-USE Drafts folder.
func (b *Backend) AppendDraft(ctx context.Context, folder string, raw []byte) (MutationResult,error) {
	return b.appendRaw(ctx,folder,"drafts",raw,[]imap.Flag{imap.FlagDraft})
}

// AppendSent is for a message whose SMTP acceptance was already confirmed.
// A failure here must be reported as a filing failure, never retried by sending
// SMTP again. This helper never sends mail and never guesses the Sent folder.
func (b *Backend) AppendSent(ctx context.Context, raw []byte) (MutationResult,error) {
	return b.appendRaw(ctx,"","sent",raw,[]imap.Flag{imap.FlagSeen})
}

func (b *Backend) appendRaw(ctx context.Context, folder, role string, raw []byte, flags []imap.Flag) (MutationResult,error) {
	out := MutationResult{Status:"not_applied"}
	if (folder != "" && !validFolder(folder)) || len(raw) == 0 || len(raw) > maxMessageBytes || bytes.IndexByte(raw,0) >= 0 { return out,ErrInvalidInput }
	if _,err := netmail.ReadMessage(bufio.NewReader(bytes.NewReader(raw))); err != nil { return out,ErrInvalidInput }
	s,err := b.connectIMAP(ctx); if err != nil { return out,err }; defer s.close()
	if folder == "" { folder,err = resolveSpecialFolder(s,role); if err != nil { return out,err } }
	if limit,ok := s.client.Caps().AppendLimit(); ok && limit != nil && uint64(len(raw)) > uint64(*limit) { return out,ErrLimit }
	cmd := s.client.Append(folder,int64(len(raw)),&imap.AppendOptions{Flags:flags})
	if _,err := io.Copy(cmd,bytes.NewReader(raw)); err != nil { cmd.Close(); out.Status = "unknown"; return out,commandMutationError(err) }
	if err := cmd.Close(); err != nil { out.Status = "unknown"; return out,commandMutationError(err) }
	data,err := cmd.Wait(); if err != nil { out.Status = "unknown"; return out,commandMutationError(err) }
	out.Status = "appended"
	if data.UID != 0 && data.UIDValidity != 0 { out.Destination = &Reference{Folder:folder,UIDValidity:data.UIDValidity,UID:uint32(data.UID)} } else { out.Warnings = []string{"The server confirmed the appended message but did not return its UID. Search the destination before editing or retrying."} }
	return out,nil
}

// Delete permanently removes exactly one UID, never other messages that Apple
// Mail marked Deleted. The caller must separately authorize permanent deletion.
func (b *Backend) Delete(ctx context.Context, ref Reference) (MutationResult,error) {
	out := MutationResult{Source:&ref,Status:"not_applied"}
	if !validWriteReference(ref) { return out,ErrInvalidInput }
	s,err := b.connectIMAP(ctx); if err != nil { return out,err }; defer s.close()
	if !s.client.Caps().Has(imap.CapUIDPlus) { return out,ErrUnsupported }
	selected,err := s.selectWritableMailbox(ref); if err != nil { return out,err }
	if !flagsPermitted([]imap.Flag{imap.FlagDeleted},selected.PermanentFlags) { return out,ErrUnsupported }
	conditional := s.client.Caps().Has(imap.CapCondStore) && selected.HighestModSeq != 0
	before,err := readFlagSnapshot(s,ref.UID,conditional); if err != nil { return out,err }
	options := &imap.StoreOptions{}; if conditional { options.UnchangedSince = before.modSeq }
	flagged,err := collectFlagSnapshot(s.client.Store(imap.UIDSetNum(imap.UID(ref.UID)),&imap.StoreFlags{Op:imap.StoreFlagsAdd,Flags:[]imap.Flag{imap.FlagDeleted}},options),ref.UID)
	if err != nil { out.Status = "unknown"; return out,commandMutationError(err) }
	if !flagged.found || !flagged.hasFlags || (conditional && flagged.modSeq == 0) || !flagPostcondition(flagged.flags,[]imap.Flag{imap.FlagDeleted},imap.StoreFlagsAdd) { return out,ErrConflict }
	out.Status = "marked_deleted"
	if err := s.client.UIDExpunge(imap.UIDSetNum(imap.UID(ref.UID))).Close(); err != nil {
		out.Warnings = []string{"The message was marked Deleted, but permanent removal was not confirmed. Verify it before retrying; no mailbox-wide expunge was attempted."}
		return out,ErrOutcomeUnknown
	}
	// Expunge responses carry unstable sequence numbers. Ignore those values
	// and verify absence using the original UID while this selection is valid.
	remaining,err := readFlagSnapshot(s,ref.UID,false)
	if errors.Is(err,ErrNotFound) { out.Status = "deleted"; return out,nil }
	if err != nil || remaining.found { out.Status = "unknown"; return out,ErrOutcomeUnknown }
	return out,ErrOutcomeUnknown
}

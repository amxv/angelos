package mail

import (
	"context"
	"errors"
)

var (
	ErrUnsupported = errors.New("mail server does not support this operation safely")
	ErrConflict = errors.New("message changed concurrently; read it again before changing flags")
	ErrOutcomeUnknown = errors.New("mail change may have succeeded; verify its outcome before retrying")
)

// Capabilities describes server features, not the permissions granted to a token.
// SpecialFolders lists the exact server-advertised names, including ambiguities.
type Capabilities struct {
	IMAP []string `json:"imap"`
	Move bool `json:"move"`
	UIDExpunge bool `json:"uid_expunge"`
	CondStore bool `json:"condstore"`
	SpecialUse bool `json:"special_use"`
	SpecialFolders map[string][]string `json:"special_folders"`
}

// FlagRequest deliberately supports deltas only. Replacing all flags would
// overwrite changes made by Apple Mail or another client. Deleted and Recent
// cannot be changed here; permanent removal has a separate narrow operation.
type FlagRequest struct {
	Reference Reference `json:"reference"`
	Operation string `json:"operation"` // add or remove
	Flags []string `json:"flags"`
	UnchangedSince uint64 `json:"unchanged_since,omitempty"`
}

type FlagResult struct {
	Reference Reference `json:"reference"`
	Flags []string `json:"flags"`
	ModSeq uint64 `json:"modseq,omitempty"`
	Conditional bool `json:"conditional"`
	Warnings []string `json:"warnings,omitempty"`
}

// MutationResult preserves a partial or uncertain outcome. A successful server
// response can lack a new UID; callers must not invent or reuse a destination UID.
type MutationResult struct {
	Source *Reference `json:"source,omitempty"`
	Destination *Reference `json:"destination,omitempty"`
	Status string `json:"status"`
	Warnings []string `json:"warnings,omitempty"`
}

// Writer is separate from Reader so an HTTP/MCP boundary can grant read-only
// access without accidentally exposing mailbox mutations.
type Writer interface {
	Capabilities(context.Context) (Capabilities,error)
	SetFlags(context.Context,FlagRequest) (FlagResult,error)
	CreateFolder(context.Context,string) error
	RenameFolder(context.Context,string,string) error
	Copy(context.Context,Reference,string) (MutationResult,error)
	Move(context.Context,Reference,string) (MutationResult,error)
	Trash(context.Context,Reference) (MutationResult,error)
	AppendDraft(context.Context,string,[]byte) (MutationResult,error)
	Delete(context.Context,Reference) (MutationResult,error)
}

// Package mail implements bounded, TLS-only access to a single configured account.
// Email contents are untrusted data, never instructions or active HTML.
package mail

import (
 "context"
 "errors"
 "time"
)

var (
 ErrInvalidInput = errors.New("invalid mail request")
 ErrStaleReference = errors.New("mailbox UIDVALIDITY changed; search again")
 ErrNotFound = errors.New("message not found")
 ErrLimit = errors.New("mail server response exceeded safety limits")
 ErrUnavailable = errors.New("mail service unavailable or authentication failed")
)

type Folder struct { Name string `json:"name"`; Delimiter string `json:"delimiter"`; Attributes []string `json:"attributes"` }
type Reference struct { Folder string `json:"folder"`; UIDValidity uint32 `json:"uid_validity"`; UID uint32 `json:"uid"` }
type Address struct { Name string `json:"name,omitempty"`; Address string `json:"address"` }
type Summary struct {
 Reference Reference `json:"reference"`
 Subject string `json:"subject"`
 From []Address `json:"from"`
 To []Address `json:"to"`
 Date time.Time `json:"date"`
 Flags []string `json:"flags"`
 Size int64 `json:"size_bytes"`
 ModSeq uint64 `json:"modseq,omitempty"`
}
type SearchRequest struct {
 Folder string `json:"folder"`
 Query string `json:"query"`
 Order string `json:"order,omitempty"` // newest (default) or oldest, by UID
 From string `json:"from,omitempty"`
 To string `json:"to,omitempty"`
 Subject string `json:"subject,omitempty"`
 Since string `json:"since,omitempty"`
 Before string `json:"before,omitempty"`
 Unread *bool `json:"unread,omitempty"`
 Flagged *bool `json:"flagged,omitempty"`
 Cursor string `json:"cursor,omitempty"`
 Limit int `json:"limit,omitempty"`
}
type SearchResult struct {
 Messages []Summary `json:"messages"`
 NextCursor string `json:"next_cursor,omitempty"`
 UIDValidity uint32 `json:"uid_validity"`
 // A page scans at most 1000 UID values, not the entire mailbox. An empty page
 // can have a next cursor. Keep paging until next_cursor is absent.
 ScannedUIDs int `json:"scanned_uids"`
 Order string `json:"order"`
}
type Attachment struct { Index int `json:"index"`; Filename string `json:"filename,omitempty"`; ContentType string `json:"content_type"`; Size int64 `json:"size_bytes"` }
type Message struct {
 raw []byte
 Summary
 Headers map[string]string `json:"headers"`
 Text string `json:"text"`
 Attachments []Attachment `json:"attachments"`
 Truncated bool `json:"truncated"`
 Warnings []string `json:"warnings,omitempty"`
}
// Reader is the complete externally exposable mailbox surface in v1.
type Reader interface {
 ListFolders(context.Context) ([]Folder,error)
 Search(context.Context,SearchRequest) (SearchResult,error)
 Read(context.Context,Reference) (Message,error)
}

type AttachmentResult struct {
 Reference Reference `json:"reference"`
 Attachment Attachment `json:"attachment"`
 DataBase64 string `json:"data_base64"`
}

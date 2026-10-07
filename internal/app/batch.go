package app

import (
 "context"
 "encoding/json"
 "fmt"
 "unicode"
 "unicode/utf8"

 "github.com/amxv/angelos/internal/mail"
)

const (
 maxBatchReferences = 10
 defaultBatchResponseBytes = 64 << 10
 maxBatchResponseBytes = 128 << 10
 maxBatchDecodedBytes = 1 << 20
)

type batchItem struct {
 Reference mail.Reference `json:"reference"`
 Status string `json:"status"`
 Message any `json:"message,omitempty"`
 Error result `json:"error,omitempty"`
}

type batchResult struct {
 Items []batchItem `json:"items"`
 MaxResponseBytes int `json:"max_response_bytes"`
 ResponseBytes int `json:"response_bytes"`
 DecodedBytes int `json:"decoded_bytes"`
 NextIndex *int `json:"next_index,omitempty"`
 StopReason string `json:"stop_reason,omitempty"`
}

// measure includes every item and all budget/continuation metadata in the UTF-8
// JSON payload. The MCP envelope may contain both text and structured copies.
func (r *batchResult) measure() (int, error) {
 for {
  b, err := json.Marshal(r)
  if err != nil { return 0, err }
  if r.ResponseBytes == len(b) { return len(b), nil }
  r.ResponseBytes = len(b)
 }
}

func (a *App) readMany(ctx context.Context, in queryInput) (any, error) {
 budget := in.MaxResponseBytes
 if budget == 0 { budget = defaultBatchResponseBytes }
 if budget < 4096 || budget > maxBatchResponseBytes || len(in.References) < 1 || len(in.References) > maxBatchReferences {
  return nil, fmt.Errorf("%w: read_many needs 1-10 references and max_response_bytes 4096-131072", mail.ErrInvalidInput)
 }
 seen := make(map[mail.Reference]bool)
 for _, ref := range in.References {
  valid := len(ref.Folder) > 0 && len(ref.Folder) <= 1024 && utf8.ValidString(ref.Folder) && ref.UID != 0 && ref.UIDValidity != 0
  for _, r := range ref.Folder { if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) { valid = false } }
  if !valid || seen[ref] { return nil, fmt.Errorf("%w: read_many needs distinct valid exact references", mail.ErrInvalidInput) }
  seen[ref] = true
 }
 out := batchResult{Items: make([]batchItem, len(in.References)), MaxResponseBytes: budget}
 for i, ref := range in.References { out.Items[i] = batchItem{Reference: ref, Status: "not_read"} }
 // Reserve a complete result skeleton plus continuation metadata before any I/O.
 index := 0
 out.NextIndex, out.StopReason = &index, "decoded_limit"
 n, err := out.measure()
 if err != nil || n + 128 > budget { return nil, fmt.Errorf("%w: reference metadata exceeds response budget; split references or increase max_response_bytes", mail.ErrInvalidInput) }
 out.NextIndex, out.StopReason = nil, ""
 for i, ref := range in.References {
  index = i
  if ctx.Err() != nil { out.NextIndex, out.StopReason = &index, "cancelled"; break }
  m, readErr := a.Mail.Read(ctx, ref)
  item := batchItem{Reference: ref, Status: "error"}
  if readErr != nil {
   item.Error = errorPayload(readErr, nil, true)
  } else {
   raw, marshalErr := json.Marshal(m)
   if marshalErr != nil { item.Error = errorPayload(mail.ErrUnavailable, nil, true) } else {
    if len(raw) > maxBatchDecodedBytes-out.DecodedBytes {
     out.Items[i].Status = "not_returned"
     out.NextIndex, out.StopReason = &index, "decoded_limit"
     break
    }
    out.DecodedBytes += len(raw)
    item.Status = "ok"
    if in.Detail == "full" { item.Message = m } else { item.Message = messageSummary(m) }
   }
  }
  out.Items[i] = item
  // Always reserve room to describe why the current item cannot fit.
  n, err = out.measure()
  if err != nil || n + 128 > budget {
   out.Items[i] = batchItem{Reference: ref, Status: "not_returned"}
   out.NextIndex, out.StopReason = &index, "response_limit"
   break
  }
 }
 _, err = out.measure()
 if err != nil { return nil, mail.ErrUnavailable }
 return out, nil
}

package app

import (
	"github.com/amxv/angelos/internal/mail"
	"unicode/utf8"
)

// Search pages share a mailbox identity. Keep UID/MODSEQ/flags on every row;
// full mode exposes the original nested reference shape and every original field.
func searchSummary(page mail.SearchResult, folder string) result {
	if folder == "" {
		folder = "INBOX"
	}
	rows := make([]result, 0, len(page.Messages))
	for _, m := range page.Messages {
		row := summaryFields(m)
		delete(row, "reference")
		row["uid"] = m.Reference.UID
		// Defensive fallback preserves unexpected backend identities without inventing one.
		if m.Reference.Folder != folder || m.Reference.UIDValidity != page.UIDValidity {
			row["reference"] = m.Reference
		}
		rows = append(rows, row)
	}
	out := result{"folder": folder, "uid_validity": page.UIDValidity, "messages": rows, "scanned_uids": page.ScannedUIDs, "order": page.Order}
	if page.NextCursor != "" {
		out["next_cursor"] = page.NextCursor
	}
	return out
}

const summaryTextBytes = 4096

// Clipping here is presentation-only: backend Truncated still reports MIME/read
// incompleteness and continues to guard reply/forward preparation independently.
func messageSummary(m mail.Message) result {
	out := summaryFields(m.Summary)
	out["text"] = m.Text
	out["truncated"] = m.Truncated
	if len(m.Headers) > 0 {
		out["headers"] = m.Headers
	}
	if len(m.Attachments) > 0 {
		out["attachments"] = m.Attachments
	}
	if len(m.Warnings) > 0 {
		out["warnings"] = m.Warnings
	}
	if len(m.Text) > summaryTextBytes {
		n := summaryTextBytes
		for n > 0 && !utf8.RuneStart(m.Text[n]) {
			n--
		}
		out["text"] = m.Text[:n]
		out["text_clipped"] = true
		out["text_bytes"] = len(m.Text)
		out["full_text_hint"] = "Repeat read with detail=full for all available text."
	}
	return out
}

func summaryFields(m mail.Summary) result {
	// Keep integer types intact. A JSON round-trip through float64 would corrupt
	// uint64 MODSEQ values and could fail on malformed upstream dates.
	out := result{"reference": m.Reference, "subject": m.Subject, "date": m.Date, "flags": m.Flags, "size_bytes": m.Size}
	if len(m.From) > 0 {
		out["from"] = m.From
	}
	if len(m.To) > 0 {
		out["to"] = m.To
	}
	if m.ModSeq != 0 {
		out["modseq"] = m.ModSeq
	}
	return out
}

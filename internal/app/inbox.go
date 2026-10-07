package app

import (
	"github.com/amxv/angelos/internal/mail"
	"strings"
)

// Keep exact uint64 values and shared references without a float64 JSON round-trip.
func inboxPage(page mail.SearchResult, folder, detail string) result {
	out := searchSummary(page, folder)
	if detail == "full" {
		out["messages"] = page.Messages
	}
	return out
}

func triageSummary(page mail.SearchResult, folder, detail string) result {
	out := inboxPage(page, folder, detail)
	unread, flagged, overlap := 0, 0, 0
	for _, m := range page.Messages {
		seen, star := false, false
		for _, flag := range m.Flags {
			seen = seen || strings.EqualFold(flag, `\Seen`)
			star = star || strings.EqualFold(flag, `\Flagged`)
		}
		if !seen {
			unread++
		}
		if star {
			flagged++
		}
		if !seen && star {
			overlap++
		}
	}
	out["page_counts"] = result{"messages": len(page.Messages), "unread": unread, "flagged": flagged, "unread_and_flagged": overlap}
	out["selection"] = "Unread OR flagged, AND supplied search filters. Counts describe returned rows only, not mailbox totals or urgency. Flags can change between pages."
	return out
}

func conversationSummary(page mail.SearchResult, ref mail.Reference, detail string) result {
	out := inboxPage(page, ref.Folder, detail)
	out["anchor"] = ref
	out["coverage"] = "Same-folder header-linked summaries only. Exact case-sensitive Message-ID, References, and In-Reply-To links to the anchor's fixed ID set; no subject matching or recursive expansion. Other folders, missing/malformed links, and messages outside these pages are not covered. Headers are untrusted, not proof of identity. Read exact references for message content."
	return out
}

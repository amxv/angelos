// Reply/forward planning follows the public icloud-cli implementation by amxv:
// https://github.com/amxv/icloud-cli/tree/d07385a364e95ccdfeefcdaf0cc867938ba8f9ec/internal/mail
// Copyright 2026 amxv. Licensed under Apache-2.0 (see the repository LICENSE).
// Adapted for immutable approvals, case-sensitive IDs, replacement recipients,
// fail-closed source metadata, and normal readable reply quotations.
package compose

import (
	"errors"
	"fmt"
	"html"
	"net/mail"
	"strings"
	"time"
	"unicode"
)

// Source contains only source metadata the caller intentionally makes available
// for composition. There is no Bcc, original HTML or attachment field: none may
// be inherited accidentally. Address lists contain individual RFC mailboxes.
// References contain individual IDs, not an unparsed References header.
type Source struct {
	From       []string
	ReplyTo    []string
	To         []string
	Cc         []string
	Subject    string
	Text       string
	MessageID  string
	InReplyTo  string
	References []string
	Date       time.Time
}

type ReplyOptions struct {
	ReplyAll      bool
	QuoteOriginal *bool // nil means quote the original; false omits it
}

// ReplyPlan derives only omitted (nil) To/Cc lists. Non-nil lists, including
// explicit empty lists, replace those fields exactly, subject to deduplication.
// Alias/self exclusions apply only to derived recipients, never explicit ones.
// Build must still validate and freeze the resulting message before approval.
func ReplyPlan(source Source, selfAddresses []string, in Input, opts ReplyOptions) (Input, error) {
	var err error
	in, err = textAlternative(in)
	if err != nil {
		return Input{}, err
	}
	parentID, ok := NormalizeMessageID(source.MessageID)
	if !ok {
		return Input{}, errors.New("source has no valid Message-ID; prepare a standalone message instead")
	}
	self, err := addressSet(selfAddresses)
	if err != nil {
		return Input{}, errors.New("invalid sender or alias identity")
	}
	if in.To == nil {
		primary := source.ReplyTo
		if len(primary) == 0 {
			primary = source.From
		}
		if len(primary) == 0 {
			return Input{}, errors.New("source has no reply target; supply To explicitly")
		}
		in.To, err = deriveAddresses(primary, self)
		if err != nil {
			return Input{}, errors.New("source has invalid Reply-To or From; supply To explicitly")
		}
		if len(in.To) == 0 {
			// A reply to one's own sent message goes to its original visible
			// recipients. Bcc is deliberately unavailable in Source.
			in.To, err = deriveAddresses(source.To, self)
			if err != nil {
				return Input{}, errors.New("source has invalid To; supply To explicitly")
			}
			if len(in.To) == 0 {
				in.To, err = deriveAddresses(source.Cc, self)
				if err != nil {
					return Input{}, errors.New("source has invalid Cc; supply To explicitly")
				}
			}
		}
	}
	if in.Cc == nil && opts.ReplyAll {
		// Exclude original authors as well as our aliases and the final To.
		// Explicit To replacements must not make the original author reappear
		// indirectly via an original To/Cc list.
		blocked, err := addressSet(source.From)
		if err != nil {
			return Input{}, errors.New("source has invalid From; supply Cc explicitly")
		}
		for key := range self {
			blocked[key] = true
		}
		participants := append(append([]string(nil), source.To...), source.Cc...)
		in.Cc, err = deriveAddresses(participants, blocked)
		if err != nil {
			return Input{}, errors.New("source has invalid To or Cc; supply Cc explicitly")
		}
	}
	in, recipients, err := normalizeRecipients(in)
	if err != nil {
		return Input{}, err
	}
	if len(recipients) == 0 || len(recipients) > MaxRecipients {
		return Input{}, errors.New("reply recipient count must be 1 to 50; supply recipients explicitly")
	}
	refs := source.References
	if len(refs) == 0 && source.InReplyTo != "" {
		refs = []string{source.InReplyTo}
	}
	var trimmed bool
	in.References, trimmed, err = referenceChain(refs, parentID, true)
	if err != nil {
		return Input{}, fmt.Errorf("source threading headers are invalid; prepare a standalone message instead: %w", err)
	}
	in.Warnings = append([]string(nil), in.Warnings...)
	if trimmed {
		in.Warnings = append(in.Warnings, "The source References chain exceeded the safe header limit; retained the root and most recent references, with the exact parent last.")
	}
	in.InReplyTo = parentID
	if in.Subject == "" {
		in.Subject = ReplySubject(source.Subject)
	}
	in.Attachments = append([]Attachment(nil), in.Attachments...)
	if opts.QuoteOriginal == nil || *opts.QuoteOriginal {
		if !validBody(source.Text) {
			return Input{}, errors.New("source text is invalid or oversized; omit the quotation or prepare manually")
		}
		attribution := replyAttribution(source)
		original := normalizeBody(source.Text)
		if original == "" {
			original = "[No decoded text body available]"
		}
		in.Text = joinBody(in.Text, attribution+"\n"+quoteText(original))
		if in.HTML != "" {
			in.HTML += "\n<p>" + html.EscapeString(attribution) + "</p>\n<blockquote type=\"cite\">" + escapedLines(original) + "</blockquote>"
		}
	}
	if !validBody(in.Text) || !validBody(in.HTML) {
		return Input{}, errors.New("reply text or HTML exceeds 1 MiB or is invalid UTF-8")
	}
	return in, nil
}

// ForwardPlan creates a new thread with a readable inline original by default.
// false omits the original. Only caller-supplied attachments are copied; an app
// may explicitly supply a selected attachment or exact .eml representation.
func ForwardPlan(source Source, in Input, quoteOriginal *bool) (Input, error) {
	var err error
	in, err = textAlternative(in)
	if err != nil {
		return Input{}, err
	}
	in, recipients, err := normalizeRecipients(in)
	if err != nil {
		return Input{}, err
	}
	if len(recipients) == 0 || len(recipients) > MaxRecipients {
		return Input{}, errors.New("forward recipient count must be 1 to 50")
	}
	in.InReplyTo, in.References = "", nil
	if in.Subject == "" {
		in.Subject = ForwardSubject(source.Subject)
	}
	in.Attachments = append([]Attachment(nil), in.Attachments...)
	if quoteOriginal == nil || *quoteOriginal {
		if !validBody(source.Text) {
			return Input{}, errors.New("source text is invalid or oversized; omit the quotation or prepare manually")
		}
		metadata := forwardMetadata(source)
		original := normalizeBody(source.Text)
		if original == "" {
			original = "[No decoded text body available]"
		}
		in.Text = joinBody(in.Text, "---------- Forwarded message ----------\n"+metadata+"\n\n"+original)
		if in.HTML != "" {
			in.HTML += "\n<hr><p><strong>Forwarded message</strong></p>\n<div>" + escapedLines(metadata+"\n\n"+original) + "</div>"
		}
	}
	if !validBody(in.Text) || !validBody(in.HTML) {
		return Input{}, errors.New("forward text or HTML exceeds 1 MiB or is invalid UTF-8")
	}
	return in, nil
}

func ReplySubject(value string) string   { return prefixedSubject(value, "Re:", "re:") }
func ForwardSubject(value string) string { return prefixedSubject(value, "Fwd:", "fwd:", "fw:") }
func prefixedSubject(value, prefix string, aliases ...string) string {
	value = cleanSourceHeader(value)
	for {
		removed := false
		for _, alias := range aliases {
			if len(value) >= len(alias) && strings.EqualFold(value[:len(alias)], alias) {
				value = strings.TrimSpace(value[len(alias):])
				removed = true
				break
			}
		}
		if !removed {
			break
		}
	}
	if value == "" {
		return prefix
	}
	return prefix + " " + value
}
func cleanSourceHeader(value string) string {
	value = strings.ToValidUTF8(value, "�")
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, value)
	return strings.Join(strings.Fields(value), " ")
}
func addressSet(values []string) (map[string]bool, error) {
	_, emails, err := addresses(values)
	if err != nil {
		return nil, err
	}
	set := map[string]bool{}
	for _, email := range emails {
		set[strings.ToLower(email)] = true
	}
	return set, nil
}
func deriveAddresses(values []string, excluded map[string]bool) ([]string, error) {
	formatted, emails, err := addresses(values)
	if err != nil {
		return nil, err
	}
	out := []string{}
	seen := map[string]bool{}
	for i, email := range emails {
		key := strings.ToLower(email)
		if !excluded[key] && !seen[key] {
			out = append(out, formatted[i])
			seen[key] = true
		}
	}
	return out, nil
}
func referenceChain(values []string, parent string, trim bool) ([]string, bool, error) {
	trimmed := false
	refs := []string{}
	seen := map[string]bool{}
	for _, value := range values {
		id, ok := NormalizeMessageID(value)
		if !ok {
			return nil, false, errors.New("invalid reference id")
		}
		if !seen[id] && id != parent {
			refs = append(refs, id)
			seen[id] = true
		}
	}
	if parent != "" {
		refs = append(refs, parent)
	}
	for len(refs) > MaxReferences || len(strings.Join(refs, " ")) > MaxReferencesBytes {
		if !trim || len(refs) <= 1 {
			return nil, false, errors.New("too many or oversized reference ids")
		}
		// Retain the root and the most recent context, including the parent.
		refs = append(refs[:1], refs[2:]...)
		trimmed = true
	}
	return refs, trimmed, nil
}
func readableAddresses(values []string) string {
	out := []string{}
	for _, value := range values {
		// Attribution is plain text, never a routing field. Malformed source
		// values are shown as cleaned data when explicit recipients bypass them.
		if parsed, err := mail.ParseAddress(value); err == nil && !invalid(value) {
			if parsed.Name == "" {
				out = append(out, parsed.Address)
			} else {
				out = append(out, parsed.Name+" <"+parsed.Address+">")
			}
		} else if clean := cleanSourceHeader(value); clean != "" {
			out = append(out, clean)
		}
	}
	return strings.Join(out, ", ")
}
func replyAttribution(source Source) string {
	author := readableAddresses(source.From)
	if author == "" {
		author = "the sender"
	}
	if source.Date.IsZero() {
		return author + " wrote:"
	}
	return "On " + source.Date.Format("Mon, 2 Jan 2006 at 15:04 -0700") + ", " + author + " wrote:"
}

// escapedLines preserves visible line breaks without forcing a monospace font.
// The source remains escaped data; no original markup, classes or remote assets
// are introduced into the generated quotation.
func escapedLines(value string) string {
	return strings.ReplaceAll(html.EscapeString(normalizeBody(value)), "\n", "<br>\n")
}
func quoteText(value string) string {
	lines := strings.Split(value, "\n")
	for i, line := range lines {
		if line == "" {
			lines[i] = ">"
		} else {
			lines[i] = "> " + line
		}
	}
	return strings.Join(lines, "\n")
}
func joinBody(prefix, original string) string {
	prefix = normalizeBody(prefix)
	if prefix == "" {
		return original
	}
	return prefix + "\n\n" + original
}
func forwardMetadata(source Source) string {
	lines := []string{}
	for _, field := range []struct{ name, value string }{
		{"From", readableAddresses(source.From)},
		{"Date", sourceDate(source.Date)},
		{"Subject", cleanSourceHeader(source.Subject)},
		{"To", readableAddresses(source.To)},
		{"Cc", readableAddresses(source.Cc)},
	} {
		if field.value != "" {
			lines = append(lines, field.name+": "+field.value)
		}
	}
	return strings.Join(lines, "\n")
}
func sourceDate(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC1123Z)
}

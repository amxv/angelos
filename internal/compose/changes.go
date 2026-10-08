package compose

// Changes uses nil for omitted fields. Non-nil empty strings/lists explicitly
// clear fields; attachments replaces the entire list. Protocol rejects null.
type Changes struct {
	To          []string     `json:"to,omitempty"`
	Cc          []string     `json:"cc,omitempty"`
	Bcc         []string     `json:"bcc,omitempty"`
	Subject     *string      `json:"subject,omitempty"`
	Text        *string      `json:"text,omitempty"`
	HTML        *string      `json:"html,omitempty"`
	Attachments []Attachment `json:"attachments,omitempty"`
	InReplyTo   *string      `json:"in_reply_to,omitempty"`
	References  []string     `json:"references,omitempty"`
}

func (c Changes) Apply(in Input) Input {
	if c.To != nil {
		in.To = c.To
	}
	if c.Cc != nil {
		in.Cc = c.Cc
	}
	if c.Bcc != nil {
		in.Bcc = c.Bcc
	}
	if c.Subject != nil {
		in.Subject = *c.Subject
	}
	if c.Text != nil {
		in.Text = *c.Text
		in.PreserveEmptyText = true
	}
	if c.HTML != nil {
		in.HTML = *c.HTML
	}
	if c.Attachments != nil {
		in.Attachments = c.Attachments
	}
	if c.InReplyTo != nil {
		in.InReplyTo = *c.InReplyTo
	}
	if c.References != nil {
		in.References = c.References
	}
	return in
}

package compose

import (
	"errors"
	"strings"

	"golang.org/x/net/html"
)

// textAlternative uses only the caller's authored HTML when no plain alternative
// was supplied. It never fetches resources, evaluates markup, or reads source HTML.
// The resulting text is persisted and reviewed just like an explicit text body.
func textAlternative(in Input) (Input, error) {
	if !validBody(in.Text) || !validBody(in.HTML) {
		return Input{}, errors.New("text and HTML must be valid UTF-8, without prohibited controls, and at most 1 MiB each")
	}
	if in.Text != "" || in.HTML == "" || in.PreserveEmptyText {
		return in, nil
	}
	doc, err := html.Parse(strings.NewReader(in.HTML))
	if err != nil {
		return Input{}, errors.New("could not derive a complete plain-text alternative from HTML; provide text explicitly or simplify the HTML")
	}
	var b strings.Builder
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "head", "script", "style", "template", "noscript", "iframe", "object":
				return
			case "br", "p", "div", "li", "tr", "blockquote", "pre", "h1", "h2", "h3", "h4", "h5", "h6":
				b.WriteByte('\n')
			}
		}
		if n.Type == html.TextNode {
			b.WriteString(n.Data)
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
		if n.Type == html.ElementNode {
			switch n.Data {
			case "p", "div", "li", "tr", "blockquote", "pre", "h1", "h2", "h3", "h4", "h5", "h6":
				b.WriteByte('\n')
			case "td", "th":
				b.WriteByte(' ')
			}
		}
	}
	walk(doc)
	// Numeric character references can introduce controls not present in the
	// authored HTML bytes. Validate before whitespace cleanup can hide them.
	if !validBody(b.String()) {
		return Input{}, errors.New("derived HTML text is invalid or exceeds 1 MiB; provide a valid plain-text alternative explicitly")
	}
	lines := []string{}
	for _, line := range strings.Split(normalizeBody(b.String()), "\n") {
		line = strings.Join(strings.Fields(line), " ")
		if line != "" {
			lines = append(lines, line)
		}
	}
	in.Text = strings.Join(lines, "\n")
	if !validBody(in.Text) {
		return Input{}, errors.New("derived HTML text is invalid or exceeds 1 MiB")
	}
	return in, nil
}

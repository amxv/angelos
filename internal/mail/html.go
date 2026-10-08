package mail

import (
	"io"
	"net/url"
	"strings"
	"unicode"

	"golang.org/x/net/html"
)

// htmlText extracts text with a streaming tokenizer. No DOM, scripts, styles,
// remote resources, or links are evaluated. Selected hrefs are untrusted text.
// Bounds apply even to malformed HTML and extremely long or deeply nested markup.
func htmlText(r io.Reader) (string, bool) {
	limited := &io.LimitedReader{R: r, N: (1 << 20) + 1}
	tokenizer := html.NewTokenizer(limited)
	tokenizer.SetMaxBuf(64 << 10)
	type frame struct {
		tag       string
		hidden    bool
		href      string
		textStart int
	}
	stack := make([]frame, 0, 32)
	var out strings.Builder
	hidden := func() bool { return len(stack) > 0 && stack[len(stack)-1].hidden }
	add := func(s string) bool {
		left := maxTextBytes - out.Len()
		if len(s) > left {
			out.WriteString(clean(s, left))
			return false
		}
		out.WriteString(s)
		return true
	}
	finish := func(truncated bool) (string, bool) {
		lines := strings.Split(clean(out.String(), maxTextBytes), "\n")
		normalized := lines[:0]
		for _, line := range lines {
			line = strings.Join(strings.Fields(line), " ")
			// Nested layout tags and source indentation are not paragraphs.
			// Keep at most one blank line, while preserving nonempty lines.
			if line == "" && (len(normalized) == 0 || normalized[len(normalized)-1] == "") {
				continue
			}
			normalized = append(normalized, line)
		}
		return strings.TrimSpace(strings.Join(normalized, "\n")), truncated
	}
	for count := 0; count < 20000; count++ {
		kind := tokenizer.Next()
		switch kind {
		case html.ErrorToken:
			return finish(tokenizer.Err() != io.EOF || limited.N <= 0)
		case html.TextToken:
			if !hidden() {
				if !add(string(tokenizer.Text())) {
					return finish(true)
				}
			}
		case html.StartTagToken, html.SelfClosingTagToken:
			name, hasAttrs := tokenizer.TagName()
			tag := string(name)
			discard := hidden() || htmlDiscardTag(tag)
			if !discard && htmlBlockTag(tag) {
				if !add("\n") {
					return finish(true)
				}
			}
			var href string
			if tag == "a" && !discard {
				for hasAttrs {
					key, value, more := tokenizer.TagAttr()
					hasAttrs = more
					if string(key) == "href" {
						href = htmlLinkDestination(string(value))
						break // HTML uses the first occurrence of an attribute.
					}
				}
			}
			// In HTML, a self-closing slash does not close non-void elements
			// such as script/style/iframe. Keep their contents hidden. SVG and
			// MathML switch namespaces and do honor self-closing syntax.
			if !htmlVoidTag(tag) && (kind == html.StartTagToken || (tag != "svg" && tag != "math")) {
				if len(stack) >= 128 {
					return finish(true)
				}
				stack = append(stack, frame{tag: tag, hidden: discard, href: href, textStart: out.Len()})
			}
		case html.EndTagToken:
			name, _ := tokenizer.TagName()
			tag := string(name)
			wasHidden := hidden()
			for i := len(stack) - 1; i >= 0; i-- {
				if stack[i].tag == tag {
					f := stack[i]
					if !wasHidden && f.href != "" {
						label := strings.TrimSpace(out.String()[f.textStart:])
						if label != "" && label != f.href && label != strings.TrimPrefix(f.href, "mailto:") {
							if !add(" <" + f.href + ">") {
								return finish(true)
							}
						}
					}
					stack = stack[:i]
					break
				}
			}
			if !wasHidden && htmlBlockTag(tag) {
				if !add("\n") {
					return finish(true)
				}
			}
		}
	}
	return finish(true)
}
func htmlDiscardTag(tag string) bool {
	switch tag {
	case "script", "style", "head", "iframe", "object", "template", "noscript", "svg", "math", "title":
		return true
	}
	return false
}
func htmlVoidTag(tag string) bool {
	switch tag {
	case "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr":
		return true
	}
	return false
}
func htmlBlockTag(tag string) bool {
	switch tag {
	case "br", "hr", "p", "div", "section", "article", "header", "footer", "blockquote", "pre", "li", "ul", "ol", "table", "tr", "td", "th", "h1", "h2", "h3", "h4", "h5", "h6":
		return true
	}
	return false
}

// htmlLinkDestination allows only bounded absolute web/mail destinations. It
// does not resolve relative references, decode escapes, or verify trust/safety.
func htmlLinkDestination(raw string) string {
	if raw == "" || len(raw) > 2048 || clean(raw, len(raw)) != raw {
		return ""
	}
	for _, r := range raw {
		if unicode.IsSpace(r) || r == '<' || r == '>' {
			return ""
		}
	}
	u, err := url.Parse(raw)
	if err != nil || u.User != nil {
		return ""
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		if u.Hostname() != "" && u.Opaque == "" {
			return raw
		}
	case "mailto":
		if u.Opaque != "" && u.Host == "" {
			return raw
		}
	}
	return ""
}

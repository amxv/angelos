package mail

import (
	"io"
	"strings"

	"golang.org/x/net/html"
)

// htmlText extracts text with a streaming tokenizer. No DOM, scripts, styles,
// attributes, remote resources, or links are evaluated. Bounds apply even to
// malformed HTML and to extremely long tokens or deeply nested markup.
func htmlText(r io.Reader) (string, bool) {
	limited := &io.LimitedReader{R: r, N: (1 << 20) + 1}
	tokenizer := html.NewTokenizer(limited)
	tokenizer.SetMaxBuf(64 << 10)
	type frame struct {
		tag    string
		hidden bool
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
		for i, line := range lines {
			lines[i] = strings.Join(strings.Fields(line), " ")
		}
		return strings.TrimSpace(strings.Join(lines, "\n")), truncated
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
			name, _ := tokenizer.TagName()
			tag := string(name)
			discard := hidden() || htmlDiscardTag(tag)
			if !discard && htmlBlockTag(tag) {
				if !add("\n") {
					return finish(true)
				}
			}
			if kind == html.StartTagToken && !htmlVoidTag(tag) {
				if len(stack) >= 128 {
					return finish(true)
				}
				stack = append(stack, frame{tag: tag, hidden: discard})
			}
		case html.EndTagToken:
			name, _ := tokenizer.TagName()
			tag := string(name)
			wasHidden := hidden()
			for i := len(stack) - 1; i >= 0; i-- {
				if stack[i].tag == tag {
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

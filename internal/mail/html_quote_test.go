package mail

import (
	"strings"
	"testing"
)

func TestHTMLSelfClosingNonVoidContentStaysOutOfQuotes(t *testing.T) {
	for _, tag := range []string{"script", "style", "iframe", "object", "template", "noscript", "head", "title"} {
		t.Run(tag, func(t *testing.T) {
			input := "<" + tag + "/>doNotQuote()</" + tag + "><p>Real message</p>"
			text, truncated := htmlText(strings.NewReader(input))
			if truncated || strings.Contains(text, "doNotQuote") || text != "Real message" {
				t.Fatalf("hidden content entered source text: %q, truncated=%v", text, truncated)
			}
			var message Message
			parseMessage([]byte("Content-Type: text/html\r\n\r\n"+input), &message)
			if message.Text != "Real message" || message.Truncated {
				t.Fatalf("read-to-quote text: %+v", message)
			}
		})
	}
}

func TestHTMLSelfClosingForeignElementsDoNotHideFollowingText(t *testing.T) {
	for _, input := range []string{"<svg/><p>Real message</p>", "<math/><p>Real message</p>", "<img/><p>Real message</p>"} {
		text, truncated := htmlText(strings.NewReader(input))
		if text != "Real message" || truncated {
			t.Fatalf("text=%q truncated=%v", text, truncated)
		}
	}
}

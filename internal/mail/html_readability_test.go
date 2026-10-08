package mail

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestHTMLReadabilityBlankLines(t *testing.T) {
	input := "<table>\n<tr><td><div><p>First</p></div></td></tr>\n\n<tr><td><div><p>Second</p></div></td></tr></table>"
	got, truncated := htmlText(strings.NewReader(input))
	if got != "First\n\nSecond" || truncated {
		t.Fatalf("got %q, truncated=%v", got, truncated)
	}
	// Preserve explicit line breaks and the existing separation of table cells.
	got, truncated = htmlText(strings.NewReader("<p>First<br>line</p><table><tr><td>A</td><td>B</td></tr></table>"))
	if got != "First\nline\n\nA\n\nB" || truncated {
		t.Fatalf("got %q, truncated=%v", got, truncated)
	}
}

func TestHTMLReadabilityLinks(t *testing.T) {
	for _, tt := range []struct{ name, input, want string }{
		{"web", `<p>Open <a href="https://example.test/path?a=1&amp;b=2"><b>the report</b></a>.</p>`, "Open the report <https://example.test/path?a=1&b=2>."},
		{"http", `<a href="http://example.test">Report</a>`, "Report <http://example.test>"},
		{"mail", `<a href="mailto:person@example.test">Email us</a>`, "Email us <mailto:person@example.test>"},
		{"duplicate web", `<a href="https://example.test">https://example.test</a>`, "https://example.test"},
		{"duplicate mail", `<a href="mailto:person@example.test">person@example.test</a>`, "person@example.test"},
		{"phishing label", `<a href="https://other.test">https://example.test</a>`, "https://example.test <https://other.test>"},
		{"hidden", `<template><a href="https://example.test">Hidden</a></template>Visible`, "Visible"},
		{"image only", `<a href="https://example.test"><img src="https://tracker.test"></a>Visible`, "Visible"},
		{"first attribute", `<a href="javascript:alert(1)" href="https://example.test">Visible</a>`, "Visible"},
		{"relative", `<base href="https://example.test"><a href="/report">Report</a>`, "Report"},
		{"unclosed", `<a href="https://example.test">Report`, "Report"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, truncated := htmlText(strings.NewReader(tt.input))
			if got != tt.want || truncated {
				t.Fatalf("got %q, want %q, truncated=%v", got, tt.want, truncated)
			}
		})
	}
}

func TestHTMLLinkDestinationRejections(t *testing.T) {
	for _, href := range []string{
		"javascript:alert(1)", "data:text/html,hello", "file:///etc/passwd", "//example.test", "#fragment", "/relative", "https:", "https:example.test", "https:///missing-host", "https://user:secret@example.test", "mailto:", "mailto://example.test", "https://example.test/%zz", "https://example.test/white space", "https://example.test/\nheader", "https://example.test/\tname", "https://example.test/\u202ereverse", "https://example.test/<markup>", "https://example.test/" + strings.Repeat("x", 2048),
	} {
		if got := htmlLinkDestination(href); got != "" {
			t.Errorf("accepted %q as %q", href, got)
		}
	}
	got, truncated := htmlText(strings.NewReader(`<a href="https://example.test/&#10;header">Report</a>`))
	if got != "Report" || truncated {
		t.Fatalf("control-bearing href: %q %v", got, truncated)
	}
}

func TestHTMLReadabilityLimitsAndWarning(t *testing.T) {
	input := strings.Repeat(`<a href="https://example.test/`+strings.Repeat("x", 1800)+`">Report</a>`, 180)
	got, truncated := htmlText(strings.NewReader(input))
	if !truncated || len(got) > maxTextBytes || !utf8.ValidString(got) {
		t.Fatalf("output limit: len=%d truncated=%v", len(got), truncated)
	}
	var message Message
	parseMessage([]byte("Content-Type: text/html\r\n\r\n<p><a href=\"https://example.test\">Report</a></p>"), &message)
	if message.Text != "Report <https://example.test>" || message.Truncated || !strings.Contains(strings.Join(message.Warnings, " "), "untrusted text") {
		t.Fatalf("read-to-quote result: %+v", message)
	}
}

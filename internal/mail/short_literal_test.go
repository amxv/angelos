package mail

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
)

// Mid-literal disconnects must not race a second discard against the decoder.
func TestReadAndExactSearchPrematureLiteral(t *testing.T) {
	for _, action := range []string{"read", "search"} {
		t.Run(action, func(t *testing.T) {
			b := backendForTest(t, func(c net.Conn) {
				fmt.Fprint(c, "* OK [CAPABILITY IMAP4rev1] short literal test\r\n")
				r := bufio.NewReader(c)
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					parts := strings.SplitN(strings.TrimSpace(line), " ", 2)
					if len(parts) != 2 {
						return
					}
					tag, cmd := parts[0], strings.ToUpper(parts[1])
					switch {
					case strings.HasPrefix(cmd, "LOGIN "):
						fmt.Fprintf(c, "%s OK [CAPABILITY IMAP4rev1] login\r\n", tag)
					case cmd == "CAPABILITY":
						fmt.Fprintf(c, "* CAPABILITY IMAP4rev1\r\n%s OK capabilities\r\n", tag)
					case strings.HasPrefix(cmd, "EXAMINE "):
						fmt.Fprintf(c, "* 1 EXISTS\r\n* OK [UIDVALIDITY 7] valid\r\n* OK [UIDNEXT 2] next\r\n%s OK [READ-ONLY] selected\r\n", tag)
					case strings.HasPrefix(cmd, "UID SEARCH "):
						fmt.Fprintf(c, "* SEARCH 1\r\n%s OK searched\r\n", tag)
					case strings.HasPrefix(cmd, "UID FETCH "):
						section := "BODY[]<0>"
						if action == "search" {
							section = "BODY[HEADER.FIELDS (MESSAGE-ID)]<0>"
						}
						fmt.Fprintf(c, "* 1 FETCH (UID 1 RFC822.SIZE 128 %s {128}\r\npartial", section)
						c.Close()
						return
					default:
						fmt.Fprintf(c, "%s BAD unexpected\r\n", tag)
					}
				}
			}, true)
			var err error
			if action == "read" {
				_, err = b.Read(context.Background(), Reference{Folder: "INBOX", UIDValidity: 7, UID: 1})
			} else {
				_, err = b.Search(context.Background(), SearchRequest{MessageID: "id@example"})
			}
			if err != ErrUnavailable {
				t.Fatal("premature literal did not fail safely", err)
			}
		})
	}
}

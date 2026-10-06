package mail

import (
 "fmt"
 "strings"
 "testing"
)
func TestParseMIME(t *testing.T){
 raw:="From: Sender <sender@example.com>\r\nSubject: =?UTF-8?Q?caf=C3=A9?=\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nhello=20world\r\n--x\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=example.txt\r\nContent-Transfer-Encoding: base64\r\n\r\naGVsbG8=\r\n--x--\r\n"
 out:=Message{Headers:map[string]string{}};parseMessage([]byte(raw),&out)
 if out.Headers["Subject"]!="café"||!strings.Contains(out.Text,"hello world")||len(out.Attachments)!=1||out.Attachments[0].Size!=5 {t.Fatalf("unexpected parse: %+v",out)}
}
func TestHTMLNeverReturned(t *testing.T){out:=Message{Headers:map[string]string{}};parseMessage([]byte("Content-Type: text/html\r\n\r\n<script>bad()</script><img src=\"https://example.com/track\">"),&out);if out.Text!=""{t.Fatalf("HTML leaked: %+v",out)}}
func TestMIMEBounded(t *testing.T){out:=Message{Headers:map[string]string{}};parseMessage([]byte("Content-Type: text/plain\r\n\r\n"+strings.Repeat("x",maxTextBytes+10)),&out);if !out.Truncated||len(out.Text)>maxTextBytes{t.Fatal("unbounded text")}}
func TestNestedMIMEDepthBound(t *testing.T){body:="Content-Type: text/plain\r\n\r\nhello";for i:=0;i<20;i++{body=fmt.Sprintf("Content-Type: multipart/mixed; boundary=b%d\r\n\r\n--b%d\r\n%s\r\n--b%d--\r\n",i,i,body,i)};out:=Message{Headers:map[string]string{}};parseMessage([]byte(body),&out);if !out.Truncated{t.Fatal("depth not bounded")}}
func TestSanitizeControls(t *testing.T){if got:=cleanHeader("a\x1b[31m\r\n b\u202ec",100);got!="a[31m bc"{t.Fatalf("got %q",got)}}
func TestCursorScope(t *testing.T){scope:=searchScope("INBOX","term");c:=encodeCursor(cursor{Version:9,Before:20,Scope:scope});if _,e:=decodeCursor(c,scope);e!=nil{t.Fatal(e)};if _,e:=decodeCursor(c,searchScope("Sent","term"));e==nil{t.Fatal("cross-folder cursor accepted")};if _,e:=decodeCursor(strings.Repeat("A",513),scope);e==nil{t.Fatal("oversized cursor accepted")}}

func TestHTMLTextExtraction(t *testing.T){raw:="Content-Type: text/html; charset=utf-8\r\n\r\n<html><head><title>hidden</title><style>.x { color: red }</style></head><body><p>Hello &amp; welcome.</p><script>secret()</script><p>Next <b>part</b>.</p><img src=\"https://example.com/tracker\"></body></html>";out:=Message{Headers:map[string]string{}};parseMessage([]byte(raw),&out);if !strings.Contains(out.Text,"Hello & welcome.")||!strings.Contains(out.Text,"Next part.")||strings.Contains(out.Text,"secret")||strings.Contains(out.Text,"tracker")||strings.Contains(out.Text,"hidden"){t.Fatalf("bad HTML text %q",out.Text)}}
func TestHTMLBounded(t *testing.T){for _,raw:=range []string{strings.Repeat("<div>",150)+"hello",strings.Repeat("<p>x</p>",10000),"<p>"+strings.Repeat("x",70<<10)+"</p>"}{_,truncated:=htmlText(strings.NewReader(raw));if !truncated{t.Fatal("HTML bound not enforced")}}}
func TestPlainPreferredToHTML(t *testing.T){raw:="Content-Type: multipart/alternative; boundary=x\r\n\r\n--x\r\nContent-Type: text/plain\r\n\r\nplain\r\n--x\r\nContent-Type: text/html\r\n\r\n<p>html</p>\r\n--x--\r\n";out:=Message{Headers:map[string]string{}};parseMessage([]byte(raw),&out);if strings.TrimSpace(out.Text)!="plain"{t.Fatalf("wrong alternative %q",out.Text)}}

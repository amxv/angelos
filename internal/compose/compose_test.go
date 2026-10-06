package compose
import("bytes";"strings";"testing";"time")
func TestBuildBCCAndDigest(t *testing.T){
 in:=Input{To:[]string{"to@example.com"},Bcc:[]string{"hidden@example.com"},Subject:"Hello",Text:"hi",Attachments:[]Attachment{{"note.txt","text/plain","aGVsbG8="}}}
 a,e:=Build("sender@example.com",in,strings.Repeat("a",32),time.Unix(100,0));if e!=nil{t.Fatal(e)}
 if bytes.Contains(a.Raw,[]byte("Bcc:")) || bytes.Contains(a.Raw,[]byte("hidden@example.com")){t.Fatal("Bcc leaked into MIME")};if len(a.Recipients)!=2{t.Fatal("missing envelope recipient")}
 in.Bcc=[]string{"other@example.com"};b,e:=Build("sender@example.com",in,strings.Repeat("a",32),time.Unix(100,0));if e!=nil{t.Fatal(e)};if a.Digest==b.Digest{t.Fatal("Bcc not bound")}
}
func TestBuildRejectsInjection(t *testing.T){for _,in:=range []Input{{To:[]string{"x@example.com\r\nBcc:evil@example.com"}}, {To:[]string{"x@example.com"},Subject:"x\nY"},{To:[]string{"x@example.com"},InReplyTo:"<x@y>\r\nX: y"},{To:[]string{"x@example.com"},Attachments:[]Attachment{{"../x","text/plain","aA=="}}}} {if _,e:=Build("sender@example.com",in,strings.Repeat("b",32),time.Now());e==nil{t.Fatal("accepted invalid input")}}}
func TestDraftPreservesBCCOnlyInDraft(t *testing.T){p,e:=Build("sender@example.com",Input{Bcc:[]string{"secret@example.com"},Text:"private"},strings.Repeat("c",32),time.Now());if e!=nil{t.Fatal(e)};raw,e:=DraftBytes(p);if e!=nil||!bytes.Contains(raw,[]byte("Bcc:")){t.Fatal("draft missing Bcc")};if bytes.Contains(p.Raw,[]byte("Bcc:")){t.Fatal("outbound mutated")}}
func TestRecipientlessDraft(t *testing.T){if _,e:=Build("sender@example.com",Input{Text:"unfinished"},strings.Repeat("d",32),time.Now());e==nil{t.Fatal("recipientless send accepted")};p,e:=BuildDraft("sender@example.com",Input{Text:"unfinished"},strings.Repeat("d",32),time.Now());if e!=nil||len(p.Recipients)!=0{t.Fatal(e)};if _,e=DraftBytes(p);e!=nil{t.Fatal(e)}}

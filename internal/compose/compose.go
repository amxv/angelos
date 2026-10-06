// Package compose creates bounded immutable MIME messages. It never sends mail.
package compose

import (
 "bytes"
 "crypto/sha256"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "mime"
 "mime/multipart"
 "mime/quotedprintable"
 "net/mail"
 "net/textproto"
 "strings"
 "time"
)

const MaxMessageBytes = 5 << 20
const MaxAttachmentBytes = 3 << 20
const MaxRecipients = 50

type Attachment struct {
 Filename string `json:"filename" jsonschema:"Attachment filename; no paths"`
 ContentType string `json:"content_type" jsonschema:"MIME type such as application/pdf"`
 DataBase64 string `json:"data_base64" jsonschema:"Base64 bytes; maximum total decoded attachments 3 MiB"`
}
type Input struct {
 To []string `json:"to"`
 Cc []string `json:"cc,omitempty"`
 Bcc []string `json:"bcc,omitempty"`
 Subject string `json:"subject"`
 Text string `json:"text"`
 Attachments []Attachment `json:"attachments,omitempty"`
 InReplyTo string `json:"in_reply_to,omitempty"`
 References []string `json:"references,omitempty"`
}
type Prepared struct {
 ID string `json:"id"`
 Digest string `json:"digest"`
 From string `json:"from"`
 To []string `json:"to"`
 Cc []string `json:"cc,omitempty"`
 Bcc []string `json:"bcc,omitempty"`
 Subject string `json:"subject"`
 Text string `json:"text"`
 Attachments []AttachmentSummary `json:"attachments,omitempty"`
 MessageID string `json:"message_id"`
 ExpiresAt time.Time `json:"expires_at"`
 Raw []byte `json:"raw"`
 Recipients []string `json:"recipients"`
}
type AttachmentSummary struct { Filename string `json:"filename"`; ContentType string `json:"content_type"`; Bytes int `json:"bytes"`; SHA256 string `json:"sha256"` }

func invalid(s string) bool { return strings.ContainsAny(s,"\r\n\x00") }
func addresses(in []string) ([]string, []string, error) {
 formatted, envelope := []string{}, []string{}
 for _, s := range in {
  if len(s)>512 || invalid(s) { return nil,nil,errors.New("invalid recipient") }
  a,e:=mail.ParseAddress(s); if e!=nil || !strings.Contains(a.Address,"@") || !ascii(a.Address) { return nil,nil,errors.New("invalid recipient; SMTPUTF8 addresses are not supported") }
  formatted=append(formatted,a.String()); envelope=append(envelope,a.Address)
 }
 return formatted,envelope,nil
}
func ascii(s string) bool {for _,r:=range s {if r>127{return false}};return true}
func validMessageID(s string) bool { return len(s)<=998 && len(s)>4 && strings.HasPrefix(s,"<") && strings.HasSuffix(s,">") && !strings.ContainsAny(s,"\r\n\x00 \t") && strings.Count(s,"<")==1 && strings.Count(s,">")==1 && strings.Contains(s,"@") }

// Build fixes Date, Message-ID, MIME boundaries, recipients and bytes before approval.
func Build(from string, in Input, id string, now time.Time) (Prepared,error) {
 var out Prepared
 if len(id)!=32 {return out,errors.New("invalid preparation id")}; if _,e:=hex.DecodeString(id);e!=nil{return out,errors.New("invalid preparation id")}
 fromHeader,fromEnvelope,e:=addresses([]string{from});if e!=nil{return out,errors.New("invalid configured sender")}
 if len(in.To)+len(in.Cc)+len(in.Bcc)==0 || len(in.To)+len(in.Cc)+len(in.Bcc)>MaxRecipients{return out,errors.New("recipient count must be 1 to 50")}
 if len(in.Subject)>512 || invalid(in.Subject) || len(in.Text)>1<<20 || strings.ContainsRune(in.Text,0){return out,errors.New("invalid or oversized subject or text")}
 if len(in.Attachments)>20{return out,errors.New("too many attachments")}
 to,te,e:=addresses(in.To);if e!=nil{return out,e};cc,ce,e:=addresses(in.Cc);if e!=nil{return out,e};bc,be,e:=addresses(in.Bcc);if e!=nil{return out,e}
 if in.InReplyTo!="" && !validMessageID(in.InReplyTo){return out,errors.New("invalid reply message id")}
 if len(in.References)>30{return out,errors.New("too many reference ids")};for _,ref:=range in.References {if !validMessageID(ref){return out,errors.New("invalid reference id")}}
 var body bytes.Buffer
 boundary:="angelos-"+id
 multi:=multipart.NewWriter(&body);if e=multi.SetBoundary(boundary);e!=nil{return out,e}
 h:=textproto.MIMEHeader{};h.Set("Content-Type","text/plain; charset=utf-8");h.Set("Content-Transfer-Encoding","quoted-printable")
 p,e:=multi.CreatePart(h);if e!=nil{return out,e};qp:=quotedprintable.NewWriter(p);if _,e=qp.Write([]byte(in.Text));e!=nil{return out,e};if e=qp.Close();e!=nil{return out,e}
 total:=0;summaries:=[]AttachmentSummary{}
 for _,a:=range in.Attachments {
  if len(a.Filename)==0 || len(a.Filename)>200 || invalid(a.Filename) || strings.ContainsAny(a.Filename,"/\\") {return out,errors.New("invalid attachment filename")}
  if len(a.DataBase64)>((MaxAttachmentBytes+2)/3)*4{return out,errors.New("attachment too large")}
  data,e:=base64.StdEncoding.Strict().DecodeString(a.DataBase64);if e!=nil{return out,errors.New("invalid attachment base64")};total+=len(data);if total>MaxAttachmentBytes{return out,errors.New("attachments exceed 3 MiB")}
  ct,_,e:=mime.ParseMediaType(a.ContentType);if e!=nil || invalid(ct){return out,errors.New("invalid attachment content type")}
  h:=textproto.MIMEHeader{};h.Set("Content-Type",ct);h.Set("Content-Disposition",mime.FormatMediaType("attachment",map[string]string{"filename":a.Filename}));h.Set("Content-Transfer-Encoding","base64")
  p,e:=multi.CreatePart(h);if e!=nil{return out,e};enc:=base64.StdEncoding.EncodeToString(data)
  for len(enc)>0 {n:=76;if len(enc)<n {n=len(enc)};fmt.Fprintf(p,"%s\r\n",enc[:n]);enc=enc[n:]}
  sum:=sha256.Sum256(data);summaries=append(summaries,AttachmentSummary{a.Filename,ct,len(data),hex.EncodeToString(sum[:])})
 }
 if e=multi.Close();e!=nil{return out,e}
 domain:=strings.SplitN(fromEnvelope[0],"@",2)[1];mid:="<"+id+"@"+domain+">"
 var msg bytes.Buffer
 fmt.Fprintf(&msg,"From: %s\r\n",fromHeader[0]);if len(to)>0{fmt.Fprintf(&msg,"To: %s\r\n",strings.Join(to,", "))};if len(cc)>0{fmt.Fprintf(&msg,"Cc: %s\r\n",strings.Join(cc,", "))}
 fmt.Fprintf(&msg,"Subject: %s\r\nDate: %s\r\nMessage-ID: %s\r\nMIME-Version: 1.0\r\n",mime.QEncoding.Encode("utf-8",in.Subject),now.UTC().Format(time.RFC1123Z),mid)
 if in.InReplyTo!=""{fmt.Fprintf(&msg,"In-Reply-To: %s\r\n",in.InReplyTo)};if len(in.References)>0{fmt.Fprintf(&msg,"References: %s\r\n",strings.Join(in.References," "))}
 fmt.Fprintf(&msg,"Content-Type: multipart/mixed; boundary=%q\r\n\r\n",boundary);msg.Write(body.Bytes());if msg.Len()>MaxMessageBytes{return out,errors.New("encoded message exceeds 5 MiB")}
 recipients:=append(append(te,ce...),be...)
 // Digest includes the SMTP envelope (including Bcc) and exact wire bytes.
 binding,_:=json.Marshal(struct{From string;Recipients []string;Raw []byte}{fromEnvelope[0],recipients,msg.Bytes()});sum:=sha256.Sum256(binding)
 out=Prepared{ID:id,Digest:hex.EncodeToString(sum[:]),From:fromEnvelope[0],To:to,Cc:cc,Bcc:bc,Subject:in.Subject,Text:in.Text,Attachments:summaries,MessageID:mid,ExpiresAt:now.Add(15*time.Minute),Raw:msg.Bytes(),Recipients:recipients}
 return out,nil
}

// DraftBytes preserves Bcc in the private IMAP draft, never in outbound SMTP.
func DraftBytes(p Prepared)([]byte,error){
 if len(p.Bcc)==0{return append([]byte(nil),p.Raw...),nil}
 header:="Bcc: "+strings.Join(p.Bcc,", ")+"\r\n"
 if len(header)>998{return nil,errors.New("draft Bcc header too long")}
 raw:=append([]byte(header),p.Raw...);if len(raw)>MaxMessageBytes{return nil,errors.New("draft too large")};return raw,nil
}

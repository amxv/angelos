package mail

import (
 "bufio"
 "context"
 "crypto/tls"
 "crypto/x509"
 "fmt"
 "io"
 "net"
 "strings"
 "sync/atomic"
 "testing"
)
var testMessage=[]byte("From: person@example.com\r\nTo: recipient@example.net\r\nSubject: test\r\n\r\nhello\r\n")
func smtpFixture(mode string,dataSeen *atomic.Bool)func(net.Conn){return func(c net.Conn){serveSMTPFixture(c,mode,dataSeen,true)}}
func serveSMTPFixture(c net.Conn,mode string,dataSeen *atomic.Bool,greeting bool){
 if greeting{fmt.Fprint(c,"220 mail.test ESMTP\r\n")};r:=bufio.NewReader(c)
 for {line,e:=r.ReadString('\n');if e!=nil{return};cmd:=strings.ToUpper(strings.TrimSpace(line));switch {
 case strings.HasPrefix(cmd,"EHLO"):fmt.Fprint(c,"250-mail.test\r\n250-AUTH PLAIN\r\n250 SIZE 6000000\r\n")
 case strings.HasPrefix(cmd,"AUTH PLAIN"):fmt.Fprint(c,"235 2.7.0 authenticated\r\n")
 case strings.HasPrefix(cmd,"MAIL FROM:"):fmt.Fprint(c,"250 2.1.0 ok\r\n")
 case strings.HasPrefix(cmd,"RCPT TO:"):if mode=="rcpt_reject"{fmt.Fprint(c,"550 5.1.1 rejected\r\n")}else{fmt.Fprint(c,"250 2.1.5 ok\r\n")}
 case cmd=="DATA":dataSeen.Store(true);fmt.Fprint(c,"354 send message\r\n");for {part,e:=r.ReadString('\n');if e!=nil{return};if part==".\r\n"{break}};switch mode{case "unknown":return;case "data_reject":fmt.Fprint(c,"550 5.7.1 rejected\r\n");default:fmt.Fprint(c,"250 2.0.0 queued\r\n")}
 default:return
 }
 }
}
func TestSMTPOutcomes(t *testing.T){for _,tc:=range []struct{mode,status string;data bool}{{"accept","accepted",true},{"rcpt_reject","rejected",false},{"data_reject","rejected",true},{"unknown","unknown",true}}{t.Run(tc.mode,func(t *testing.T){var seen atomic.Bool;b:=backendForTest(t,smtpFixture(tc.mode,&seen),true);got,e:=b.Send(context.Background(),Envelope{From:"person@example.com",To:[]string{"recipient@example.net"}},testMessage);if got.Status!=tc.status||seen.Load()!=tc.data{t.Fatalf("got %+v err %v data %v",got,e,seen.Load())};if (e==nil)!=(tc.status=="accepted"){t.Fatalf("bad result error %v",e)}})}}
func TestSMTPRequiresSTARTTLS(t *testing.T){var authSeen atomic.Bool;b:=backendForTest(t,func(c net.Conn){fmt.Fprint(c,"220 mail.test\r\n");r:=bufio.NewReader(c);line,_:=r.ReadString('\n');if strings.HasPrefix(line,"EHLO"){fmt.Fprint(c,"250-mail.test\r\n250 AUTH PLAIN\r\n")};rest,_:=io.ReadAll(r);if strings.Contains(string(rest),"AUTH"){authSeen.Store(true)}},false);b.config.SMTP.Port=587;b.config.SMTP.TLSMode="starttls";result,e:=b.Send(context.Background(),Envelope{From:"person@example.com",To:[]string{"recipient@example.net"}},testMessage);if e==nil||result.Status!="rejected"||authSeen.Load(){t.Fatalf("insecure SMTP accepted: %+v %v",result,e)}}
func TestSMTPRejectsHeaderInjection(t *testing.T){b:=backendForTest(t,func(net.Conn){t.Error("invalid message made a network connection")},true);for _,recipient:=range []string{"a@example.com\r\nRCPT TO:<b@example.com>","Name <a@example.com>"}{if _,e:=b.Send(context.Background(),Envelope{From:"person@example.com",To:[]string{recipient}},testMessage);e==nil{t.Fatal("unsafe recipient accepted")}};if _,e:=b.Send(context.Background(),Envelope{From:"person@example.com",To:[]string{"a@example.com"}},[]byte("From: person@example.com\r\nBcc: secret@example.com\r\n\r\nhi"));e==nil{t.Fatal("Bcc header accepted")}}

func TestSMTPSTARTTLSSuccess(t *testing.T){cert,roots:=backendTestCertificate(t);var seen atomic.Bool;b:=backendForTest(t,func(c net.Conn){fmt.Fprint(c,"220 mail.test ESMTP\r\n");r:=bufio.NewReader(c);line,e:=r.ReadString('\n');if e!=nil||!strings.HasPrefix(line,"EHLO "){return};fmt.Fprint(c,"250-mail.test\r\n250 STARTTLS\r\n");line,e=r.ReadString('\n');if e!=nil||strings.TrimSpace(line)!="STARTTLS"{return};fmt.Fprint(c,"220 begin TLS\r\n");secure:=tls.Server(c,&tls.Config{Certificates:[]tls.Certificate{cert},MinVersion:tls.VersionTLS12});serveSMTPFixture(secure,"accept",&seen,false)},false);b.roots=roots;b.config.SMTP.Port=587;b.config.SMTP.TLSMode="starttls";result,e:=b.Send(context.Background(),Envelope{From:"person@example.com",To:[]string{"recipient@example.net"}},testMessage);if e!=nil||result.Status!="accepted"||!seen.Load(){t.Fatalf("STARTTLS result %+v %v",result,e)}}
func TestSMTPRejectsUntrustedTLS(t *testing.T){var seen atomic.Bool;b:=backendForTest(t,smtpFixture("accept",&seen),true);b.roots=x509.NewCertPool();result,e:=b.Send(context.Background(),Envelope{From:"person@example.com",To:[]string{"recipient@example.net"}},testMessage);if e==nil||result.Status!="rejected"||seen.Load(){t.Fatalf("untrusted TLS accepted %+v %v",result,e)}}

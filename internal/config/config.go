// Package config loads the one administrator-configured mailbox. Credentials are
// never accepted from MCP arguments and are deliberately excluded from JSON.
package config

import (
 "errors"
 "net"
 "net/mail"
 "os"
 "strconv"
 "strings"
 "time"
)

type Endpoint struct { Host string; Port int; TLSMode string }
type Config struct {
 Username string `json:"-"`
 Password string `json:"-"`
 From string
 IMAP Endpoint
 SMTP Endpoint
 Timeout time.Duration
}

func LoadFromEnv() (Config, error) { return Load(os.Getenv) }
func Load(getenv func(string) string) (Config, error) {
 c := Config{Username:getenv("MAIL_USERNAME"), Password:getenv("MAIL_PASSWORD"), From:getenv("MAIL_FROM"), Timeout:30*time.Second}
 preset := getenv("MAIL_PROVIDER")
 if preset == "" || preset == "spacemail" {
  c.IMAP = Endpoint{"mail.spacemail.com", 993, "tls"}
  c.SMTP = Endpoint{"mail.spacemail.com", 465, "tls"}
 } else if preset != "custom" { return c, errors.New("MAIL_PROVIDER must be spacemail or custom") }
 if v:=getenv("IMAP_HOST"); v!="" { c.IMAP.Host=v }
 if v:=getenv("SMTP_HOST"); v!="" { c.SMTP.Host=v }
 if v:=getenv("IMAP_PORT"); v!="" { n,e:=strconv.Atoi(v); if e!=nil{return c,errors.New("invalid IMAP_PORT")}; c.IMAP.Port=n }
 if v:=getenv("SMTP_PORT"); v!="" { n,e:=strconv.Atoi(v); if e!=nil{return c,errors.New("invalid SMTP_PORT")}; c.SMTP.Port=n }
 if c.IMAP.Port==0 {c.IMAP.Port=993}; if c.SMTP.Port==0 {c.SMTP.Port=465}
 c.IMAP.TLSMode="tls"
 if c.SMTP.Port==587 {c.SMTP.TLSMode="starttls"} else if c.SMTP.TLSMode=="" {c.SMTP.TLSMode="tls"}
 if v:=getenv("SMTP_TLS_MODE"); v!="" {c.SMTP.TLSMode=v}
 if v:=getenv("MAIL_TIMEOUT"); v!="" { d,e:=time.ParseDuration(v); if e!=nil{return c,errors.New("invalid MAIL_TIMEOUT")};c.Timeout=d }
 if c.From=="" {c.From=c.Username}
 return c,c.Validate()
}
func (c Config) Validate() error {
 if c.Username=="" || c.Password=="" {return errors.New("MAIL_USERNAME and MAIL_PASSWORD are required")}
 if strings.ContainsAny(c.Username,"\r\n\x00") || strings.ContainsAny(c.Password,"\r\n\x00") {return errors.New("invalid mailbox credentials")}
 a,e:=mail.ParseAddress(c.From);if e!=nil || a.Address!=c.From || strings.ContainsAny(c.From,"\r\n") {return errors.New("MAIL_FROM must be a bare email address")}
 if c.Timeout<time.Second || c.Timeout>2*time.Minute {return errors.New("MAIL_TIMEOUT must be between 1s and 2m")}
 for _,ep:=range []Endpoint{c.IMAP,c.SMTP} {
  if ep.Host=="" || len(ep.Host)>253 || strings.ContainsAny(ep.Host,"/\\:@ \t\r\n\x00") || net.ParseIP(ep.Host)!=nil {return errors.New("mail hosts must be DNS hostnames")}
  for _,label:=range strings.Split(ep.Host,".") {if label=="" || len(label)>63 || label[0]=='-' || label[len(label)-1]=='-' {return errors.New("invalid mail hostname")};for _,r:=range label {if !(r>='a'&&r<='z'||r>='A'&&r<='Z'||r>='0'&&r<='9'||r=='-'){return errors.New("invalid mail hostname")}}}
  if ep.Port<1||ep.Port>65535{return errors.New("invalid mail port")}
 }
 if c.IMAP.TLSMode!="tls" {return errors.New("IMAP requires implicit TLS")}
 if c.SMTP.TLSMode!="tls"&&c.SMTP.TLSMode!="starttls" {return errors.New("SMTP requires tls or starttls")}
 if c.SMTP.Port==587 && c.SMTP.TLSMode!="starttls" {return errors.New("SMTP port 587 requires STARTTLS")}
 if c.SMTP.Port==465 && c.SMTP.TLSMode!="tls" {return errors.New("SMTP port 465 requires implicit TLS")}
 return nil
}

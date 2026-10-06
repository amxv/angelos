package config

import (
	"strings"
	"testing"
	"time"
)

func env(values map[string]string) func(string) string {
	return func(k string) string { return values[k] }
}
func TestSpacemailDefaults(t *testing.T) {
	c, e := Load(env(map[string]string{"MAIL_USERNAME": "person@example.com", "MAIL_PASSWORD": "test-only"}))
	if e != nil {
		t.Fatal(e)
	}
	if c.IMAP.Host != "mail.spacemail.com" || c.IMAP.Port != 993 || c.IMAP.TLSMode != "tls" || c.SMTP.Port != 465 || c.SMTP.TLSMode != "tls" || c.Timeout != 30*time.Second {
		t.Fatalf("unexpected config: %+v", c)
	}
}
func TestConfigRejectsUnsafe(t *testing.T) {
	cases := []map[string]string{{"MAIL_USERNAME": ""}, {"IMAP_HOST": "127.0.0.1"}, {"IMAP_HOST": "https://mail.example.com"}, {"IMAP_HOST": "mail.example.com\r\n"}, {"SMTP_TLS_MODE": "plain"}, {"SMTP_PORT": "587", "SMTP_TLS_MODE": "tls"}, {"SMTP_PORT": "465", "SMTP_TLS_MODE": "starttls"}, {"MAIL_TIMEOUT": "5m"}, {"MAIL_FROM": "hello\r\nBcc: victim@example.com"}, {"IMAP_PORT": "-1"}}
	for i, changes := range cases {
		values := map[string]string{"MAIL_USERNAME": "person@example.com", "MAIL_PASSWORD": "test-only"}
		for k, v := range changes {
			values[k] = v
		}
		if _, e := Load(env(values)); e == nil {
			t.Errorf("case %d accepted", i)
		}
	}
}
func TestConfigCustomSTARTTLS(t *testing.T) {
	c, e := Load(env(map[string]string{"MAIL_PROVIDER": "custom", "MAIL_USERNAME": "person@example.com", "MAIL_PASSWORD": "test-only", "IMAP_HOST": "imap.example.net", "SMTP_HOST": "smtp.example.net", "SMTP_PORT": "587"}))
	if e != nil {
		t.Fatal(e)
	}
	if c.SMTP.TLSMode != "starttls" {
		t.Fatal("missing STARTTLS")
	}
}
func TestConfigErrorsDoNotContainSecrets(t *testing.T) {
	_, e := Load(env(map[string]string{"MAIL_USERNAME": "person@example.com", "MAIL_PASSWORD": "super-secret", "SMTP_TLS_MODE": "plain"}))
	if e == nil || strings.Contains(e.Error(), "super-secret") {
		t.Fatal("bad error")
	}
}

package config

import "testing"

func providerEnv(provider string) map[string]string {
	return map[string]string{"MAIL_PROVIDER": provider, "MAIL_USERNAME": "person@example.com", "MAIL_PASSWORD": "synthetic-app-password"}
}

func TestAppPasswordProviderDefaults(t *testing.T) {
	for _, tc := range []struct {
		provider, imap, smtp string
		port                 int
		mode                 string
	}{
		{"icloud", "imap.mail.me.com", "smtp.mail.me.com", 587, "starttls"},
		{"yahoo", "imap.mail.yahoo.com", "smtp.mail.yahoo.com", 465, "tls"},
	} {
		t.Run(tc.provider, func(t *testing.T) {
			c, err := Load(env(providerEnv(tc.provider)))
			if err != nil {
				t.Fatal(err)
			}
			if c.AuthMode != "app_password" || c.From != c.Username || c.IMAP != (Endpoint{tc.imap, 993, "tls"}) || c.SMTP != (Endpoint{tc.smtp, tc.port, tc.mode}) {
				t.Fatal("unexpected preset")
			}
			if c.UsesGoogleOAuth2() || c.IsGmailIMAP() || c.SMTPStoresSent() {
				t.Fatal("unverified provider semantics inherited")
			}
		})
	}
}

func TestAppPasswordProviderRejectsUnsafeConfiguration(t *testing.T) {
	for _, provider := range []string{"icloud", "yahoo"} {
		for name, changes := range map[string]map[string]string{
			"password_mode": {"MAIL_AUTH_MODE": "password"}, "oauth_mode": {"MAIL_AUTH_MODE": "google_oauth2"},
			"unknown_mode": {"MAIL_AUTH_MODE": "oauth2"}, "missing_password": {"MAIL_PASSWORD": ""},
			"google_credentials": {"GOOGLE_REFRESH_TOKEN": "synthetic-token"},
			"short_username":     {"MAIL_USERNAME": "person", "MAIL_FROM": "person@example.com"},
			"display_name":       {"MAIL_USERNAME": "Person <person@example.com>"},
			"imap_override":      {"IMAP_HOST": "imap.attacker.example"}, "smtp_override": {"SMTP_HOST": "smtp.attacker.example"},
			"imap_port": {"IMAP_PORT": "143"}, "smtp_port": {"SMTP_PORT": "25"},
			"plaintext": {"SMTP_TLS_MODE": "plain"},
		} {
			t.Run(provider+"/"+name, func(t *testing.T) {
				values := providerEnv(provider)
				for k, v := range changes {
					values[k] = v
				}
				if _, err := Load(env(values)); err == nil {
					t.Fatal("invalid preset accepted")
				}
			})
		}
	}
}

func TestProviderSupportedSMTPAlternatives(t *testing.T) {
	values := providerEnv("yahoo")
	values["SMTP_PORT"] = "587"
	c, err := Load(env(values))
	if err != nil || c.SMTP.TLSMode != "starttls" {
		t.Fatal("Yahoo STARTTLS alternative rejected", err)
	}
	values = providerEnv("icloud")
	values["SMTP_PORT"] = "465"
	values["SMTP_TLS_MODE"] = "tls"
	if _, err := Load(env(values)); err == nil {
		t.Fatal("undocumented iCloud endpoint accepted")
	}
	for _, provider := range []string{"spacemail", "custom"} {
		values = providerEnv(provider)
		values["IMAP_HOST"] = "imap.example.net"
		values["SMTP_HOST"] = "smtp.example.net"
		if _, err := Load(env(values)); err != nil {
			t.Fatal("existing endpoint override broken", err)
		}
	}
}

func TestCustomProviderOwnPortsRemainSupported(t *testing.T) {
	for _, mode := range []string{"tls", "starttls"} {
		values := providerEnv("custom")
		values["IMAP_HOST"] = "imap.owner.example"
		values["SMTP_HOST"] = "smtp.owner.example"
		values["IMAP_PORT"] = "1993"
		values["SMTP_PORT"] = "1587"
		values["SMTP_TLS_MODE"] = mode
		c, err := Load(env(values))
		if err != nil || c.IMAP.Port != 1993 || c.SMTP.Port != 1587 || c.IMAP.TLSMode != "tls" || c.SMTP.TLSMode != mode {
			t.Fatalf("custom ports broken: %v", err)
		}
	}
}

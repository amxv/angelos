package config

import (
	"encoding/json"
	"strings"
	"testing"
)

func gmailEnv() map[string]string {
	return map[string]string{
		"MAIL_PROVIDER": "gmail", "MAIL_USERNAME": "person@workspace.example",
		"GOOGLE_CLIENT_ID": "fake-client-id", "GOOGLE_CLIENT_SECRET": "fake-client-secret", "GOOGLE_REFRESH_TOKEN": "fake-refresh-token",
	}
}

func TestGmailOAuthDefaultsConsumerAndWorkspace(t *testing.T) {
	for _, user := range []string{"person@gmail.com", "person@workspace.example"} {
		values := gmailEnv()
		values["MAIL_USERNAME"] = user
		c, err := Load(env(values))
		if err != nil {
			t.Fatal(err)
		}
		if !c.IsGmail() || !c.UsesGoogleOAuth2() || !c.IsGmailIMAP() || !c.SMTPStoresSent() || c.AuthMode != "google_oauth2" || c.From != user ||
			c.IMAP != (Endpoint{"imap.gmail.com", 993, "tls"}) || c.SMTP != (Endpoint{"smtp.gmail.com", 465, "tls"}) {
			t.Fatal("incorrect Gmail defaults")
		}
		values["SMTP_PORT"] = "587"
		c, err = Load(env(values))
		if err != nil || c.SMTP.TLSMode != "starttls" {
			t.Fatal("Gmail STARTTLS unavailable")
		}
	}
}

func TestGmailRejectsUnsafeOrMixedConfiguration(t *testing.T) {
	cases := []map[string]string{
		{"MAIL_USERNAME": "local-login"}, {"MAIL_USERNAME": "person\x01@workspace.example"},
		{"MAIL_AUTH_MODE": "password"}, {"MAIL_AUTH_MODE": "unknown"}, {"MAIL_PASSWORD": "fake-password"},
		{"GOOGLE_CLIENT_ID": ""}, {"GOOGLE_CLIENT_SECRET": ""}, {"GOOGLE_REFRESH_TOKEN": ""},
		{"GOOGLE_CLIENT_ID": "a\n"}, {"GOOGLE_CLIENT_SECRET": "a\x01"}, {"GOOGLE_REFRESH_TOKEN": "a\t"},
		{"GOOGLE_CLIENT_SECRET": strings.Repeat("a", 16<<10+1)},
		{"IMAP_HOST": "mail.example.com"}, {"SMTP_HOST": "mail.example.com"},
		{"IMAP_HOST": "imap.gmail.com.attacker.test"}, {"SMTP_HOST": "smtp.gmail.com.attacker.test"},
		{"IMAP_HOST": "imap.googlemail.com"}, {"SMTP_HOST": "smtp.googlemail.com"},
		{"IMAP_PORT": "143"}, {"SMTP_PORT": "25"}, {"SMTP_TLS_MODE": "plain"},
		{"SMTP_PORT": "587", "SMTP_TLS_MODE": "tls"}, {"SMTP_PORT": "465", "SMTP_TLS_MODE": "starttls"},
		{"MAIL_PROVIDER": "custom", "IMAP_HOST": "imap.gmail.com", "SMTP_HOST": "smtp.gmail.com"},
		{"MAIL_PROVIDER": "spacemail", "MAIL_AUTH_MODE": "google_oauth2"},
		{"MAIL_AUTH_MODE": "app_password", "MAIL_PASSWORD": "fake-app-password"},
	}
	for i, changes := range cases {
		values := gmailEnv()
		for k, v := range changes {
			values[k] = v
		}
		if _, err := Load(env(values)); err == nil {
			t.Errorf("unsafe case %d accepted", i)
		} else {
			for _, secret := range []string{"fake-client-id", "fake-client-secret", "fake-refresh-token", "fake-password", "fake-app-password", "attacker.test"} {
				if strings.Contains(err.Error(), secret) {
					t.Errorf("case %d leaks input", i)
				}
			}
		}
	}
}

func TestGmailAppPasswordExplicitOnly(t *testing.T) {
	values := map[string]string{"MAIL_PROVIDER": "gmail", "MAIL_USERNAME": "person@gmail.com", "MAIL_PASSWORD": "fake-app-password", "MAIL_AUTH_MODE": "app_password"}
	c, err := Load(env(values))
	if err != nil || c.UsesGoogleOAuth2() || !c.IsGmail() {
		t.Fatalf("app password mode: %v", err)
	}
	for _, key := range []string{"IMAP_HOST", "SMTP_HOST"} {
		values[key] = "other.example"
		if _, err := Load(env(values)); err == nil {
			t.Fatal("app password sent to unpinned endpoint")
		}
		delete(values, key)
	}
	delete(values, "MAIL_AUTH_MODE")
	if _, err := Load(env(values)); err == nil {
		t.Fatal("silently fell back to password")
	}
}

func TestGoogleSecretsExcludedFromJSON(t *testing.T) {
	values := gmailEnv()
	values["MAIL_FROM"] = "alias@workspace.example"
	c, err := Load(env(values))
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{c.Username, c.GoogleClientID, c.GoogleClientSecret, c.GoogleRefreshToken} {
		if strings.Contains(string(data), secret) {
			t.Fatal("credential serialized")
		}
	}
	var decoded Config
	if err := json.Unmarshal([]byte(`{"Username":"injected","Password":"injected","GoogleClientID":"injected","GoogleClientSecret":"injected","GoogleRefreshToken":"injected"}`), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Username != "" || decoded.Password != "" || decoded.GoogleClientID != "" || decoded.GoogleClientSecret != "" || decoded.GoogleRefreshToken != "" {
		t.Fatal("JSON accepted credential fields")
	}
}

func TestGooglePolicyHostDetectionAndLegacyConfig(t *testing.T) {
	for _, host := range []string{"imap.gmail.com", "IMAP.GOOGLEMAIL.COM"} {
		c := Config{IMAP: Endpoint{Host: host}}
		if !c.IsGmailIMAP() || c.SMTPStoresSent() || c.IsGmail() || c.UsesGoogleOAuth2() {
			t.Fatal("wrong IMAP policy")
		}
	}
	for _, host := range []string{"smtp.gmail.com", "SMTP.GOOGLEMAIL.COM"} {
		c := Config{SMTP: Endpoint{Host: host}}
		if !c.SMTPStoresSent() || c.IsGmailIMAP() || c.IsGmail() || c.UsesGoogleOAuth2() {
			t.Fatal("wrong SMTP policy")
		}
	}
	c, err := Load(env(map[string]string{"MAIL_USERNAME": "person@example.com", "MAIL_PASSWORD": "fake-password"}))
	if err != nil || c.Provider != "spacemail" || c.AuthMode != "password" {
		t.Fatal("legacy defaults changed")
	}
	c.Provider, c.AuthMode = "", ""
	if c.Validate() != nil || c.IsGmail() || c.UsesGoogleOAuth2() {
		t.Fatal("legacy programmatic config changed")
	}
}

package config

import (
	"encoding/json"
	"strings"
	"testing"
)

func microsoftValues() map[string]string {
	return map[string]string{"MAIL_PROVIDER": "microsoft", "MAIL_USERNAME": "person@example.com", "MICROSOFT_CLIENT_ID": "11111111-1111-1111-1111-111111111111", "MICROSOFT_CLIENT_SECRET": "synthetic-secret", "MICROSOFT_REFRESH_TOKEN": "synthetic-refresh", "MICROSOFT_TENANT_ID": "consumers", "MICROSOFT_ACCOUNT_ID": "account-id", "MICROSOFT_TOKEN_ENCRYPTION_KEY": strings.Repeat("12", 32)}
}
func TestMicrosoftConfiguration(t *testing.T) {
	v := microsoftValues()
	c, e := Load(func(k string) string { return v[k] })
	if e != nil || c.AuthMode != "microsoft_graph" || !c.SMTPStoresSent() {
		t.Fatal(c.AuthMode, e)
	}
	raw, _ := json.Marshal(c)
	if strings.Contains(string(raw), "synthetic") || strings.Contains(string(raw), "account-id") {
		t.Fatal("credential disclosure")
	}
}
func TestMicrosoftRejectsUnsafeConfiguration(t *testing.T) {
	for key, values := range map[string][]string{"MAIL_AUTH_MODE": {"password", "app_password", "google_oauth2"}, "MAIL_PASSWORD": {"secret"}, "MAIL_FROM": {"alias@example.com"}, "MAIL_ALIASES": {"alias@example.com"}, "IMAP_HOST": {"outlook.office365.com"}, "SMTP_HOST": {"smtp.office365.com"}, "MICROSOFT_TENANT_ID": {"common", "organizations", "../tenant", "tenant.example", "https://evil.example"}, "MICROSOFT_CLIENT_ID": {"not-uuid"}, "MICROSOFT_ACCOUNT_ID": {""}, "MICROSOFT_TOKEN_ENCRYPTION_KEY": {"", "short", strings.Repeat("g", 64)}, "GOOGLE_REFRESH_TOKEN": {"other-secret"}} {
		for _, value := range values {
			t.Run(key+value, func(t *testing.T) {
				v := microsoftValues()
				v[key] = value
				if _, e := Load(func(k string) string { return v[k] }); e == nil {
					t.Fatal("accepted", key)
				}
			})
		}
	}
}

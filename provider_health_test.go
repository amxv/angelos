package main

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHealthReportsOnlyValidatedProviderMode(t *testing.T) {
	for _, provider := range []string{"icloud", "yahoo", "untrusted-provider-label"} {
		t.Run(provider, func(t *testing.T) {
			for _, key := range []string{"MAIL_AUTH_MODE", "MAIL_FROM", "MAIL_ALIASES", "IMAP_HOST", "SMTP_HOST", "IMAP_PORT", "SMTP_PORT", "SMTP_TLS_MODE", "GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET", "GOOGLE_REFRESH_TOKEN", "MCP_RESOURCE_URL", "MCP_OAUTH_ISSUER", "MCP_OAUTH_JWKS_URL", "MCP_ALLOWED_SUBJECTS", "ANGELOS_OAUTH_ENABLED"} {
				t.Setenv(key, "")
			}
			t.Setenv("MAIL_PROVIDER", provider)
			t.Setenv("MAIL_USERNAME", "private@example.com")
			t.Setenv("MAIL_PASSWORD", "private-test-password")
			w := httptest.NewRecorder()
			newHandler().ServeHTTP(w, httptest.NewRequest("GET", "http://example.com/healthz", nil))
			var got map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if got["configured"] != false {
				t.Fatal("mailbox-only config claimed MCP configured")
			}
			if provider == "untrusted-provider-label" {
				if _, ok := got["mail_provider"]; ok {
					t.Fatal("invalid provider disclosed")
				}
			} else if got["mail_provider"] != provider || got["mail_auth_mode"] != "app_password" {
				t.Fatal("missing validated provider mode")
			}
			if strings.Contains(w.Body.String(), "private") {
				t.Fatal("private config leaked")
			}
		})
	}
}

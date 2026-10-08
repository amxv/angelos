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
	"unicode"
)

type Endpoint struct {
	Host    string
	Port    int
	TLSMode string
}
type Config struct {
	Provider                    string
	MicrosoftClientID           string `json:"-"`
	MicrosoftClientSecret       string `json:"-"`
	MicrosoftRefreshToken       string `json:"-"`
	MicrosoftTenantID           string `json:"-"`
	MicrosoftAccountID          string `json:"-"`
	MicrosoftTokenEncryptionKey string `json:"-"`
	AuthMode                    string
	GoogleClientID              string `json:"-"`
	GoogleClientSecret          string `json:"-"`
	GoogleRefreshToken          string `json:"-"`
	Username                    string `json:"-"`
	Password                    string `json:"-"`
	From                        string
	Aliases                     []string `json:"-"`
	IMAP                        Endpoint
	SMTP                        Endpoint
	Timeout                     time.Duration
}

func LoadFromEnv() (Config, error) { return Load(os.Getenv) }
func Load(getenv func(string) string) (Config, error) {
	c := Config{
		Provider: getenv("MAIL_PROVIDER"), AuthMode: getenv("MAIL_AUTH_MODE"),
		MicrosoftClientID: getenv("MICROSOFT_CLIENT_ID"), MicrosoftClientSecret: getenv("MICROSOFT_CLIENT_SECRET"), MicrosoftRefreshToken: getenv("MICROSOFT_REFRESH_TOKEN"), MicrosoftTenantID: getenv("MICROSOFT_TENANT_ID"), MicrosoftAccountID: getenv("MICROSOFT_ACCOUNT_ID"), MicrosoftTokenEncryptionKey: getenv("MICROSOFT_TOKEN_ENCRYPTION_KEY"),
		GoogleClientID: getenv("GOOGLE_CLIENT_ID"), GoogleClientSecret: getenv("GOOGLE_CLIENT_SECRET"),
		GoogleRefreshToken: getenv("GOOGLE_REFRESH_TOKEN"),
		Username:           getenv("MAIL_USERNAME"), Password: getenv("MAIL_PASSWORD"),
		From: getenv("MAIL_FROM"), Timeout: 30 * time.Second,
	}
	if value := getenv("MAIL_ALIASES"); value != "" {
		if len(value) > 16<<10 || strings.IndexFunc(value, unicode.IsControl) >= 0 {
			return c, errors.New("invalid MAIL_ALIASES")
		}
		for _, alias := range strings.Split(value, ",") {
			c.Aliases = append(c.Aliases, strings.TrimSpace(alias))
		}
	}
	if c.Provider == "" {
		c.Provider = "spacemail"
	}
	if c.AuthMode == "" {
		c.AuthMode = "password"
		if c.IsMicrosoft() {
			c.AuthMode = "microsoft_graph"
		} else if c.IsGmail() {
			c.AuthMode = "google_oauth2"
		} else if c.isAppPasswordProvider() {
			c.AuthMode = "app_password"
		}
	}
	if c.Provider == "spacemail" {
		c.IMAP = Endpoint{"mail.spacemail.com", 993, "tls"}
		c.SMTP = Endpoint{"mail.spacemail.com", 465, "tls"}
	} else if c.IsGmail() {
		c.IMAP = Endpoint{"imap.gmail.com", 993, "tls"}
		c.SMTP = Endpoint{"smtp.gmail.com", 465, "tls"}
	} else if c.Provider == "icloud" {
		c.IMAP = Endpoint{"imap.mail.me.com", 993, "tls"}
		c.SMTP = Endpoint{"smtp.mail.me.com", 587, "starttls"}
	} else if c.Provider == "yahoo" {
		c.IMAP = Endpoint{"imap.mail.yahoo.com", 993, "tls"}
		c.SMTP = Endpoint{"smtp.mail.yahoo.com", 465, "tls"}
	} else if c.IsMicrosoft() {
		// Graph uses only fixed HTTPS endpoints; IMAP/SMTP are unused.
	} else if c.Provider != "custom" {
		return c, errors.New("MAIL_PROVIDER must be spacemail, gmail, microsoft, icloud, yahoo or custom")
	}
	if v := getenv("IMAP_HOST"); v != "" {
		c.IMAP.Host = v
	}
	if v := getenv("SMTP_HOST"); v != "" {
		c.SMTP.Host = v
	}
	if v := getenv("IMAP_PORT"); v != "" {
		n, e := strconv.Atoi(v)
		if e != nil {
			return c, errors.New("invalid IMAP_PORT")
		}
		c.IMAP.Port = n
	}
	if v := getenv("SMTP_PORT"); v != "" {
		n, e := strconv.Atoi(v)
		if e != nil {
			return c, errors.New("invalid SMTP_PORT")
		}
		c.SMTP.Port = n
	}
	if c.IMAP.Port == 0 {
		c.IMAP.Port = 993
	}
	if c.SMTP.Port == 0 {
		c.SMTP.Port = 465
	}
	c.IMAP.TLSMode = "tls"
	if c.SMTP.Port == 587 {
		c.SMTP.TLSMode = "starttls"
	} else if c.SMTP.TLSMode == "" {
		c.SMTP.TLSMode = "tls"
	}
	if v := getenv("SMTP_TLS_MODE"); v != "" {
		c.SMTP.TLSMode = v
	}
	if v := getenv("MAIL_TIMEOUT"); v != "" {
		d, e := time.ParseDuration(v)
		if e != nil {
			return c, errors.New("invalid MAIL_TIMEOUT")
		}
		c.Timeout = d
	}
	if c.From == "" {
		c.From = c.Username
	}
	return c, c.Validate()
}
func (c Config) Validate() error {
	if c.IsMicrosoft() {
		return c.validateMicrosoft()
	}
	if c.MicrosoftClientID != "" || c.MicrosoftClientSecret != "" || c.MicrosoftRefreshToken != "" || c.MicrosoftTenantID != "" || c.MicrosoftAccountID != "" || c.MicrosoftTokenEncryptionKey != "" {
		return errors.New("Microsoft credentials require the microsoft provider")
	}
	if c.Provider != "" && c.Provider != "spacemail" && c.Provider != "custom" && !c.IsGmail() && !c.isAppPasswordProvider() {
		return errors.New("invalid MAIL_PROVIDER")
	}
	if c.Username == "" {
		return errors.New("MAIL_USERNAME is required")
	}
	if c.IsGmail() {
		if !bareAddress(c.Username) {
			return errors.New("Gmail MAIL_USERNAME must be a complete bare email address")
		}
		if c.IMAP != (Endpoint{"imap.gmail.com", 993, "tls"}) ||
			(c.SMTP != (Endpoint{"smtp.gmail.com", 465, "tls"}) && c.SMTP != (Endpoint{"smtp.gmail.com", 587, "starttls"})) {
			return errors.New("Gmail requires its pinned IMAP and SMTP TLS endpoints")
		}
		if !c.UsesGoogleOAuth2() && c.AuthMode != "app_password" {
			return errors.New("Gmail MAIL_AUTH_MODE must be google_oauth2 or app_password")
		}
	} else if c.isAppPasswordProvider() {
		if !bareAddress(c.Username) {
			return errors.New("iCloud and Yahoo MAIL_USERNAME must be a complete bare email address")
		}
		if c.AuthMode != "app_password" {
			return errors.New("iCloud and Yahoo MAIL_AUTH_MODE must be app_password")
		}
		if c.Provider == "icloud" {
			if c.IMAP != (Endpoint{"imap.mail.me.com", 993, "tls"}) || c.SMTP != (Endpoint{"smtp.mail.me.com", 587, "starttls"}) {
				return errors.New("iCloud requires its pinned IMAP and SMTP TLS endpoints")
			}
		} else if c.IMAP != (Endpoint{"imap.mail.yahoo.com", 993, "tls"}) ||
			(c.SMTP != (Endpoint{"smtp.mail.yahoo.com", 465, "tls"}) && c.SMTP != (Endpoint{"smtp.mail.yahoo.com", 587, "starttls"})) {
			return errors.New("Yahoo requires its pinned IMAP and SMTP TLS endpoints")
		}
	} else if c.AuthMode != "" && c.AuthMode != "password" {
		return errors.New("MAIL_AUTH_MODE requires a compatible provider")
	}
	if c.UsesGoogleOAuth2() {
		if c.Password != "" {
			return errors.New("MAIL_PASSWORD must be unset for Google OAuth")
		}
		for _, value := range []string{c.GoogleClientID, c.GoogleClientSecret, c.GoogleRefreshToken} {
			if len(value) == 0 || len(value) > 16<<10 || strings.IndexFunc(value, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) }) >= 0 {
				return errors.New("Google OAuth requires valid GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET and GOOGLE_REFRESH_TOKEN")
			}
		}
	} else {
		if c.GoogleClientID != "" || c.GoogleClientSecret != "" || c.GoogleRefreshToken != "" {
			return errors.New("Google credentials require Gmail google_oauth2 authentication")
		}
		if c.Password == "" {
			return errors.New("MAIL_PASSWORD is required for password authentication")
		}
	}
	if strings.ContainsAny(c.Username, "\r\n\x00") || strings.ContainsAny(c.Password, "\r\n\x00") {
		return errors.New("invalid mailbox credentials")
	}
	a, e := mail.ParseAddress(c.From)
	if e != nil || a.Address != c.From || strings.ContainsAny(c.From, "\r\n") {
		return errors.New("MAIL_FROM must be a bare email address")
	}
	if len(c.Aliases) > 50 {
		return errors.New("MAIL_ALIASES supports at most 50 addresses")
	}
	seen := make(map[string]bool)
	for _, alias := range c.Aliases {
		if !bareAddress(alias) || seen[strings.ToLower(alias)] {
			return errors.New("MAIL_ALIASES requires unique bare email addresses")
		}
		seen[strings.ToLower(alias)] = true
	}
	if c.Timeout < time.Second || c.Timeout > 2*time.Minute {
		return errors.New("MAIL_TIMEOUT must be between 1s and 2m")
	}
	for _, ep := range []Endpoint{c.IMAP, c.SMTP} {
		if ep.Host == "" || len(ep.Host) > 253 || strings.ContainsAny(ep.Host, "/\\:@ \t\r\n\x00") || net.ParseIP(ep.Host) != nil {
			return errors.New("mail hosts must be DNS hostnames")
		}
		for _, label := range strings.Split(ep.Host, ".") {
			if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return errors.New("invalid mail hostname")
			}
			for _, r := range label {
				if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
					return errors.New("invalid mail hostname")
				}
			}
		}
		if ep.Port < 1 || ep.Port > 65535 {
			return errors.New("invalid mail port")
		}
	}
	if c.IMAP.TLSMode != "tls" {
		return errors.New("IMAP requires implicit TLS")
	}
	if c.SMTP.TLSMode != "tls" && c.SMTP.TLSMode != "starttls" {
		return errors.New("SMTP requires tls or starttls")
	}
	if c.SMTP.Port == 587 && c.SMTP.TLSMode != "starttls" {
		return errors.New("SMTP port 587 requires STARTTLS")
	}
	if c.SMTP.Port == 465 && c.SMTP.TLSMode != "tls" {
		return errors.New("SMTP port 465 requires implicit TLS")
	}
	return nil
}

// SelfAddresses only controls exclusion from derived reply recipients. It never
// changes the configured sender, credentials or SMTP authority.
func (c Config) SelfAddresses() []string {
	out := []string{c.From}
	if bareAddress(c.Username) {
		out = append(out, c.Username)
	}
	return append(out, c.Aliases...)
}

func bareAddress(value string) bool {
	if len(value) == 0 || len(value) > 254 {
		return false
	}
	for _, r := range value {
		if r <= 32 || r >= 127 {
			return false
		}
	}
	a, err := mail.ParseAddress(value)
	return err == nil && a.Address == value && strings.Contains(value, "@")
}

// IsGmail identifies the explicit Gmail/Google Workspace preset.
func (c Config) IsGmail() bool { return c.Provider == "gmail" }

// UsesGoogleOAuth2 retains the Gmail default for programmatic configurations.
func (c Config) UsesGoogleOAuth2() bool {
	return c.IsGmail() && (c.AuthMode == "" || c.AuthMode == "google_oauth2")
}

// IsGmailIMAP applies Gmail mailbox safeguards even to a custom configuration
// using a known Google hostname. It does not enable Google authentication.
func (c Config) IsGmailIMAP() bool {
	return c.IsGmail() || strings.EqualFold(c.IMAP.Host, "imap.gmail.com") || strings.EqualFold(c.IMAP.Host, "imap.googlemail.com")
}

// SMTPStoresSent identifies Google's automatic Sent storage independently from
// the configured IMAP service, including known custom Google SMTP endpoints.
func (c Config) SMTPStoresSent() bool {
	return c.IsMicrosoft() || c.IsGmail() || strings.EqualFold(c.SMTP.Host, "smtp.gmail.com") || strings.EqualFold(c.SMTP.Host, "smtp.googlemail.com")
}

// isAppPasswordProvider identifies presets requiring an owner-created app password.
func (c Config) isAppPasswordProvider() bool { return c.Provider == "icloud" || c.Provider == "yahoo" }

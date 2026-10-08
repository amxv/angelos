package config

import (
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode"
)

var microsoftUUID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func (c Config) IsMicrosoft() bool { return c.Provider == "microsoft" }
func (c Config) validateMicrosoft() error {
	key, keyErr := hex.DecodeString(c.MicrosoftTokenEncryptionKey)
	if keyErr != nil || len(key) != 32 {
		return errors.New("Microsoft requires a dedicated 32-byte hex MICROSOFT_TOKEN_ENCRYPTION_KEY")
	}
	if c.AuthMode != "microsoft_graph" {
		return errors.New("Microsoft requires microsoft_graph delegated OAuth")
	}
	if !microsoftUUID.MatchString(c.MicrosoftClientID) || (c.MicrosoftTenantID != "consumers" && !microsoftUUID.MatchString(c.MicrosoftTenantID)) {
		return errors.New("Microsoft requires an application UUID and tenant UUID (or consumers for Outlook.com)")
	}
	for _, v := range []string{c.MicrosoftClientSecret, c.MicrosoftRefreshToken, c.MicrosoftAccountID} {
		if len(v) == 0 || len(v) > 16<<10 || strings.IndexFunc(v, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
			return errors.New("Microsoft requires valid client secret, refresh token and verified account ID")
		}
	}
	if len(c.MicrosoftAccountID) > 256 || !bareAddress(c.Username) || !bareAddress(c.From) || !strings.EqualFold(c.Username, c.From) || len(c.Aliases) > 0 {
		return errors.New("Microsoft requires MAIL_USERNAME and MAIL_FROM to match the verified primary mailbox; aliases/shared mailboxes are unsupported")
	}
	if c.Password != "" || c.GoogleClientID != "" || c.GoogleClientSecret != "" || c.GoogleRefreshToken != "" {
		return errors.New("Microsoft Graph does not accept mailbox passwords or Google credentials")
	}
	if c.IMAP.Host != "" || c.SMTP.Host != "" || c.IMAP.Port != 0 && c.IMAP.Port != 993 || c.SMTP.Port != 0 && c.SMTP.Port != 465 || c.SMTP.TLSMode != "" && c.SMTP.TLSMode != "tls" {
		return errors.New("Microsoft Graph does not accept IMAP/SMTP endpoint overrides")
	}
	if c.Timeout < time.Second || c.Timeout > 2*time.Minute {
		return errors.New("MAIL_TIMEOUT must be between 1s and 2m")
	}
	return nil
}

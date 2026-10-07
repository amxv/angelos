package oauth

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

const passkeyRPID = "api.angelos.ashray.xyz"
const maxOwnerCredentials = 8

type ownerRecord struct {
	Version     int                   `json:"version"`
	Subject     string                `json:"subject"`
	Credentials []webauthn.Credential `json:"credentials"`
}

func (o *ownerRecord) WebAuthnID() []byte {
	id := sha256.Sum256([]byte("angelos:owner:" + o.Subject))
	return id[:]
}
func (o *ownerRecord) WebAuthnName() string                       { return "Angelos mailbox owner" }
func (o *ownerRecord) WebAuthnDisplayName() string                { return "Angelos mailbox owner" }
func (o *ownerRecord) WebAuthnCredentials() []webauthn.Credential { return o.Credentials }

type passkeyCeremony struct {
	Version        int                  `json:"version"`
	Mode           string               `json:"mode"`
	SessionBinding string               `json:"session_binding"`
	Bootstrap      bool                 `json:"bootstrap"`
	ExpiresUnix    int64                `json:"expires_unix"`
	Data           webauthn.SessionData `json:"webauthn"`
}

func newPasskeys() (*webauthn.WebAuthn, error) {
	return webauthn.New(&webauthn.Config{
		RPID: passkeyRPID, RPDisplayName: "Angelos", RPOrigins: []string{Issuer},
		RPAllowCrossOrigin: false, AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{UserVerification: protocol.VerificationRequired, ResidentKey: protocol.ResidentKeyRequirementPreferred},
		Timeouts:               webauthn.TimeoutsConfig{Login: webauthn.TimeoutConfig{Enforce: true, Timeout: ceremonyLifetime}, Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: ceremonyLifetime}},
	})
}
func (b *Browser) loadOwner(r *http.Request) ([]byte, *ownerRecord, error) {
	raw, err := b.server.store.LoadOwner(r.Context())
	if err != nil {
		return nil, nil, err
	}
	var owner ownerRecord
	if json.Unmarshal(raw, &owner) != nil || owner.Version != 1 || owner.Subject != b.server.config.OwnerSubject || len(owner.Credentials) == 0 || len(owner.Credentials) > maxOwnerCredentials {
		return nil, nil, ErrUnavailable
	}
	return raw, &owner, nil
}
func (b *Browser) passkeyBegin(w http.ResponseWriter, r *http.Request, register bool) {
	token, session, ok := b.requireSession(w, r, false)
	if !ok {
		return
	}
	if !b.csrf(w, r, session, r.Header.Get("X-CSRF-Token")) {
		return
	}
	var input struct {
		BootstrapToken string `json:"bootstrap_token"`
	}
	if !browserJSON(w, r, &input) {
		return
	}
	if !b.rate(w, r, "passkey-begin", 20, time.Minute) {
		return
	}
	_, owner, err := b.loadOwner(r)
	bootstrap := false
	if err != nil && !errors.Is(err, ErrNotFound) {
		browserError(w, 503, "Authentication state unavailable.")
		return
	}
	if register {
		if owner == nil {
			secret, decodeErr := base64.RawURLEncoding.Strict().DecodeString(input.BootstrapToken)
			if decodeErr != nil || len(secret) < 32 || len(secret) > 64 || !equalSecret(browserHash(input.BootstrapToken), b.server.config.BootstrapTokenHash) {
				browserError(w, 403, "Enrollment is not authorized.")
				return
			}
			owner = &ownerRecord{Version: 1, Subject: b.server.config.OwnerSubject}
			bootstrap = true
		} else if session.Subject != owner.Subject || !b.recent(session) {
			browserError(w, 401, "Sign in again before adding a passkey.")
			return
		}
		if len(owner.Credentials) >= maxOwnerCredentials {
			browserError(w, 409, "Authenticator limit reached.")
			return
		}
	} else if owner == nil {
		browserError(w, 401, "Owner enrollment is required.")
		return
	}
	var options any
	var data *webauthn.SessionData
	if register {
		exclusions := make([]protocol.CredentialDescriptor, 0, len(owner.Credentials))
		for _, credential := range owner.Credentials {
			exclusions = append(exclusions, credential.Descriptor())
		}
		options, data, err = b.passkeys.BeginRegistration(owner, webauthn.WithRegistrationOrigin(Issuer), webauthn.WithExclusions(exclusions))
	} else {
		options, data, err = b.passkeys.BeginLogin(owner, webauthn.WithLoginOrigin(Issuer), webauthn.WithUserVerification(protocol.VerificationRequired))
	}
	if err != nil {
		browserError(w, 503, "Unable to begin passkey ceremony.")
		return
	}
	id, err := browserRandom()
	if err != nil {
		browserError(w, 503, "Unable to begin passkey ceremony.")
		return
	}
	mode := "login"
	if register {
		mode = "register"
	}
	ceremony := passkeyCeremony{Version: 1, Mode: mode, SessionBinding: browserHash(token), Bootstrap: bootstrap, ExpiresUnix: b.server.now().Add(ceremonyLifetime).Unix(), Data: *data}
	raw, _ := json.Marshal(ceremony)
	if err = b.server.store.Put(r.Context(), "challenge", id, raw, ceremonyLifetime); err != nil {
		browserError(w, 503, "Authentication state unavailable.")
		return
	}
	browserWriteJSON(w, map[string]any{"ceremony": id, "options": options})
}
func (b *Browser) recent(session *browserSession) bool {
	now := b.server.now().Unix()
	return session.Subject == b.server.config.OwnerSubject && session.AuthenticatedUnix > 0 && now >= session.AuthenticatedUnix && now-session.AuthenticatedUnix <= int64(recentAuthentication/time.Second)
}
func (b *Browser) passkeyFinish(w http.ResponseWriter, r *http.Request, register bool) {
	token, session, ok := b.requireSession(w, r, false)
	if !ok {
		return
	}
	if !b.csrf(w, r, session, r.Header.Get("X-CSRF-Token")) {
		return
	}
	if !b.rate(w, r, "passkey-finish", 30, time.Minute) {
		return
	}
	var input struct {
		Ceremony   string          `json:"ceremony"`
		Credential json.RawMessage `json:"credential"`
	}
	if !browserJSON(w, r, &input) {
		return
	}
	if !validBrowserToken(input.Ceremony) {
		browserError(w, 400, "Invalid passkey ceremony.")
		return
	}
	raw, err := b.server.store.Consume(r.Context(), "challenge", input.Ceremony)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			browserError(w, 400, "Passkey ceremony expired or already used.")
		} else {
			browserError(w, 503, "Authentication state unavailable.")
		}
		return
	}
	var ceremony passkeyCeremony
	mode := "login"
	if register {
		mode = "register"
	}
	if json.Unmarshal(raw, &ceremony) != nil || ceremony.Version != 1 || ceremony.Mode != mode || !equalSecret(ceremony.SessionBinding, browserHash(token)) || b.server.now().Unix() >= ceremony.ExpiresUnix || ceremony.Data.RelyingPartyID != passkeyRPID || ceremony.Data.Origin != Issuer || ceremony.Data.UserVerification != protocol.VerificationRequired {
		browserError(w, 400, "Invalid passkey ceremony.")
		return
	}
	previous, owner, err := b.loadOwner(r)
	if err != nil && !errors.Is(err, ErrNotFound) {
		browserError(w, 503, "Authentication state unavailable.")
		return
	}
	if register && ceremony.Bootstrap {
		if owner != nil {
			browserError(w, 403, "Initial enrollment is disabled.")
			return
		}
		owner = &ownerRecord{Version: 1, Subject: b.server.config.OwnerSubject}
	} else if owner == nil {
		browserError(w, 401, "Owner enrollment is required.")
		return
	}
	var credential *webauthn.Credential
	if register {
		if !ceremony.Bootstrap && (!b.recent(session) || len(owner.Credentials) >= maxOwnerCredentials) {
			browserError(w, 401, "Sign in again before adding a passkey.")
			return
		}
		parsed, parseErr := protocol.ParseCredentialCreationResponseBytes(input.Credential)
		if parseErr != nil || parsed.Response.CollectedClientData.Origin != Issuer {
			browserError(w, 400, "Passkey verification failed.")
			return
		}
		credential, err = b.passkeys.CreateCredential(owner, ceremony.Data, parsed)
		if err == nil {
			for _, existing := range owner.Credentials {
				if bytes.Equal(existing.ID, credential.ID) {
					err = ErrConflict
					break
				}
			}
		}
		if err == nil {
			owner.Credentials = append(owner.Credentials, *credential)
		}
	} else {
		parsed, parseErr := protocol.ParseCredentialRequestResponseBytes(input.Credential)
		if parseErr != nil || parsed.Response.CollectedClientData.Origin != Issuer {
			browserError(w, 400, "Passkey verification failed.")
			return
		}
		credential, err = b.passkeys.ValidateLogin(owner, ceremony.Data, parsed)
		if err == nil && credential.Authenticator.CloneWarning {
			err = ErrConflict
		}
		if err == nil {
			found := false
			for i := range owner.Credentials {
				if bytes.Equal(owner.Credentials[i].ID, credential.ID) {
					owner.Credentials[i] = *credential
					found = true
					break
				}
			}
			if !found {
				err = ErrConflict
			}
		}
	}
	if err != nil {
		browserError(w, 400, "Passkey verification failed.")
		return
	}
	updated, err := json.Marshal(owner)
	if err != nil {
		browserError(w, 503, "Unable to save credential.")
		return
	}
	var saved bool
	if register && ceremony.Bootstrap {
		saved, err = b.server.store.BootstrapOwner(r.Context(), updated)
	} else {
		saved, err = b.server.store.CASOwner(r.Context(), previous, updated)
	}
	if err != nil {
		browserError(w, 503, "Authentication state unavailable.")
		return
	}
	if !saved {
		browserError(w, 409, "Authentication state changed. Please start again.")
		return
	}
	next, err := b.rotateSession(w, r, token, session)
	if err != nil {
		browserError(w, 503, "Please sign in again.")
		return
	}
	browserWriteJSON(w, map[string]string{"next": next})
}

package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

const (
	browserCookie        = "__Host-angelos"
	anonymousLifetime    = 10 * time.Minute
	sessionIdle          = 30 * time.Minute
	sessionLifetime      = 12 * time.Hour
	recentAuthentication = 5 * time.Minute
	ceremonyLifetime     = 5 * time.Minute
	consentLifetime      = 10 * time.Minute
)

// browserSession contains no raw bearer token. Its Redis key hashes the cookie.
// AuthenticatedUnix never slides: adding authenticators requires recent UV.
type browserSession struct {
	Version           int    `json:"version"`
	Subject           string `json:"subject,omitempty"`
	CSRF              string `json:"csrf"`
	PendingID         string `json:"pending_id,omitempty"`
	CreatedUnix       int64  `json:"created_unix"`
	SeenUnix          int64  `json:"seen_unix"`
	ExpiresUnix       int64  `json:"expires_unix"`
	AuthenticatedUnix int64  `json:"authenticated_unix,omitempty"`
}

func browserRandom() (string, error) {
	var value [32]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value[:]), nil
}
func browserHash(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}
func equalSecret(a, b string) bool {
	return len(a) > 0 && len(a) == len(b) && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
func validBrowserToken(value string) bool {
	v, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return err == nil && len(v) == 32
}

func (b *Browser) session(r *http.Request) (string, *browserSession, error) {
	c, err := r.Cookie(browserCookie)
	if err != nil || !validBrowserToken(c.Value) {
		return "", nil, ErrNotFound
	}
	for i := 0; i < 3; i++ {
		raw, err := b.server.store.Get(r.Context(), "session", c.Value)
		if err != nil {
			return "", nil, err
		}
		var session browserSession
		if json.Unmarshal(raw, &session) != nil || session.Version != 1 || !validBrowserToken(session.CSRF) {
			return "", nil, ErrNotFound
		}
		now := b.server.now().Unix()
		idle := int64(sessionIdle / time.Second)
		if session.Subject == "" {
			idle = int64(anonymousLifetime / time.Second)
		}
		if session.Subject != "" && session.Subject != b.server.config.OwnerSubject {
			return "", nil, ErrNotFound
		}
		if now >= session.ExpiresUnix || now-session.SeenUnix >= idle || now < session.CreatedUnix || session.SeenUnix < session.CreatedUnix || session.ExpiresUnix <= session.CreatedUnix {
			if err = b.server.store.Delete(r.Context(), "session", c.Value); err != nil {
				return "", nil, err
			}
			return "", nil, ErrNotFound
		}
		session.SeenUnix = now
		updated, _ := json.Marshal(session)
		ttl := time.Duration(session.ExpiresUnix-now) * time.Second
		if ttl > time.Duration(idle)*time.Second {
			ttl = time.Duration(idle) * time.Second
		}
		ok, err := b.server.store.CompareAndSwap(r.Context(), "session", c.Value, raw, updated, ttl)
		if err != nil {
			return "", nil, err
		}
		if ok {
			return c.Value, &session, nil
		}
	}
	return "", nil, ErrConflict
}
func (b *Browser) newSession(ctx context.Context, subject, pending string) (string, *browserSession, error) {
	token, err := browserRandom()
	if err != nil {
		return "", nil, err
	}
	csrf, err := browserRandom()
	if err != nil {
		return "", nil, err
	}
	now := b.server.now().Unix()
	lifetime := anonymousLifetime
	idle := anonymousLifetime
	authenticated := int64(0)
	if subject != "" {
		lifetime = sessionLifetime
		idle = sessionIdle
		authenticated = now
	}
	session := &browserSession{Version: 1, Subject: subject, CSRF: csrf, PendingID: pending, CreatedUnix: now, SeenUnix: now, ExpiresUnix: now + int64(lifetime/time.Second), AuthenticatedUnix: authenticated}
	raw, _ := json.Marshal(session)
	if err = b.server.store.Put(ctx, "session", token, raw, idle); err != nil {
		return "", nil, err
	}
	return token, session, nil
}
func setBrowserCookie(w http.ResponseWriter, token string, expires int64) {
	http.SetCookie(w, &http.Cookie{Name: browserCookie, Value: token, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, Expires: time.Unix(expires, 0)})
}
func clearBrowserCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: browserCookie, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1, Expires: time.Unix(1, 0)})
}
func (b *Browser) ensureSession(w http.ResponseWriter, r *http.Request) (string, *browserSession, error) {
	token, session, err := b.session(r)
	if err == nil {
		return token, session, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return "", nil, err
	}
	token, session, err = b.newSession(r.Context(), "", "")
	if err == nil {
		setBrowserCookie(w, token, session.ExpiresUnix)
	}
	return token, session, err
}
func (b *Browser) updateSession(ctx context.Context, token string, session *browserSession) error {
	// Re-read and compare to ensure a concurrent logout cannot resurrect a session.
	raw, err := b.server.store.Get(ctx, "session", token)
	if err != nil {
		return err
	}
	var old browserSession
	if json.Unmarshal(raw, &old) != nil || old.CSRF != session.CSRF || old.Subject != session.Subject {
		return ErrNotFound
	}
	session.SeenUnix = old.SeenUnix
	updated, _ := json.Marshal(session)
	ttl := time.Duration(session.ExpiresUnix-b.server.now().Unix()) * time.Second
	if ttl <= 0 {
		return ErrNotFound
	}
	idle := sessionIdle
	if session.Subject == "" {
		idle = anonymousLifetime
	}
	if ttl > idle {
		ttl = idle
	}
	ok, err := b.server.store.CompareAndSwap(ctx, "session", token, raw, updated, ttl)
	if err != nil {
		return err
	}
	if !ok {
		return ErrConflict
	}
	return nil
}
func (b *Browser) rotateSession(w http.ResponseWriter, r *http.Request, oldToken string, old *browserSession) (string, error) {
	// Consume, rather than delete, ensures only one ceremony can rotate this session.
	raw, err := b.server.store.Consume(r.Context(), "session", oldToken)
	if err != nil {
		return "", err
	}
	var current browserSession
	if json.Unmarshal(raw, &current) != nil || !equalSecret(current.CSRF, old.CSRF) {
		return "", ErrNotFound
	}
	token, session, err := b.newSession(r.Context(), b.server.config.OwnerSubject, current.PendingID)
	if err != nil {
		return "", err
	}
	setBrowserCookie(w, token, session.ExpiresUnix)
	if session.PendingID != "" {
		return "/oauth/consent?request=" + session.PendingID, nil
	}
	return "/oauth/grants", nil
}
func (b *Browser) requireSession(w http.ResponseWriter, r *http.Request, authenticated bool) (string, *browserSession, bool) {
	token, session, err := b.session(r)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			browserError(w, http.StatusUnauthorized, "Sign in again.")
		} else {
			browserError(w, http.StatusServiceUnavailable, "Authentication state unavailable.")
		}
		return "", nil, false
	}
	if authenticated && session.Subject != b.server.config.OwnerSubject {
		browserError(w, http.StatusUnauthorized, "Sign in again.")
		return "", nil, false
	}
	return token, session, true
}
func browserOrigin(r *http.Request, issuer string) bool {
	origins := r.Header.Values("Origin")
	sites := r.Header.Values("Sec-Fetch-Site")
	return len(origins) == 1 && origins[0] == issuer && (len(sites) == 0 || (len(sites) == 1 && sites[0] == "same-origin"))
}
func (b *Browser) csrf(w http.ResponseWriter, r *http.Request, session *browserSession, value string) bool {
	if !browserOrigin(r, b.server.config.Issuer) || !equalSecret(session.CSRF, value) {
		browserError(w, http.StatusForbidden, "Invalid browser request.")
		return false
	}
	return true
}

package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"time"
)

type Server struct {
	config           Config
	store            Store
	keys             signingKeys
	browser          *Browser
	now              func() time.Time
	clientHTTP       *http.Client
	clientMu         sync.Mutex
	cachedClient     *Client
	clientCacheUntil time.Time
	clientRetryAfter time.Time
}

// New never generates signing keys or substitutes an in-memory store. Invalid
// configuration leaves both login and token issuance unavailable.
func New(c Config, store Store) (*Server, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	if store == nil || (reflect.ValueOf(store).Kind() == reflect.Pointer && reflect.ValueOf(store).IsNil()) {
		return nil, errors.New("durable OAuth state required")
	}
	keys, err := loadSigningKeys(c)
	if err != nil {
		return nil, err
	}
	// Do not retain mutable caller-owned redirect slices or key maps.
	c.Clients = append([]Client(nil), c.Clients...)
	for i := range c.Clients {
		c.Clients[i].RedirectURIs = append([]string(nil), c.Clients[i].RedirectURIs...)
	}
	s := &Server{config: c, store: store, keys: keys, now: time.Now, clientHTTP: metadataHTTPClient(c.HTTPClient)}
	s.browser, err = NewBrowser(s)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Server) JWKS() []byte { return append([]byte(nil), s.keys.jwks...) }

func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		if !s.config.MatchRequest(r) {
			oauthError(w, http.StatusBadRequest, "invalid_request")
			return
		}
		switch r.URL.Path {
		case MetadataPath:
			if !getOnly(w, r) {
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"issuer": s.config.Issuer, "authorization_endpoint": s.config.Issuer + "/oauth/authorize", "token_endpoint": s.config.Issuer + "/oauth/token", "jwks_uri": s.config.Issuer + JWKSPath,
				"response_types_supported": []string{"code"}, "response_modes_supported": []string{"query"}, "grant_types_supported": []string{"authorization_code", "refresh_token"},
				"code_challenge_methods_supported": []string{"S256"}, "token_endpoint_auth_methods_supported": []string{"none"},
				"scopes_supported": []string{ScopeRead, ScopeWrite, ScopeSend}, "authorization_response_iss_parameter_supported": true,
				"client_id_metadata_document_supported": s.config.EnableChatGPTCIMD,
			})
		case JWKSPath:
			if !getOnly(w, r) {
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(s.JWKS())
		case "/oauth/authorize":
			s.authorize(w, r)
		case "/oauth/token":
			s.token(w, r)
		default:
			s.browser.Handler().ServeHTTP(w, r)
		}
	})
}

// MatchRequest enforces the configured origin on every first-party route,
// including requests arriving over a platform's internal HTTP/loopback hop.
// An invalid trusted issuer denies every request; request headers never select it.
func (c Config) MatchRequest(r *http.Request) bool {
	host, err := issuerHost(c.Issuer)
	if err != nil {
		return false
	}
	if r.Host != host || (r.URL.Scheme != "" && r.URL.Scheme != "https") || (r.URL.Host != "" && r.URL.Host != host) {
		return false
	}
	// Vercel includes Forwarded on every request. Deliberately ignore it rather
	// than interpreting untrusted proxy claims; Host and X-Forwarded-* are
	// independently validated against the explicitly configured first-party issuer.
	for name, want := range map[string]string{"X-Forwarded-Host": host, "X-Forwarded-Proto": "https"} {
		values := r.Header.Values(name)
		if len(values) > 1 || (len(values) == 1 && values[0] != want) {
			return false
		}
	}
	return r.URL.RawPath == "" && len(r.URL.RawQuery) <= 8192
}

// AuthorizationRequest contains only validated data. Browser consent stores this
// server-side, bound to its owner session; posted hidden fields are never trusted.
type AuthorizationRequest struct {
	ClientID    string   `json:"client_id"`
	ClientName  string   `json:"client_name"`
	RedirectURI string   `json:"redirect_uri"`
	Resource    string   `json:"resource"`
	State       string   `json:"state"`
	Challenge   string   `json:"challenge"`
	Scopes      []string `json:"scopes"`
}

type AuthorizationCode struct {
	Subject     string   `json:"subject"`
	ClientID    string   `json:"client_id"`
	RedirectURI string   `json:"redirect_uri"`
	Resource    string   `json:"resource"`
	Scopes      []string `json:"scopes"`
	Challenge   string   `json:"challenge"`
	GrantID     string   `json:"grant_id"`
	ExpiresUnix int64    `json:"expires_unix"`
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	if !getOnly(w, r) {
		return
	}
	params, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || !singleValues(params) {
		oauthError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if !s.knownClient(params.Get("client_id")) {
		oauthError(w, http.StatusBadRequest, "invalid_client")
		return
	}
	allowed, err := s.store.Allow(r.Context(), "authorize:"+params.Get("client_id"), 60, time.Minute)
	if err != nil {
		oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable")
		return
	}
	if !allowed {
		w.Header().Set("Retry-After", "60")
		oauthError(w, http.StatusTooManyRequests, "temporarily_unavailable")
		return
	}
	client, err := s.resolveClient(r.Context(), params.Get("client_id"))
	if err != nil || !client.allowsRedirect(params.Get("redirect_uri")) {
		oauthError(w, http.StatusBadRequest, "invalid_client")
		return
	}
	a := AuthorizationRequest{ClientID: client.ID, ClientName: client.Name, RedirectURI: params.Get("redirect_uri"), Resource: params.Get("resource"), State: params.Get("state"), Challenge: params.Get("code_challenge")}
	// No untrusted callback is used before both client and exact redirect match.
	fail := func(code string) { http.Redirect(w, r, s.authorizationRedirect(a, "error", code), http.StatusSeeOther) }
	if !boundedText(a.State, 1024) {
		fail("invalid_request")
		return
	}
	if params.Get("response_type") != "code" {
		fail("unsupported_response_type")
		return
	}
	if a.Resource != s.config.Resource {
		fail("invalid_target")
		return
	}
	if params.Get("code_challenge_method") != "S256" || !validOpaque(a.Challenge) {
		fail("invalid_request")
		return
	}
	if mode := params.Get("response_mode"); mode != "" && mode != "query" {
		fail("invalid_request")
		return
	}
	for _, forbidden := range []string{"request", "request_uri", "client_secret", "client_assertion", "client_assertion_type"} {
		if _, ok := params[forbidden]; ok {
			fail("invalid_request")
			return
		}
	}
	a.Scopes, err = parseScopes(params.Get("scope"))
	if err != nil {
		fail("invalid_scope")
		return
	}
	s.browser.BeginAuthorization(w, r, a)
}

// ApproveAuthorization may only be called by the CSRF-protected browser flow
// after a live owner session approves these precise scopes.
func (s *Server) ApproveAuthorization(ctx context.Context, a AuthorizationRequest, subject string, approvedScopes []string) (string, error) {
	if subject != s.config.OwnerSubject || a.Resource != s.config.Resource || !boundedText(a.State, 1024) || !validOpaque(a.Challenge) {
		return "", errors.New("invalid owner authorization")
	}
	client, err := s.resolveClient(ctx, a.ClientID)
	if err != nil || !client.allowsRedirect(a.RedirectURI) {
		return "", errors.New("invalid authorization client")
	}
	wanted, err := canonicalScopes(a.Scopes)
	if err != nil {
		return "", err
	}
	approved, err := canonicalScopes(approvedScopes)
	if err != nil || !scopeSubset(approved, wanted) {
		return "", errors.New("unapproved scopes")
	}
	grantID, err := opaqueToken()
	if err != nil {
		return "", err
	}
	code, err := opaqueToken()
	if err != nil {
		return "", err
	}
	now := s.now()
	grant := Grant{ID: grantID, Subject: subject, ClientID: client.ID, ClientName: client.Name, Resource: s.config.Resource, Scopes: approved, CreatedUnix: now.Unix(), ExpiresUnix: now.Add(GrantTTL).Unix()}
	if err := s.store.CreateGrant(ctx, grant); err != nil {
		return "", err
	}
	record := AuthorizationCode{Subject: subject, ClientID: client.ID, RedirectURI: a.RedirectURI, Resource: s.config.Resource, Scopes: approved, Challenge: a.Challenge, GrantID: grantID, ExpiresUnix: now.Add(CodeTTL).Unix()}
	encoded, err := json.Marshal(record)
	if err == nil {
		err = s.store.Put(ctx, "code", code, encoded, CodeTTL)
	}
	if err != nil {
		_ = s.store.RevokeGrant(ctx, grantID)
		return "", err
	}
	return s.authorizationRedirect(a, "code", code), nil
}

func (s *Server) DenyAuthorization(a AuthorizationRequest) string {
	return s.authorizationRedirect(a, "error", "access_denied")
}

func (s *Server) authorizationRedirect(a AuthorizationRequest, kind, value string) string {
	u, err := url.Parse(a.RedirectURI)
	if err != nil || !validRedirect(a.RedirectURI) {
		return s.config.Issuer + "/oauth/login"
	}
	q := u.Query()
	q.Set(kind, value)
	q.Set("iss", s.config.Issuer)
	if a.State != "" {
		q.Set("state", a.State)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		oauthError(w, http.StatusMethodNotAllowed, "invalid_request")
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery || len(r.Header.Values("Authorization")) != 0 {
		oauthError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/x-www-form-urlencoded" {
		oauthError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16384))
	if err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	params, err := url.ParseQuery(string(body))
	if err != nil || !singleValues(params) {
		oauthError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	// OAuth requires ignoring unknown extensions, but unsupported client
	// authentication must never be silently downgraded to public-client mode.
	for _, key := range []string{"client_secret", "client_assertion", "client_assertion_type", "assertion", "username", "password"} {
		if params.Has(key) {
			oauthError(w, http.StatusBadRequest, "invalid_request")
			return
		}
	}
	if !s.knownClient(params.Get("client_id")) {
		oauthError(w, http.StatusBadRequest, "invalid_client")
		return
	}
	if params.Get("resource") != s.config.Resource {
		oauthError(w, http.StatusBadRequest, "invalid_target")
		return
	}
	allowed, err := s.store.Allow(r.Context(), "token:"+params.Get("client_id"), 120, time.Minute)
	if err != nil {
		oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable")
		return
	}
	if !allowed {
		w.Header().Set("Retry-After", "60")
		oauthError(w, http.StatusTooManyRequests, "temporarily_unavailable")
		return
	}
	client, err := s.resolveClient(r.Context(), params.Get("client_id"))
	if err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_client")
		return
	}
	switch params.Get("grant_type") {
	case "authorization_code":
		s.exchangeCode(w, r, params, client)
	case "refresh_token":
		s.exchangeRefresh(w, r, params, client)
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type")
	}
}

func (s *Server) exchangeCode(w http.ResponseWriter, r *http.Request, p url.Values, client Client) {
	if !validOpaque(p.Get("code")) || !validVerifier(p.Get("code_verifier")) || !client.allowsRedirect(p.Get("redirect_uri")) || p.Has("refresh_token") || p.Has("scope") {
		oauthError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	data, err := s.store.Consume(r.Context(), "code", p.Get("code"))
	if err != nil {
		tokenStateError(w, err)
		return
	}
	var code AuthorizationCode
	if strictJSON(data, &code) != nil || code.Subject != s.config.OwnerSubject || code.ClientID != client.ID || code.Resource != s.config.Resource || code.RedirectURI != p.Get("redirect_uri") || code.ExpiresUnix <= s.now().Unix() || !verifyPKCE(p.Get("code_verifier"), code.Challenge) {
		oauthError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	if _, err := canonicalScopes(code.Scopes); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	grant, err := s.store.GetGrant(r.Context(), code.GrantID)
	if err != nil {
		tokenStateError(w, err)
		return
	}
	if grant.ID != code.GrantID || grant.Subject != code.Subject || grant.ClientID != client.ID || grant.Resource != s.config.Resource || grant.ExpiresUnix <= s.now().Unix() || !scopeSubset(code.Scopes, grant.Scopes) {
		oauthError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	access, err := s.signAccess(grant, code.Scopes)
	if err != nil {
		oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable")
		return
	}
	refresh, err := opaqueToken()
	if err != nil {
		oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable")
		return
	}
	family, err := opaqueToken()
	if err != nil {
		oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable")
		return
	}
	if err := s.store.CreateRefresh(r.Context(), refresh, Refresh{FamilyID: family, GrantID: grant.ID, Subject: code.Subject, ClientID: client.ID, Resource: s.config.Resource, Scopes: code.Scopes, ExpiresUnix: grant.ExpiresUnix}); err != nil {
		tokenStateError(w, err)
		return
	}
	if err := s.GrantActive(r.Context(), grant.ID, client.ID, code.Subject, code.Scopes); err != nil {
		tokenStateError(w, err)
		return
	}
	s.tokenResponse(w, access, refresh, code.Scopes, grant.ExpiresUnix)
}

func (s *Server) exchangeRefresh(w http.ResponseWriter, r *http.Request, p url.Values, client Client) {
	if !validOpaque(p.Get("refresh_token")) || p.Has("code") || p.Has("code_verifier") || p.Has("redirect_uri") {
		oauthError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	var requested []string
	if p.Has("scope") {
		var err error
		requested, err = parseScopes(p.Get("scope"))
		if err != nil {
			oauthError(w, http.StatusBadRequest, "invalid_scope")
			return
		}
	}
	next, err := opaqueToken()
	if err != nil {
		oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable")
		return
	}
	ref, err := s.store.RotateRefresh(r.Context(), p.Get("refresh_token"), next, client.ID, s.config.Resource, s.now())
	if err != nil {
		tokenStateError(w, err)
		return
	}
	if ref.Subject != s.config.OwnerSubject || ref.ClientID != client.ID || ref.Resource != s.config.Resource || ref.ExpiresUnix <= s.now().Unix() {
		oauthError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	scopes := ref.Scopes
	if requested != nil {
		if !scopeSubset(requested, scopes) {
			// Rotation has happened atomically. Do not leave an inaccessible new
			// token alive after an attempted scope expansion; reconnect with consent.
			_ = s.store.RevokeGrant(r.Context(), ref.GrantID)
			oauthError(w, http.StatusBadRequest, "invalid_scope")
			return
		}
		scopes = requested
	}
	grant, err := s.store.GetGrant(r.Context(), ref.GrantID)
	if err != nil {
		tokenStateError(w, err)
		return
	}
	if grant.ID != ref.GrantID || grant.ClientID != ref.ClientID || grant.Subject != ref.Subject || grant.Resource != s.config.Resource || !scopeSubset(scopes, grant.Scopes) {
		oauthError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	access, err := s.signAccess(grant, scopes)
	if err != nil {
		oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable")
		return
	}
	if err := s.GrantActive(r.Context(), grant.ID, client.ID, ref.Subject, scopes); err != nil {
		tokenStateError(w, err)
		return
	}
	s.tokenResponse(w, access, next, scopes, grant.ExpiresUnix)
}

func (s *Server) tokenResponse(w http.ResponseWriter, access, refresh string, scopes []string, expires int64) {
	writeJSON(w, http.StatusOK, map[string]any{"access_token": access, "token_type": "Bearer", "expires_in": expiresIn(s.now(), expires), "refresh_token": refresh, "scope": strings.Join(scopes, " ")})
}

func singleValues(values url.Values) bool {
	for name, value := range values {
		if name == "" || len(value) != 1 {
			return false
		}
	}
	return true
}

func getOnly(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodGet {
		return true
	}
	w.Header().Set("Allow", http.MethodGet)
	oauthError(w, http.StatusMethodNotAllowed, "invalid_request")
	return false
}

func oauthError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}

func tokenStateError(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrNotFound) || errors.Is(err, ErrReplay) || errors.Is(err, ErrConflict) {
		oauthError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable")
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

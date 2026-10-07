package auth

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

var (
	ErrInvalidToken      = errors.New("invalid access token")
	ErrInsufficientScope = errors.New("insufficient OAuth scope")
)

// Principal contains verified identity and scopes, never the bearer token.
type Principal struct {
	Issuer   string
	Resource string
	Subject  string
	Scopes   []string
}

type principalKey struct{}

// PrincipalFromContext returns a copy so callers cannot change later checks.
func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	p.Scopes = append([]string(nil), p.Scopes...)
	return p, ok
}

// PrincipalBinding returns a stable, opaque owner identifier for the verified
// issuer, resource, and subject, or "" when the context has no verified principal.
// Scopes and token lifetimes are deliberately excluded so refreshed tokens retain
// ownership. The versioned, length-prefixed encoding prevents tuple ambiguity.
func PrincipalBinding(ctx context.Context) string {
	p, ok := ctx.Value(principalKey{}).(Principal)
	if !ok {
		return ""
	}
	h := sha256.New()
	h.Write([]byte("angelos/principal-binding/v1\x00"))
	var size [8]byte
	for _, field := range []string{p.Issuer, p.Resource, p.Subject} {
		binary.BigEndian.PutUint64(size[:], uint64(len(field)))
		h.Write(size[:])
		h.Write([]byte(field))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func HasScope(ctx context.Context, scope string) bool {
	p, ok := ctx.Value(principalKey{}).(Principal)
	if !ok {
		return false
	}
	for _, granted := range p.Scopes {
		if granted == scope {
			return true
		}
	}
	return false
}

// RequireScope is intended for every mail-writing or sending tool handler.
func RequireScope(ctx context.Context, scope string) error {
	if !HasScope(ctx, scope) {
		return ErrInsufficientScope
	}
	return nil
}

// Authenticator is safe for concurrent HTTP requests. Its only mutable state is
// a bounded public signing-key cache; authenticated sessions are not retained.
type Authenticator struct {
	config      Config
	allowed     map[string]struct{}
	client      *http.Client
	metadataURL string
	now         func() time.Time
	mu          sync.Mutex
	keys        map[string]verificationKey
	keysExpire  time.Time
	lastAttempt time.Time
}

// New validates configuration without network access. Signing keys are fetched
// on the first otherwise well-formed bearer request and cached for five minutes.
func New(c Config) (*Authenticator, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	c.AllowedSubjects = append([]string(nil), c.AllowedSubjects...)
	c.LocalJWKS = append([]byte(nil), c.LocalJWKS...)
	if c.LocalJWKS != nil {
		if len(c.LocalJWKS) > maxJWKSBytes {
			return nil, errors.New("local public signing keys exceed size limit")
		}
		if _, err := parseKeys(c.LocalJWKS); err != nil {
			return nil, errors.New("invalid local public signing keys")
		}
	}
	client := newPublicClient()
	if c.HTTPClient != nil {
		copy := *c.HTTPClient
		client = &copy
		if client.Timeout <= 0 || client.Timeout > requestTimeout {
			client.Timeout = requestTimeout
		}
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resource, _ := url.Parse(c.ResourceURL)
	allowed := make(map[string]struct{}, len(c.AllowedSubjects))
	for _, subject := range c.AllowedSubjects {
		allowed[subject] = struct{}{}
	}
	return &Authenticator{
		config: c, allowed: allowed, client: client,
		metadataURL: resource.Scheme + "://" + resource.Host + MetadataPath,
		now:         time.Now,
	}, nil
}

// MetadataURL is based exclusively on trusted configuration, never Host or a
// forwarded header from the request.
func (a *Authenticator) MetadataURL() string { return a.metadataURL }

// Challenge returns an RFC 9728 / RFC 6750 challenge suitable for HTTP headers
// and MCP mcp/www_authenticate tool metadata. Only known mail scopes are emitted.
func (a *Authenticator) Challenge(scope string) string {
	if scope == ScopeWrite+" "+ScopeSend {
		scope = ScopeRead + " " + ScopeWrite + " " + ScopeSend
	} else if scope == ScopeWrite || scope == ScopeSend {
		scope = ScopeRead + " " + scope
	} else {
		scope = ScopeRead
	}
	return `Bearer resource_metadata="` + a.metadataURL + `", scope="` + scope + `"`
}

// MetadataHandler is public and must be mounted outside Middleware at
// MetadataPath. It may additionally be mounted at MetadataPath + the MCP path.
func (a *Authenticator) MetadataHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=300")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodHead {
			return
		}
		_ = json.NewEncoder(w).Encode(struct {
			Resource               string   `json:"resource"`
			AuthorizationServers   []string `json:"authorization_servers"`
			ScopesSupported        []string `json:"scopes_supported"`
			BearerMethodsSupported []string `json:"bearer_methods_supported"`
		}{a.config.ResourceURL, []string{a.config.Issuer}, []string{ScopeRead, ScopeWrite, ScopeSend}, []string{"header"}})
	})
}

// Middleware protects every method, including MCP initialization and discovery.
// Bearer tokens in query strings, cookies, or request bodies are never accepted.
func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.URL.Query().Has("access_token") {
			a.reject(w, http.StatusUnauthorized, "invalid_token")
			return
		}
		headers := r.Header.Values("Authorization")
		if len(headers) != 1 {
			a.reject(w, http.StatusUnauthorized, "")
			return
		}
		scheme, token, found := strings.Cut(headers[0], " ")
		token = strings.TrimLeft(token, " ")
		if !found || !strings.EqualFold(scheme, "Bearer") {
			a.reject(w, http.StatusUnauthorized, "invalid_token")
			return
		}
		p, err := a.verify(r.Context(), token)
		if err != nil {
			status, code := http.StatusUnauthorized, "invalid_token"
			if errors.Is(err, ErrInsufficientScope) {
				status, code = http.StatusForbidden, "insufficient_scope"
			}
			a.reject(w, status, code)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, p)))
	})
}

func (a *Authenticator) reject(w http.ResponseWriter, status int, code string) {
	challenge := a.Challenge(ScopeRead)
	if code != "" {
		challenge += `, error="` + code + `"`
	}
	w.Header().Set("WWW-Authenticate", challenge)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// Do not disclose token contents, configured subjects, claims, or key errors.
	_ = json.NewEncoder(w).Encode(map[string]string{"error": http.StatusText(status)})
}

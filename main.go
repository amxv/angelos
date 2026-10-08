package main

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/amxv/angelos/internal/app"
	"github.com/amxv/angelos/internal/auth"
	"github.com/amxv/angelos/internal/config"
	"github.com/amxv/angelos/internal/dispatch"
	"github.com/amxv/angelos/internal/mail"
	"github.com/amxv/angelos/internal/oauth"
)

func enabled(name string) bool { return os.Getenv(name) == "1" }
func newHandler() http.Handler {
	mux := http.NewServeMux()
	configured := false
	unavailable := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		http.Error(w, "Angelos is not configured", http.StatusServiceUnavailable)
	})
	var mcpHandler http.Handler = unavailable
	mailConfig, mailErr := config.LoadFromEnv()
	authConfig, authErr := auth.ConfigFromEnv()
	// First-party mode is deliberately opt-in. A configured mailbox alone can
	// never enable it, and invalid first-party configuration cannot silently
	// fall back to the external-issuer verifier.
	firstParty := enabled("ANGELOS_OAUTH_ENABLED")
	if firstParty {
		issuerConfig, err := oauth.ConfigFromEnv()
		if err == nil && authErr == nil {
			var transport *dispatch.Redis
			transport, err = dispatch.NewRedis(os.Getenv("ANGELOS_REDIS_REST_URL"), os.Getenv("ANGELOS_REDIS_REST_TOKEN"))
			if err == nil {
				var state *oauth.RedisStore
				state, err = oauth.NewRedisStore(transport, issuerConfig.OwnerSubject)
				if err == nil {
					var issuer *oauth.Server
					issuer, err = oauth.New(issuerConfig, state)
					if err == nil {
						handler := issuer.Handler()
						mux.Handle(oauth.MetadataPath, handler)
						mux.Handle("/oauth/", handler)
						authConfig.LocalJWKS = issuer.JWKS()
						authConfig.CheckGrant = issuer.GrantActive
					}
				}
			}
		}
		if err != nil {
			authErr = auth.ErrInvalidToken
		}
	} else if authConfig.Issuer == oauth.Issuer || sameRootIssuerOrigin(authConfig.Issuer, authConfig.ResourceURL) {
		// The local issuer must always use online first-party grant revocation,
		// even if all resource-server environment variables happen to be set.
		authErr = auth.ErrInvalidToken
	}
	if authErr == nil {
		u, _ := url.Parse(authConfig.ResourceURL)
		if u.Path != "/mcp" {
			authErr = auth.ErrInvalidToken
		}
	}
	if authErr == nil {
		gate, e := auth.New(authConfig)
		if e == nil {
			mux.Handle(auth.MetadataPath, gate.MetadataHandler())
			// RFC 9728 path-specific discovery for a resource ending in /mcp.
			mux.Handle(auth.MetadataPath+"/mcp", gate.MetadataHandler())
			if mailErr == nil {
				var backend app.Backend
				var e error
				if mailConfig.IsMicrosoft() {
					var graph *mail.GraphBackend
					graph, e = mail.NewGraph(mailConfig)
					if e == nil {
						var tokenTransport *dispatch.Redis
						tokenTransport, e = dispatch.NewRedis(os.Getenv("ANGELOS_REDIS_REST_URL"), os.Getenv("ANGELOS_REDIS_REST_TOKEN"))
						if e == nil {
							e = graph.ConfigureTokenStore(tokenTransport)
						}
					}
					backend = graph
				} else {
					backend, e = mail.New(mailConfig)
				}
				if e == nil {
					a := &app.App{Mail: backend, Config: mailConfig, EnableWrites: enabled("MAIL_ENABLE_WRITES"), EnableSend: enabled("MAIL_ENABLE_SEND"), EnableDelete: enabled("MAIL_ENABLE_DELETE"), AuthChallenge: gate.Challenge}
					configureStore(a)
					transport := a.Handler()
					if firstParty {
						// The Vercel function receives public-host HTTPS traffic over a
						// loopback hop. The outer canonicalHost gate below enforces
						// the exact trusted public hostname before this MCP transport.
						transport = a.HandlerBehindCanonicalHostGate()
					}
					mcpHandler = gate.Middleware(transport)
					configured = true
				}
			}
		}
	}
	if !configured {
		log.Print("MCP unavailable: mailbox or OAuth configuration is incomplete or invalid")
	}
	mux.Handle("/mcp", mcpHandler)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		status := map[string]any{"service": "angelos", "version": app.Version, "configured": configured}
		// Only validated, non-secret configuration labels are public. This is
		// not a live mailbox login or provider-availability check.
		if mailErr == nil {
			status["mail_provider"] = mailConfig.Provider
			status["mail_auth_mode"] = mailConfig.AuthMode
		}
		json.NewEncoder(w).Encode(status)
	})
	var handler http.Handler = mux
	if firstParty {
		handler = canonicalHost(handler, os.Getenv("MCP_OAUTH_ISSUER"))
	}
	return secureHeaders(handler)
}

// A root issuer on the MCP origin must use first-party mode and its online
// grant checks. Path-based external issuers remain supported on the same host.
// Compare origin components here only to detect that boundary; token issuer and
// audience validation remain byte-for-byte exact in the resource server.
func sameRootIssuerOrigin(a, b string) bool {
	left, leftErr := url.Parse(a)
	right, rightErr := url.Parse(b)
	if leftErr != nil || rightErr != nil || (left.Path != "" && left.Path != "/") || left.Scheme != "https" || right.Scheme != "https" || left.Hostname() == "" || !strings.EqualFold(left.Hostname(), right.Hostname()) {
		return false
	}
	port := func(u *url.URL) string {
		if u.Port() == "" {
			return "443"
		}
		return u.Port()
	}
	return port(left) == port(right)
}

func canonicalHost(next http.Handler, issuer string) http.Handler {
	// The issuer is trusted deployment configuration, captured at construction.
	// Reuse the authorization server's exact host/proxy checks for MCP and all
	// discovery routes before allowing the platform's internal loopback hop.
	config := oauth.Config{Issuer: issuer}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !config.MatchRequest(r) {
			http.Error(w, "invalid host", http.StatusBadRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// A configured receipt store remains readable after the operator disables sends.
// Loading its configuration does not grant send authority or contact Redis.
func configureStore(a *app.App) {
	store, err := dispatch.NewRedis(os.Getenv("ANGELOS_REDIS_REST_URL"), os.Getenv("ANGELOS_REDIS_REST_TOKEN"))
	if err == nil {
		a.Store = store
	} else if a.EnableSend {
		a.EnableSend = false
		log.Print("send disabled: durable store configuration is incomplete")
	}
}
func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if strings.ContainsAny(r.Host, "\r\n") {
			http.Error(w, "invalid host", 400)
			return
		}
		next.ServeHTTP(w, r)
	})
}
func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	server := &http.Server{Addr: ":" + port, Handler: newHandler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 110 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 32 << 10}
	log.Print("Angelos listening")
	if e := server.ListenAndServe(); e != nil && e != http.ErrServerClosed {
		log.Fatal("server stopped")
	}
}

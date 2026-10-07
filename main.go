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
	} else if authConfig.Issuer == oauth.Issuer {
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
				backend, e := mail.New(mailConfig)
				if e == nil {
					a := &app.App{Mail: backend, Config: mailConfig, EnableWrites: enabled("MAIL_ENABLE_WRITES"), EnableSend: enabled("MAIL_ENABLE_SEND"), EnableDelete: enabled("MAIL_ENABLE_DELETE"), AuthChallenge: gate.Challenge}
					configureStore(a)
					mcpHandler = gate.Middleware(a.Handler())
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
		json.NewEncoder(w).Encode(map[string]any{"service": "angelos", "version": app.Version, "configured": configured})
	})
	var handler http.Handler = mux
	if firstParty {
		handler = canonicalHost(handler)
	}
	return secureHeaders(handler)
}

func canonicalHost(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Vercel injects the RFC 7239 Forwarded header on legitimate requests.
		// It is never trusted for issuer, origin, host, or redirect decisions;
		// validate the actual Host and platform-normalized forwarding headers.
		if r.Host != "api.angelos.ashray.xyz" || (r.URL.Host != "" && r.URL.Host != r.Host) {
			http.Error(w, "invalid host", http.StatusBadRequest)
			return
		}
		for name, want := range map[string]string{"X-Forwarded-Host": r.Host, "X-Forwarded-Proto": "https"} {
			values := r.Header.Values(name)
			if len(values) > 1 || (len(values) == 1 && values[0] != want) {
				http.Error(w, "invalid host", http.StatusBadRequest)
				return
			}
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

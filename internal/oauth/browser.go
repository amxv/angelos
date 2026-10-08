package oauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"mime"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// Browser implements the single-owner UI. Authorization requests are immutable
// server-side records; URL or form fields can never replace client/redirect/PKCE.
type Browser struct {
	server   *Server
	passkeys *webauthn.WebAuthn
}
type pendingConsent struct {
	Version     int                  `json:"version"`
	ExpiresUnix int64                `json:"expires_unix"`
	Request     AuthorizationRequest `json:"request"`
}
type browserPage struct {
	Title, Page, CSRF, Mailbox, RequestID string
	Bootstrap                             bool
	Authenticated                         bool
	Request                               AuthorizationRequest
	Grants                                []Grant
	Credentials                           int
}

func NewBrowser(server *Server) (*Browser, error) {
	passkeys, err := newPasskeys(server.config)
	if err != nil {
		return nil, err
	}
	return &Browser{server: server, passkeys: passkeys}, nil
}
func browserHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'")
	w.Header().Set("Permissions-Policy", "publickey-credentials-get=(self), publickey-credentials-create=(self)")
}
func browserError(w http.ResponseWriter, status int, message string) {
	browserHeaders(w)
	http.Error(w, message, status)
}
func browserWriteJSON(w http.ResponseWriter, value any) {
	browserHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}
func browserJSON(w http.ResponseWriter, r *http.Request, out any) bool {
	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || contentType != "application/json" {
		browserError(w, 415, "Expected JSON.")
		return false
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	if err != nil {
		browserError(w, 413, "Request too large.")
		return false
	}
	if err = strictJSON(raw, out); err != nil {
		browserError(w, 400, "Invalid JSON request.")
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(out) != nil {
		browserError(w, 400, "Invalid JSON request.")
		return false
	}
	return true
}
func (b *Browser) rate(w http.ResponseWriter, r *http.Request, bucket string, limit int, window time.Duration) bool {
	allowed, err := b.server.store.Allow(r.Context(), "browser:"+bucket, limit, window)
	if err != nil {
		browserError(w, 503, "Authentication state unavailable.")
		return false
	}
	if !allowed {
		w.Header().Set("Retry-After", "60")
		browserError(w, 429, "Too many requests. Please try again later.")
		return false
	}
	return true
}
func (b *Browser) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		browserHeaders(w)
		// No proxy header can relax the canonical issuer or relying party.
		if !b.server.config.MatchRequest(r) {
			browserError(w, 400, "Invalid host.")
			return
		}
		if r.URL.Path == "/oauth/assets/app.js" && r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
			_, _ = io.WriteString(w, browserJS)
			return
		}
		if r.URL.Path == "/oauth/assets/app.css" && r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "text/css; charset=utf-8")
			_, _ = io.WriteString(w, browserCSS)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			w.Header().Set("Allow", "GET, POST")
			browserError(w, 405, "Method not allowed.")
			return
		}
		if r.Method == http.MethodPost && !browserOrigin(r, b.server.config.Issuer) {
			browserError(w, 403, "Invalid browser origin.")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		if !b.rate(w, r, "requests", 180, time.Minute) {
			return
		}
		switch {
		case r.URL.Path == "/oauth/login" && r.Method == http.MethodGet:
			b.loginPage(w, r)
		case r.URL.Path == "/oauth/consent":
			b.consent(w, r)
		case r.URL.Path == "/oauth/grants":
			b.grants(w, r)
		case r.URL.Path == "/oauth/logout" && r.Method == http.MethodPost:
			b.logout(w, r)
		case r.URL.Path == "/oauth/passkeys/register/begin" && r.Method == http.MethodPost:
			b.passkeyBegin(w, r, true)
		case r.URL.Path == "/oauth/passkeys/register/finish" && r.Method == http.MethodPost:
			b.passkeyFinish(w, r, true)
		case r.URL.Path == "/oauth/passkeys/login/begin" && r.Method == http.MethodPost:
			b.passkeyBegin(w, r, false)
		case r.URL.Path == "/oauth/passkeys/login/finish" && r.Method == http.MethodPost:
			b.passkeyFinish(w, r, false)
		default:
			browserError(w, 404, "Not found.")
		}
	})
}
func (b *Browser) render(w http.ResponseWriter, page browserPage) {
	browserHeaders(w)
	// These pages contain same-origin HTML forms for consent, revocation, or
	// logout. Referrer-Policy: no-referrer makes some browsers submit those
	// forms with Origin: null, which correctly fails our strict origin check.
	// Same-origin retains referrer privacy across sites without interfering
	// with the exact Origin and CSRF validation on every browser POST.
	w.Header().Set("Referrer-Policy", "same-origin")
	// Browsers may apply form-action to the entire POST redirect chain. Permit
	// only the already-validated client's exact HTTPS callback origin here.
	if page.Page == "consent" {
		callback, err := url.Parse(page.Request.RedirectURI)
		if err != nil || !validRedirect(page.Request.RedirectURI) {
			browserError(w, 500, "Invalid consent destination.")
			return
		}
		policy := w.Header().Get("Content-Security-Policy")
		w.Header().Set("Content-Security-Policy", strings.Replace(policy, "form-action 'self'", "form-action 'self' "+callback.Scheme+"://"+callback.Host, 1))
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	var body bytes.Buffer
	if err := browserTemplate.Execute(&body, page); err != nil {
		browserError(w, 500, "Unable to render page.")
		return
	}
	_, _ = w.Write(body.Bytes())
}
func (b *Browser) loginPage(w http.ResponseWriter, r *http.Request) {
	_, session, err := b.ensureSession(w, r)
	if err != nil {
		browserError(w, 503, "Authentication state unavailable.")
		return
	}
	_, owner, err := b.loadOwner(r)
	if err != nil && !errors.Is(err, ErrNotFound) {
		browserError(w, 503, "Authentication state unavailable.")
		return
	}
	b.render(w, browserPage{Title: "Owner sign-in", Page: "login", CSRF: session.CSRF, Bootstrap: owner == nil, Authenticated: session.Subject != ""})
}
func (b *Browser) BeginAuthorization(w http.ResponseWriter, r *http.Request, request AuthorizationRequest) {
	browserHeaders(w)
	token, session, err := b.ensureSession(w, r)
	if err != nil {
		browserError(w, 503, "Authentication state unavailable.")
		return
	}
	id, err := browserRandom()
	if err != nil {
		browserError(w, 503, "Unable to begin authorization.")
		return
	}
	pending := pendingConsent{Version: 1, ExpiresUnix: b.server.now().Add(consentLifetime).Unix(), Request: request}
	raw, _ := json.Marshal(pending)
	if err = b.server.store.Put(r.Context(), "consent", id, raw, consentLifetime); err != nil {
		browserError(w, 503, "Authentication state unavailable.")
		return
	}
	session.PendingID = id
	if err = b.updateSession(r.Context(), token, session); err != nil {
		browserError(w, 503, "Authentication state changed. Start again.")
		return
	}
	if session.Subject == "" {
		http.Redirect(w, r, "/oauth/login", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/oauth/consent?request="+id, http.StatusSeeOther)
}
func (b *Browser) pending(r *http.Request, id string, session *browserSession, consume bool) (*pendingConsent, error) {
	if !validBrowserToken(id) || !equalSecret(id, session.PendingID) {
		return nil, ErrNotFound
	}
	var raw []byte
	var err error
	if consume {
		raw, err = b.server.store.Consume(r.Context(), "consent", id)
	} else {
		raw, err = b.server.store.Get(r.Context(), "consent", id)
	}
	if err != nil {
		return nil, err
	}
	var pending pendingConsent
	if json.Unmarshal(raw, &pending) != nil || pending.Version != 1 || b.server.now().Unix() >= pending.ExpiresUnix {
		return nil, ErrNotFound
	}
	return &pending, nil
}
func (b *Browser) consent(w http.ResponseWriter, r *http.Request) {
	token, session, ok := b.requireSession(w, r, true)
	if !ok {
		return
	}
	id := r.URL.Query().Get("request")
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			browserError(w, 400, "Invalid consent form.")
			return
		}
		if !b.csrf(w, r, session, r.PostForm.Get("csrf")) {
			return
		}
		if len(r.PostForm["csrf"]) != 1 || len(r.PostForm["request"]) != 1 || len(r.PostForm["decision"]) != 1 {
			browserError(w, 400, "Invalid consent form.")
			return
		}
		id = r.PostForm.Get("request")
	}
	pending, err := b.pending(r, id, session, false)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			browserError(w, 400, "Consent request expired or superseded. Start again from your client.")
		} else {
			browserError(w, 503, "Authentication state unavailable.")
		}
		return
	}
	if r.Method == http.MethodGet {
		b.render(w, browserPage{Title: "Approve mailbox access", Page: "consent", CSRF: session.CSRF, Mailbox: b.server.config.OwnerMailbox, RequestID: id, Request: pending.Request, Authenticated: true})
		return
	}
	decision := r.PostForm.Get("decision")
	if decision != "approve" && decision != "deny" {
		browserError(w, 400, "Choose approve or deny.")
		return
	}
	approved := r.PostForm["scope"]
	if decision == "approve" {
		approved, err = canonicalScopes(approved)
		if err != nil || !scopeSubset(approved, pending.Request.Scopes) {
			browserError(w, 400, "Select only requested scopes, including mail.read, or deny access.")
			return
		}
	}
	// Consume before issuing a grant/code. Repeated submissions cannot issue twice.
	pending, err = b.pending(r, id, session, true)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			browserError(w, 400, "Consent request already used or expired.")
		} else {
			browserError(w, 503, "Authentication state unavailable.")
		}
		return
	}
	session.PendingID = ""
	if err = b.updateSession(r.Context(), token, session); err != nil {
		browserError(w, 503, "Authentication state changed. Start again.")
		return
	}
	next := b.server.DenyAuthorization(pending.Request)
	if decision == "approve" {
		next, err = b.server.ApproveAuthorization(r.Context(), pending.Request, session.Subject, approved)
		if err != nil {
			browserError(w, 503, "Unable to approve authorization. Start again.")
			return
		}
	}
	http.Redirect(w, r, next, http.StatusSeeOther)
}
func (b *Browser) grants(w http.ResponseWriter, r *http.Request) {
	_, session, ok := b.requireSession(w, r, true)
	if !ok {
		return
	}
	if r.Method == http.MethodPost {
		if r.ParseForm() != nil || len(r.PostForm["csrf"]) != 1 || len(r.PostForm["grant"]) != 1 {
			browserError(w, 400, "Invalid revocation request.")
			return
		}
		if !b.csrf(w, r, session, r.PostForm.Get("csrf")) {
			return
		}
		grant, err := b.server.store.GetGrant(r.Context(), r.PostForm.Get("grant"))
		if err != nil || grant.Subject != session.Subject {
			if err != nil && !errors.Is(err, ErrNotFound) {
				browserError(w, 503, "Authentication state unavailable.")
			} else {
				browserError(w, 400, "Grant not found.")
			}
			return
		}
		if err = b.server.store.RevokeGrant(r.Context(), grant.ID); err != nil {
			browserError(w, 503, "Unable to revoke grant.")
			return
		}
		http.Redirect(w, r, "/oauth/grants", http.StatusSeeOther)
		return
	}
	grants, err := b.server.store.ListGrants(r.Context())
	if err != nil {
		browserError(w, 503, "Unable to load grants.")
		return
	}
	_, owner, err := b.loadOwner(r)
	if err != nil {
		browserError(w, 503, "Authentication state unavailable.")
		return
	}
	visible := make([]Grant, 0, len(grants))
	for _, grant := range grants {
		if grant.Subject == session.Subject {
			visible = append(visible, grant)
		}
	}
	sort.Slice(visible, func(i, j int) bool { return visible[i].CreatedUnix > visible[j].CreatedUnix })
	b.render(w, browserPage{Title: "Connected clients", Page: "grants", CSRF: session.CSRF, Mailbox: b.server.config.OwnerMailbox, Grants: visible, Credentials: len(owner.Credentials), Authenticated: true})
}
func (b *Browser) logout(w http.ResponseWriter, r *http.Request) {
	token, session, ok := b.requireSession(w, r, false)
	if !ok {
		return
	}
	if r.ParseForm() != nil || len(r.PostForm["csrf"]) != 1 {
		browserError(w, 400, "Invalid logout request.")
		return
	}
	if !b.csrf(w, r, session, r.PostForm.Get("csrf")) {
		return
	}
	if err := b.server.store.Delete(r.Context(), "session", token); err != nil {
		browserError(w, 503, "Unable to end session. Try again.")
		return
	}
	clearBrowserCookie(w)
	http.Redirect(w, r, "/oauth/login", http.StatusSeeOther)
}

var browserTemplate = template.Must(template.New("browser").Funcs(template.FuncMap{"join": strings.Join}).Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="csrf-token" content="{{.CSRF}}">
  <title>{{.Title}} · Angelos</title>
  <link rel="stylesheet" href="/oauth/assets/app.css">
  <script src="/oauth/assets/app.js" defer></script>
</head>
<body>
  <div class="app-shell">
    <header class="site-header">
      <a href="/oauth/grants" class="wordmark" aria-label="Angelos home">
        <span class="brand-mark" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="5" width="18" height="14" rx="3"/><path d="m4 8 8 6 8-6"/></svg></span>
        <span>angelos</span>
      </a>
      <span class="site-label"><span class="status-dot" aria-hidden="true"></span> Private access</span>
    </header>

    <main class="auth-card auth-card--{{.Page}}">
      <div class="card-content">
        <div class="eyebrow"><span class="eyebrow-line" aria-hidden="true"></span>{{if eq .Page "login"}}Identity verification{{else if eq .Page "consent"}}Connection request{{else}}Security settings{{end}}</div>
        <h1>{{.Title}}</h1>
        <p class="page-subtitle">{{if eq .Page "login"}}{{if .Bootstrap}}Set up your passkey to protect access to your mailbox.{{else}}Sign in securely to manage your connected applications.{{end}}{{else if eq .Page "consent"}}Review which permissions this application can use before connecting.{{else}}Control the applications and passkeys trusted with your inbox.{{end}}</p>
        <p id="status" class="action-status" role="status" aria-live="polite"></p>

        {{if eq .Page "login"}}
          <div class="passkey-emblem" aria-hidden="true">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2 20 6v5c0 5-3.4 8.5-8 11-4.6-2.5-8-6-8-11V6z"/><path d="m9 12 2 2 4-4"/></svg>
          </div>
          {{if .Bootstrap}}
            <p class="body-copy">Only the mailbox owner can enroll. Enter the one-time enrollment token supplied privately by your operator.</p>
            <label for="bootstrap" class="field-label">One-time enrollment token</label>
            <input id="bootstrap" class="text-input" type="password" autocomplete="off" spellcheck="false" placeholder="Paste enrollment token">
            <button type="button" class="button button-primary button-wide" data-passkey="register">Enroll owner passkey <span class="button-arrow" aria-hidden="true">↗</span></button>
          {{else}}
            <p class="body-copy">Verify with your owner passkey to continue. Your mailbox credentials stay on the server.</p>
            <button type="button" class="button button-primary button-wide" data-passkey="login">Sign in with a passkey <span class="button-arrow" aria-hidden="true">↗</span></button>
          {{end}}
          <p class="supporting-note">Secured by passkeys and scoped authorization.</p>
        {{end}}

        {{if eq .Page "consent"}}
          <section class="request-card" aria-label="Application requesting access">
            <span class="client-icon" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M7 17 17 7M9 7h8v8"/></svg></span>
            <div class="client-info"><span class="overline">Application</span><strong class="client-name">{{.Request.ClientName}}</strong><span class="client-summary">requests access to <strong>{{.Mailbox}}</strong></span></div>
            <span class="client-badge">OAuth</span>
          </section>
          <details class="connection-details">
            <summary>Connection details <span class="chevron" aria-hidden="true"></span></summary>
            <dl class="connection-list"><dt>Client identity</dt><dd>{{.Request.ClientID}}</dd><dt>Return address</dt><dd>{{.Request.RedirectURI}}</dd><dt>Resource</dt><dd>{{.Request.Resource}}</dd></dl>
          </details>
          <form action="/oauth/consent" method="post" class="consent-form">
            <input type="hidden" name="csrf" value="{{.CSRF}}">
            <input type="hidden" name="request" value="{{.RequestID}}">
            <fieldset class="permissions"><legend>Choose the permissions you approve</legend>
              {{range .Request.Scopes}}
                <label class="permission-row"><input type="checkbox" name="scope" value="{{.}}" checked><span class="permission-copy"><strong>{{.}}</strong><span>{{if eq . "mail.read"}}Read mailbox contents, search, and view folders. Required to connect.{{end}}{{if eq . "mail.write"}}Change flags and folders, move or trash messages, save drafts, and permanently delete messages when the server deletion gate is enabled.{{end}}{{if eq . "mail.send"}}Prepare and send email as this mailbox when sending is enabled. Sending may disclose content and cannot be undone.{{end}}</span></span></label>
              {{end}}
            </fieldset>
            <p class="fine-print">Only selected permissions are granted. Write, send, and delete actions also depend on the operator's server gates and your client's action confirmations. Access can renew for up to 30 days; revoke it at any time.</p>
            <div class="approval-actions"><button class="button button-primary" name="decision" value="approve">Approve selected permissions <span class="button-arrow" aria-hidden="true">↗</span></button><button class="button button-outline" name="decision" value="deny">Deny</button></div>
          </form>
        {{end}}

        {{if eq .Page "grants"}}
          <p class="mailbox-label">Connected mailbox <strong>{{.Mailbox}}</strong></p>
          <div class="section-heading"><h2>Connected applications</h2><span class="section-context">Manage access</span></div>
          <div class="grants-list">{{range .Grants}}
            <section class="grant-card">
              <div class="grant-overview"><span class="client-icon client-icon-small" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M7 17 17 7M9 7h8v8"/></svg></span><div class="grant-info"><h3>{{.ClientName}}</h3><p>{{.ClientID}}</p></div><span class="connected-pill">Connected</span></div>
              <p class="granted-scopes">Permissions: <strong>{{join .Scopes ", "}}</strong></p>
              <form action="/oauth/grants" method="post" class="revoke-form"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="grant" value="{{.ID}}"><button class="button button-danger-outline">Revoke this access</button></form>
            </section>
          {{else}}
            <div class="empty-state"><span class="empty-state-icon" aria-hidden="true">◎</span><strong>No connected clients.</strong><span>Applications you approve will appear here.</span></div>
          {{end}}</div>
          <section class="authenticator-card">
            <div class="section-heading"><div><h2>Owner authenticators</h2><p class="section-description">Keep a second authenticator for recovery. Adding one requires a passkey sign-in within the last five minutes.</p></div><span class="count-badge">{{.Credentials}} enrolled</span></div>
            <div class="authenticator-actions"><button type="button" class="button button-outline" data-passkey="register">Add another passkey</button><a class="quiet-link" href="/oauth/login">Sign in again <span aria-hidden="true">↗</span></a></div>
          </section>
        {{end}}
      </div>
      {{if .Authenticated}}
        <footer class="session-footer">{{if eq .Page "grants"}}<span class="session-note"><span class="status-dot" aria-hidden="true"></span> Owner session active</span>{{else}}<a href="/oauth/grants" class="quiet-link">Review connected clients</a>{{end}}<form action="/oauth/logout" method="post"><input type="hidden" name="csrf" value="{{.CSRF}}"><button class="sign-out-button">Sign out <span aria-hidden="true">↗</span></button></form></footer>
      {{end}}
    </main>

    <footer class="site-footer"><span>Angelos <span class="footer-dot">·</span> Your inbox, under your control</span><span>Private by design</span></footer>
  </div>
</body>
</html>`))

const browserJS = `'use strict';
const statusNode = document.getElementById('status');
const csrf = document.querySelector('meta[name="csrf-token"]').content;
function decode(value) { const s = value.replace(/-/g, '+').replace(/_/g, '/'); const raw = atob(s + '='.repeat((4 - s.length % 4) % 4)); return Uint8Array.from(raw, c => c.charCodeAt(0)); }
function encode(value) { const raw = new Uint8Array(value); let s = ''; for (const byte of raw) s += String.fromCharCode(byte); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
async function post(path, body) { const response = await fetch(path, { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf }, body: JSON.stringify(body) }); if (!response.ok) throw new Error((await response.text()).trim() || 'Request failed.'); return response.json(); }
function optionsJSON(options, register) { const p = options.publicKey; p.challenge = decode(p.challenge); if (register) p.user.id = decode(p.user.id); const key = register ? 'excludeCredentials' : 'allowCredentials'; if (p[key]) p[key] = p[key].map(c => ({...c, id: decode(c.id)})); return {publicKey: p}; }
function credentialJSON(c) { const response = {clientDataJSON: encode(c.response.clientDataJSON)}; for (const key of ['attestationObject', 'authenticatorData', 'signature', 'userHandle']) { if (c.response[key] != null) response[key] = encode(c.response[key]); } if (c.response.getTransports) response.transports = c.response.getTransports(); return { id: c.id, rawId: encode(c.rawId), type: c.type, authenticatorAttachment: c.authenticatorAttachment || undefined, clientExtensionResults: c.getClientExtensionResults(), response }; }
for (const button of document.querySelectorAll('[data-passkey]')) button.addEventListener('click', async () => { button.disabled = true; statusNode.textContent = 'Waiting for your passkey…'; try { if (!window.PublicKeyCredential || !navigator.credentials) throw new Error('Use a browser with passkey support.'); const mode = button.dataset.passkey; const input = document.getElementById('bootstrap'); const body = input ? {bootstrap_token: input.value.trim()} : {}; if (input) input.value = ''; const start = await post('/oauth/passkeys/' + mode + '/begin', body); const options = optionsJSON(start.options, mode === 'register'); const credential = mode === 'register' ? await navigator.credentials.create(options) : await navigator.credentials.get(options); if (!credential) throw new Error('Passkey request cancelled.'); const result = await post('/oauth/passkeys/' + mode + '/finish', {ceremony: start.ceremony, credential: credentialJSON(credential)}); if (!result.next || !result.next.startsWith('/oauth/')) throw new Error('Invalid continuation.'); window.location.assign(result.next); } catch (error) { statusNode.textContent = error.name === 'NotAllowedError' ? 'Passkey request cancelled or timed out. You can try again.' : error.message; button.disabled = false; } });
`

// Self-hosted appearance: no remote font, CSS framework, runtime dependency,
// tracking request, or extra authentication entrypoint. Use locally installed
// modern UI fonts and let users' preferred light/dark appearance lead.
const browserCSS = `:root {
  color-scheme: dark;
  --page: #09090b;
  --panel: #111113;
  --panel-soft: #171719;
  --panel-hover: #202023;
  --border: #2c2c30;
  --border-strong: #414147;
  --text: #f4f4f5;
  --muted: #a1a1aa;
  --quiet: #7f7f89;
  --primary: #f4f4f5;
  --primary-text: #18181b;
  --focus: #b2b2bb;
  --success: #5bce91;
  --success-bg: rgba(91,206,145,.08);
  --danger: #ff9999;
  --danger-bg: rgba(255,153,153,.07);
  --glow: rgba(137,137,152,.055);
  --shadow: 0 22px 75px rgba(0,0,0,.24), 0 4px 14px rgba(0,0,0,.15);
  --font: "Avenir Next", "SF Pro Display", -apple-system, BlinkMacSystemFont, "Segoe UI Variable", "Segoe UI", sans-serif;
  --mono: "SFMono-Regular", "SF Mono", "Cascadia Code", "Segoe UI Mono", monospace;
  font-family: var(--font);
  font-synthesis: none;
  -webkit-font-smoothing: antialiased;
  text-rendering: optimizeLegibility;
}

@media (prefers-color-scheme: light) {
  :root {
    color-scheme: light;
    --page: #fafafa;
    --panel: #fff;
    --panel-soft: #fafafa;
    --panel-hover: #f4f4f5;
    --border: #e4e4e7;
    --border-strong: #d4d4d8;
    --text: #18181b;
    --muted: #63636c;
    --quiet: #7e7e89;
    --primary: #18181b;
    --primary-text: #fafafa;
    --focus: #52525b;
    --success: #15803d;
    --success-bg: #f0fdf4;
    --danger: #b91c1c;
    --danger-bg: #fef2f2;
    --glow: rgba(89,89,110,.045);
    --shadow: 0 24px 64px rgba(24,24,27,.045), 0 3px 15px rgba(24,24,27,.035);
  }
}

* { box-sizing: border-box; }
html { min-width: 320px; }
body {
  margin: 0;
  min-height: 100vh;
  background: var(--page);
  color: var(--text);
  font-size: 14px;
  line-height: 1.5;
}
button, input { font: inherit; }
button { cursor: pointer; }
a { color: inherit; text-decoration: none; }
a:hover { color: var(--text); }
:focus-visible { outline: 2px solid var(--focus); outline-offset: 3px; }
::selection { background: var(--border-strong); color: var(--text); }

.app-shell {
  display: flex;
  flex-direction: column;
  min-height: 100vh;
  min-height: 100svh;
  padding: 0 24px;
  background: radial-gradient(ellipse 64% 38% at 50% 0%, var(--glow), transparent 85%);
}
.site-header, .site-footer {
  width: 100%;
  max-width: 760px;
  margin: 0 auto;
  display: flex;
  align-items: center;
  justify-content: space-between;
}
.site-header { min-height: 108px; padding: 26px 0; }
.wordmark { display: inline-flex; align-items: center; gap: 11px; font-size: 18px; font-weight: 750; letter-spacing: -.06em; }
.wordmark:hover { opacity: .83; }
.brand-mark {
  display: grid;
  place-items: center;
  width: 35px;
  height: 35px;
  border: 1px solid var(--border);
  border-radius: 11px;
  background: var(--panel);
}
.brand-mark svg { width: 20px; height: 20px; }
.site-label { display: flex; align-items: center; gap: 8px; color: var(--muted); font-size: 12px; font-weight: 550; }
.status-dot { width: 6px; height: 6px; border-radius: 50%; background: var(--success); box-shadow: 0 0 0 3px var(--success-bg); }

.auth-card {
  width: 100%;
  max-width: 490px;
  margin: auto;
  border: 1px solid var(--border);
  border-radius: 17px;
  background: var(--panel);
  box-shadow: var(--shadow);
  animation: enter .36s cubic-bezier(.2,.75,.3,1) both;
}
.auth-card--consent { max-width: 670px; }
.auth-card--grants { max-width: 710px; }
.card-content { padding: 42px 42px 37px; }
.eyebrow { display: flex; align-items: center; gap: 9px; color: var(--muted); font-size: 11px; font-weight: 700; letter-spacing: .12em; text-transform: uppercase; }
.eyebrow-line { width: 15px; height: 1px; background: var(--quiet); }
h1 { margin: 17px 0 9px; font-size: clamp(26px, 4.5vw, 31px); line-height: 1.18; font-weight: 700; letter-spacing: -.045em; }
h2, h3, p { margin-top: 0; }
.page-subtitle { margin: 0; max-width: 51ch; color: var(--muted); font-size: 14px; line-height: 1.65; }
.action-status {
  padding: 12px 14px;
  margin: 21px 0 0;
  border: 1px solid var(--border);
  border-radius: 9px;
  background: var(--panel-soft);
  color: var(--text);
  font-size: 13px;
}
.action-status:empty { display: none; }

.passkey-emblem {
  width: 57px;
  height: 57px;
  display: grid;
  place-items: center;
  margin: 34px 0 21px;
  border: 1px solid var(--border);
  border-radius: 17px;
  background: var(--panel-soft);
  color: var(--text);
}
.passkey-emblem svg { width: 27px; height: 27px; }
.body-copy { margin: 0 0 23px; color: var(--muted); font-size: 13px; line-height: 1.7; }
.field-label { display: block; margin-bottom: 9px; font-size: 13px; font-weight: 650; }
.text-input {
  display: block;
  width: 100%;
  height: 44px;
  padding: 0 13px;
  margin: 0 0 13px;
  background: var(--panel-soft);
  color: var(--text);
  border: 1px solid var(--border-strong);
  border-radius: 9px;
  outline: none;
  transition: border-color .16s ease, box-shadow .16s ease;
}
.text-input::placeholder { color: var(--quiet); }
.text-input:focus { border-color: var(--focus); box-shadow: 0 0 0 3px var(--glow); }

.button {
  min-height: 43px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 10px;
  padding: 11px 17px;
  border: 1px solid transparent;
  border-radius: 9px;
  font-size: 13px;
  font-weight: 680;
  letter-spacing: -.008em;
  line-height: 1.4;
  transition: opacity .16s ease, background .16s ease, border-color .16s ease, transform .16s ease;
}
.button:disabled { cursor: wait; opacity: .55; }
.button:not(:disabled):active { transform: translateY(1px); }
.button-primary { color: var(--primary-text); background: var(--primary); }
.button-primary:hover:not(:disabled) { opacity: .88; }
.button-wide { width: 100%; }
.button-arrow { margin-left: auto; font-size: 17px; line-height: 1; font-weight: 400; }
.button-outline { color: var(--text); background: var(--panel); border-color: var(--border-strong); }
.button-outline:hover:not(:disabled) { background: var(--panel-hover); }
.button-danger-outline { color: var(--danger); border-color: var(--border); background: transparent; }
.button-danger-outline:hover:not(:disabled) { background: var(--danger-bg); border-color: var(--danger); }
.supporting-note { margin: 20px 0 0; color: var(--quiet); text-align: center; font-size: 11px; }

.request-card {
  display: flex;
  align-items: center;
  gap: 14px;
  padding: 19px;
  margin: 28px 0 0;
  border: 1px solid var(--border);
  border-radius: 12px;
  background: var(--panel-soft);
}
.client-icon { width: 41px; height: 41px; display: grid; place-items: center; flex-shrink: 0; border-radius: 12px; background: var(--panel); border: 1px solid var(--border); }
.client-icon svg { width: 19px; height: 19px; }
.client-info { display: flex; flex: 1; min-width: 0; flex-direction: column; gap: 2px; }
.overline { color: var(--quiet); text-transform: uppercase; letter-spacing: .09em; font-size: 10px; font-weight: 650; }
.client-name { font-size: 15px; font-weight: 700; overflow-wrap: anywhere; }
.client-summary { color: var(--muted); font-size: 12px; overflow-wrap: anywhere; }
.client-summary strong { color: var(--text); font-weight: 600; }
.client-badge { flex: 0 0 auto; padding: 5px 9px; border: 1px solid var(--border); border-radius: 7px; color: var(--muted); font-family: var(--mono); font-size: 10px; }
.connection-details { border-bottom: 1px solid var(--border); }
.connection-details summary { display: flex; align-items: center; justify-content: space-between; padding: 16px 1px; color: var(--muted); cursor: pointer; font-size: 12px; font-weight: 600; list-style: none; }
.connection-details summary::-webkit-details-marker { display: none; }
.connection-details summary:hover { color: var(--text); }
.chevron { display: inline-block; width: 7px; height: 7px; margin-right: 4px; border-right: 1.5px solid currentColor; border-bottom: 1.5px solid currentColor; transform: rotate(45deg); transition: transform .16s ease; }
.connection-details[open] .chevron { transform: rotate(225deg); }
.connection-list { margin: 0 0 18px; padding: 14px; border: 1px solid var(--border); background: var(--panel-soft); border-radius: 9px; }
.connection-list dt { margin: 13px 0 5px; color: var(--quiet); font-size: 11px; font-weight: 650; }
.connection-list dt:first-child { margin-top: 0; }
.connection-list dd { margin: 0; font-family: var(--mono); font-size: 11px; color: var(--text); overflow-wrap: anywhere; line-height: 1.7; }
.permissions { margin: 27px 0 0; padding: 0; border: 0; min-width: 0; }
.permissions legend { padding: 0; margin-bottom: 13px; font-size: 13px; font-weight: 700; letter-spacing: -.015em; }
.permission-row {
  display: flex;
  align-items: flex-start;
  gap: 13px;
  margin: 0 0 9px;
  padding: 14px 15px;
  border: 1px solid var(--border);
  border-radius: 10px;
  cursor: pointer;
  transition: background .16s ease, border-color .16s ease;
}
.permission-row:hover { background: var(--panel-soft); border-color: var(--border-strong); }
.permission-row input[type=checkbox] {
  flex-shrink: 0;
  appearance: none;
  display: grid;
  place-items: center;
  width: 17px;
  height: 17px;
  margin: 2px 0 0;
  border: 1px solid var(--border-strong);
  border-radius: 5px;
  background: var(--panel);
  cursor: pointer;
}
.permission-row input[type=checkbox]::before { content: ''; width: 9px; height: 5px; border-left: 2px solid var(--primary-text); border-bottom: 2px solid var(--primary-text); transform: translateY(-1px) rotate(-45deg) scale(0); transition: transform .12s ease; }
.permission-row input[type=checkbox]:checked { background: var(--primary); border-color: var(--primary); }
.permission-row input[type=checkbox]:checked::before { transform: translateY(-1px) rotate(-45deg) scale(1); }
.permission-copy { display: flex; flex-direction: column; gap: 4px; min-width: 0; }
.permission-copy strong { font-family: var(--mono); font-size: 12px; font-weight: 650; }
.permission-copy > span { color: var(--muted); font-size: 12px; line-height: 1.58; }
.fine-print { color: var(--quiet); font-size: 11px; line-height: 1.7; margin: 15px 0 22px; }
.approval-actions { display: flex; gap: 10px; align-items: center; }
.approval-actions .button-primary { flex: 1; }
.approval-actions .button-outline { min-width: 108px; }

.mailbox-label { display: inline-flex; gap: 8px; align-items: center; flex-wrap: wrap; margin: 25px 0 24px; color: var(--muted); font-size: 12px; }
.mailbox-label strong { padding: 5px 9px; border-radius: 6px; background: var(--panel-soft); border: 1px solid var(--border); color: var(--text); font-family: var(--mono); font-size: 11px; font-weight: 550; overflow-wrap: anywhere; }
.section-heading { display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; margin: 0 0 12px; }
.section-heading h2 { margin: 0; font-size: 14px; font-weight: 700; letter-spacing: -.02em; }
.section-context { color: var(--quiet); font-size: 11px; }
.grants-list { display: flex; flex-direction: column; gap: 11px; }
.grant-card, .authenticator-card { border: 1px solid var(--border); border-radius: 11px; background: var(--panel-soft); padding: 18px; }
.grant-overview { display: flex; align-items: flex-start; gap: 11px; }
.client-icon-small { width: 35px; height: 35px; border-radius: 10px; }
.client-icon-small svg { width: 16px; height: 16px; }
.grant-info { min-width: 0; flex: 1; }
.grant-info h3 { margin: 0 0 3px; font-size: 13px; font-weight: 700; }
.grant-info p { margin: 0; color: var(--quiet); font-family: var(--mono); font-size: 11px; overflow-wrap: anywhere; }
.connected-pill { flex-shrink: 0; color: var(--success); background: var(--success-bg); font-size: 10px; padding: 5px 8px; border-radius: 5px; }
.granted-scopes { margin: 17px 0 13px; color: var(--muted); font-size: 12px; }
.granted-scopes strong { color: var(--text); font-family: var(--mono); font-weight: 550; }
.revoke-form { margin: 0; }
.revoke-form .button { min-height: 35px; padding: 7px 11px; font-size: 11px; }
.empty-state { display: flex; flex-direction: column; align-items: center; padding: 27px 12px; gap: 5px; border: 1px dashed var(--border-strong); border-radius: 11px; color: var(--muted); text-align: center; font-size: 12px; }
.empty-state strong { color: var(--text); font-size: 13px; }
.empty-state-icon { color: var(--quiet); font-size: 28px; margin-bottom: 4px; }
.authenticator-card { margin-top: 24px; }
.authenticator-card .section-heading { margin-bottom: 20px; }
.section-description { max-width: 48ch; margin: 7px 0 0; color: var(--muted); font-size: 12px; line-height: 1.65; }
.count-badge { flex: 0 0 auto; color: var(--muted); border: 1px solid var(--border); background: var(--panel); padding: 5px 8px; font-size: 10px; border-radius: 6px; }
.authenticator-actions { display: flex; align-items: center; gap: 15px; flex-wrap: wrap; }
.quiet-link { color: var(--muted); font-size: 12px; font-weight: 550; }
.quiet-link:hover { color: var(--text); }

.session-footer { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 17px 42px; border-top: 1px solid var(--border); }
.session-footer form { margin: 0; }
.session-note { display: inline-flex; align-items: center; gap: 8px; color: var(--muted); font-size: 12px; }
.sign-out-button { padding: 3px 0; border: 0; background: transparent; color: var(--quiet); font-size: 12px; font-weight: 550; }
.sign-out-button:hover { color: var(--text); }
.site-footer { gap: 16px; padding: 29px 0 32px; color: var(--quiet); font-size: 11px; }
.footer-dot { padding: 0 3px; }

@keyframes enter { from { opacity: 0; transform: translateY(7px); } to { opacity: 1; transform: translateY(0); } }
@media (prefers-reduced-motion: reduce) { *, *::before, *::after { animation: none !important; transition: none !important; } }

@media (max-width: 600px) {
  .app-shell { padding: 0 15px; }
  .site-header { min-height: 88px; }
  .auth-card { border-radius: 14px; }
  .card-content { padding: 30px 24px; }
  .session-footer { padding: 16px 24px; }
  .site-footer { padding: 20px 3px 26px; }
  .request-card { padding: 14px; gap: 10px; }
  .client-badge { display: none; }
  .permission-row { padding: 13px 12px; }
  .approval-actions { flex-direction: column; align-items: stretch; }
  .approval-actions .button { width: 100%; }
  .site-footer > span:last-child { display: none; }
}
@media (max-width: 375px) {
  .site-label { font-size: 10px; }
  .card-content { padding: 28px 19px; }
  .session-footer { padding: 16px 19px; }
  .count-badge { white-space: nowrap; }
}`

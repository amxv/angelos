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
	passkeys, err := newPasskeys()
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
		if !canonicalRequest(r) {
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
		if r.Method == http.MethodPost && !browserOrigin(r) {
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
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="csrf-token" content="{{.CSRF}}"><title>{{.Title}} · Angelos</title><link rel="stylesheet" href="/oauth/assets/app.css"><script src="/oauth/assets/app.js" defer></script></head>
<body><main><header><a href="/oauth/grants">Angelos</a><p>Private mailbox access</p></header><h1>{{.Title}}</h1><p id="status" role="status" aria-live="polite"></p>
{{if eq .Page "login"}}{{if .Bootstrap}}<p>Only the mailbox owner can enroll. Use the one-time enrollment token supplied privately by your operator.</p><label for="bootstrap">One-time enrollment token</label><input id="bootstrap" type="password" autocomplete="off" spellcheck="false"><button type="button" data-passkey="register">Enroll owner passkey</button>{{else}}<p>Verify with your owner passkey to continue.</p><button type="button" data-passkey="login">Sign in with a passkey</button>{{end}}{{end}}
{{if eq .Page "consent"}}<p><strong>{{.Request.ClientName}}</strong> requests access to <strong>{{.Mailbox}}</strong>.</p><dl><dt>Client identity</dt><dd>{{.Request.ClientID}}</dd><dt>Return address</dt><dd>{{.Request.RedirectURI}}</dd><dt>Resource</dt><dd>{{.Request.Resource}}</dd></dl><form action="/oauth/consent" method="post"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="request" value="{{.RequestID}}"><fieldset><legend>Choose the permissions you approve</legend>{{range .Request.Scopes}}<label><input type="checkbox" name="scope" value="{{.}}" checked> <strong>{{.}}</strong>{{if eq . "mail.read"}}: Read mailbox contents, search, and view folders. Required to connect.{{end}}{{if eq . "mail.write"}}: Change flags and folders, move or trash messages, save drafts, and permanently delete messages when the server deletion gate is enabled.{{end}}{{if eq . "mail.send"}}: Prepare and send email as this mailbox when sending is enabled. Sending may disclose content and cannot be undone.{{end}}</label>{{end}}</fieldset><p>Only selected permissions are granted. Write, send, and delete actions also depend on the operator's server gates and your client obtaining the required action confirmations. Renewed access can continue for up to 30 days; revoke it at any time.</p><div class="actions"><button name="decision" value="approve">Approve selected permissions</button><button name="decision" value="deny" class="secondary">Deny</button></div></form>{{end}}
{{if eq .Page "grants"}}<p>Mailbox: <strong>{{.Mailbox}}</strong></p>{{range .Grants}}<section><h2>{{.ClientName}}</h2><p>{{.ClientID}}</p><p>Permissions: {{join .Scopes ", "}}</p><form action="/oauth/grants" method="post"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="grant" value="{{.ID}}"><button class="secondary">Revoke this access</button></form></section>{{else}}<p>No connected clients.</p>{{end}}<section><h2>Owner authenticators</h2><p>{{.Credentials}} enrolled. Keep a second authenticator for recovery. Adding one requires a passkey sign-in within the last five minutes.</p><button type="button" data-passkey="register">Add another passkey</button><p><a href="/oauth/login">Sign in again</a></p></section>{{end}}
{{if .Authenticated}}<footer><a href="/oauth/grants">Review connected clients</a><form action="/oauth/logout" method="post"><input type="hidden" name="csrf" value="{{.CSRF}}"><button class="secondary">Sign out</button></form></footer>{{end}}</main></body></html>`))

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
const browserCSS = `:root{color-scheme:light dark;font-family:system-ui,sans-serif;background:#11151b;color:#edf2f7}body{margin:0}main{max-width:720px;margin:3rem auto;padding:0 1.4rem 3rem}header{border-bottom:1px solid #44505f;margin-bottom:2rem}header>a{font-weight:750;font-size:1.7rem}a{color:#9dccff}h1{font-size:1.8rem}h2{font-size:1.2rem}p,dd,label{line-height:1.6}dd{margin:.3rem 0 1rem;overflow-wrap:anywhere}dt{font-weight:700}section,fieldset{border:1px solid #44505f;border-radius:.6rem;padding:1.2rem;margin:1.5rem 0}label{display:block;margin:1rem 0}input[type=password]{display:block;box-sizing:border-box;width:100%;padding:.8rem;margin-bottom:1.2rem}button{padding:.8rem 1rem;border:0;border-radius:.4rem;background:#b8dbff;color:#102136;font-weight:650;cursor:pointer}button:disabled{opacity:.6;cursor:wait}.secondary{background:#354454;color:#fff}.actions{display:flex;flex-wrap:wrap;gap:.8rem}footer{border-top:1px solid #44505f;margin-top:2rem;padding-top:1.5rem;display:flex;align-items:center;justify-content:space-between}#status{color:#ffd390}input[type=checkbox]{width:1.1rem;height:1.1rem;margin-right:.4rem}`

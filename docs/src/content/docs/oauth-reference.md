---
title: OAuth reference
description: Identity boundaries, token requirements, retention, revocation, and recovery for operators.
summary: The protocol and operational details behind passkey sign-in and external issuers.
order: 43
category: Reference
---

For the complete installation and assistant connection, use [Connect Your Assistant](/docs/quickstart). This page is technical reference, not another setup path.

## Configured origin and owner

In built-in mode, `MCP_OAUTH_ISSUER` is your exact public HTTPS origin, with a lowercase hostname and no path, port, query, fragment, or trailing slash. `MCP_RESOURCE_URL` must equal that origin plus `/mcp`; `MCP_OAUTH_JWKS_URL` must equal that origin plus `/oauth/jwks.json`. The passkey relying-party ID is the origin's hostname. Request and forwarded headers cannot redefine these values. Alternate and preview hostnames are not additional trusted origins.

`MCP_ALLOWED_SUBJECTS` contains one explicit stable owner subject. It selects the Redis identity namespace. Choose a permanent hostname and owner before enrollment; changing them needs deliberate migration/re-enrollment and new client authorization. Do not reuse a populated identity store with a new origin without a reviewed migration.

The signing key is a stable ES256 P-256 private key (PKCS#8 or EC PEM), with a unique key ID. Built-in OAuth requires Redis even when email mutations are off. All mailbox credentials remain separate from OAuth client tokens. See [all environment variables](/docs/configuration#mcp-access).

## Client validation

Predefined clients have an exact `client_id`, `client_name`, and HTTPS `redirect_uris` array. Each client gets its own entry; adding one must preserve the other approved entries. Token endpoint authentication is `none`, with PKCE S256. Dynamic registration and client secrets are not supported. Claude.ai uses a predefined public client with its exact hosted callback `https://claude.ai/api/mcp/auth_callback`; enter the configured client ID and leave its secret blank. Claude Code’s HTTP loopback redirect is unsupported by this server. The optional ChatGPT metadata mode accepts only `https://chatgpt.com/oauth/client.json` and the exact callback `https://chatgpt.com/connector_platform_oauth_redirect`.

Metadata retrieval is restricted to that public HTTPS identity, without redirects, within five seconds and 32 KiB. Duplicate JSON members are rejected; the document must support `code`, authorization-code and refresh-token grants, and public-client authentication. Its process-local cache lasts at most five minutes, honors shorter cache directives, and fails closed after expiry. Invalid client/redirect requests fail locally, never redirecting to an untrusted destination. Authorization redirects carry the exact `iss` under RFC 9207.

## Owner recovery

Enroll a second independent authenticator during setup and verify it can sign in. Adding a passkey requires recent authentication within five minutes; at most eight passkeys are supported, with no self-service credential-removal screen. Browser sessions have a 30-minute idle limit and 12-hour absolute limit. Logout ends the browser session, not the client's OAuth grant.

If all authenticators are lost, take the API out of service for reviewed offline recovery: verify the owner, invalidate old sessions/grants, and deliberately replace owner credentials and bootstrap state. There is no public reset endpoint. Do not clear Redis to reopen enrollment. Preserve dispatch records; deleting consumed sends destroys duplicate-prevention evidence. Restoring old backups can also restore revoked access, so state loss or rollback is an identity incident.

## Consent, logout, and revocation

Authorization requires owner sign-in and explicit consent identifying the actual client, the connected mailbox, the requested scopes, and their consequences. Every grant requires `mail.read`; `mail.write` and `mail.send` add capabilities, and all existing server gates still apply. A client cannot expand scopes by refreshing an existing grant. New scopes require a new authorization and consent flow. The full setup sets `MCP_OAUTH_INITIAL_SCOPES=mail.read mail.write mail.send` so a new connection requests all three at once. Without this setting the initial challenge defaults to `mail.read`. Initial write/send scopes are only requested when their corresponding server gates are enabled; operation-specific challenges still require their exact scopes. Configuring an initial request never upgrades an existing grant.

Open `/oauth/grants` to review and revoke connected grants. Revocation invalidates the grant for refresh and subsequent authenticated MCP requests, even if an issued access JWT has time remaining. Refresh-token replay also revokes the affected grant. Redis failure denies grant validation rather than allowing cached-token access. This does not cancel a mailbox operation that already passed authentication, undo a completed mail action, or make an ambiguous send safe to retry.

Logout ends the current browser session; revoke the connected grant to withdraw a client's API access. OAuth consent is a permission grant to a client, not approval of any particular outgoing email, deletion, or mailbox modification. The trusted client remains responsible for per-action approval and prepared-message review.

## Protocol and token contract

| Endpoint | Purpose |
| --- | --- |
| `/.well-known/oauth-authorization-server` | RFC 8414 metadata for the configured issuer |
| `/.well-known/oauth-protected-resource` | RFC 9728 resource metadata |
| `/.well-known/oauth-protected-resource/mcp` | Path-specific resource metadata for `/mcp` |
| `/oauth/authorize` | Validated authorization request, owner login, and consent |
| `/oauth/token` | Authorization-code exchange and rotating refresh-token exchange |
| `/oauth/jwks.json` | Active and configured retiring public signing keys |
| `/oauth/login` | Owner enrollment/sign-in page |
| `/oauth/passkeys/register/begin`, `/oauth/passkeys/register/finish` | One-time registration ceremonies |
| `/oauth/passkeys/login/begin`, `/oauth/passkeys/login/finish` | One-time sign-in ceremonies |
| `/oauth/consent` | Owner consent for a pending authorization request |
| `/oauth/grants` | Owner-connected grants and additional passkey enrollment |
| `/oauth/logout` | End the current browser session |

This is OAuth access authorization, not an OpenID Connect provider: there are no OIDC scopes, ID tokens, UserInfo endpoint, or inferred workspace-email-domain enforcement.

Request limits are 8 KiB of OAuth query text and a 16 KiB form-encoded token body. Duplicate parameters are rejected. Redis rate limits allow 60 authorization requests and 120 token requests per minute per client, 180 browser requests per minute for the owner, and tighter passkey begin/finish limits of 20/30 per minute. These fixed limits can require a short wait or a fresh flow after rejection.

The only authorization response type is `code`; grants are `authorization_code` and `refresh_token`. PKCE S256 is required. Both authorization and token requests must carry the exact `resource`, and code exchange must preserve its bound client and redirect. Missing state, unknown clients, redirect substitutions, invalid scopes/resource, weak PKCE, expired/reused codes, and invalid verifiers fail closed.

Authorization codes are unpredictable, stored under hashes, expire after five minutes, and are atomically consumed once. They are bound to owner, client, exact redirect, resource, scopes, and PKCE. A consumed code is deleted rather than retained as a replay tombstone: reuse is rejected, but code reuse cannot be distinguished from an expired/missing code and does not itself revoke an already-issued grant. Refresh tokens are unpredictable, stored under hashes, and rotate atomically. Their grant has a 30-day absolute limit; rotation does not extend that lifetime. Reusing a consumed refresh token revokes the grant rather than issuing another token.

Access tokens are ES256 JWTs with the exact `iss`, `/mcp` audience, fixed owner `sub`, integer `iat` and `exp`, unique `jti`, and a space-separated `scope`. They expire after five minutes and carry a grant binding for Redis-backed revocation. No static API key or mailbox token authenticates an MCP call. Once configuration is valid, unauthenticated `/mcp` requests receive `401` with a `WWW-Authenticate` protected-resource metadata challenge. The six MCP tools retain their operation-specific scopes, annotations, and independent read/create/modify/delete/prepare/send boundaries.

## Redis state and retention

OAuth and mail dispatch share infrastructure, not key ownership. OAuth schema version 1 keys use `angelos:oauth:{<SHA-256(owner subject)>}:v1:*`; prepared mail and receipts retain `angelos:send:*`. The braces are an owner hash tag that keeps multi-key Lua operations in one Redis Cluster slot. Changing the owner subject selects a different OAuth namespace rather than migrating credentials. Never use a wildcard flush, broad cleanup job, or cache-eviction policy that can silently remove security or dispatch state. Choose a durable service and restrict credentials to the API runtime.

OAuth state contains only the owner/passkey data, one-time challenge and bootstrap state, browser sessions, authorization bindings, consent/grants, refresh-token hashes, and revocation state required for the protocol. Raw private signing keys, bootstrap tokens, authorization codes, and refresh tokens are not stored as OAuth records. State is owner-scoped; client/grant bindings are validated at issuance and refresh. Atomic Redis operations enforce challenge/code consumption, bootstrap binding, refresh rotation, and revocation across stateless instances.

- Owner credentials and the bootstrap-consumed marker are persistent.
- WebAuthn challenges and authorization codes last at most five minutes.
- Anonymous browser and pending-consent state last at most ten minutes.
- Authenticated browser sessions are bounded by idle and absolute expiry.
- Grants are usable for at most 30 days. Expired members are pruned from the owner-scoped grants hash during grant reads/lists/creation; the hash also expires 30 days after its latest insertion. This physical container retention is distinct from a grant's access expiry.
- Refresh family and token/replay records expire at the original 30-day grant deadline; rotation does not extend it. Consumed hashes remain as spent tombstones until then so reuse remains detectable.
- Rate-limit counters expire after their configured short window; the store allows at most one hour.
- Prepared message MIME, recipients, and attachments remain for up to 15 minutes. An atomic send claim replaces them with a minimal digest/status/Message-ID receipt retained for seven days.

The v1 state shapes are:

| Record | Stored fields and limits |
| --- | --- |
| `owner`, `bootstrap-disabled` | Versioned owner subject and WebAuthn public credential/authenticator state; persistent disabled marker. Owner record maximum 128 KiB; at most eight credentials. |
| `session:<hash>` | Version, owner subject after login, CSRF value, pending consent ID, creation/last-seen/authentication/absolute-expiry times. Cookie bearer value is not stored. |
| `challenge:<hash>`, `consent:<hash>`, `code:<hash>` | One-time protocol bindings and expiry. Code secret is a hashed key; authorization data binds the client, redirect, resource, scopes, state, and PKCE as appropriate. |
| `grants` | Hash of grant IDs to subject, client ID/name, resource, approved scopes, creation, expiry, and a refresh-family hash; at most 128 active grants. Revocation deletes the grant member. |
| `refresh:<hash>`, `family:<hash>` | Family/grant IDs and hashes, subject/client/resource/scopes, absolute expiry, active/spent/revoked status, and rotation count. One refresh family per grant; at most 10,000 rotations per family. Reaching the cap revokes its grant. |
| `rate:<hash>` | Bounded counter with expiring rate-limit window. |

Generic OAuth JSON records are limited to 32 KiB. Keys hash their secret identifiers; the `v1` namespace and versioned browser records define the current schema. There is no automatic schema migration or operator reset endpoint. Reject malformed state rather than coercing it into a valid session or grant.

Loss of a one-time response requires starting a fresh authorization or login flow; do not reconstruct a consumed code or retry refresh with an already-consumed token. Redis outage or malformed state fails closed. Recovery of OAuth state must not rewrite or delete send claims. Missing or expired dispatch status is not proof that no message was sent. SMTP acceptance is not delivery, and ambiguous outcomes must never be retried automatically.

The application does not add an encrypted-at-rest layer over Redis. Obtain operator approval of that data destination, including its temporary storage of full prepared mail, and review provider access controls, encryption, backups, and retention. Provider logs/backups may outlive application TTLs. See [Safety and permissions](/docs/safety#stored-data).

## Signing-key rotation

Keep the active private key stable across restarts and deployments. `/oauth/jwks.json` publishes only public material, with the configured active `kid` and any retiring keys.

For routine rotation, assign the new key a new ID. First publish its public key in `ANGELOS_OAUTH_VERIFICATION_KEYS_JSON` while retaining the old active signer, and ensure that configuration has reached every serving instance. Then deploy the new active private key and ID together, replacing that extra public-key entry with the old signer's public key. This two-stage overlap matters because first-party verification uses the configured local public keys, rather than fetching a missing key from another instance. Retain the old verification key until no old signer remains and all of its five-minute access tokens have expired. Do not reuse a `kid` for different key material. Remove the old public key only after that overlap window.

A compromised key is an incident, not routine rotation. Disable access, revoke affected grants, replace the signing configuration, and account for any old serving instances before restoring service. Refresh grants do not require the old private key. External-issuer JWKS cache behavior is documented separately in [Authentication](/docs/oauth-reference#signing-key-rotation-and-troubleshooting).

## Migrate from an external issuer

First-party mode is disabled by default. Existing deployments keep their external `MCP_OAUTH_ISSUER`, same-origin JWKS URL, subject allowlist, and verifier behavior until the operator deliberately changes modes. A root issuer on the MCP resource’s own origin requires first-party mode and its online grant checks; switching it off cannot fall back to external verification of that root issuer. External issuers with a nonempty path on the same hostname, such as `/realms/owner`, remain supported. There is no simultaneous trust of both issuers.

Before switching, finish or expire pending preparations and record any unresolved send outcome. New prepared sends are bound to verified issuer/resource/subject; changing any of those identifiers makes old owned preparations and receipts unavailable to the new identity. Preserve the send namespace and its existing retention. Never interpret inaccessible old status as permission to resend.

Prepare durable OAuth state, a stable key, one owner subject, approved client callbacks, and owner enrollment before connecting clients to the new issuer. Revoke old external grants and replace the verifier settings with the configured first-party values. Clients must reconnect and consent to the new issuer. A rollback to external mode can make still-valid external tokens usable again, so coordinate revocation with that issuer rather than assuming a mode switch revoked them.

## External issuer requirements

With `ANGELOS_OAUTH_ENABLED=0`, your external provider owns sign-in, client registration, consent, and refresh. The resource server still enforces the following requirements. There is no static API-key mode or authentication bypass.

### Configure the resource server

Set these environment variables on the API deployment:

| Variable | Meaning |
| --- | --- |
| `MCP_RESOURCE_URL` | Canonical public HTTPS MCP URL, including its path, such as `https://mail-api.example.com/mcp` |
| `MCP_OAUTH_ISSUER` | Exact issuer identifier expected in the token's `iss` claim |
| `MCP_OAUTH_JWKS_URL` | Public HTTPS signing-key endpoint on the issuer's origin |
| `MCP_ALLOWED_SUBJECTS` | Comma-separated allowlist of exact OAuth `sub` identifiers, between 1 and 32 entries |

Use the stable production API URL ending in `/mcp` as the resource identifier. The running service requires that exact path, without a trailing slash. The audience comparison is exact. Changing the identifier requires corresponding issuer/client configuration changes.

URLs must use public DNS names and HTTPS on port 443. Credentials, query strings, fragments, IP literals, and redirects are rejected. The JWKS endpoint must have the same hostname and effective port as the issuer. Providers that host keys on a different origin require an implementation change; do not work around this restriction by disabling verification.

### Issuer prerequisites

Configure your authorization server for an OAuth authorization-code flow with PKCE S256 and a client that your assistant can use. A predefined client is sufficient; the issuer can instead support dynamic client registration or Client ID Metadata Documents.

The issuer must publish discovery metadata and issue access tokens for the exact resource identified by `MCP_RESOURCE_URL`. Angelos accepts compact signed JWT access tokens with:

- `RS256` with a 2048–8192-bit RSA key, or `ES256` with a P-256 key
- A matching `iss` and an `aud` string or array containing the exact resource URL
- A future integer Unix `exp`; optional `nbf` and `iat` must not be in the future
- An exact allowlisted `sub`
- A space-separated `scope` claim containing `mail.read`

Opaque tokens, ID tokens without the required resource audience/scopes, symmetric JWTs, and other algorithms are unsupported. An email address is not substituted for the OAuth subject.

Additional operations require `mail.write` or `mail.send` as well as their server-side feature switches. Granting a scope does not enable a disabled mutation or dispatch. The read-only `mail_query` action `send_status` also requires `mail.send`, but remains available with a configured store when sending is disabled.

### Preparation ownership

Version 0.4 binds each new prepared-send record to an opaque hash of the verified issuer, resource URL, and subject. No bearer token is stored in that binding. Status inspection and claiming a new owned preparation require the same identity; a refreshed token or changed scopes retain the binding. Multiple allowlisted subjects still share the configured mailbox, but cannot enumerate or claim one another's new send preparations.

Changing issuer, resource, or subject intentionally prevents access to older owned preparations in that namespace. Older unowned records are not retroactively assigned to a user: read-only status returns `unavailable`, while the previous exact-ID/digest send behavior remains until those records expire. Missing status must not be interpreted as permission to resend.

### Signing-key rotation and troubleshooting

In external-issuer mode, signing keys are fetched on demand and cached for five minutes. An unknown key ID can trigger a refresh, limited to once a minute. Fetches have a five-second timeout and bounded response size; redirects are not followed.

In external-issuer mode, validation is local after keys are cached. There is no external token-introspection request, token-revocation lookup, or replay ledger. Use short-lived access tokens. For this external-key cache, removing a signing key can take up to the cache lifetime to affect an instance; changing the subject allowlist requires restarting or redeploying with the new configuration. First-party mode uses its configured local public keys and additionally checks Redis-backed grant validity on authenticated requests; see its [revocation and rotation rules](/docs/oauth-reference).

Check exact issuer, audience, subject, scope, and time claims when authorization fails. Check that the published JWKS includes the signing key and is reachable at its configured public address. Do not log access tokens, mailbox passwords, or complete private mail while debugging.


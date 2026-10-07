---
title: First-party OAuth
description: Operate the opt-in single-owner passkey issuer, Redis state, and scoped client grants.
summary: Owner enrollment, exact ChatGPT callbacks, key rotation, recovery, and rollout boundaries.
order: 24
category: Run Angelos
---

Angelos can host its authorization server in the same Go API as `/mcp`. This mode is explicitly opt-in, uses one mailbox owner, and requires a durable Redis REST service. It does not use Auth0 or PostgreSQL. Existing external-issuer deployments remain supported with first-party mode disabled; see [Authentication](/docs/authentication).

The implementation is not production setup. Enabling an environment variable does not provision Redis, install signing secrets, enroll a passkey, verify a ChatGPT connection, or enable mailbox writes. Live acceptance requires the separate operator steps below. Never put production mailbox or OAuth secrets in the documentation project, tests, source control, or client tool arguments.

## Fixed issuer and resource

These values are intentionally fixed in first-party mode:

| Identifier | Exact value |
| --- | --- |
| Issuer and browser origin | `https://api.angelos.ashray.xyz` |
| MCP resource/audience | `https://api.angelos.ashray.xyz/mcp` |
| Passkey relying-party ID | `api.angelos.ashray.xyz` |
| JWKS | `https://api.angelos.ashray.xyz/oauth/jwks.json` |

No trailing slash is added to the issuer or resource. Preview deployments, alternate hostnames, Host headers, and forwarded headers cannot silently redefine these identifiers. A localhost browser is not an owner-enrollment origin. Use external-issuer mode for a different resource hostname; changing the first-party trust boundary requires a reviewed implementation change.

## Configuration

Set `ANGELOS_OAUTH_ENABLED=1` only in the intended API runtime after completing setup. Preserve these resource-verifier settings:

```dotenv
MCP_RESOURCE_URL=https://api.angelos.ashray.xyz/mcp
MCP_OAUTH_ISSUER=https://api.angelos.ashray.xyz
MCP_OAUTH_JWKS_URL=https://api.angelos.ashray.xyz/oauth/jwks.json
MCP_ALLOWED_SUBJECTS=
```

Supply exactly one stable owner subject in `MCP_ALLOWED_SUBJECTS`; the blank example is deliberately incomplete. It is an identifier, not an email-address lookup. First-party mode requires an explicit bare email address in `MAIL_FROM`; it identifies the connected mailbox shown during consent. Mailbox credentials remain independently required for mail access.

Configure these additional values through the API project's trusted secret manager:

- `ANGELOS_REDIS_REST_URL` and `ANGELOS_REDIS_REST_TOKEN`: the existing HTTPS Redis REST transport, with atomic `SET`/`EVAL` support. A raw Redis TCP address is not supported. The same service can hold OAuth and dispatch state under isolated namespaces.
- `ANGELOS_OAUTH_SIGNING_KEY_PEM`: a durable P-256 ES256 private key, using PKCS#8 or EC PEM. Generate and retain it through an operator-controlled secure process. Never generate a fresh key on each cold start or deployment.
- `ANGELOS_OAUTH_SIGNING_KEY_ID`: a stable, unique `kid` for that key.
- `ANGELOS_OAUTH_VERIFICATION_KEYS_JSON`: optional JSON object mapping up to four retiring key IDs to PKIX public-key PEM strings. Do not put retiring private keys here.
- `ANGELOS_OAUTH_CLIENTS_JSON`: the predefined clients described below, or enable the restricted ChatGPT metadata mode.
- `ANGELOS_OAUTH_BOOTSTRAP_TOKEN_HASH`: the lowercase SHA-256 hex digest of the one-time enrollment token. Remove it after binding the first passkey.

`ANGELOS_OAUTH_CHATGPT_CIMD_ENABLED=1` separately opts into the pinned metadata-document client. Unset or `0` disables it. All three mail gates remain separate and default off: `MAIL_ENABLE_WRITES`, `MAIL_ENABLE_SEND`, and `MAIL_ENABLE_DELETE`.

The cookie name and security flags, browser origin, relying-party ID, and session lifetimes are fixed in code. There is no extra cookie signing secret, configurable insecure-cookie mode, or development authentication bypass. The complete environment checklist is in [Configuration](/docs/configuration#mcp-access) and `.env.example`.

## Configure the ChatGPT client

First verify the connection UI's actual client and redirect metadata against the current [OpenAI authentication guide](https://developers.openai.com/plugins/build/auth) and [MCP setup guide](https://developers.openai.com/api/docs/guides/custom-mcp-server). Callback URLs from older connections or tutorials are not interchangeable.

### Predefined client fallback

Set `ANGELOS_OAUTH_CLIENTS_JSON` to an array of objects with `client_id`, a human-readable `client_name`, and an array of `redirect_uris`. Use an owner-chosen client ID and copy each exact HTTPS callback from the intended connection UI. The server matches the entire URI, with no wildcard or prefix matching.

These are public clients: the token endpoint authentication method is `none`. No client secret substitutes for owner sign-in, consent, PKCE, or exact redirect validation. Dynamic client registration is not implemented. Unsupported client authentication methods are not advertised.

### Restricted ChatGPT metadata document

When explicitly enabled, CIMD accepts only the client ID `https://chatgpt.com/oauth/client.json`. Retrieval is pinned to that HTTPS identity; arbitrary client metadata URLs are rejected. The response must be JSON no larger than 32 KiB, arrive within five seconds without an HTTP redirect, and resolve through public addresses on `chatgpt.com:443`. Duplicate JSON members are rejected. A process-local cache lasts at most five minutes, honors shorter cache directives, and does not reuse expired metadata after a fetch failure. Known-client rate limits apply before fetching; failed fetches also have a five-second backoff. It validates the fetched client identity/name and requires the exact callback `https://chatgpt.com/connector_platform_oauth_redirect` to appear in that metadata. Every returned redirect must be that pinned callback. The metadata must support `code`, both implemented grant types, and the public-client `none` method. It does not turn an unrecognized callback into an allowed callback, fetch arbitrary logos/JWKS URLs, or implement private-key JWT client authentication.

The authorization server uses RFC 9207 issuer identification: authorization redirects, including redirectable errors, carry the exact `iss`. Invalid client or redirect requests fail locally instead of redirecting to an untrusted destination. This allows the stable callback mode when supported by the actual ChatGPT connection. It is not evidence that a live connection has been tested.

## Owner enrollment and recovery

There is one owner and no public registration or password login.

1. Before first enrollment, create a cryptographically random bootstrap token containing 32–64 random bytes, encoded as unpadded base64url. Hash the exact encoded token string, not the decoded random bytes, and store only its lowercase SHA-256 hex digest in `ANGELOS_OAUTH_BOOTSTRAP_TOKEN_HASH`. Keep the raw token in an operator-controlled secret store until enrollment.
2. Open `https://api.angelos.ashray.xyz/oauth/login` in the owner's browser. Enter the bootstrap token only in the enrollment form. Never put it in a URL, chat, log, screenshot, or MCP argument.
3. Complete the browser passkey ceremony with user verification. The relying-party ID and exact HTTPS origin are checked. Redis atomically binds the owner and marks bootstrap consumed, so a retained old hash cannot register another owner while that state is preserved.
4. Remove the bootstrap hash from runtime configuration and redeploy intentionally. Its removal does not remove the durable consumed marker.
5. While signed in, open `/oauth/grants` and enroll a second independent authenticator. Adding another passkey requires recent authentication within five minutes. Verify that each authenticator can sign in before relying on either for recovery. Up to eight passkeys can be enrolled; there is currently no self-service credential-removal screen.

Browser sessions use the `__Host-angelos` cookie with `Secure`, `HttpOnly`, `SameSite=Lax`, and `Path=/`. Anonymous sessions expire after ten minutes. Authenticated sessions have a 30-minute idle limit and a 12-hour absolute limit; login rotates the session. WebAuthn ceremonies expire after five minutes, and pending consent requests after ten minutes. Browser mutation requests require both the exact Origin and a matching CSRF value. Browser pages reject framing, restrict scripts/styles/connections to the same origin, and limit request bodies to 64 KiB. The consent page's form-action policy also permits the exact validated callback origin so the approved POST-to-303 redirect can complete in the browser. Logout deletes the current server-side session and clears its cookie.

Use the second enrolled authenticator if the first is lost. There is no email/password reset, public recovery account, or automatic lost-all-passkeys recovery endpoint. If every authenticator is lost, take the API out of service and perform a reviewed offline recovery that verifies the owner, invalidates old sessions/grants, and deliberately replaces owner credentials and bootstrap state. Do not simply clear Redis or delete the owner namespace to reopen enrollment. Preserve dispatch records throughout recovery; deleting consumed sends destroys duplicate-prevention evidence.

Redis backups and their access controls are part of the identity system: the owner credentials and consumed bootstrap marker are durable state, not disposable cache. A restored snapshot can restore revoked access. Treat state loss or rollback as an incident and keep the API closed until the recovery state is reviewed.

## Consent, logout, and revocation

Authorization requires owner sign-in and explicit consent identifying the actual client, the connected mailbox, the requested scopes, and their consequences. Every grant requires `mail.read`; `mail.write` and `mail.send` add capabilities, and all existing server gates still apply. A client cannot expand scopes by refreshing an existing grant. New scopes require a new authorization and consent flow.

Open `/oauth/grants` to review and revoke connected grants. Revocation invalidates the grant for refresh and subsequent authenticated MCP requests, even if an issued access JWT has time remaining. Refresh-token replay also revokes the affected grant. Redis failure denies grant validation rather than allowing cached-token access. This does not cancel a mailbox operation that already passed authentication, undo a completed mail action, or make an ambiguous send safe to retry.

Logout ends the current browser session; revoke the connected grant to withdraw a client's API access. OAuth consent is a permission grant to a client, not approval of any particular outgoing email, deletion, or mailbox modification. The trusted client remains responsible for per-action approval and prepared-message review.

## Protocol and token contract

| Endpoint | Purpose |
| --- | --- |
| `/.well-known/oauth-authorization-server` | RFC 8414 metadata for the fixed issuer |
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

A compromised key is an incident, not routine rotation. Disable access, revoke affected grants, replace the signing configuration, and account for any old serving instances before restoring service. Refresh grants do not require the old private key. External-issuer JWKS cache behavior is documented separately in [Authentication](/docs/authentication#signing-key-rotation-and-troubleshooting).

## Migrate from an external issuer

First-party mode is disabled by default. Existing deployments keep their external `MCP_OAUTH_ISSUER`, same-origin JWKS URL, subject allowlist, and verifier behavior until the operator deliberately changes modes. The canonical first-party issuer is rejected while first-party mode is off, so disabling the mode cannot bypass its grant-revocation checks. There is no simultaneous trust of both issuers.

Before switching, finish or expire pending preparations and record any unresolved send outcome. New prepared sends are bound to verified issuer/resource/subject; changing any of those identifiers makes old owned preparations and receipts unavailable to the new identity. Preserve the send namespace and its existing retention. Never interpret inaccessible old status as permission to resend.

Prepare durable OAuth state, a stable key, one owner subject, approved client callbacks, and owner enrollment before connecting clients to the new issuer. Revoke old external grants and replace the verifier settings with the fixed first-party values. Clients must reconnect and consent to the new issuer. A rollback to external mode can make still-valid external tokens usable again, so coordinate revocation with that issuer rather than assuming a mode switch revoked them.

## Rollout and live acceptance

Keep first-party OAuth off until the operator approves production setup. This implementation has not provisioned production OAuth state, generated live signing/bootstrap secrets, enrolled the owner, or proven a live ChatGPT connection. Existing mailbox credentials may already have been provisioned separately; do not copy or inspect them to validate this change.

After implementation checks pass and setup is approved:

1. Confirm the intended API project and canonical HTTPS hostname. Keep the docs project and previews separate from all production secrets.
2. Provision the approved durable Redis destination and stable signing configuration; leave all mail gates at `0`.
3. Configure the exact owner and verified client metadata. Enroll two authenticators and remove the bootstrap hash.
4. Verify both protected-resource documents, authorization-server metadata, public JWKS, and the unauthenticated `401` challenge. Check that metadata URLs and `iss` match the fixed issuer exactly.
5. Complete a real ChatGPT authorization-code/PKCE flow with `resource` in both authorization and token requests, then initialize MCP and discover all six tools. Verify token renewal, grant revocation, logout, and rejection of wrong client, audience, scope, and redirect.
6. Only with permission for the intended mailbox, perform a bounded read-only capabilities/folder/search/read check. Confirm that a previously unread message remains unread.
7. Enable writes, sending, or targeted deletion only as separate deliberate choices after read-only validation, following [Safety and permissions](/docs/safety).

Synthetic tests can verify protocol and concurrency behavior without contacting a live mailbox. They do not establish owner passkey enrollment, real ChatGPT compatibility, production Redis availability, mailbox credential validity, or delivery. Record the exact tested commit and distinguish local/CI checks from live acceptance.

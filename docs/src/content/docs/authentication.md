---
title: Authentication
description: Connect Angelos to an existing OAuth issuer and restrict access to the mailbox owner.
summary: OAuth setup, token requirements, and ChatGPT connection prerequisites.
order: 30
category: Guides
---

# Authentication

For MCP clients, Angelos is an OAuth resource server. It verifies access tokens issued by an existing authorization server. It does not provide sign-in pages, issue MCP tokens, register OAuth clients, or store MCP-client refresh tokens.

Mailbox authentication is a separate system: the Gmail preset uses an owner-provisioned Google refresh token on the server to obtain IMAP/SMTP access tokens. That Google grant cannot authenticate an MCP call or replace this issuer configuration. See [Gmail and Google Workspace](/docs/gmail-workspace) for its broader scope and setup restrictions.

Every MCP request, including initialization and tool discovery, requires an access token. There is no anonymous mode, static API-key mode, or development authentication bypass.

## Configure the resource server

Set these environment variables on the API deployment:

| Variable | Meaning |
| --- | --- |
| `MCP_RESOURCE_URL` | Canonical public HTTPS MCP URL, including its path, such as `https://mail-api.example.com/mcp` |
| `MCP_OAUTH_ISSUER` | Exact issuer identifier expected in the token's `iss` claim |
| `MCP_OAUTH_JWKS_URL` | Public HTTPS signing-key endpoint on the issuer's origin |
| `MCP_ALLOWED_SUBJECTS` | Comma-separated allowlist of exact OAuth `sub` identifiers, between 1 and 32 entries |

Use the stable production API URL ending in `/mcp` as the resource identifier. The running service requires that exact path, without a trailing slash. The audience comparison is exact. Changing the identifier requires corresponding issuer/client configuration changes.

URLs must use public DNS names and HTTPS on port 443. Credentials, query strings, fragments, IP literals, and redirects are rejected. The JWKS endpoint must have the same hostname and effective port as the issuer. Providers that host keys on a different origin require an implementation change; do not work around this restriction by disabling verification.

## Issuer prerequisites

Configure your authorization server for an OAuth authorization-code flow with PKCE S256 and a client that ChatGPT can use. A predefined client is sufficient; the issuer can instead support dynamic client registration or Client ID Metadata Documents.

The issuer must publish discovery metadata and issue access tokens for the exact resource identified by `MCP_RESOURCE_URL`. Angelos accepts compact signed JWT access tokens with:

- `RS256` with a 2048–8192-bit RSA key, or `ES256` with a P-256 key
- A matching `iss` and an `aud` string or array containing the exact resource URL
- A future integer Unix `exp`; optional `nbf` and `iat` must not be in the future
- An exact allowlisted `sub`
- A space-separated `scope` claim containing `mail.read`

Opaque tokens, ID tokens without the required resource audience/scopes, symmetric JWTs, and other algorithms are unsupported. An email address is not substituted for the OAuth subject.

Additional operations require `mail.write` or `mail.send` as well as their server-side feature switches. Granting a scope does not enable a disabled mutation or dispatch. The read-only `mail_query` action `send_status` also requires `mail.send`, but remains available with a configured store when sending is disabled.

## Preparation ownership

Version 0.4 binds each new prepared-send record to an opaque hash of the verified issuer, resource URL, and subject. No bearer token is stored in that binding. Status inspection and claiming a new owned preparation require the same identity; a refreshed token or changed scopes retain the binding. Multiple allowlisted subjects still share the configured mailbox, but cannot enumerate or claim one another's new send preparations.

Changing issuer, resource, or subject intentionally prevents access to older owned preparations in that namespace. Older unowned records are not retroactively assigned to a user: read-only status returns `unavailable`, while the previous exact-ID/digest send behavior remains until those records expire. Missing status must not be interpreted as permission to resend.

## Connect ChatGPT

1. Create a custom MCP connection using the deployed `/mcp` endpoint and OAuth authentication.
2. If using a predefined OAuth client, supply that client's details in the connection setup.
3. Copy the exact redirect URI shown by ChatGPT into the issuer's allowlist. Current ChatGPT connections can use callback-specific URLs; do not guess or copy an old tutorial's callback.
4. Sign in as an allowlisted subject and authorize the relevant scopes.
5. Refresh the connection's tools after changing the server's exposed tool set.

The public `/.well-known/oauth-protected-resource` endpoint advertises the configured resource, issuer, and mail scopes. Unauthenticated requests receive `401` with a `WWW-Authenticate` discovery challenge. A valid token missing the base read scope receives `403`.

See the current [OpenAI MCP setup guide](https://developers.openai.com/api/docs/guides/custom-mcp-server), [OpenAI authentication guide](https://developers.openai.com/plugins/build/auth), and [MCP authorization specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) for issuer/client setup.

## Signing-key rotation and troubleshooting

Signing keys are fetched on demand and cached for five minutes. An unknown key ID can trigger a refresh, limited to once a minute. Fetches have a five-second timeout and bounded response size; redirects are not followed.

Validation is local after keys are cached. There is no token-introspection request, token-revocation lookup, or replay ledger. Use short-lived access tokens. Removing a signing key can take up to the cache lifetime to affect an instance; changing the subject allowlist requires restarting or redeploying with the new configuration.

Check exact issuer, audience, subject, scope, and time claims when authorization fails. Check that the published JWKS includes the signing key and is reachable at its configured public address. Do not log access tokens, mailbox passwords, or complete private mail while debugging.

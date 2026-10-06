---
title: Authentication
description: Connect Angelos to an existing OAuth issuer and restrict access to the mailbox owner.
summary: OAuth setup, token requirements, and ChatGPT connection prerequisites.
order: 30
category: Guides
---

# Authentication

Angelos is an OAuth resource server. It verifies access tokens issued by an existing authorization server. It does not provide sign-in pages, issue tokens, register OAuth clients, or store refresh tokens.

Every MCP request, including initialization and tool discovery, requires an access token. There is no anonymous mode, static API-key mode, or development authentication bypass.

## Configure the resource server

Set these environment variables on the API deployment:

| Variable | Meaning |
| --- | --- |
| `MCP_RESOURCE_URL` | Canonical public HTTPS MCP URL, including its path, such as `https://mail-api.example.com/mcp` |
| `MCP_OAUTH_ISSUER` | Exact issuer identifier expected in the token's `iss` claim |
| `MCP_OAUTH_JWKS_URL` | Public HTTPS signing-key endpoint on the issuer's origin |
| `MCP_ALLOWED_SUBJECTS` | Comma-separated allowlist of exact OAuth `sub` identifiers, between 1 and 32 entries |

Use the stable production API URL as the resource identifier. The audience comparison is exact, including paths and trailing slashes. Changing the identifier requires corresponding issuer/client configuration changes.

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

Additional operations require `mail.write` or `mail.send` as well as their server-side feature switches. Granting a scope does not enable a disabled operation.

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

Check exact issuer, audience, subject, scope, and time claims when authorization fails. Check that the published JWKS includes the signing key and is reachable at its configured public address. Do not log access tokens, mailbox passwords, or complete private mail while debugging.

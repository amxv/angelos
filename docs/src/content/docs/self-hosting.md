---
title: Self-host Angelos
description: Bring one existing mailbox online, verify read-only access, and enable additional capabilities deliberately.
summary: A step-by-step operator setup with separate mailbox and MCP authentication.
order: 20
category: Run Angelos
---

Already have an Angelos endpoint from your operator? Start with [Connect your inbox](/docs/quickstart). This guide is for the person running the server.

One Angelos deployment connects one existing mailbox to trusted MCP clients. You supply the mailbox, an OAuth issuer, and an HTTPS API host. Angelos does not create mail accounts, provide a hosted signup flow, or set up an authorization server for you. The source repository is currently private; you need access to its checkout before following these steps.

## Before you start

Have these ready:

- **Source access and Go 1.27.1.** The checked-in `go.mod` declares Go `1.26.0` and requests toolchain `go1.27.1`; CI uses `1.27.1`. Use that toolchain for this checkout. Bun is only needed to work on the separate docs site.
- **An existing mailbox with IMAP and SMTP access.** Its credentials are configured on the server, never passed through an MCP tool or an agent conversation.
- **An existing trusted OAuth authorization server.** It must support the client sign-in flow and issue the signed JWT access tokens described in [Set up OAuth access](/docs/authentication). Angelos verifies tokens; it does not issue them.
- **A public HTTPS API hostname**, such as `https://mail-api.example.com`, with `/mcp` as its endpoint. The resource identifier, issuer, and issuer signing-key URL must meet the public-HTTPS requirements. A localhost URL cannot be the configured resource identifier.
- **A host that can reach your mail provider and issuer.** Mail connections use verified TLS; private-address endpoints and arbitrary tool-supplied hosts are not supported.

A Redis REST store is optional until you enable message preparation or sending. Start without it and leave all write/send/delete gates off.

## 1. Choose the mailbox connection

Choose one provider configuration:

- **Spacemail:** the default preset. Configure your full mailbox address and primary mailbox password. It uses `mail.spacemail.com` on IMAP port 993 and SMTP port 465 with implicit TLS.
- **Gmail or Google Workspace:** use `MAIL_PROVIDER=gmail`. The default is server-side Google OAuth/XOAUTH2 with owner-provisioned client credentials and an offline refresh token. Complete the [Gmail setup](/docs/gmail-workspace) first. Ordinary Google account passwords are unsupported; the explicit app-password alternative depends on account/admin eligibility.
- **Another password-based IMAP/SMTP provider:** use `MAIL_PROVIDER=custom` and its documented TLS endpoints. See [Configuration reference](/docs/configuration#other-providers). Other providers' OAuth flows are not implemented.

For Gmail, the Google grant uses the broad `https://mail.google.com/` IMAP/SMTP scope even if Angelos is read-only. Personal/internal use, Workspace administrator rules, consent, and public-app verification restrictions still apply. Installing Angelos does not complete any Google consent or grant setup.

**There are two independent logins:** the mailbox credentials let the server connect to the provider; MCP OAuth lets your client connect to Angelos. A Google mailbox token or mailbox password cannot replace the MCP access token.

## 2. Prepare MCP OAuth access

Follow [Set up OAuth access](/docs/authentication) with your issuer administrator before trying to connect a client:

1. Choose the stable API resource URL, ending exactly in `/mcp`, with no trailing slash.
2. Configure the issuer to issue JWT access tokens whose audience contains that exact URL. Start with `mail.read`.
3. Allowlist the intended user's exact OAuth `sub` in `MCP_ALLOWED_SUBJECTS`. An email address is not a substitute unless it is actually the issuer's subject identifier.
4. Configure a compatible OAuth client and authorization-code flow with PKCE S256. When connecting ChatGPT, use the exact redirect URI it shows, rather than a guessed callback URL.
5. Set the exact issuer and its public signing-key URL. The JWKS URL must be on the issuer's origin; supported signature algorithms are RS256 and ES256 with the documented key constraints.

These are issuer-side setup steps, not commands Angelos runs. There is no static API-key mode or local authentication bypass. Adding another allowed subject grants access to this same mailbox, rather than provisioning a separate account.

## 3. Configure the server environment

Use `.env.example` as a checklist and [Configuration reference](/docs/configuration) for every setting. Provision secrets with your host's secret manager or trusted runtime environment loader. The Go process does **not** load a `.env` file automatically. Never commit a populated environment file or paste credentials into tool arguments.

For a read-only Spacemail deployment, the required values have this shape. All addresses, URLs, subjects, and secret values below are placeholders to replace with your own configured values:

```dotenv
MAIL_PROVIDER=spacemail
MAIL_USERNAME=mailbox@example.com
MAIL_PASSWORD=REPLACE_WITH_MAILBOX_SECRET
MAIL_FROM=mailbox@example.com

MCP_RESOURCE_URL=https://mail-api.example.com/mcp
MCP_OAUTH_ISSUER=https://auth.example.com/
MCP_OAUTH_JWKS_URL=https://auth.example.com/.well-known/jwks.json
MCP_ALLOWED_SUBJECTS=REPLACE_WITH_EXACT_OAUTH_SUBJECT

MAIL_ENABLE_WRITES=0
MAIL_ENABLE_SEND=0
MAIL_ENABLE_DELETE=0
```

For Gmail, replace the mailbox section with the [Google OAuth configuration](/docs/gmail-workspace#server-configuration), including all three matching Google values, and remove `MAIL_PASSWORD`. Keep the independent MCP settings and all three disabled gates.

Set `MAIL_FROM` to a provider-authorized sender. Optional `MAIL_ALIASES` helps exclude your own addresses from derived replies; it does not grant permission to send as those addresses.

## 4. Check the checkout and start locally

From the repository root, run the fixture-based checks before using real mail:

```bash
go version
go mod download
go test -race -cover ./...
go vet ./...
go build ./...
```

The automated tests use synthetic data, not a live mailbox. Redis integration tests require a separate loopback fixture and otherwise skip; see [Run the tests](/docs/testing). Passing these checks does not validate your provider credentials or OAuth tenant.

Once the required environment is injected into your process, start the API:

```bash
go run .
```

By default it listens over HTTP on port 8080, on all interfaces. Keep the local port behind your host's access controls; production access needs HTTPS termination. From a second local terminal:

```bash
curl -sS http://127.0.0.1:8080/healthz
curl -i http://127.0.0.1:8080/.well-known/oauth-protected-resource
curl -i http://127.0.0.1:8080/mcp
```

Check these results:

- `/healthz` reports `service: "angelos"`, the version, and `configured: true`. A false value means required local configuration is incomplete or invalid.
- Protected-resource metadata names your intended **public** resource URL and issuer, even when you fetched it locally.
- An unauthenticated `/mcp` request receives `401` and a `WWW-Authenticate` discovery challenge. A `503` means the API is not configured; it is not a sign-in prompt.

Health checks do not log in to the mailbox, fetch signing keys, or verify Redis. Local development still requires the same valid public resource and issuer configuration. If you use a trusted local MCP test client, it must obtain an issuer-issued token for that configured resource before testing reads. Do not replace the public resource with localhost to bypass authentication. For ChatGPT, continue to the reachable HTTPS deployment below.

## 5. Deploy the API, then verify reads

Follow [Deploy the API](/docs/deployment) for the repository's Vercel setup. The root Go API and `docs/` website are separate projects. Deploying the documentation site does not create an MCP endpoint, and the documentation build must not receive mailbox secrets.

For another hosting environment, run the root Go server behind trusted HTTPS termination, preserve `/mcp` and the protected-resource metadata routes, and configure `PORT` as required. Check that its networking and request limits support the mail operations you plan to use.

Use your actual API URL and an allowlisted identity to complete [Connect your inbox](/docs/quickstart). Keep all mutation gates off for this first pass:

1. Check the deployed health response, resource metadata, and unauthenticated `401` again.
2. Ask for provider capabilities and folder names. Confirm they belong to the intended mailbox.
3. Search a small page, read one exact returned message, and check it in your ordinary mail client. An unread message should remain unread after an Angelos read.
4. Confirm that the reported write, send, and permanent-delete gates are disabled.

These checks verify an actual read connection. They do not verify SMTP submission or prove that all provider-specific mutations will work. Once reads work, the [inbox guide](/docs/inbox-guide) covers everyday use.

## 6. Enable only the operations you need

Read [Safety and permissions](/docs/safety) before changing these gates. A scope and a server switch are both required; tool discovery alone does not mean an operation is enabled.

- **Organize mail or save new drafts:** add `mail.write` alongside `mail.read` and set `MAIL_ENABLE_WRITES=1`. Test with disposable messages and folders. Saving a draft creates a new message; it does not edit an existing draft in place.
- **Prepare and send mail:** configure a compatible durable Redis REST store, add `mail.send` alongside `mail.read`, and set `MAIL_ENABLE_SEND=1`. Its API must support the store's commands, including atomic Lua `EVAL`; a Redis TCP URL alone is insufficient. The store receives complete private prepared messages for up to 15 minutes and minimal dispatch records for seven days.
- **Save a separate Sent copy after sending:** also require `mail.write` and the write gate when requesting `append_sent: true`. Gmail SMTP saves Sent automatically, so Gmail requires `append_sent: false`.
- **Permanently delete a message:** additionally set `MAIL_ENABLE_DELETE=1`, use a provider with safe targeted UID EXPUNGE support, and require exact per-action confirmation in the trusted client. Gmail permanent deletion remains unavailable regardless of the gate.

Restart or redeploy after changing environment settings, then inspect capabilities again. Use the [sending guide](/docs/sending-guide) to review the complete prepared message before dispatch. The trusted MCP client is responsible for human confirmation; the server's digest binds content, not proof of consent.

SMTP acceptance is not delivery. If a send reports `sending`, `unknown`, or an ambiguous failure, inspect its receipt and the provider before deciding what to do. Never create a replacement send automatically just to get a successful result.

## If setup stops working

- **`configured: false` or `/mcp` returns `503`:** compare the injected environment with [Configuration reference](/docs/configuration), including the exact `/mcp` path and provider/auth-mode combination.
- **`401` or `403`:** check the issuer, audience, subject allowlist, token times, and scopes in [OAuth troubleshooting](/docs/authentication#signing-key-rotation-and-troubleshooting). Use a valid access token, not an ID token or mailbox credential.
- **Health succeeds, mailbox reads fail:** check provider login, TLS/network reachability, and account/admin permissions. For Gmail, inspect the owner-managed grant and [reauthorization guidance](/docs/gmail-workspace#reauthorization-and-testing).
- **Reads work, preparation or writes fail:** inspect capabilities, operation scopes, gates, provider support, and store configuration. Enabling one does not enable the others.

Keep credentials, tokens, and private message content out of logs and support requests.

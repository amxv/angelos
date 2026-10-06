---
title: Configuration
description: Configure one mailbox, TLS endpoints, OAuth access, and optional write features.
summary: Environment variables for Spacemail, Gmail/Workspace, and generic mail servers.
order: 40
category: Reference
---

# Configuration

One Angelos deployment connects to one administrator-configured mailbox. Tool arguments cannot choose a mail server, supply a password, or change the sender account.

The process reads environment variables. A `.env` file is not loaded automatically by Go; use your runtime's environment loader or a trusted secret manager. Never commit populated environment files.

## Mail connection

| Variable | Default | Meaning |
| --- | --- | --- |
| `MAIL_PROVIDER` | `spacemail` | `spacemail`, `gmail` (including Workspace), or `custom` |
| `MAIL_AUTH_MODE` | `password`, or `google_oauth2` for Gmail | Gmail accepts `google_oauth2` or explicit eligible `app_password`; other providers use `password` |
| `MAIL_USERNAME` | Required | Mailbox login, normally the full email address |
| `MAIL_PASSWORD` | Required for password modes | Spacemail/custom mailbox password, or eligible Google app password in its explicit mode; unset for Google OAuth |
| `MAIL_FROM` | `MAIL_USERNAME` | Bare sender address accepted by the provider |
| `GOOGLE_CLIENT_ID` | Required for Google OAuth | Matching owner-provisioned Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | Required for Google OAuth | Client secret, excluded from JSON/output |
| `GOOGLE_REFRESH_TOKEN` | Required for Google OAuth | Offline grant for the configured mailbox; excluded from JSON/output |
| `MAIL_ALIASES` | Empty | Comma-separated own addresses excluded from derived reply/reply-all recipients; maximum 50 |
| `IMAP_HOST` | Provider preset | IMAP DNS hostname |
| `IMAP_PORT` | `993` | Implicit-TLS IMAP port |
| `SMTP_HOST` | Provider preset | SMTP DNS hostname |
| `SMTP_PORT` | `465` | SMTP submission port |
| `SMTP_TLS_MODE` | `tls`, or `starttls` for port 587 | Required TLS mode |
| `MAIL_TIMEOUT` | `30s` | Per-operation timeout, between `1s` and `2m` |
| `PORT` | `8080` | HTTP listening port; Vercel supplies this value |

IMAP uses implicit TLS only. SMTP port 465 requires implicit TLS; port 587 requires STARTTLS. Plaintext SMTP and insecure certificate verification are unsupported. Hosts must be DNS names, not URLs or IP literals.

### Spacemail

The preset uses `mail.spacemail.com:993` for IMAP and `mail.spacemail.com:465` for SMTP, both with implicit TLS. Set your complete mailbox address and its primary mailbox password. Angelos does not require or configure a separate app-password flow. Confirm that IMAP/SMTP access is enabled in your provider account.

These are the settings published in [Spacemail's official client setup guide](https://www.spaceship.com/knowledgebase/set-up-spacemail-outlook-imap-pop3/). The preset configures endpoints; it does not create an account or discover credentials.

### Gmail and Google Workspace

Use `MAIL_PROVIDER=gmail` and server-side Google OAuth credentials. The preset pins official Gmail hosts and defaults to XOAUTH2 refresh-token authentication. An explicit app-password alternative is conditional on account/admin eligibility. Read [Gmail and Google Workspace](/docs/gmail-workspace) before setup, including the personal/internal scope, full-mail grant, Sent-copy behavior and permanent-delete restriction.

### Other providers

Use `MAIL_PROVIDER=custom`, then set `IMAP_HOST` and `SMTP_HOST` to the provider's documented endpoints. For STARTTLS submission, set `SMTP_PORT=587` and `SMTP_TLS_MODE=starttls`.

Spacemail and custom providers use the existing username/password flow. Gmail has a dedicated server-side Google OAuth flow. Other providers requiring OAuth need their own implementation; arbitrary token endpoints are not supported. OAuth on the MCP endpoint authenticates the agent client and remains separate from mailbox authentication.

## Reply identities

`MAIL_FROM`, an address-valued `MAIL_USERNAME`, and configured `MAIL_ALIASES` identify the owner when deriving reply recipients. Comparisons are case-insensitive. Add aliases explicitly; Angelos does not guess plus-addresses or provider identities. Aliases do not authorize sending from another address: the visible sender and SMTP envelope remain `MAIL_FROM`. Explicit recipient overrides are preserved and remain part of the full preparation preview.

## MCP access

`MCP_RESOURCE_URL`, `MCP_OAUTH_ISSUER`, `MCP_OAUTH_JWKS_URL`, and `MCP_ALLOWED_SUBJECTS` are required. See [Authentication](/docs/authentication) for their exact constraints and accepted JWT format.

## Optional capabilities

| Variable | Default | Effect |
| --- | --- | --- |
| `MAIL_ENABLE_WRITES` | Disabled | Allows mailbox mutations when the token also has `mail.write` |
| `MAIL_ENABLE_SEND` | Disabled | Allows preparation and sending when the token has `mail.send` and a durable store is configured |
| `MAIL_ENABLE_DELETE` | Disabled | Additional gate for permanent single-message deletion; ordinary writes must also be enabled; unavailable for Gmail/Workspace |
| `ANGELOS_REDIS_REST_URL` | Unset | HTTPS endpoint for preparation/dispatch and read-only receipt lookup |
| `ANGELOS_REDIS_REST_TOKEN` | Unset | Secret used to authenticate durable-store requests |

Set an enable flag to `1` to opt in. A scoped token does not override a disabled gate. The Redis endpoint must support the command API used by the store, including `SET` and atomic Lua `EVAL`; a raw Redis TCP URL is unsupported.

A valid configured store remains available for owner-scoped receipt reads when `MAIL_ENABLE_SEND=0`; this does not enable preparation or SMTP submission. The store contains private prepared mail for up to 15 minutes and minimal dispatch records for seven days. Review [data handling](/docs/safety) before configuring a third-party store.

## Startup status

`GET /healthz` reports the service version and whether required local configuration validated. It does not test the provider login, fetch OAuth signing keys, or prove Redis is reachable. Incomplete mail or OAuth configuration leaves `/mcp` unavailable with `503`. Incomplete store configuration leaves sending disabled while valid mailbox reads can still run.

## Secrets and deployment environments

Keep production credentials in the API project's secret environment settings. Public documentation and the static docs build do not need mail credentials. Do not give preview deployments production mailbox access by default.

Start with read access, verify the correct mailbox and subject, then enable optional capabilities deliberately. Changes made through Angelos affect the same server mailbox used by other IMAP clients.

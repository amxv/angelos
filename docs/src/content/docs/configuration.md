---
title: Configuration reference
description: Configure one mailbox, TLS endpoints, OAuth access, and optional write features.
summary: Environment variables for Spacemail, Gmail/Workspace, iCloud, Yahoo, Microsoft Graph, and generic mail servers.
order: 41
category: Reference
---

For a guided first setup, follow [Connect Your Assistant](/docs/quickstart); use this page to look up individual settings.

One Angelos deployment connects to one administrator-configured mailbox. Tool arguments cannot choose a mail server, supply a password, or change the sender account.

The process reads environment variables. A `.env` file is not loaded automatically by Go; use your runtime's environment loader or a trusted secret manager. Never commit populated environment files.

## Mail connection

| Variable | Default | Meaning |
| --- | --- | --- |
| `MAIL_PROVIDER` | `spacemail` | `spacemail`, `gmail` (including Workspace), `icloud`, `yahoo`, `microsoft`, or `custom` |
| `MAIL_AUTH_MODE` | `password`; Gmail: `google_oauth2`; iCloud/Yahoo: `app_password`; Microsoft: `microsoft_graph` | Gmail accepts `google_oauth2` or eligible `app_password`; iCloud/Yahoo require `app_password`; Spacemail/custom use `password`; Microsoft uses `microsoft_graph` |
| `MAIL_USERNAME` | Required | Mailbox login, normally the full email address |
| `MAIL_PASSWORD` | Required for password modes | Spacemail/custom mailbox password, or a provider-issued app password in `app_password` mode; unset for Google/Microsoft OAuth |
| `MAIL_FROM` | `MAIL_USERNAME` | Bare sender address accepted by the provider |
| `GOOGLE_CLIENT_ID` | Required for Google OAuth | Matching owner-provisioned Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | Required for Google OAuth | Client secret, excluded from JSON/output |
| `GOOGLE_REFRESH_TOKEN` | Required for Google OAuth | Offline grant for the configured mailbox; excluded from JSON/output |
| `MAIL_ALIASES` | Empty | Comma-separated own addresses excluded from derived reply/reply-all recipients; maximum 50 |
| `IMAP_HOST` | Provider preset | IMAP DNS hostname |
| `IMAP_PORT` | `993` | Implicit-TLS IMAP port |
| `SMTP_HOST` | Provider preset | SMTP DNS hostname |
| `SMTP_PORT` | `465`; iCloud: `587` | SMTP submission port |
| `SMTP_TLS_MODE` | `tls`, or `starttls` for port 587 | Required TLS mode |
| `MAIL_TIMEOUT` | `30s` | Per-operation timeout, between `1s` and `2m` |
| `PORT` | `8080` | HTTP listening port; Vercel supplies this value |

IMAP uses implicit TLS only. SMTP port 465 requires implicit TLS; port 587 requires STARTTLS. Plaintext SMTP and insecure certificate verification are unsupported. Hosts must be DNS names, not URLs or IP literals.

### Spacemail

The preset uses `mail.spacemail.com:993` for IMAP and `mail.spacemail.com:465` for SMTP, both with implicit TLS. Set your complete mailbox address and its primary mailbox password. Angelos does not require or configure a separate app-password flow. Confirm that IMAP/SMTP access is enabled in your provider account.

These are the settings published in [Spacemail's official client setup guide](https://www.spaceship.com/knowledgebase/set-up-spacemail-outlook-imap-pop3/). The preset configures endpoints; it does not create an account or discover credentials.

### Gmail and Google Workspace

Use `MAIL_PROVIDER=gmail` and server-side Google OAuth credentials. The preset pins official Gmail hosts and defaults to XOAUTH2 refresh-token authentication. An explicit app-password alternative is conditional on account/admin eligibility. Read [Gmail and Google Workspace](/docs/gmail-workspace) before setup, including the personal/internal scope, full-mail grant, Sent-copy behavior and permanent-delete restriction.

### iCloud and Yahoo

Both presets require `MAIL_AUTH_MODE=app_password` (their default), the full bare mailbox address in `MAIL_USERNAME`, and an owner-created app password in `MAIL_PASSWORD`. Clear all `GOOGLE_*` credentials. These modes reuse the existing password-authenticated IMAP/SMTP backend and the same six MCP tools; they do not implement Apple or Yahoo OAuth.

| Provider | IMAP (implicit TLS) | SMTP | Authentication |
| --- | --- | --- | --- |
| `icloud` | `imap.mail.me.com:993` | `smtp.mail.me.com:587` with STARTTLS | Apple app-specific password |
| `yahoo` | `imap.mail.yahoo.com:993` | `smtp.mail.yahoo.com:465` with implicit TLS; alternatively port `587` with STARTTLS | Yahoo app password |

Endpoints are pinned: host overrides and undocumented port/TLS combinations fail startup validation. Yahoo's documented port 587 alternative can be selected with `SMTP_PORT=587` and `SMTP_TLS_MODE=starttls`. Remove stale endpoint overrides when changing providers. Spacemail/custom override behavior and Gmail pinning are unchanged.

For iCloud, [Apple's server settings](https://support.apple.com/en-us/102525) require a full email address for SMTP; using the full address for both protocols satisfies the shared username configuration. [Apple app-specific passwords](https://support.apple.com/en-us/102654) require two-factor authentication. The owner creates the password in their Apple Account and enters it directly into the deployment's private secret settings. Do not paste passwords into agent chat.

For Yahoo, use the [official IMAP/SMTP settings](https://help.yahoo.com/kb/sln4075.html) and [app-password instructions](https://my.help.yahoo.com/kb/mail/generate-app-specific-password-sln15241.html). The owner must generate and privately enter the password. Yahoo can restrict app-password generation based on account eligibility; the preset cannot bypass that restriction.

Special-use folders and IMAP capabilities are discovered from the server. Angelos does not hardcode an iCloud/Yahoo Sent folder or assert that their SMTP service automatically files Sent copies. For these presets, `smtp_stores_sent: false` means no automatic-filing guarantee is configured, not proof the provider never files a copy. Start with `append_sent=false`, verify the actual account's behavior after an explicitly approved test send, and request explicit filing only when needed. Deterministic local TLS fixtures cover configuration and protocol behavior; real iCloud/Yahoo account login and Sent-copy behavior have not been verified.

### Other providers

Use `MAIL_PROVIDER=custom`, then set `IMAP_HOST` and `SMTP_HOST` to the provider's documented endpoints. For STARTTLS submission, set `SMTP_PORT=587` and `SMTP_TLS_MODE=starttls`.

Spacemail and custom providers use the existing username/password flow. Gmail has a dedicated server-side Google OAuth flow; Microsoft uses its dedicated Graph adapter. Other providers requiring OAuth need their own implementation; arbitrary token endpoints are not supported. OAuth on the MCP endpoint authenticates the agent client and remains separate from mailbox authentication.

### Microsoft Graph

`MAIL_PROVIDER=microsoft` selects the delegated Graph adapter and defaults to `MAIL_AUTH_MODE=microsoft_graph`. Remove `MAIL_PASSWORD` and Google credentials. IMAP/SMTP endpoint overrides are not used for this connection. The primary mailbox address in `MAIL_USERNAME` and `MAIL_FROM` must match Graph `/me.mail`; aliases and shared mailboxes are unsupported.

| Variable | Meaning |
| --- | --- |
| `MICROSOFT_CLIENT_ID` | UUID of the owner-provisioned confidential application |
| `MICROSOFT_CLIENT_SECRET` | Private client secret; never expose in logs or JSON |
| `MICROSOFT_REFRESH_TOKEN` | Delegated owner refresh grant |
| `MICROSOFT_TENANT_ID` | Exact organization tenant UUID, or `consumers` for personal Outlook.com |
| `MICROSOFT_ACCOUNT_ID` | Exact verified Graph `/me.id`, bound to returned message references |
| `MICROSOFT_TOKEN_ENCRYPTION_KEY` | Stable 32-byte random AES-GCM key encoded as 64 hex characters; keep outside Redis |

All six settings and the configured Redis REST store are required, including for read-only Microsoft access with an external MCP issuer. Rotated refresh tokens are encrypted in Redis; preserve the encryption key across redeployments and reauthorization. Global-cloud endpoints are pinned to `login.microsoftonline.com` and `graph.microsoft.com`. This does not authorize tenant administration or bypass consent policy. See the [Microsoft reference](/docs/microsoft) for grant setup, scope breadth, and different message/paging semantics.

## Reply identities

`MAIL_FROM`, an address-valued `MAIL_USERNAME`, and configured `MAIL_ALIASES` identify the owner when deriving reply recipients. Comparisons are case-insensitive. Add aliases explicitly; Angelos does not guess plus-addresses or provider identities. Aliases do not authorize sending from another address: the visible sender and SMTP envelope remain `MAIL_FROM`. Explicit recipient overrides are preserved and remain part of the full preparation preview.

## MCP access

`MCP_RESOURCE_URL`, `MCP_OAUTH_ISSUER`, `MCP_OAUTH_JWKS_URL`, and `MCP_ALLOWED_SUBJECTS` are required. See [OAuth reference](/docs/oauth-reference#external-issuer-requirements) for their exact constraints and accepted JWT format.

### First-party OAuth (opt-in)

Leave `ANGELOS_OAUTH_ENABLED=0` or unset to keep external-issuer mode. When enabled, the four `MCP_*` settings above must use the [configured origin and single-owner configuration](/docs/configuration#mcp-access). The same `ANGELOS_REDIS_REST_URL` and `ANGELOS_REDIS_REST_TOKEN` are required even with sending disabled. Set an explicit bare mailbox address in `MAIL_FROM` for the owner consent screen.

| Variable | Default | Meaning |
| --- | --- | --- |
| `ANGELOS_OAUTH_ENABLED` | Disabled | `1` enables the built-in owner-only authorization server |
| `ANGELOS_OAUTH_SIGNING_KEY_PEM` | Required when enabled | Durable ES256 P-256 private key as PKCS#8 or EC PEM; sensitive API runtime secret |
| `ANGELOS_OAUTH_SIGNING_KEY_ID` | Required when enabled | Stable, unique active signing-key ID (`kid`) |
| `ANGELOS_OAUTH_VERIFICATION_KEYS_JSON` | Empty | Optional JSON object mapping up to four retiring key IDs to PKIX public-key PEM strings |
| `ANGELOS_OAUTH_CLIENTS_JSON` | Empty | Predefined public-client array with `client_id`, `client_name`, and exact `redirect_uris` |
| `ANGELOS_OAUTH_CHATGPT_CIMD_ENABLED` | Disabled | `1` enables only the pinned ChatGPT metadata identity described in the runbook |
| `ANGELOS_OAUTH_BOOTSTRAP_TOKEN_HASH` | Empty | Lowercase SHA-256 hex digest of the high-entropy one-time owner-enrollment token; remove after enrollment |

Configure an allowed client before connecting. First-party mode does not expose dynamic client registration, passwords, or public account signup. The cookie name, secure flags, and session lifetimes are fixed; the relying-party ID and allowed origin come from the explicitly configured issuer; there is no cookie signing secret or permissive development override. See [owner setup and recovery](/docs/oauth-reference#owner-recovery).

## Optional capabilities

| Variable | Default | Effect |
| --- | --- | --- |
| `MAIL_ENABLE_WRITES` | Disabled | Allows mailbox mutations when the token also has `mail.write` |
| `MAIL_ENABLE_SEND` | Disabled | Allows preparation and sending when the token has `mail.send` and a durable store is configured |
| `MAIL_ENABLE_DELETE` | Disabled | Additional gate for permanent single-message deletion; ordinary writes must also be enabled; unavailable for Gmail/Workspace |
| `ANGELOS_REDIS_REST_URL` | Unset | HTTPS endpoint shared by first-party OAuth state, preparation/dispatch, and receipt lookup |
| `ANGELOS_REDIS_REST_TOKEN` | Unset | Secret used to authenticate durable-store requests |

Set an enable flag to `1` to opt in. A scoped token does not override a disabled gate. The Redis endpoint must support the command API used by the store, including `SET` and atomic Lua `EVAL`; a raw Redis TCP URL is unsupported.

A valid configured store remains available for owner-scoped receipt reads when `MAIL_ENABLE_SEND=0`; this does not enable preparation or SMTP submission. The store contains private prepared mail for up to 15 minutes and minimal dispatch records for seven days. Review [data handling](/docs/safety) before configuring a third-party store.

## Startup status

`GET /healthz` reports the service version and whether required local configuration validated. When mailbox configuration validates, `mail_provider` and `mail_auth_mode` report its non-secret preset/mode labels, even if MCP access configuration is still incomplete; invalid mailbox configuration omits those fields. It does not test the provider login, fetch OAuth signing keys, or prove Redis is reachable. Incomplete mail or OAuth configuration leaves `/mcp` unavailable with `503`. In external-issuer mode, incomplete store configuration leaves sending disabled while valid mailbox reads can still run. First-party mode also requires valid Redis and signing configuration; a runtime Redis failure denies token issuance and authenticated MCP calls. `configured: true` is not a Redis availability check.

## Secrets and deployment environments

Keep production credentials in the API project's secret environment settings. Public documentation and the static docs build do not need mail credentials. Do not give preview deployments production mailbox access by default.

Start with read access, verify the correct mailbox and subject, then enable optional capabilities deliberately. Changes made through Angelos affect the same server mailbox used by other IMAP clients.

## Hosting and runtime constraints

The repository root is the Go API; `docs/` is a separate static Astro website and never needs mailbox secrets. The root Vercel build runs `go test -buildvcs=false ./... && go build -buildvcs=false -o server .`. The flag skips VCS metadata stamping, not tests. For local validation use the toolchain requested by `go.mod`; see [Run the tests](/docs/testing).

For non-Vercel hosting, run the Go server behind HTTPS termination, preserve `/mcp` and the discovery/OAuth routes, and inject the environment before startup. `PORT` defaults to 8080. A local `.env` file is not automatically loaded. Built-in OAuth browser requests must use the configured public HTTPS origin, not localhost or an alternate preview domain.

Keep per-operation mail timeouts within your host's function duration. Do not rely on background work continuing after an HTTP response. Vercel blocks SMTP port 25; use authenticated TLS submission on 465 or 587. Durable OAuth and send state must remain outside the server instance. See [Vercel SMTP guidance](https://vercel.com/kb/guide/serverless-functions-and-smtp).

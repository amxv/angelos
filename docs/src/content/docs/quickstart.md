---
title: Connect Your Assistant
description: Have your agent set up a personal Angelos instance, then connect ChatGPT with your passkey.
summary: One agent-led checklist for your fork, Vercel, Redis, mailbox, passkey, and ChatGPT.
order: 1
category: Get started
---

**Ask your agent to set up Angelos in your own accounts.** It can inspect what already exists, prepare your personal fork, configure hosting, and verify the connection. You take over for account approvals, private credentials, passkeys, and ChatGPT’s custom-app controls. The result is your own private server connected to one existing mailbox, with reading enabled first.

Give your agent this request, filling in the non-secret details:

> Set up my personal Angelos instance using this guide. Use my GitHub account, Vercel account, and Upstash account. My mailbox provider is [provider] and my email address is [address]. Reuse any existing Angelos setup after checking it belongs to this instance. Start read-only. Ask me for approvals and secure credential entry when needed; never ask me to paste passwords or tokens into chat. Verify the production endpoint and an authenticated mailbox read, then give me the exact MCP URL. Offer automatic updates after the connection works.

Your agent should follow the sequential checklist below. The repository also includes a [setup skill](https://github.com/amxv/angelos/blob/main/.agents/skills/setup-personal-angelos/SKILL.md) for coding agents; this page remains the complete setup guide. These are instructions for provisioning, not evidence that any accounts have already been configured.

Already have a working server and an enrolled passkey? Your agent should verify its domain and configuration, then jump to [Connect ChatGPT](#6-connect-chatgpt).

<div class="setup-route" aria-label="Setup journey"><span>01 · Your fork</span><span>02 · Redis</span><span>03 · Mailbox</span><span>04 · Deploy</span><span>05 · Passkey</span><span>06 · ChatGPT</span></div>

## Before your agent begins

Share only non-secret inputs: your GitHub account/repository, Vercel project if one exists, preferred stable domain if you have one, provider, mailbox address, and intended sender address. The agent checks:

- **Source access:** [Angelos](https://github.com/amxv/angelos) is currently private. Your GitHub identity needs access and permission to fork it. A 404 needs source access, not a new deployment. Private forks remain tied to upstream permissions; losing access can remove the fork. If forking is unavailable, stop and resolve source-sharing permission rather than publishing a copy.
- **Your accounts:** Vercel and Upstash must be yours. Reuse this instance’s existing project and dedicated database where possible; never reuse another person’s Redis or credentials.
- **Mailbox eligibility:** the provider must allow its selected authentication and mail-access route. Spacemail, Gmail/Workspace, Microsoft Outlook/365, iCloud, Yahoo, and custom TLS providers are covered below.
- **ChatGPT eligibility:** check custom MCP apps/developer mode before provisioning. Plan, role, and workspace policies may restrict it. [Current availability](https://help.openai.com/en/articles/12584461-developer-mode-and-mcp-apps-in-chatgpt)
- **Execution access:** use the agent’s approved connected-computer tools and existing signed-in sessions. If a login, permission, or secret entry needs you, pause that step and provide the exact page. A browser that supports passkeys is needed for enrollment.

Angelos does not create an email account or offer a hosted signup. Each person gets their own fork, Vercel API project, Redis database, production domain, and passkey owner. Your regular mail app keeps working.

**Approval and secrets:** authorize the accounts, mailbox data hosting, and any costs before provisioning. The agent must not accept paid plans, grant persistent access, enter credentials, or complete security prompts outside its permitted tool routes and your approvals. Use secure login/credential handoff; never put secrets in chat, source code, screenshots, logs, or the docs project. You complete provider consent and passkey prompts yourself.

**Cost and privacy:** small instances may fit free tiers, but hosting is not guaranteed free. Review [Vercel’s plan terms](https://vercel.com/docs/plans) and [Upstash’s limits](https://upstash.com/pricing/redis). Redis holds sign-in state and, if sending is enabled later, complete prepared messages for up to 15 minutes. Use a durable database in your account. Private-repository deployment eligibility also depends on repository ownership and Vercel plan/team rules; verify it for your account rather than assuming a paid seat is always necessary. [Vercel Git rules](https://vercel.com/docs/git)

## 1. Create your Vercel API project

**Agent does:** inspect the existing GitHub repository, Vercel project, production domain, and deployment status first. Record non-secret identifiers so interrupted setup can resume without duplicating infrastructure.

1. Create your permitted private fork in your GitHub account, or verify and reuse your existing fork. Keep its application code unchanged; per-person settings belong in production environment variables. In [Vercel](https://vercel.com/new), import that fork as a new project, for example `my-angelos`, only if this instance has no project yet.
2. Set the **Root Directory to the repository root**, not `docs/`. Keep the checked-in root `vercel.json`: it selects the Go API and runs its tests before building. You do not need a second project for this documentation website.
3. Create the initial deployment. It can run before secrets are configured, but mail access will remain unavailable. A configuration error at this stage is expected.
4. In the project’s Domains settings, copy its **stable production domain**, such as `my-angelos.vercel.app`. A custom domain works too, once DNS and HTTPS are ready. Do not use a commit-specific preview address.

Throughout this guide, replace `my-angelos.vercel.app` with that exact hostname. Choose it before enrolling a passkey: passkeys belong to this domain. Changing it later changes the passkey relying party; existing passkeys will not work on the new domain. Configurable hosting is not automatic domain migration.

The API’s OAuth endpoints must be publicly reachable over HTTPS. Ensure Vercel Deployment Protection does not put a Vercel login in front of this production domain; keep previews protected and free of production secrets. Angelos itself requires OAuth for all mail access. See [Vercel deployment protection](https://vercel.com/docs/deployment-protection).

## 2. Create hosted Redis

**Agent does:** find and verify this instance’s existing dedicated database. If none exists, prepare a **dedicated, permanent Redis database in your Upstash account**, preferably near your Vercel region, and create it only with the required account/cost approvals. Do not share another deployment’s database, even with the same owner label.

In the [Upstash console](https://console.upstash.com/), its **REST** connection details map to:

- `UPSTASH_REDIS_REST_URL` → Angelos variable `ANGELOS_REDIS_REST_URL`
- `UPSTASH_REDIS_REST_TOKEN` → Angelos variable `ANGELOS_REDIS_REST_TOKEN`

Transfer the token through a supported secure credential route or let the owner enter it directly in Vercel. Use the normal read/write REST token, not a read-only token or a Redis TCP connection string. Angelos needs atomic `SET` and Lua `EVAL`, even when email is read-only. [Upstash REST connection details](https://upstash.com/docs/redis/features/restapi)

Keep this database durable. Don’t enable eviction or delete/reset it as if it were a disposable cache: it stores your passkeys, sessions, revoked grants, and send-duplicate protections. Free-tier limits or an outage can interrupt access; monitor usage and review backup and security options before relying on it.

## 3. Choose your mailbox settings

**Agent does:** select and validate the non-secret provider settings. **You do:** generate any required app password or authorize the selected Google/Microsoft application, then enter credentials through the secure handoff for the API project. The following are templates, never requests to send secrets in chat.

### Spacemail

Use your full address and existing mailbox password:

```dotenv
MAIL_PROVIDER=spacemail
MAIL_USERNAME=you@example.com
MAIL_FROM=you@example.com
MAIL_PASSWORD=YOUR_MAILBOX_PASSWORD
```

The preset supplies `mail.spacemail.com`, IMAP 993, and SMTP 465 with TLS. Confirm the account permits IMAP/SMTP. `MAIL_FROM` must be an address your provider allows you to send from.

### Gmail or Google Workspace

For eligible accounts with an app password, use:

```dotenv
MAIL_PROVIDER=gmail
MAIL_AUTH_MODE=app_password
MAIL_USERNAME=you@gmail.com
MAIL_FROM=you@gmail.com
MAIL_PASSWORD=YOUR_GOOGLE_APP_PASSWORD
```

This must be an actual [Google app password](https://support.google.com/accounts/answer/185833), not your normal Google password. Availability depends on two-step verification and account/admin policy. Do not weaken organization security settings to enable it.

If app passwords are unavailable, your agent can prepare Google's OAuth route using the repository's local helper. The agent handles setup and token exchange; you enter the private client secret and approve the mailbox grant.

1. After the required project/access approvals, the agent configures or reuses your Google Cloud project, audience/consent screen, `https://mail.google.com/` scope, and **Web application** OAuth client. It registers exactly `http://127.0.0.1:8401/callback` as an authorized redirect URI. For an External Testing app, add your intended mailbox as a test user. Creating persistent credentials and granting full-mail access need your approval; organization policy still applies.
2. The agent verifies that the **Gmail API is enabled in this same Google Cloud project before consent**. The helper uses its profile endpoint to confirm the intended mailbox, even though Angelos itself uses IMAP/SMTP. An API-disabled or administrator-blocked profile check cannot be skipped. [Gmail API prerequisite](https://developers.google.com/workspace/gmail/api/quickstart/python)
3. On your approved Linux/macOS computer with Python 3.9 or newer, the agent prepares a private owner-only `0700` directory outside every repository, then runs this command from the checkout. The output filename must be new:

```bash
python3 scripts/google_grant.py \
  --client-id YOUR_CLIENT_ID.apps.googleusercontent.com \
  --mailbox you@gmail.com \
  --output "$HOME/.angelos-private/google.env"
```

4. You enter the client secret at the private terminal prompt and open the Google consent URL in a browser on that same computer. The helper checks state and PKCE, exchanges the code once, and verifies the exact full-mail scope and intended primary mailbox. It writes the settings below to a protected `0600` file without printing tokens. Keep the callback URL private; do not copy it into chat, screenshots, or support logs.
5. Transfer the resulting settings to Vercel Production through the approved secure route in step 4 below. The file is a JSON-quoted dotenv reference: **do not source or execute it**; enter decoded values without surrounding quotes. Never attach or display the file in chat. The helper supports `--client-secret-file` for an already protected owner-only secret file instead of terminal entry.

```dotenv
MAIL_PROVIDER=gmail
MAIL_AUTH_MODE=google_oauth2
MAIL_USERNAME=you@gmail.com
MAIL_FROM=you@gmail.com
GOOGLE_CLIENT_ID=YOUR_CLIENT_ID
GOOGLE_CLIENT_SECRET=YOUR_CLIENT_SECRET
GOOGLE_REFRESH_TOKEN=YOUR_REFRESH_TOKEN
```

Remove `MAIL_PASSWORD` in OAuth mode. This grants full IMAP/SMTP mail access even though Angelos starts read-only. External Testing grants can expire after seven days; Workspace policy and restricted-scope rules still apply. If an existing grant no longer works, repeat the approved local flow with a new output filename and update the production secret securely. The [Gmail reference](/docs/gmail-workspace) explains eligibility, expiry, and verification requirements. No account or grant is created merely by installing the helper.

### Outlook.com and Microsoft 365

Use Microsoft's delegated **Graph** connection, including for eligible enterprise Exchange Online mailboxes. It does not use IMAP/SMTP passwords or an app-password workaround:

```dotenv
MAIL_PROVIDER=microsoft
MAIL_AUTH_MODE=microsoft_graph
MAIL_USERNAME=you@example.com
MAIL_FROM=you@example.com
MICROSOFT_CLIENT_ID=YOUR_APPLICATION_CLIENT_ID
MICROSOFT_CLIENT_SECRET=YOUR_CLIENT_SECRET
MICROSOFT_REFRESH_TOKEN=YOUR_OWNER_REFRESH_TOKEN
MICROSOFT_TENANT_ID=YOUR_ORGANIZATION_TENANT_UUID
MICROSOFT_ACCOUNT_ID=YOUR_GRAPH_ME_ID
MICROSOFT_TOKEN_ENCRYPTION_KEY=YOUR_STABLE_64_HEX_CHARACTER_KEY
```

For a personal Outlook.com account, set `MICROSOFT_TENANT_ID=consumers`; for work/school, use the exact organization tenant UUID. `MAIL_USERNAME` and `MAIL_FROM` must match the verified primary `mail` address returned by Graph `/me`; aliases, shared mailboxes, application-wide permissions, and sovereign clouds are not supported.

**Agent does:** inspect existing Entra app registration and mailbox eligibility, then prepare the appropriate delegated application and environment settings with your authorization. **You or your administrator do:** approve app registration, persistent credentials, and delegated `User.Read`, `Mail.ReadWrite`, `Mail.Send`, plus `offline_access` for the refresh grant. These provider permissions are broader than Angelos's initial read-only switches. The agent cannot bypass tenant consent policy or create an organization account on your behalf without permission.

The agent prepares the initial grant with the repository's local helper:

1. After app-registration approval, add the exact **Web** redirect `http://127.0.0.1:8400/callback` to the app's `web.redirectUris` manifest array, preserving existing settings. Microsoft's portal textbox can reject HTTP IP-loopback URIs; use its manifest editor rather than substituting an unregistered callback. [Microsoft redirect rules](https://learn.microsoft.com/en-us/entra/identity-platform/reply-url)
2. On your approved Linux/macOS computer with Python 3.9 or newer, the agent ensures a private, owner-only directory outside every repository exists (mode `0700`), then runs this command from the checkout with your non-secret client ID, tenant, and mailbox. The output path must be new; `--new-instance` is only for first setup.

```bash
python3 scripts/microsoft_grant.py \
  --client-id YOUR_APPLICATION_CLIENT_UUID \
  --tenant-id YOUR_TENANT_UUID_OR_consumers \
  --mailbox you@example.com \
  --new-instance \
  --output "$HOME/.angelos-private/microsoft.env"
```

3. You enter the client secret at the helper's private prompt and open its Microsoft consent URL in a browser on that same computer. The helper uses state and PKCE, checks the intended mailbox, and saves the resulting settings to the protected file without printing tokens. The consent window expires after five minutes. If another process owns its callback port, stop and resolve that conflict.
4. Transfer the saved settings to Vercel Production through the approved secure route in step 4 below. The file is a JSON-quoted dotenv reference, not an executable script: do not source it; enter decoded values without surrounding quotes. Never display or attach the file in chat. For an existing instance's renewed grant, replace `--new-instance` with `--token-encryption-key-file` pointing to a protected file containing the **existing** key, and use a new output filename. Do not generate a replacement encryption key during reauthorization.

The [Microsoft reference](/docs/microsoft) covers the grant and its limitations, including encrypted refresh-token persistence in your existing Redis and renewal after expiry or revocation. Keep the generated token-encryption key stable across updates and renewal. Keep the refresh token and client secret out of chat. Server health cannot establish tenant eligibility: complete an authenticated folder/read check after deployment. Other enterprise providers can use the custom connection below only when they permit password-based TLS IMAP/SMTP.

### iCloud Mail

Use your full iCloud mailbox address and an Apple **app-specific password**:

```dotenv
MAIL_PROVIDER=icloud
MAIL_AUTH_MODE=app_password
MAIL_USERNAME=you@icloud.com
MAIL_FROM=you@icloud.com
MAIL_PASSWORD=YOUR_APPLE_APP_SPECIFIC_PASSWORD
```

The preset pins `imap.mail.me.com:993` with TLS and `smtp.mail.me.com:587` with STARTTLS. Apple requires two-factor authentication to generate the app-specific password at [account.apple.com](https://account.apple.com/). You complete that step and enter the result securely, not in chat. Changing your primary Apple Account password revokes app-specific passwords. [Apple server settings](https://support.apple.com/en-us/102525) · [App-specific passwords](https://support.apple.com/en-us/102654)

### Yahoo Mail

Use your full Yahoo address and a Yahoo **app password**:

```dotenv
MAIL_PROVIDER=yahoo
MAIL_AUTH_MODE=app_password
MAIL_USERNAME=you@yahoo.com
MAIL_FROM=you@yahoo.com
MAIL_PASSWORD=YOUR_YAHOO_APP_PASSWORD
```

The preset pins `imap.mail.yahoo.com:993` and `smtp.mail.yahoo.com:465`, both with TLS. Your ordinary account password is not the app password. Availability of app-password generation depends on your account; if Yahoo does not offer it, resolve provider eligibility before deploying. [Yahoo server settings](https://help.yahoo.com/kb/sln4075.html) · [Generate an app password](https://my.help.yahoo.com/kb/mail/generate-app-specific-password-sln15241.html)

### Another IMAP/SMTP provider

**Agent does:** obtain the provider's official settings and configure your own IMAP/SMTP hostnames and ports, rather than trying to fit them into another provider's preset. Use its documented TLS endpoints and mailbox password (or required provider app password):

```dotenv
MAIL_PROVIDER=custom
MAIL_USERNAME=you@example.com
MAIL_FROM=you@example.com
MAIL_PASSWORD=YOUR_PROVIDER_PASSWORD
IMAP_HOST=imap.example.com
IMAP_PORT=993
SMTP_HOST=smtp.example.com
SMTP_PORT=465
SMTP_TLS_MODE=tls
```

For SMTP port 587, use `SMTP_TLS_MODE=starttls`. IMAP must support implicit TLS. Custom-provider OAuth is not implemented; use a supported password connection or the dedicated Google/Microsoft connection.

## 4. Add secrets and deploy

### Generate the signing key and enrollment token

**Agent does:** check whether a signing key and owner already exist. Reuse the stable signing key and key ID; do not generate a new identity during a retry or update. If this is a new instance, run the commands below on the approved computer in a new private folder **outside the repository**, without printing the resulting secrets. Stop if the folder or files already exist; inspect setup state rather than overwriting them.

```bash
mkdir -m 700 angelos-private && cd angelos-private || exit 1
umask 077
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out signing-key.pem
python3 - <<'PY'
import hashlib, secrets
from pathlib import Path
raw = secrets.token_urlsafe(32)
Path("bootstrap-token.txt").write_text(raw)
Path("bootstrap-hash.txt").write_text(hashlib.sha256(raw.encode()).hexdigest())
PY
```

Keep the signing key in an owner-approved secure backup through a supported secret-handling route. Reuse it across deployments. The raw bootstrap token is only for your browser’s enrollment form; Vercel gets its hash, not the token. These files contain secrets: never commit them or upload the folder as an attachment. Transferring an individual required secret to Vercel must use the authorized secure route; if the agent cannot use one, you enter it directly.

### Enter the production environment

**Agent does:** prepare the non-secret settings and check the existing environment without exposing values. In your **API project → Settings → Environment Variables**, configure the mailbox settings from step 3 and the values below, scoped to **Production only**. **You do:** enter private values when secure handoff is required. Use Vercel’s sensitive setting for credentials and private keys. Enter values without surrounding quotes; paste the PEM’s full multiline contents, including its BEGIN/END lines.

| Variable | Value |
| --- | --- |
| `ANGELOS_OAUTH_ENABLED` | `1` |
| `MCP_OAUTH_ISSUER` | `https://my-angelos.vercel.app` |
| `MCP_RESOURCE_URL` | `https://my-angelos.vercel.app/mcp` |
| `MCP_OAUTH_JWKS_URL` | `https://my-angelos.vercel.app/oauth/jwks.json` |
| `MCP_ALLOWED_SUBJECTS` | `owner` — your single stable owner identifier |
| `ANGELOS_REDIS_REST_URL` | Upstash REST URL from step 2 |
| `ANGELOS_REDIS_REST_TOKEN` | Upstash read/write REST token |
| `ANGELOS_OAUTH_SIGNING_KEY_PEM` | Full contents of `signing-key.pem` |
| `ANGELOS_OAUTH_SIGNING_KEY_ID` | `owner-key-1` — keep stable with this key |
| `ANGELOS_OAUTH_BOOTSTRAP_TOKEN_HASH` | Contents of `bootstrap-hash.txt` |
| `ANGELOS_OAUTH_CHATGPT_CIMD_ENABLED` | `1` |
| `MAIL_ENABLE_WRITES` | `0` |
| `MAIL_ENABLE_SEND` | `0` |
| `MAIL_ENABLE_DELETE` | `0` |

Use lowercase hostnames and no trailing slashes. The issuer is just your HTTPS origin; the other two URLs must use that same origin and exactly the paths shown. `owner` is a label you choose, not an email login or an account to register. Don’t change it after enrollment: it selects your stored identity.

Leave `ANGELOS_OAUTH_CLIENTS_JSON` and `ANGELOS_OAUTH_VERIFICATION_KEYS_JSON` unset for this path. The ChatGPT switch enables its pinned client metadata document; it does not permit arbitrary clients or public registration.

**Agent does:** once configuration is complete, **redeploy Production** and wait for its terminal status. Saving environment variables alone does not update an existing deployment. The application reads the runtime environment, not a local `.env` file. [Vercel environment variables](https://vercel.com/docs/environment-variables)

### Check the deployment

**Agent does:** replace the hostname with the verified production domain and run these checks; no secrets are needed:

```bash
curl -sS https://my-angelos.vercel.app/healthz
curl -sS https://my-angelos.vercel.app/.well-known/oauth-protected-resource
curl -sS https://my-angelos.vercel.app/.well-known/oauth-authorization-server
curl -i https://my-angelos.vercel.app/mcp
```

Expect `configured: true` in health, your exact issuer and `/mcp` resource in discovery, and **401 Unauthorized** with a `WWW-Authenticate` header for `/mcp`. That 401 is correct: anonymous callers cannot read mail. Health confirms configuration, not a successful mailbox login or working Redis; the next steps verify those.

## 5. Enroll your passkey

**Agent does:** open the exact enrollment page and explain the remaining owner steps. Skip initial enrollment if this instance already has a working owner; never reset Redis to start over.

**You do:**

1. Open `https://my-angelos.vercel.app/oauth/login` in your browser, on the exact domain you configured.
2. Enter the contents of `bootstrap-token.txt` in the enrollment form. Complete the browser’s passkey prompt using your password manager, device, or security key.
3. Open `/oauth/grants` while signed in and add a **second independent authenticator**. Sign in with each to check it works. If your session is no longer recent, sign in again before adding a passkey.

**Agent does, after verifying enrollment:** remove `ANGELOS_OAUTH_BOOTSTRAP_TOKEN_HASH` from Vercel with the required approval and redeploy Production again. Keep Redis’s consumed-enrollment state. Remove the local bootstrap token and hash files only with appropriate deletion approval after successful enrollment; keep the signing key securely backed up.

There is no public signup or email/password reset. Losing every passkey needs deliberate offline recovery; clearing Redis is not a safe reset. [Recovery and revocation reference](/docs/oauth-reference#owner-recovery)

## 6. Connect ChatGPT

Your mailbox password or provider OAuth grant connects **Angelos to your mail provider**. Your passkey connects **ChatGPT to Angelos**. Never enter mailbox credentials into ChatGPT.

**Agent does:** give you the exact verified production MCP URL and open the right setup instructions. **You do:** complete the custom-app controls and consent in your own account; the agent must not impersonate you in a passkey or consent prompt.

1. On ChatGPT web, enable developer mode if your account/workspace permits it. The control may be under **Settings → Apps → Advanced Settings**, or your administrator’s workspace controls.
2. From **Settings → Apps → Create** (or the workspace’s Apps page), create a custom MCP app. Name it `Angelos`.
3. Enter **`https://my-angelos.vercel.app/mcp`** as the server URL and choose **OAuth**. For the metadata-document path configured above, leave optional client ID and client secret fields blank. Angelos is a public OAuth client setup; no client secret is generated.
4. Start the tool scan/connection. In the Angelos browser page, sign in with your passkey, check the mailbox and requested permissions, and approve only the access you want. Keep `mail.read` selected; it is required for every connection. Return to ChatGPT and finish creating the app after its tools load.
5. Open a new conversation and select or mention your Angelos app.

Labels and availability can change; consult [OpenAI’s current connection instructions](https://help.openai.com/en/articles/12584461-developer-mode-and-mcp-apps-in-chatgpt). If your UI exposes neither custom apps nor developer mode, resolve account/workspace eligibility first. An API key is not a replacement.

**If client registration fails:** check the connection’s displayed client metadata and callback. The built-in metadata mode accepts exactly `https://chatgpt.com/oauth/client.json` with callback `https://chatgpt.com/connector_platform_oauth_redirect`. A different callback needs the [predefined-client option](#if-chatgpt-needs-a-predefined-client), not a guessed URL or wildcard. [OpenAI OAuth client requirements](https://developers.openai.com/plugins/build/auth)

### Try your first read

Send this prompt:

> Use Angelos to check capabilities and list my mailbox folders. Tell me which actions are enabled. Don’t change or send anything.

Confirm the folders belong to the intended mailbox and the write/send/delete switches are off. Then try:

> Show me the five newest messages in INBOX. Read the one I choose without changing its read status.

Check that message in your usual mail app: reading through Angelos should leave an unread message unread. The agent should report the production domain, exact MCP URL, deployed revision if verified, and which checks passed. Do not report success from health alone: tool discovery, the intended folders, and an authenticated selected-message read must work. You’re connected. Continue with [Work with your inbox](/docs/inbox-guide), [Write and send mail](/docs/sending-guide), or the [Agent playbook](/docs/agent-guide).

## 7. Keep your personal instance updated

Once the first connection works, ask your agent to configure [Keep Angelos updated](/docs/keep-updated). The optional daily updater follows eligible upstream releases, validates them, and deploys to your existing project. It needs a one-time approved setup for repository access, Actions, and Vercel deployment credentials; it is not enabled just by forking. Keep your domain, Redis, environment, and signing key unchanged.

## 8. Enable more when you’re ready

Read [Safety and permissions](/docs/safety) first. Change the relevant Vercel variables, redeploy, then reconnect/consent if the client needs additional scopes. Scope changes cannot be added by refreshing an existing grant.

- **Organize mail or save new drafts:** `MAIL_ENABLE_WRITES=1` and `mail.write` permission.
- **Prepare and send messages:** `MAIL_ENABLE_SEND=1` and `mail.send` permission. Redis is already configured. Review the full prepared recipients, body, and attachments before sending. Preparation alone does not send mail.
- **Permanent deletion:** keep `MAIL_ENABLE_DELETE=0` unless you deliberately need it. It also requires writes and safe provider support; Gmail and Microsoft Graph permanent deletion are unavailable.

Start with disposable messages. Gmail and Microsoft Graph save their own Sent copy, so use `append_sent: false`; other providers require write permission if you request an extra Sent copy. Sending approval belongs to the trusted assistant client; OAuth consent is not approval of an individual email. If a send result is uncertain, inspect its receipt instead of sending a replacement. Provider acceptance or queueing is not confirmed delivery.

## Troubleshooting

| What you see | What to check |
| --- | --- |
| GitHub 404 | The repository is private; obtain source access. |
| Vercel page instead of JSON | Confirm the API project root is the repository root, the domain targets it, and production deployment protection permits OAuth discovery. |
| Health says `configured: false`, or MCP returns 503 | Check production variables, exact matching URLs, full PEM, mailbox mode, Redis URL/token, and redeploy after edits. |
| Health works, passkey enrollment fails | Use the configured production domain and fresh enrollment form; check Redis access and the SHA-256 hash of the exact raw token text. |
| ChatGPT says unknown client or invalid redirect | Check its displayed callback and use the predefined-client option below if it differs from the pinned metadata mode. |
| Sign-in works, mail fails | Check provider credentials, IMAP access, TLS hostnames, and Google/Microsoft grant or administrator restrictions. Health does not test these. |
| Mail changes or preparation are denied | Check both scopes and server switches; refresh ChatGPT’s tool definitions after an upgrade. |
| Access stops after working | Check Redis quotas/outages, provider grant expiry, and your connected OAuth grant. Reconnect when its lifetime ends. |

Keep secrets and message contents out of support logs. Do not disable authentication or TLS to work around an error.

### If ChatGPT needs a predefined client

Use this only when the connection offers manual OAuth client settings. Choose a public client ID such as `angelos-chatgpt`, copy the **exact redirect URI from that connection**, and set `ANGELOS_OAUTH_CLIENTS_JSON` to:

```json
[{"client_id":"angelos-chatgpt","client_name":"ChatGPT","redirect_uris":["REPLACE_WITH_EXACT_HTTPS_CALLBACK"]}]
```

Set `ANGELOS_OAUTH_CHATGPT_CIMD_ENABLED=0`, redeploy, and enter that same client ID in ChatGPT with no client secret. Use public-client authentication (`none`) and PKCE. If the UI requires a client secret or a different authentication method, stop: that flow is not supported by Angelos. It does not implement dynamic registration. Never broaden the callback to a wildcard.

For protocol limits, external identity providers, signing-key rotation, and recovery, use the [OAuth reference](/docs/oauth-reference). For every variable and advanced hosting constraints, use the [Configuration reference](/docs/configuration).

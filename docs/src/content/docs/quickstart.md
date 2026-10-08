---
title: Connect Your Assistant
description: From your own Vercel deployment to your first email conversation in ChatGPT. One guide, start to finish.
summary: Set up Vercel, Redis, your mailbox, passkey sign-in, and ChatGPT in one place.
order: 1
category: Get started
---

**By the end, ChatGPT can find and read mail from your existing inbox through your own private Angelos server.** You’ll deploy the API on Vercel, give it a small hosted Redis database, connect your mailbox, and secure access with a passkey. Reading comes first; sending and mailbox changes stay off until you choose them.

Already have a working Angelos server and an enrolled passkey? Jump to [Connect ChatGPT](#6-connect-chatgpt).

<div class="setup-route" aria-label="Setup journey"><span>01 · Vercel</span><span>02 · Redis</span><span>03 · Mailbox</span><span>04 · Secrets</span><span>05 · Passkey</span><span>06 · ChatGPT</span></div>

## Before you begin

You need:

- Access to the [Angelos repository](https://github.com/amxv/angelos). It is currently private; if GitHub shows 404, request source access before continuing.
- Your own **Vercel** and **Upstash** accounts, and permission to host your mailbox data there.
- An existing email account with IMAP/SMTP access. Spacemail is the simplest preset; Gmail and other providers are covered below.
- A macOS/Linux terminal, or Windows WSL/Git Bash, with Git, Python 3, and OpenSSL for generating local secrets, plus a browser that supports passkeys.
- ChatGPT on the web with custom MCP app/developer-mode access. Check this before deploying: plan, workspace role, and administrator settings can restrict access. [Current ChatGPT availability](https://help.openai.com/en/articles/12584461-developer-mode-and-mcp-apps-in-chatgpt)

Angelos does not create an email account or offer a hosted signup. One deployment serves one mailbox and one passkey owner. Your regular mail app keeps working.

**Cost and privacy:** small personal deployments may fit free tiers, but hosting is not guaranteed free. Review [Vercel’s plan terms](https://vercel.com/docs/plans) and [Upstash’s limits](https://upstash.com/pricing/redis), including durability and security features. Redis holds sign-in state and, if sending is enabled later, complete prepared messages for up to 15 minutes. Use a permanent database in your account, never an expiring demo database.

## 1. Create your Vercel API project

1. Get your own permitted copy of the repository in GitHub. In [Vercel](https://vercel.com/new), import that repository as a new project, for example `my-angelos`.
2. Set the **Root Directory to the repository root**, not `docs/`. Keep the checked-in root `vercel.json`: it selects the Go API and runs its tests before building. You do not need a second project for this documentation website.
3. Create the initial deployment. It can run before secrets are configured, but mail access will remain unavailable. A configuration error at this stage is expected.
4. In the project’s Domains settings, copy its **stable production domain**, such as `my-angelos.vercel.app`. A custom domain works too, once DNS and HTTPS are ready. Do not use a commit-specific preview address.

Throughout this guide, replace `my-angelos.vercel.app` with that exact hostname. Choose it before enrolling a passkey: passkeys belong to this domain. Changing it later changes the passkey relying party; existing passkeys will not work on the new domain. Configurable hosting is not automatic domain migration.

The API’s OAuth endpoints must be publicly reachable over HTTPS. Ensure Vercel Deployment Protection does not put a Vercel login in front of this production domain; keep previews protected and free of production secrets. Angelos itself requires OAuth for all mail access. See [Vercel deployment protection](https://vercel.com/docs/deployment-protection).

## 2. Create hosted Redis

In the [Upstash console](https://console.upstash.com/), create a **fresh, dedicated, permanent Redis database for this Angelos deployment**, preferably near your Vercel region. Do not share another Angelos deployment’s database, even with the same owner label. In its connection details, select **REST** and copy:

- `UPSTASH_REDIS_REST_URL` → Angelos variable `ANGELOS_REDIS_REST_URL`
- `UPSTASH_REDIS_REST_TOKEN` → Angelos variable `ANGELOS_REDIS_REST_TOKEN`

Use the normal read/write REST token, not a read-only token or a Redis TCP connection string. Angelos needs atomic `SET` and Lua `EVAL`, even when email is read-only. [Upstash REST connection details](https://upstash.com/docs/redis/features/restapi)

Keep this database durable. Don’t enable eviction or delete/reset it as if it were a disposable cache: it stores your passkeys, sessions, revoked grants, and send-duplicate protections. Free-tier limits or an outage can interrupt access; monitor usage and review backup and security options before relying on it.

## 3. Choose your mailbox settings

You will enter these values in Vercel in the next step. Keep credentials out of source code, screenshots, and assistant conversations.

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

If app passwords are unavailable, use Google OAuth instead. In your Google Cloud project’s Auth Platform, configure the appropriate audience and consent, declare the `https://mail.google.com/` scope, and create a Web application OAuth client. Register `https://developers.google.com/oauthplayground` as its exact redirect URI. In the [official OAuth Playground](https://developers.google.com/oauthplayground/), choose your own OAuth credentials, server-side flow, and offline access; authorize that scope as the mailbox owner and exchange the code for a refresh token. Then use:

```dotenv
MAIL_PROVIDER=gmail
MAIL_AUTH_MODE=google_oauth2
MAIL_USERNAME=you@gmail.com
MAIL_FROM=you@gmail.com
GOOGLE_CLIENT_ID=YOUR_CLIENT_ID
GOOGLE_CLIENT_SECRET=YOUR_CLIENT_SECRET
GOOGLE_REFRESH_TOKEN=YOUR_REFRESH_TOKEN
```

Remove `MAIL_PASSWORD` in OAuth mode. The grant includes full IMAP/SMTP mail access even though Angelos starts read-only. External Testing grants can expire after seven days; Workspace policy and restricted-scope rules still apply. Playground receives the credentials you enter. The [Gmail reference](/docs/gmail-workspace) explains audience, expiry, and verification requirements before you choose this route.

### Another IMAP/SMTP provider

Use its documented TLS hostnames and mailbox password (or provider app password):

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

For SMTP port 587, use `SMTP_TLS_MODE=starttls`. IMAP must support implicit TLS. Custom-provider OAuth is not implemented; use a supported password connection or the Gmail preset.

## 4. Add secrets and deploy

### Generate the signing key and enrollment token

Run these commands on your own computer in a private folder **outside your repository**. They create a stable signing key, a one-time enrollment token, and its hash without printing the secrets into terminal history:

```bash
mkdir -m 700 angelos-private
cd angelos-private
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

Keep the signing key in your password manager or another secure backup. Reuse it across deployments. The raw bootstrap token is only for your browser’s enrollment form; Vercel gets its hash, not the token. These files contain secrets: never commit or upload the folder.

### Enter the production environment

Open your **API project → Settings → Environment Variables**. Add the mailbox settings from step 3, then the values below, scoped to **Production only**. Use Vercel’s sensitive setting for credentials and private keys. Enter values without surrounding quotes; paste the PEM’s full multiline contents, including its BEGIN/END lines.

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

Now **redeploy Production** from Vercel’s Deployments page. Saving environment variables alone does not update an existing deployment. The application reads the runtime environment, not a local `.env` file. [Vercel environment variables](https://vercel.com/docs/environment-variables)

### Check the deployment

Replace the hostname, then run these checks; no secrets are needed:

```bash
curl -sS https://my-angelos.vercel.app/healthz
curl -sS https://my-angelos.vercel.app/.well-known/oauth-protected-resource
curl -sS https://my-angelos.vercel.app/.well-known/oauth-authorization-server
curl -i https://my-angelos.vercel.app/mcp
```

Expect `configured: true` in health, your exact issuer and `/mcp` resource in discovery, and **401 Unauthorized** with a `WWW-Authenticate` header for `/mcp`. That 401 is correct: anonymous callers cannot read mail. Health confirms configuration, not a successful mailbox login or working Redis; the next steps verify those.

## 5. Enroll your passkey

1. Open `https://my-angelos.vercel.app/oauth/login` in your browser, on the exact domain you configured.
2. Enter the contents of `bootstrap-token.txt` in the enrollment form. Complete the browser’s passkey prompt using your password manager, device, or security key.
3. Open `/oauth/grants` while signed in and add a **second independent authenticator**. Sign in with each to check it works. If your session is no longer recent, sign in again before adding a passkey.
4. Remove `ANGELOS_OAUTH_BOOTSTRAP_TOKEN_HASH` from Vercel, then redeploy Production again. Keep Redis’s consumed-enrollment state. Delete the local bootstrap token and hash files after successful enrollment; keep the signing key securely backed up.

There is no public signup or email/password reset. Losing every passkey needs deliberate offline recovery; clearing Redis is not a safe reset. [Recovery and revocation reference](/docs/oauth-reference#owner-recovery)

## 6. Connect ChatGPT

Your mailbox password connects **Angelos to your mail provider**. Your passkey connects **ChatGPT to Angelos**. Never enter mailbox credentials into ChatGPT.

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

Check that message in your usual mail app: reading through Angelos should leave an unread message unread. You’re connected. Continue with [Work with your inbox](/docs/inbox-guide), [Write and send mail](/docs/sending-guide), or the [Agent playbook](/docs/agent-guide).

## 7. Enable more when you’re ready

Read [Safety and permissions](/docs/safety) first. Change the relevant Vercel variables, redeploy, then reconnect/consent if the client needs additional scopes. Scope changes cannot be added by refreshing an existing grant.

- **Organize mail or save new drafts:** `MAIL_ENABLE_WRITES=1` and `mail.write` permission.
- **Prepare and send messages:** `MAIL_ENABLE_SEND=1` and `mail.send` permission. Redis is already configured. Review the full prepared recipients, body, and attachments before sending. Preparation alone does not send mail.
- **Permanent deletion:** keep `MAIL_ENABLE_DELETE=0` unless you deliberately need it. It also requires writes and safe provider support; Gmail permanent deletion is unavailable.

Start with disposable messages. Gmail saves its own Sent copy, so use `append_sent: false`; other providers require write permission if you request an extra Sent copy. Sending approval belongs to the trusted assistant client; OAuth consent is not approval of an individual email. If a send result is uncertain, inspect its receipt instead of sending a replacement. SMTP acceptance is not confirmed delivery.

## Troubleshooting

| What you see | What to check |
| --- | --- |
| GitHub 404 | The repository is private; obtain source access. |
| Vercel page instead of JSON | Confirm the API project root is the repository root, the domain targets it, and production deployment protection permits OAuth discovery. |
| Health says `configured: false`, or MCP returns 503 | Check production variables, exact matching URLs, full PEM, mailbox mode, Redis URL/token, and redeploy after edits. |
| Health works, passkey enrollment fails | Use the configured production domain and fresh enrollment form; check Redis access and the SHA-256 hash of the exact raw token text. |
| ChatGPT says unknown client or invalid redirect | Check its displayed callback and use the predefined-client option below if it differs from the pinned metadata mode. |
| Sign-in works, mail fails | Check provider credentials, IMAP access, TLS hostnames, and Gmail grant/admin restrictions. Health does not test these. |
| Mail changes or preparation are denied | Check both scopes and server switches; refresh ChatGPT’s tool definitions after an upgrade. |
| Access stops after working | Check Redis quotas/outages, Google grant expiry, and your connected OAuth grant. Reconnect when its lifetime ends. |

Keep secrets and message contents out of support logs. Do not disable authentication or TLS to work around an error.

### If ChatGPT needs a predefined client

Use this only when the connection offers manual OAuth client settings. Choose a public client ID such as `angelos-chatgpt`, copy the **exact redirect URI from that connection**, and set `ANGELOS_OAUTH_CLIENTS_JSON` to:

```json
[{"client_id":"angelos-chatgpt","client_name":"ChatGPT","redirect_uris":["REPLACE_WITH_EXACT_HTTPS_CALLBACK"]}]
```

Set `ANGELOS_OAUTH_CHATGPT_CIMD_ENABLED=0`, redeploy, and enter that same client ID in ChatGPT with no client secret. Use public-client authentication (`none`) and PKCE. If the UI requires a client secret or a different authentication method, stop: that flow is not supported by Angelos. It does not implement dynamic registration. Never broaden the callback to a wildcard.

For protocol limits, external identity providers, signing-key rotation, and recovery, use the [OAuth reference](/docs/oauth-reference). For every variable and advanced hosting constraints, use the [Configuration reference](/docs/configuration).

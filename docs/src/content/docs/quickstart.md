---
title: Connect Your Assistant
description: Have your agent set up your own full-capability Angelos instance and connect an assistant with your passkey.
summary: One agent-led checklist for your fork, hosting, mailbox, permissions, and assistant connection.
order: 1
category: Get started
---

**Ask your agent to set up Angelos in your own accounts.** It handles the fork, hosting, configuration, and verification; you complete account approvals, secure credential entry, passkeys, and assistant consent. This guide configures reading, mailbox changes, sending, and supported permanent deletion together, so your assistant is ready for the whole workflow. ChatGPT and Claude.ai connection examples are included.

Give your agent this request, filling in the non-secret details:

> Set up my personal Angelos instance using this guide. Use my GitHub account, Vercel account, and Upstash account. My mailbox provider is [provider] and my email address is [address]. My assistant is [ChatGPT, Claude.ai, or another compatible client]. Reuse any existing Angelos setup after checking it belongs to this instance. Configure all supported capabilities and request mail.read, mail.write, and mail.send at initial consent. Explain permanent deletion, obtain the required approvals, and use secure credential entry when needed; never ask me to paste passwords or tokens into chat. Verify the production endpoint and an authenticated mailbox read, then give me the exact MCP URL. Offer automatic updates after the connection works.

Your agent should follow the sequential checklist below. The repository also includes a [setup skill](https://github.com/amxv/angelos/blob/main/.agents/skills/setup-personal-angelos/SKILL.md) for coding agents; this page remains the complete setup guide. These are instructions for provisioning, not evidence that any accounts have already been configured.

Already have a working server and an enrolled passkey? Your agent should verify its domain and configuration, then jump to [Connect your assistant](#6-connect-your-assistant).

<div class="setup-route" aria-label="Setup journey"><span>01 · Your fork</span><span>02 · Redis</span><span>03 · Mailbox</span><span>04 · Deploy</span><span>05 · Passkey</span><span>06 · Assistant</span></div>

## Full setup, with your consent

The setup enables the following permissions from the outset. Review them before approving deployment and the assistant’s OAuth grant:

| Capability | Server setting | Assistant OAuth scope |
| --- | --- | --- |
| Search, read, and retrieve attachments | Required baseline | `mail.read` |
| Organize mail, move to Trash, and save drafts | `MAIL_ENABLE_WRITES=1` | `mail.write` |
| Prepare and send messages | `MAIL_ENABLE_SEND=1` plus durable Redis | `mail.send` |
| Permanently delete a single supported message | `MAIL_ENABLE_DELETE=1` plus writes | `mail.write` |

**Permanent deletion can be irreversible.** It requires confirmation for the exact message in your trusted assistant and safe targeted deletion support from the provider. It is unavailable for Gmail/Workspace and Microsoft Graph even when the switch is on. There is no `mail.delete` scope. Moving to Trash is a separate mailbox-write action.

These settings make tools available; they do not authorize the assistant to send, change, or delete mail without the approval required for that action. OAuth consent is access permission, not blanket approval of future mail actions. The server’s unset defaults remain off; this guide explicitly enables the full profile. If you choose narrower access, tell your agent before setup. Read [Safety and permissions](/docs/safety).

## Before your agent begins

Share only non-secret inputs: your GitHub account/repository, Vercel project if one exists, preferred stable domain if you have one, provider, mailbox address, and intended sender address. The agent checks:

- **Source:** fork [amxv/angelos](https://github.com/amxv/angelos) into your own GitHub account, or reuse your existing fork. The source is separate from your private deployment settings. Never commit mailbox credentials or per-owner configuration.
- **Your accounts:** Vercel and Upstash must be yours. Reuse this instance’s existing project and dedicated database where possible; never reuse another person’s Redis or credentials.
- **Mailbox eligibility:** the provider must allow its selected authentication and mail-access route. Spacemail, Gmail/Workspace, Microsoft Outlook/365, iCloud, Yahoo, and custom TLS providers are covered below.
- **Assistant eligibility:** check that your account can add an OAuth-protected remote MCP server before provisioning. Plan, role, and workspace policy can affect the controls. See [ChatGPT availability](https://help.openai.com/en/articles/12584461-developer-mode-and-mcp-apps-in-chatgpt) or [Claude custom connectors](https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp).
- **Execution access:** use the agent’s approved connected-computer tools and existing signed-in sessions. If a login, permission, or secret entry needs you, pause that step and provide the exact page. A browser that supports passkeys is needed for enrollment.

Angelos does not create an email account or offer a hosted signup. Each person gets their own fork, Vercel API project, Redis database, production domain, and passkey owner. Your regular mail app keeps working.

**Approval and secrets:** authorize the accounts, mailbox data hosting, and any costs before provisioning. The agent must not accept paid plans, grant persistent access, enter credentials, or complete security prompts outside its permitted tool routes and your approvals. Use secure login/credential handoff; never put secrets in chat, source code, screenshots, logs, or the docs project. You complete provider consent and passkey prompts yourself.

**Cost and privacy:** small instances may fit free tiers, but hosting is not guaranteed free. Review [Vercel’s plan terms](https://vercel.com/docs/plans) and [Upstash’s limits](https://upstash.com/pricing/redis). Redis holds sign-in state and complete prepared messages for up to 15 minutes. Use a durable database in your account. Deployment eligibility depends on repository ownership and Vercel plan/team rules; verify the requirements for your account. [Vercel Git rules](https://vercel.com/docs/git)

## 1. Create your Vercel API project

**Agent does:** inspect the existing GitHub repository, Vercel project, production domain, and deployment status first. Record non-secret identifiers so interrupted setup can resume without duplicating infrastructure.

1. Create your fork in your GitHub account, or verify and reuse your existing fork. Keep its application code unchanged; per-person settings belong in production environment variables. In [Vercel](https://vercel.com/new), import that fork as a new project, for example `my-angelos`, only if this instance has no project yet.
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

Remove `MAIL_PASSWORD` in OAuth mode. This grants full IMAP/SMTP mail access; Angelos also enforces its own scopes, server gates, and provider safeguards. External Testing grants can expire after seven days; Workspace policy and restricted-scope rules still apply. If an existing grant no longer works, repeat the approved local flow with a new output filename and update the production secret securely. The [Gmail reference](/docs/gmail-workspace) explains eligibility, expiry, and verification requirements. No account or grant is created merely by installing the helper.

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

**Agent does:** inspect existing Entra app registration and mailbox eligibility, then prepare the appropriate delegated application and environment settings with your authorization. **You or your administrator do:** approve app registration, persistent credentials, and delegated `User.Read`, `Mail.ReadWrite`, `Mail.Send`, plus `offline_access` for the refresh grant. These provider permissions are separate from the assistant’s Angelos scopes and server switches. The agent cannot bypass tenant consent policy or create an organization account on your behalf without permission.

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

**Agent does:** check whether a signing key and owner already exist. Reuse the stable signing key and key ID; do not generate a new identity during a retry or update. If this is a new instance, run the recipe below on the approved Linux/macOS computer with Python 3.9+, Git, and OpenSSL. It creates `$HOME/.angelos-private-identity` with mode `0700`, refuses Git-tree or symlink paths, and writes new `0600` files without printing secrets. Stop if the folder or files already exist; inspect setup state rather than overwriting them.

```bash
python3 - <<'PYSETUP'
import hashlib, os, secrets, stat, subprocess
from pathlib import Path

# Absolute owner-private location; never relative to the checkout.
private = Path.home() / ".angelos-private-identity"
os.umask(0o077)
if not private.is_absolute():
    raise SystemExit("Use an absolute private directory outside Git.")
for parent in (private, *private.parents):
    if parent.is_symlink() or (parent / ".git").exists() or (parent / ".git").is_symlink():
        raise SystemExit("Refusing a symlink or a directory inside a Git tree.")
home = private.parent.stat()
if home.st_uid != os.getuid() or stat.S_IMODE(home.st_mode) & 0o022:
    raise SystemExit("The parent must be owner-controlled and not group/world writable.")
probe = subprocess.run(
    ["git", "-C", str(private.parent), "rev-parse", "--is-inside-work-tree"],
    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False,
)
if probe.returncode == 0:
    raise SystemExit("Refusing to generate secrets inside a Git tree.")
private.mkdir(mode=0o700, exist_ok=False)  # An existing setup is never overwritten.
key = subprocess.run(
    ["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"],
    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True,
).stdout
raw = secrets.token_urlsafe(32)
for name, data in {
    "signing-key.pem": key,
    "bootstrap-token.txt": raw.encode(),
    "bootstrap-hash.txt": hashlib.sha256(raw.encode()).hexdigest().encode(),
}.items():
    fd = os.open(private / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(data)
# No key, token, or hash is printed. Do not cat, source, or attach these files.
PYSETUP
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
| `MCP_OAUTH_INITIAL_SCOPES` | `mail.read mail.write mail.send` |
| `ANGELOS_REDIS_REST_URL` | Upstash REST URL from step 2 |
| `ANGELOS_REDIS_REST_TOKEN` | Upstash read/write REST token |
| `ANGELOS_OAUTH_SIGNING_KEY_PEM` | Full contents of `signing-key.pem` |
| `ANGELOS_OAUTH_SIGNING_KEY_ID` | `owner-key-1` — keep stable with this key |
| `ANGELOS_OAUTH_BOOTSTRAP_TOKEN_HASH` | Contents of `bootstrap-hash.txt` |
| `ANGELOS_OAUTH_CHATGPT_CIMD_ENABLED` | `1` |
| `MAIL_ENABLE_WRITES` | `1` |
| `MAIL_ENABLE_SEND` | `1` |
| `MAIL_ENABLE_DELETE` | `1` |

Use lowercase hostnames and no trailing slashes. The issuer is just your HTTPS origin; the other two URLs must use that same origin and exactly the paths shown. `owner` is a label you choose, not an email login or an account to register. Don’t change it after enrollment: it selects your stored identity.

Choose the assistant client configuration now, before deploying:

- **ChatGPT:** keep `ANGELOS_OAUTH_CHATGPT_CIMD_ENABLED=1`. This enables only its pinned metadata identity.
- **Claude.ai:** add the predefined public client below to `ANGELOS_OAUTH_CLIENTS_JSON`. Use this exact callback. If you only use Claude, set the ChatGPT switch to `0`.
- **Both:** keep the ChatGPT switch on and add the Claude entry. Preserve all existing approved entries when editing the JSON array.

```json
[{"client_id":"angelos-claude","client_name":"Claude","redirect_uris":["https://claude.ai/api/mcp/auth_callback"]}]
```

The client ID is a non-secret label. These public clients use PKCE S256 and no client secret. Leave `ANGELOS_OAUTH_VERIFICATION_KEYS_JSON` unset unless performing a deliberate key rotation. Other clients need an exact approved HTTPS callback and compatible public-client OAuth; there is no arbitrary dynamic registration. See [client validation](/docs/oauth-reference#client-validation).

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

## 6. Connect your assistant

Your mailbox password or Google/Microsoft grant connects **Angelos to your mail provider**. Your passkey and Angelos OAuth grant connect **your assistant to Angelos**. Never enter mailbox credentials into the assistant’s connector form.

**Agent does:** provide the verified production MCP URL, check the matching client settings, and guide verification. **You do:** complete the assistant’s account controls, sign in with your passkey, and approve the intended mailbox and all three requested scopes: **`mail.read mail.write mail.send`**. If the consent screen only offers read access, stop and correct the client’s request before calling full setup complete. Existing grants cannot gain scopes through refresh; reconnect and consent again when upgrading a narrower connection.

### ChatGPT example

1. On ChatGPT web, enable developer mode where your account/workspace allows it, then create a custom app from **Settings → Apps**. Name it `Angelos`.
2. Enter **`https://my-angelos.vercel.app/mcp`** and select **OAuth**. With the pinned metadata option configured above, leave optional client ID and secret fields blank.
3. Connect, complete Angelos passkey sign-in and full-scope consent, then finish saving the app after its tools load. Select the app in a new conversation.

The pinned identity is `https://chatgpt.com/oauth/client.json`, with callback `https://chatgpt.com/connector_platform_oauth_redirect`. If the connection presents a different callback or requires manual client settings, use the [predefined-client option](#another-compatible-client) below. Check [OpenAI’s current connection instructions](https://help.openai.com/en/articles/12584461-developer-mode-and-mcp-apps-in-chatgpt) for account eligibility and changing UI labels.

### Claude.ai example

1. In Claude.ai, open **Customize → Connectors → + Add → Add custom connector**. Name it `Angelos` and enter **`https://my-angelos.vercel.app/mcp`**.
2. Choose **Sign in now** for authentication and **Use your own OAuth client**. Enter `angelos-claude`, matching the predefined client configured in step 4. Leave the client secret blank.
3. Complete Angelos passkey sign-in and full-scope consent, then enable the connector in your conversation.

Use the exact hosted callback `https://claude.ai/api/mcp/auth_callback`; the built-in server does not accept Claude Code’s HTTP loopback callbacks. Labels and workspace controls can change. See [Claude’s connection instructions](https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp) and [OAuth requirements](https://claude.com/docs/connectors/building/authentication). Do not select automatic registration: Angelos does not expose that endpoint.

### Verify the connection without changing mail

Ask your connected assistant:

> Use Angelos to check capabilities and list my mailbox folders. Tell me which actions the provider supports. Don’t change or send anything.

The setup agent verifies all three gates are `1` in the deployment settings. The tool’s `permanent_delete_enabled` reports effective provider support, so it stays `false` for Gmail/Workspace and Microsoft Graph even with the delete gate configured. Actual operations also require the granted scopes; a capabilities response alone is not proof that every scoped action can execute.

Then ask:

> Show me the five newest messages in INBOX. Read the one I choose without changing its read status.

Confirm the folders belong to your intended mailbox and an unread message stays unread in your usual mail app. The agent should report the production domain, exact MCP URL, deployed revision if verified, requested/granted scope status, and checks passed. Do not infer a working connection from health alone: tool discovery, intended folders, and an authenticated selected-message read must succeed. No send or destructive action is needed for a connection test.

Your assistant is ready for [inbox work](/docs/inbox-guide), [writing and sending](/docs/sending-guide), and the [Agent playbook](/docs/agent-guide). Before an actual send, review the prepared recipients, subject, body, and attachments. Gmail and Microsoft Graph save Sent automatically: use `append_sent: false`. An uncertain send outcome needs receipt inspection, not an automatic retry.

## 7. Keep your personal instance updated

Once the first connection works, ask your agent to configure [Keep Angelos updated](/docs/keep-updated). The optional daily updater follows eligible upstream releases, validates them, and deploys to your existing project. It needs a one-time approved setup for repository access, Actions, and Vercel deployment credentials; it is not enabled just by forking. Keep your domain, Redis, environment, and signing key unchanged.

## Troubleshooting

| What you see | What to check |
| --- | --- |
| GitHub 404 | Verify the canonical repository URL and your signed-in account; resolve access rather than guessing another source. |
| Vercel page instead of JSON | Confirm the API project root is the repository root, the domain targets it, and production deployment protection permits OAuth discovery. |
| Health says `configured: false`, or MCP returns 503 | Check production variables, exact matching URLs, full PEM, mailbox mode, Redis URL/token, and redeploy after edits. |
| Health works, passkey enrollment fails | Use the configured production domain and fresh enrollment form; check Redis access and the SHA-256 hash of the exact raw token text. |
| Assistant says unknown client or invalid redirect | Verify the selected client ID and exact callback against step 4; preserve other clients when updating the JSON array. |
| Sign-in works, mail fails | Check provider credentials, IMAP access, TLS hostnames, and Google/Microsoft grant or administrator restrictions. Health does not test these. |
| Mail changes or preparation are denied | Check both scopes and server switches; refresh your assistant’s tool definitions after an upgrade. |
| Access stops after working | Check Redis quotas/outages, provider grant expiry, and your connected OAuth grant. Reconnect when its lifetime ends. |

Keep secrets and message contents out of support logs. Do not disable authentication or TLS to work around an error.

### Another compatible client

Angelos is client-neutral at the MCP layer, but each client must support its OAuth contract: authorization code, PKCE S256, public-client token authentication (`none`), exact resource audience, and an explicitly allowed HTTPS redirect. Choose a non-secret client ID and add it to `ANGELOS_OAUTH_CLIENTS_JSON`, preserving existing entries:

```json
[{"client_id":"angelos-my-assistant","client_name":"My assistant","redirect_uris":["REPLACE_WITH_EXACT_VERIFIED_HTTPS_CALLBACK"]}]
```

Redeploy, enter the same client ID in the assistant, leave its client secret blank, and request `mail.read mail.write mail.send`. Keep pinned ChatGPT metadata enabled if another connection uses it. If a client requires a secret, static API key, dynamic registration, or HTTP loopback callback, this built-in flow does not support it. Do not guess callback URLs, add wildcards, or weaken authorization. Another compatible external issuer is an advanced alternative, not an authentication bypass.

For protocol limits, external identity providers, signing-key rotation, and recovery, use the [OAuth reference](/docs/oauth-reference). For every variable and advanced hosting constraints, use the [Configuration reference](/docs/configuration).

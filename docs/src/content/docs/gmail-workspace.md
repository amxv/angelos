---
title: Gmail and Google Workspace
description: Configure one Gmail-enabled mailbox with server-side XOAUTH2 and conservative Gmail-specific safeguards.
summary: Personal/internal Gmail compatibility, separate OAuth planes, manual grant setup, and provider limits.
order: 24
category: Reference
---

If your operator has already connected Gmail, start with [Connect your inbox](/docs/quickstart); this page covers server-side Google setup and its restrictions.

Use the `gmail` preset for a consumer Gmail or Gmail-enabled Google Workspace mailbox, including a custom-domain address. This milestone targets personal/self-hosted and genuine internal Workspace use. It does not create Google credentials, run consent, change administrator settings, or establish live-account eligibility.

The preset uses `imap.gmail.com:993` with implicit TLS and `smtp.gmail.com:465` with implicit TLS. Port `587` is supported with mandatory STARTTLS. Use the complete mailbox address. Gmail endpoints are pinned; custom host overrides and incompatible auth configuration are rejected. [Google protocol settings](https://developers.google.com/workspace/gmail/imap/imap-smtp), [Workspace SMTP settings](https://knowledge.workspace.google.com/admin/gmail/send-email-from-a-printer-scanner-or-app)

## Two separate OAuth systems

- MCP OAuth authenticates a client to Angelos using its configured issuer, resource URL, subject allowlist, and `mail.read`/`mail.write`/`mail.send` scopes.
- Google mailbox OAuth authorizes the server to access its one configured Gmail mailbox. Its credentials remain server-side and never appear in MCP arguments or results.

Google's IMAP/SMTP XOAUTH2 scope is exactly `https://mail.google.com/`. Gmail API scopes such as `gmail.readonly` and `gmail.send` are not substitutes for that protocol scope. The Google grant is broad even when the MCP client has only read permission; Angelos still enforces its own operation scopes and disabled-by-default write/send gates. A Google mailbox access token is not an Angelos MCP token. [Google XOAUTH2 requirements](https://developers.google.com/workspace/gmail/imap/xoauth2-protocol)

## Server configuration

Provision secrets directly through the server's secret manager, never in a repository, chat, screenshot, or token-bearing link.

```dotenv
MAIL_PROVIDER=gmail
MAIL_AUTH_MODE=google_oauth2
MAIL_USERNAME=person@example.com
MAIL_FROM=person@example.com
GOOGLE_CLIENT_ID=your-web-application-client-id
GOOGLE_CLIENT_SECRET=
GOOGLE_REFRESH_TOKEN=
```

The secret fields above are deliberately blank; supply the owner-provisioned values securely. Remove `MAIL_PASSWORD` when using Google OAuth. `google_oauth2` is the Gmail default; it must have a complete matching client ID, client secret, and refresh token. For SMTP STARTTLS, also set `SMTP_PORT=587` and `SMTP_TLS_MODE=starttls`.

`MAIL_FROM` should be the authenticated mailbox or an already authorized Google send-as alias. Angelos does not create aliases or change Google sender settings. `MAIL_ALIASES` only excludes your own addresses from derived replies; it does not grant sender authority. [Google alias setup](https://support.google.com/mail/answer/22370?hl=en)

The server refreshes access tokens at Google's fixed HTTPS token endpoint, caches them only within the backend instance, and honors returned expiry. Refresh requests are bounded, redirects are denied, and errors exclude credentials, tokens and provider response bodies. Authentication happens only after verified TLS and advertised XOAUTH2 support. An OAuth failure never downgrades to a password or retries an email send.

## Manual offline grant setup

The owner or Workspace administrator must decide which Google project, OAuth audience, client, and mailbox grant are appropriate. No grant is created by installing or configuring Angelos.

One official manual route, without adding a callback endpoint to Angelos:

1. Configure the project's Google Auth Platform audience/consent information and a Web application OAuth client. For an External audience, declare `https://mail.google.com/` under Data Access. If the publishing status is Testing, add the intended mailbox under Audience → Test users. [Consent setup](https://developers.google.com/workspace/guides/configure-oauth-consent)
2. Register exactly `https://developers.google.com/oauthplayground` as an authorized redirect URI, without a trailing slash.
3. In [Google OAuth Playground](https://developers.google.com/oauthplayground/), select Google endpoints, Server-side, Offline, and Use your own OAuth credentials.
4. The owner enters the matching client credentials, authorizes only `https://mail.google.com/` as the intended mailbox, and exchanges the authorization code in Step 2.
5. The owner securely provisions the returned refresh token and matching credentials on Angelos. No Playground Step 3 API request or Angelos callback UI is needed.

Playground states that entered credentials pass through its proxy server. Credential entry, consent and server provisioning must therefore remain owner-manual. Do not share Playground links that contain tokens. Using your own credentials avoids Playground's default-client 24-hour token revocation; it does not remove Google's other expiry or policy restrictions. [Official Playground walkthrough](https://developers.google.com/admob/api/v1/how-tos/playground), [offline access](https://developers.google.com/identity/protocols/oauth2/web-server#offline)

This setup uses IMAP/SMTP rather than the Gmail REST API. Follow the requirements shown for the actual project and consent configuration; Angelos has no OAuth callback URL to register.

## Workspace and consent restrictions

Workspace administrators can disable IMAP for users or organizational units, restrict approved OAuth client IDs, and block applications or sensitive data access. Internal applications may still need administrator approval. Ask the administrator to review the required access; do not weaken organization policy to make a connection work. [IMAP policy](https://knowledge.workspace.google.com/admin/sync/turn-pop-and-imap-on-or-off-for-users?hl=en), [app controls](https://knowledge.workspace.google.com/admin/apps/control-which-apps-access-google-workspace-data?hl=en)

An Internal OAuth audience requires an organization-owned project and organization members. Consumer Gmail or users from other organizations need an External audience. External Testing is limited to listed test users, and mail authorizations/refresh tokens expire after seven days. Publishing an app and completing verification are separate steps. [Google audience rules](https://support.google.com/cloud/answer/15549945?hl=en)

### Public distribution caveat

The full-mail scope is restricted. Public applications generally face verification and, when restricted data is handled server-side, security-assessment requirements unless a documented exception applies. Personal use and genuine internal use have exceptions; they do not waive consent or Workspace policy. [Restricted-scope verification](https://developers.google.com/identity/protocols/oauth2/production-readiness/restricted-scope-verification)

Google's current verification FAQ says IMAP/SMTP applications must have a genuine need for permanent deletion bypassing Trash to justify the full-mail scope; otherwise it directs developers to narrower Gmail API scopes. Angelos deliberately disables Gmail permanent deletion in this milestone. Therefore this implementation does not promise eligibility for a shared public Google OAuth application's verification. Open-sourcing code is separate from operating such an application. A Gmail API adapter with narrower scopes is a possible later architecture, not an implemented feature. Destructive behavior will not be added merely to satisfy a verification criterion. [Google verification FAQ](https://support.google.com/cloud/answer/13463817?hl=en)

## Explicit app-password alternative

Where the account and administrator permit it, select `MAIL_AUTH_MODE=app_password` with `MAIL_PROVIDER=gmail` and put an eligible Google app password in `MAIL_PASSWORD`. Clear the Google OAuth credential variables for this mode. Ordinary Google account passwords are not a supported alternative.

App passwords require 2-Step Verification and may be unavailable with organizational restrictions, security-key-only verification, or Advanced Protection. Account password changes revoke them. Eligibility must be checked by the owner/admin; Angelos neither creates app passwords nor changes security settings. [Google app-password conditions](https://support.google.com/accounts/answer/185833?hl=en), [Workspace OAuth transition](https://knowledge.workspace.google.com/admin/sync/transition-from-less-secure-apps-to-oauth?hl=en)

## Gmail mailbox behavior

- Gmail labels appear as IMAP folders. One message can have multiple folder/UID references. Existing folder/UIDVALIDITY/UID identity remains authoritative for actions; Gmail global message/thread IDs are not substituted.
- Special folders are discovered from actual LIST attributes, including when the server does not advertise SPECIAL-USE. Localized names are supported; ambiguous roles fail safely. All Mail is an aggregate and is not guessed as an Archive destination.
- Native MOVE support is checked at runtime. There is no COPY/Deleted/global-EXPUNGE emulation when it is absent.
- `mail_delete_permanently` is blocked for Gmail before any Deleted/EXPUNGE mutation. Gmail's auto-expunge and last-label behavior depend on account settings; disappearance of one label UID does not prove permanent deletion.
- Gmail SMTP saves Sent automatically. Use `append_sent: false`. A true value is rejected before claim/SMTP, so the client can correct it without consuming the prepared ID. Backend Sent APPEND is also guarded.
- Gmail-specific `X-GM-RAW`, labels, global IDs, and thread APIs are not exposed as new tool inputs. The existing `query` remains plain IMAP text search, and generic keyword flags are not a Gmail label API.

[Google IMAP extensions](https://developers.google.com/workspace/gmail/imap/imap-extensions), [Gmail client behavior](https://support.google.com/mail/answer/78892?hl=en), [Gmail expunge settings](https://developers.google.com/workspace/gmail/api/reference/rest/v1/ImapSettings)

## Reauthorization and testing

Grants can stop working after revocation, inactivity, password changes affecting Gmail scopes, token limits, time-limited access, or administrator changes. The owner must reauthorize or correct configuration through an approved flow. Never treat an authentication problem as permission to resend an unknown SMTP outcome. [Google token lifecycle](https://developers.google.com/identity/protocols/oauth2#expiration)

Automated verification uses synthetic TLS IMAP/SMTP and token-endpoint fixtures: it covers refresh/cache/failure/redaction, XOAUTH2 exchanges, scope/gate separation, discovered roles, deletion rejection, Sent-copy prevention, and the existing durable send rules. No real Gmail grant, mailbox operation or delivery is established by those tests. Interactive consent UI, service-account domain-wide delegation, Gmail API transport, and account administration are outside this milestone.

Google setup and policy sources were checked on 2026-10-06. Live eligibility and administrator policy still need owner verification.

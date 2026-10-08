---
title: Microsoft Graph reference
description: Delegated Outlook.com and Microsoft 365 access, account-bound message identity, and Graph-specific limits.
summary: Provider permissions, secure grant inputs, native references, paging, and safe send behavior.
order: 44
category: Reference
---

For the full installation sequence, use [Connect Your Assistant](/docs/quickstart#outlookcom-and-microsoft-365). This page explains the Microsoft connection and its differences from IMAP. Each instance still serves one owner and one configured primary mailbox.

## Account and permission boundaries

`MAIL_PROVIDER=microsoft` uses delegated Microsoft Graph access to `/me`. It does not use Exchange Basic authentication, SMTP AUTH, a password preset, application-wide permissions, service-account impersonation, or shared mailboxes. It supports the global Microsoft cloud only; identity and API hosts are pinned to `login.microsoftonline.com` and `graph.microsoft.com`.

The configured account must have a usable primary mailbox. `MICROSOFT_ACCOUNT_ID` must equal Graph `/me.id`, and both `MAIL_USERNAME` and `MAIL_FROM` must match `/me.mail`. A display name, sign-in alias, or a guessed address is insufficient. The backend checks this identity before mailbox work. Sender aliases are unsupported.

Provider consent requests delegated `User.Read`, `Mail.ReadWrite`, `Mail.Send`, and `offline_access` for a refresh grant. These permissions allow more than Angelos's default read-only capability switches. The MCP token, feature gates, and per-action assistant approvals remain independent safeguards. Registering an app or granting consent does not enable `MAIL_ENABLE_WRITES` or `MAIL_ENABLE_SEND`.

Personal Outlook.com uses the `consumers` tenant. A work/school deployment uses the exact organization tenant UUID. The Entra application must permit the selected account audience. Organization policy can restrict app registration, user consent, or mailbox access; an administrator may need to approve it. Do not weaken tenant security or substitute application permissions to bypass a denial. [Microsoft delegated access](https://learn.microsoft.com/en-us/graph/auth-v2-user)

## Initial grant and runtime refresh

The initial grant is an owner-authorized confidential web application's authorization-code flow with PKCE, an exact registered redirect URI, and state validation. The owner enters the client secret through a secure local prompt/file and completes Microsoft's browser consent. Secrets and callback codes must never be pasted into chat or printed in logs. The executable helper and its exact command belong to the [canonical setup sequence](/docs/quickstart#outlookcom-and-microsoft-365). [Microsoft authorization-code requirements](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow)

The resulting client ID, client secret, refresh token, tenant, verified account ID, and primary mailbox address configure the API environment. The helper's private output is not automatically loaded by the Go process; transfer it through an approved secure credential route and redeploy Production. Do not upload it to GitHub, the docs project, or a support conversation.

Runtime access-token refresh is server-side. Microsoft connections require the configured durable Redis REST store even when only reading mail or using an external MCP issuer. Set `MICROSOFT_TOKEN_ENCRYPTION_KEY` to a stable 32-byte random key encoded as 64 hexadecimal characters; keep it in the API project's protected environment, outside Redis. The setup helper generates it only for an explicitly new instance. Preserve it during updates and grant renewal.

Rotated refresh tokens are encrypted with AES-GCM before Redis storage; their namespace and authenticated context bind the application, tenant, account, sender, and initial configured refresh-grant generation. Compare-and-set prevents a stale process from overwriting a newer stored value. Invalid ciphertext, wrong keys, or store errors fail closed. Records and an initialization marker have no automatic expiry. Losing either member of an initialized record/marker pair fails closed. If both are absent, the store treats it as bootstrap from the initial environment seed; that cannot distinguish a new installation from complete state loss. This is not full-store rollback/replay protection, and an expired or revoked seed requires reauthorization. Do not clear Redis, enable eviction, regenerate the key, or change identity fields as a troubleshooting shortcut.

An explicit newly authorized initial refresh token starts a new stored generation. Renewing consent must preserve the encryption key and use the approved secure deployment route. Provider expiry, revocation, client-secret expiry, Conditional Access, or administrator policy may still require a fresh owner grant; durable storage does not bypass those controls.

## Mailbox behavior

- **Native identifiers:** copy the complete returned message `reference`, including its provider, account, folder, and opaque ID. Do not invent UID/UIDVALIDITY values. Folder results use native IDs as their operational names; display names are for presentation. Discover special-folder IDs through capabilities.
- **Paging:** newest/oldest follows received time, not an IMAP UID snapshot. Concurrent arrivals, moves, or deletions can change later pages. Reuse the supplied cursor with unchanged filters; an empty page can still have a next cursor. Restart after changing filters or a rejected cursor.
- **Search:** filters are literal, with exact Message-ID matching. General text search matches decoded visible text and selected headers, not attachment bytes. It may read bounded MIME content to evaluate the query; it does not mark messages read. Graph does not provide the IMAP guide's headers-only triage promise when a text query needs content.
- **Reads and attachments:** MIME reads and attachment extraction remain bounded. Message size is unknown in Graph search summaries until the message is read. Reading does not set the Seen/read flag. Batch results retain per-item failures and continuation.
- **Mailbox changes:** supported operations include folder creation/rename, copying, moving, Trash, saved MIME drafts, and Seen/Flagged changes. Use returned destination references after moves/copies. There is no conditional MODSEQ update, arbitrary IMAP keyword support, or permanent deletion.
- **Conversations:** header-linked `conversation` traversal is unsupported on this adapter. Use supported search/read operations without claiming a complete thread.
- **Drafts and composition:** structured saved-draft limits still apply. Derived replies, reply-all, and forwards use the existing reviewed composition flow. The backend does not silently rewrite a lossy draft or choose a sender alias.
- **Sending:** Graph queues the prepared MIME message and files Sent automatically. Set `append_sent: false`; requesting a second Sent copy is rejected before dispatch. Queued/accepted does not prove delivery. [Microsoft sendMail behavior](https://learn.microsoft.com/en-us/graph/api/user-sendmail?view=graph-rest-1.0)
- **Failures:** mutation requests are not automatically retried after transport errors or ambiguous outcomes. Check the existing receipt and current mailbox state before deciding what happened. Never resend just because a response was lost.

Angelos still requires its durable one-time send claim for dispatch. It does not turn Graph into an exactly-once delivery service or provide a transaction across another mail client's changes.

## Verify an actual account

Synthetic tests validate code paths, not Microsoft consent eligibility or a live mailbox. After deployment, check provider capabilities, the verified intended folders, and an owner-selected read with write/send/delete switches off. Health alone checks configuration; it does not prove that Microsoft issued a usable grant or that the account matches `/me`.

Use disposable content and explicit permission for any later mutation or send test. If consent is blocked or a primary address is unavailable, report that account-specific blocker rather than treating fixture success as a working connection.

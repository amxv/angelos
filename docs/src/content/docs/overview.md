---
title: Meet Angelos
description: Let an AI assistant help with your existing inbox, while you keep the mail apps you already use.
summary: What Angelos does, what you need, and where to start.
order: 2
category: Get started
---

Angelos connects an AI assistant to your existing email account. Ask it to find a receipt, catch you up on an exchange, organize messages, or prepare a reply for review. You can keep using Apple Mail or another mail app alongside it.

It is a self-hosted connection between an assistant and one mailbox. There is no Angelos-hosted signup or new email account to create. Your agent can set up the service in your own accounts; you approve access, enter secrets securely, and complete passkey enrollment. Each person runs a separate instance. The setup guide configures all supported capabilities together after explaining their permissions.

## Start with something useful

Once connected, try:

> Show me unread or flagged messages from this week. Read the relevant messages and suggest which might need a response. Leave everything unchanged.

Or ask a narrower question:

> Find the invoice from billing@example.com that arrived last month. Tell me what attachments it has.

Angelos supplies the mail and the tools; your assistant interprets the request and explains what it found. Reading through Angelos does not mark a message as read. Unread or flagged mail is a useful starting point, but those flags alone do not tell the assistant what is urgent.

## What you can do

- **Find and understand mail.** Search folders, read messages, retrieve attachments, and look up related messages linked by email headers in the same folder.
- **Organize your inbox.** Mark messages read, add flags, create folders, copy or move mail, and move messages to Trash.
- **Write with review.** Prepare new messages, replies, reply-all, and forwards. Review the final recipients, text, and attachments before sending.
- **Keep your usual mail app.** Both clients use the same server mailbox. Changes made in either can appear in the other.

The setup guide enables reading, mailbox changes, sending, and supported permanent deletion from the outset. These have separate operator-controlled gates and OAuth scopes. Permanent deletion can be irreversible and is unavailable for Gmail/Workspace and Microsoft Graph. Your client remains responsible for getting approval for individual mail actions. First-party OAuth consent grants a client scopes; it is not approval of a particular message or mailbox change.

## Choose a mailbox

Spacemail is the default provider. iCloud and Yahoo use provider app passwords. Gmail and Google Workspace use eligible app passwords or Google OAuth credentials provisioned by the mailbox owner on the server. Microsoft Outlook.com and eligible Microsoft 365 accounts use delegated Microsoft Graph access. Other compatible IMAP/SMTP providers can use password authentication. Gmail setup is not an interactive Angelos account-linking flow.

## Know the boundaries

Angelos sees server mail, not local-only folders or unsynchronized drafts in a desktop app. Related-message lookup is not a complete account-wide thread: it can miss mail in other folders or without usable header links. Supported structured drafts can be read, revised into a new saved copy, and prepared for review. Revisions preserve the original; unsupported or lossy MIME is rejected.

It also does not manage mail accounts, provider filtering rules, or desktop-only rules. See [capabilities and limits](/docs/tools) for the exact surface.

## Choose your next step

- **I’m getting started:** follow [Connect Your Assistant](/docs/quickstart), from deployment to your first request in ChatGPT, Claude.ai, or a compatible assistant.
- **I want updates handled for me:** use [Keep Angelos updated](/docs/keep-updated) after your first connection works.
- **I want everyday examples:** open [Work with your inbox](/docs/inbox-guide) or [Write and send mail](/docs/sending-guide).
- **I am building an agent:** use the [Agent playbook](/docs/agent-guide), then the [tool reference](/docs/tools).

For shared-mailbox effects, private-data handling, and approval responsibilities, read [Safety and concurrency](/docs/safety).

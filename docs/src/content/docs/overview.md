---
title: Overview
description: Use an existing mailbox through a private Go MCP server while keeping your other mail clients.
summary: Start here for capabilities, safe defaults, and setup order.
order: 1
category: Start
---

# Overview

Angelos gives an agent a scoped interface to one existing IMAP/SMTP mailbox. It runs as an OAuth-protected remote MCP server written in Go. Apple Mail and other IMAP clients can remain connected to the same account.

Version 0.6.0 groups 21 operations into six MCP tools. It adds read-only inbox triage and same-folder, header-linked conversation lookup, while retaining Gmail/Workspace support through server-side XOAUTH2. See [Migration and token budget](/docs/tool-migration) for the client contract and [Gmail and Google Workspace](/docs/gmail-workspace) for provider setup and limits.

## What it supports

- Discover provider capabilities and folders, search mail, and read plain-text content without marking messages read
- Triage unread or flagged messages with counts for the returned page, then inspect a bounded conversation using exact header links
- Opt into mailbox organization, including flags, folders, copies, moves, Trash, and saved drafts
- Connect Gmail/Workspace through owner-provisioned XOAUTH2, with provider-specific safeguards
- Prepare messages, natural replies/reply-all, and quoted or attached forwards with fully reviewed recipients and attachments
- Send a reviewed immutable message through a durable, one-time dispatch claim

Read access is the default. Mailbox writes, sending, and permanent deletion have separate deployment gates. Tokens also need the applicable scopes. Some operations require provider capabilities; unsupported operations fail rather than falling back to a mailbox-wide destructive command.

The [tool reference](/docs/tools) describes current arguments, limits, and exclusions. “Email access” does not include a provider's account settings, server-side filtering rules, or desktop-only mail data.

## Inbox workflow

1. Call `mail_query` with `action: "triage"` to find unread or flagged messages. Add ordinary search filters when useful. Counts describe only the returned rows; unread and flagged counts overlap and do not indicate urgency.
2. Choose an exact message reference and call `mail_query` with `action: "conversation"` for related summaries in that folder. Follow its own cursor even after an empty page.
3. Read the exact references needed to understand the exchange. Conversation summaries contain no message bodies and are not a complete account-wide thread.
4. If a response is wanted, use `mail_prepare` with `action: "reply"` or `"reply_all"`, then review the full preparation before separately authorizing sending.

See the [copyable workflow examples](/docs/tools#inbox-workflow-example). Both query actions are read-only, with a default 25-row limit, a maximum of 100 rows, and at most one 1000-UID scan window per call. They do not mark messages read. Conversation linkage uses a fixed set of IDs from the anchor's Message-ID, References, and In-Reply-To headers, without subject matching or recursive expansion. Messages in other folders or without usable links may be missing.

Saving a draft still creates a new message. Lossless opening and editing of an existing saved draft is not supported.

## Setup order

1. Read [Safety and concurrency](/docs/safety), especially the trusted-client confirmation boundary.
2. Choose a mailbox and set its [configuration](/docs/configuration).
3. Configure an existing OAuth issuer using [Authentication](/docs/authentication).
4. [Deploy the API](/docs/deployment) separately from this static documentation site.
5. Verify reads before enabling changes or sends.

No mailbox credentials, OAuth account, or deployment are created by cloning the repository. Automated tests and a successful build do not replace validation against your own provider.

## Contribute

Keep documentation aligned with implemented behavior. See [Architecture](/docs/architecture), [Testing](/docs/testing), and [Writing docs](/docs/writing-docs).

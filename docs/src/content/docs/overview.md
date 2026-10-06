---
title: Overview
description: Use an existing mailbox through a private Go MCP server while keeping your other mail clients.
summary: Start here for capabilities, safe defaults, and setup order.
order: 1
category: Start
---

# Overview

Angelos gives an agent a scoped interface to one existing IMAP/SMTP mailbox. It runs as an OAuth-protected remote MCP server written in Go. Apple Mail and other IMAP clients can remain connected to the same account.

## What it supports

- Discover provider capabilities and folders, search mail, and read plain-text content without marking messages read
- Opt into mailbox organization, including flags, folders, copies, moves, Trash, and saved drafts
- Prepare messages, natural replies/reply-all, and quoted or attached forwards with fully reviewed recipients and attachments
- Send a reviewed immutable message through a durable, one-time dispatch claim

Read access is the default. Mailbox writes, sending, and permanent deletion have separate deployment gates. Tokens also need the applicable scopes. Some operations require provider capabilities; unsupported operations fail rather than falling back to a mailbox-wide destructive command.

The [tool reference](/docs/tools) describes current arguments, limits, and exclusions. “Email access” does not include a provider's account settings, server-side filtering rules, or desktop-only mail data.

## Setup order

1. Read [Safety and concurrency](/docs/safety), especially the trusted-client confirmation boundary.
2. Choose a mailbox and set its [configuration](/docs/configuration).
3. Configure an existing OAuth issuer using [Authentication](/docs/authentication).
4. [Deploy the API](/docs/deployment) separately from this static documentation site.
5. Verify reads before enabling changes or sends.

No mailbox credentials, OAuth account, or deployment are created by cloning the repository. Automated tests and a successful build do not replace validation against your own provider.

## Contribute

Keep documentation aligned with implemented behavior. See [Architecture](/docs/architecture), [Testing](/docs/testing), and [Writing docs](/docs/writing-docs).

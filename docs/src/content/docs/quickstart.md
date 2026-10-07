---
title: Connect your assistant
description: Connect to an existing Angelos server and try a read-only inbox task.
summary: Get the connection details, sign in, and check your first results.
order: 2
category: Get started
---

This guide is for using an Angelos server that is already running. If you are setting one up yourself, follow [Self-host Angelos](/docs/self-hosting) first. Cloning the repository or opening this documentation does not create a server, mailbox, or sign-in account.

## 1. Get the connection details

Ask the person running Angelos for:

- **The MCP URL**, usually an HTTPS address ending in `/mcp`. MCP is the connection protocol your assistant uses to access tools.
- **The sign-in service and account to use.** The operator can use Angelos's owner-only passkey sign-in or an external OAuth issuer. Use the enrolled owner passkey or the account allowed by that operator.
- **Any client setup details** required by that sign-in service and your assistant app.
- **The connected mailbox and enabled actions:** reading, mailbox changes, sending, or permanent deletion.

An Angelos deployment connects to one configured mailbox. Choosing another mailbox is an operator setup change, not an option in a prompt.

If you are the operator, [Authentication](/docs/authentication) explains the issuer, client, and redirect setup. [Configuration](/docs/configuration) covers mailbox credentials and feature switches. Gmail owners should also read [Gmail and Google Workspace](/docs/gmail-workspace).

## 2. Add Angelos to your assistant

Use an assistant app that supports remote MCP with OAuth. In its MCP connection setup, enter the operator-provided URL and select OAuth authentication. Supply client details if your setup requires them, then sign in with the approved account.

The OAuth sign-in authorizes the assistant to call Angelos. It is separate from the server's login to your mailbox. Do not paste mailbox passwords, Google refresh tokens, or other server secrets into a conversation.

The app's connection screens can vary. For ChatGPT-specific issuer and connection requirements, see [Connect ChatGPT](/docs/authentication#connect-chatgpt). An operator may need to register the exact callback shown by your app before sign-in will work.

## 3. Check access before changing anything

Try this prompt:

> Check Angelos's capabilities and list the folders in my connected mailbox. Tell me which actions are enabled. Do not change anything.

Confirm that the folder list belongs to the expected mailbox. Tool names can appear even when an action is disabled, so successful connection alone does not establish that sending or organization is available.

Then try a small read:

> Show me the five newest messages in INBOX, then read the one I choose. Leave their read status unchanged.

Reading does not mark messages read. “Newest” here means mailbox arrival order, which can differ from the date written in a message.

## 4. Start with a clear request

> Find messages from billing@example.com received since 2026-09-01. Summarize the relevant ones and tell me if any result is incomplete.

Use [Work with your inbox](/docs/inbox-guide) for search, triage, attachments, and organization. For replies and forwards, follow [Write and send mail](/docs/sending-guide).

Start with reads, then enable more capabilities deliberately. Preparing a send already requires send permission, the sending switch, and a configured durable store, even though preparation does not send mail.

## If something is unavailable

- **Sign-in fails:** ask the operator to check the exact endpoint, sign-in account, issuer, and granted permissions.
- **Reading works but changes fail:** the action may lack a permission, an enabled switch, or provider support. Do not keep retrying it.
- **The tool list looks outdated:** refresh the connection's tools after a server update.
- **Mail or folders seem missing:** check the selected folder and search range. Desktop-only mail is outside Angelos's view.

Share error text with the operator, without including credentials or private message contents unnecessarily.

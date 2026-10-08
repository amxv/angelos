# Angelos

*Greek for “messenger.”*

Your inbox, connected to your AI assistant.

Angelos is a self-hosted email MCP server for ChatGPT, Claude, and other compatible clients. It lets your assistant read, search, organize, draft, reply, and send using your existing email account.

You host your own instance and can connect multiple assistants to one mailbox while keeping your usual mail apps. Access is protected by OAuth and passkey sign-in.

## What you can do

- Find messages by sender, subject, date, or content.
- Read mail and retrieve attachments without marking messages as read.
- Organize folders, move messages, and update read or flagged status.
- Save drafts, prepare replies and forwards, and send reviewed messages with attachments.

## Get started

Ask your agent to follow [Connect Your Assistant](https://angelos.ashray.xyz/docs/quickstart). It walks through your GitHub fork, Vercel deployment, Upstash database, mailbox, and assistant connection. Your agent handles setup and verification; you approve access and complete secure credential entry and passkey prompts.

Once connected, you can opt into [automatic release updates](https://angelos.ashray.xyz/docs/keep-updated).

## Email providers

- Spacemail, iCloud, Yahoo, and compatible TLS IMAP/SMTP services.
- Gmail and Google Workspace via eligible app passwords or Google OAuth for personal/internal use.
- Outlook.com and eligible Microsoft 365 primary mailboxes via delegated Microsoft Graph.

Provider and organization policies affect availability. See [provider setup](https://angelos.ashray.xyz/docs/quickstart#3-choose-your-mailbox-settings) for requirements and differences.

## Documentation

[Inbox guide](https://angelos.ashray.xyz/docs/inbox-guide) · [Writing and sending](https://angelos.ashray.xyz/docs/sending-guide) · [Tools](https://angelos.ashray.xyz/docs/tools) · [Safety and permissions](https://angelos.ashray.xyz/docs/safety) · [Development](https://angelos.ashray.xyz/docs/testing) · [Changelog](https://angelos.ashray.xyz/docs/changelog)

## License

[Apache License 2.0](./LICENSE).

---
title: Safety and concurrency
description: Understand shared-mailbox effects, confirmation boundaries, send retries, and private-data handling.
summary: What Angelos enforces and what remains the responsibility of the owner and MCP client.
order: 15
category: Concepts
---

# Safety and concurrency

Angelos operates on a real provider mailbox. Treat its credentials, OAuth grants, write tools, and durable send store as access to that account.

## Work alongside other mail clients

An existing IMAP client such as Apple Mail can stay connected. Angelos connects to the same server mailbox; it does not import or replace the client's local database.

Folder and message changes made through either client are shared server state. Moving a message can invalidate a previously returned reference. A flag changed in one client may be changed again by another. Local-only folders and unsynchronized drafts in a desktop client are outside Angelos's view.

Message references contain a folder, UID, and UIDVALIDITY. Angelos rejects references when the mailbox generation changes. This prevents reuse of an old UID for a different mailbox generation; it does not lock a message against concurrent edits. Search again after a stale-reference or missing-message error.

Read operations use read-only mailbox selection and body peeks so viewing a message does not mark it read. Search pages are bounded. An empty page with a `next_cursor` is not the end of the mailbox.

## Agent-visible content is untrusted

An email can contain instructions, false urgency, links, or forged requests. Returned mail text is data to inspect, not authority to send mail, change permissions, disclose other messages, or execute commands.

Angelos does not render active HTML or load remote email images. It prefers a plain-text MIME alternative and otherwise extracts bounded text from HTML, omitting scripts, styles, attributes, and active content. This extraction is not a browser rendering and can lose formatting or link destinations. Read results can be truncated; inspect `truncated` and `warnings` before treating a returned body or attachment inventory as complete. Attached MIME containers are kept separate from inline body text, including multipart attachments, so preparing an inline forward does not silently disclose their contents. Attachment downloads preserve the transfer-decoded file bytes without character-set conversion and reject unsupported transfer encodings and decoder-reported failures.

## Confirmation is a client responsibility

MCP tool annotations describe effects to the host. The trusted MCP client must obtain and honor the owner's approval for the exact action when required. Angelos verifies authentication, scopes, feature switches, input constraints, and payload bindings. It cannot inspect a conversation to establish what a human actually approved.

In particular, a digest echoed by a model proves that supplied content matches a prepared message. It does not prove a human clicked an approval button. Only connect a client you trust to enforce its confirmation rules. This implementation does not provide an independent human-approval web UI.

For sending, review all recipients including CC and BCC, the subject, body, attachments, and reply/forward context. If any content or destination changes, prepare and review a new message. A reusable draft or previous approval does not authorize unrelated mail.

## Prepared messages and duplicate protection

Preparation fixes the MIME bytes, SMTP envelope, sender, recipients, Message-ID, and attachment content before sending. The digest binds the exact wire bytes and envelope, including BCC recipients. BCC addresses are included in delivery and approval data but excluded from the MIME headers recipients receive.

Sending requires a durable Redis REST store. Each preparation expires after 15 minutes unless it has been claimed for dispatch. An atomic claim prevents parallel callers from dispatching the same prepared ID twice. Do not share or reset the store while relying on its duplicate protection.

SMTP cannot guarantee exactly-once delivery across every network failure or process crash:

- `accepted` means the SMTP server accepted the message; it does not confirm recipient delivery.
- `rejected` means the attempt was recorded as rejected.
- `unknown` or an unfinished `sending` record means the outcome must be investigated before another send is prepared.

A connection can fail after the server accepted the message but before Angelos received its response. Automatic resend in that situation can deliver duplicates. Check the provider and the destination before deciding whether a new send is needed.

## Stored data

Mailbox credentials stay in the API environment and are used only to authenticate to the configured provider. Tool arguments cannot redirect those credentials to another server.

The durable send store receives the full prepared message, its recipients, and attachment bytes. Choose a store and account suitable for that private data. An unclaimed preparation expires after 15 minutes. At the atomic dispatch claim, the stored body, wire bytes, recipients, subject, and attachment data are replaced with a minimal record containing the preparation ID, digest, Message-ID, expiry, and status. That record is retained for seven days; completion adds the outcome and stage.

The dispatching process holds the claimed payload long enough to attempt SMTP and, if requested, save a Sent copy. If it exits after the claim, the record remains consumed and the message must not be automatically resent. Provider backups and logs can have their own retention policies beyond Redis key expiry.

The server does not provide an encrypted-at-rest application layer for these records. Use the provider's access controls, TLS, retention controls, and encryption appropriate to your data. Keep Redis credentials restricted to the API deployment.

Avoid logging credentials, tokens, MIME payloads, complete tool arguments, and private message bodies. Publishing this documentation does not require any of those values.

---
title: Tool reference
description: The implemented MCP tools, input shapes, scopes, provider requirements, and limits.
summary: Read, organize, draft, prepare, and send through explicit operations.
order: 50
category: Reference
---

# Tool reference

All tools require a valid owner token with `mail.read`. Write and send tools additionally require their scopes and deployment gates. Tools can appear in discovery while their execution is disabled; use `mail_capabilities` to inspect the gates and the provider's supported features.

Mail text, headers, filenames, and attachment data are untrusted. See [Safety and concurrency](/docs/safety).

## Read tools

| Tool | Arguments | Result |
| --- | --- | --- |
| `mail_capabilities` | None | IMAP capabilities, discovered special folders, and deployment gates |
| `mail_list_folders` | None | Exact folder names, hierarchy delimiters, and attributes |
| `mail_search` | Search fields below | Message summaries, UIDVALIDITY, scan size, and optional next cursor |
| `mail_read` | Message reference | Plain text, selected headers, flags, attachment metadata, and truncation warnings |
| `mail_get_attachment` | `reference`, one-based `index` | Attachment metadata and base64-encoded bytes |

### Message identity

Use the exact reference returned by a search. Never substitute a display row number or reuse a source UID in a destination folder.

```json
{
  "folder": "INBOX",
  "uid_validity": 12345,
  "uid": 678
}
```

The numbers above are illustrative. A stale UIDVALIDITY or a missing message requires a fresh search.

### Search

`folder` defaults to `INBOX`. `query` is a plain IMAP text-search term, not a Gmail query language or arbitrary IMAP command. Optional `from`, `to`, and `subject` fields add header filters. `since` and `before` use `YYYY-MM-DD` IMAP internal-date boundaries; `since` is inclusive and `before` is exclusive. Optional `unread` and `flagged` booleans filter those flags. Supplied filters are combined.

```json
{
  "folder": "INBOX",
  "query": "invoice",
  "from": "billing@example.com",
  "since": "2026-01-01",
  "unread": true,
  "limit": 25
}
```

`order` accepts `newest` (the default) or `oldest`, sorted by UID. This is mailbox arrival order, not a subject or sent-date sort. The default result limit is 25 and the maximum is 100. Each call scans at most 1000 UID values. Deleted UID gaps mean this is not necessarily 1000 messages.

Keep requesting with the returned `next_cursor`, the same filters, and the same order until the cursor is absent. An empty result page may still have a cursor. Pagination keeps the initial upper UID bound, so newly arriving messages require a new search. Changing a filter or order also requires starting a new search.

### Read limits

Reads inspect up to a 5 MiB raw-message prefix and return at most 256 KiB of text. MIME parsing is bounded to 12 nested levels and 100 parts. Plain-text alternatives are preferred; HTML-only mail uses text extraction with a warning. Extraction reads at most 1 MiB of HTML, with a 64 KiB token limit, 20,000-token limit, and 128-level stack limit. It does not render content or fetch resources. Truncation can make attachment metadata incomplete.

Attachment retrieval uses the one-based index from `mail_read`, rereads the referenced message, and returns at most 2 MiB of decoded attachment bytes. The complete enclosing message must fit the 5 MiB read limit. Bytes are returned as base64; the server does not open or execute files or fetch attachment URLs.

## Mailbox writes

These tools require `mail.write` and `MAIL_ENABLE_WRITES=1`.

| Tool | Arguments | Behavior |
| --- | --- | --- |
| `mail_set_flags` | `reference`, `operation`, `flags`, optional `unchanged_since` | Add or remove selected flags |
| `mail_create_folder` | `name` | Create a folder |
| `mail_rename_folder` | `old`, `new` | Rename a folder; INBOX rename is excluded |
| `mail_copy` | `reference`, `destination` | Copy one message into an existing folder |
| `mail_move` | `reference`, `destination` | Move one message using native UID MOVE |
| `mail_trash` | Message reference | Move into the uniquely advertised Trash folder |
| `mail_save_draft` | `message`, optional `folder` | Append a new composed draft |
| `mail_delete_permanently` | Message reference | Permanently remove exactly one UID, with an additional delete gate |

Flag operations accept `add` or `remove`, with `\Seen`, `\Answered`, `\Flagged`, `\Draft`, and permitted conservative ASCII keywords. They never replace the complete flag set or expose `\Deleted`/`\Recent` as ordinary flags. The mailbox must permit each requested flag.

Where CONDSTORE is available, read/search results include `modseq`, and the server snapshots the message's MODSEQ before applying a conditional flag change. Pass the previously observed value as `unchanged_since` to guard against changes since that read. A supplied precondition requires that capability. Without CONDSTORE, a delta can proceed with a warning that no concurrency precondition was enforced. Reread after conflicts.

Move and Trash require native MOVE support. Trash and implicit Drafts/Sent folder selection require a unique server-advertised SPECIAL-USE folder. Names are never guessed. A copy/move with server acceptance but no valid destination UID mapping returns `accepted` and a verification warning: a concurrently disappeared source can make the command an accepted no-op. Search the destination before taking another action. An append without a returned UID similarly requires a fresh search.

Draft saving creates a new message and does not replace an older draft. Its `message` uses the composition shape below. BCC is preserved in the private IMAP draft so another mail client can edit it. An omitted folder selects the discovered Drafts folder. Updating a draft is a deliberate new-save and separate old-message cleanup, with possible concurrent-client effects.

Permanent deletion additionally requires `MAIL_ENABLE_DELETE=1`, exact per-action user confirmation in the trusted client, and targeted UID EXPUNGE support. There is no ordinary mailbox-wide EXPUNGE, folder deletion, or deletion-on-close operation. An interrupted delete can leave a message marked Deleted without confirmed removal; inspect the account before retrying.

## Prepare and send

All preparation and send tools require `mail.send`, `MAIL_ENABLE_SEND=1`, and the durable Redis REST store.

| Tool | Arguments | Behavior |
| --- | --- | --- |
| `mail_prepare_send` | Composition fields | Persist an immutable message and return its review payload |
| `mail_prepare_reply` | `reference`, `message` | Prepare a reply with threading headers from the source |
| `mail_prepare_forward` | `reference`, `message` | Prepare an inline plain-text forward |
| `mail_send_confirmed` | `prepared_id`, `confirmed_digest`, `append_sent` | Claim once and send the exact prepared bytes |

### Composition shape

```json
{
  "to": ["recipient@example.com"],
  "cc": [],
  "bcc": [],
  "subject": "Project update",
  "text": "The requested update is ready.",
  "attachments": []
}
```

Optional attachments contain `filename`, `content_type`, and `data_base64`. Optional `in_reply_to` and `references` contain angle-bracketed Message-IDs. Sender identity comes from `MAIL_FROM` and cannot be chosen by the tool caller.

Limits are 50 total recipients, 512 subject bytes, 1 MiB of text, 20 attachments, 3 MiB of total decoded attachment bytes, and 5 MiB of complete encoded MIME. Internationalized SMTPUTF8 address mailboxes are unsupported. Infrastructure request/response limits may be lower than these application limits; base64 increases payload size.

Replies require explicit recipients, even when the original has Reply-To or From headers. Review those addresses before preparing. Reply-All selection is a client decision. Forwards include the source's plain text, but do not silently copy original attachments. Retrieve and explicitly include any desired attachments. Truncated source messages are rejected for reply/forward preparation.

### Approval and dispatch

Preparation returns `prepared_id`, `digest`, full recipient arrays including BCC, subject, text, attachment hashes, Message-ID, byte size, and expiry. Review that exact content with the owner. Preparation expires after 15 minutes. Any change needs a new preparation and approval.

After approval, pass the exact ID/digest pair to `mail_send_confirmed`. Set `append_sent` deliberately: `true` requests a separate IMAP Sent-folder copy after SMTP acceptance and requires both `mail.write` and `MAIL_ENABLE_WRITES=1`; missing filing permission rejects the request before any send. A provider may already save sent mail; enabling the copy can create duplicates. Failure to save a Sent copy does not undo sending and is not a reason to resend.

Repeated calls for a consumed ID return its recorded status without another SMTP attempt. `accepted` means SMTP acceptance only. Investigate `sending`, `unknown`, and persistence warnings before considering a new message. The host remains responsible for human confirmation; the digest is a content binding, not evidence of a human click.

## Outside the current surface

There is no server-side rule/Sieve administration, Apple Mail local-rule editing, account provisioning, sorting by subject/sent date, active HTML rendering, bulk global expunge, folder deletion, or OAuth login to the upstream mail provider. Provider presets beyond Spacemail are intentionally kept to explicit generic settings for now.

---
title: Tool reference
description: The implemented MCP tools, input shapes, scopes, provider requirements, and limits.
summary: Read, organize, draft, prepare, and send through explicit operations.
order: 50
category: Reference
---

# Tool reference

All tools require a valid owner token with `mail.read`. Write and send tools additionally require their scopes and deployment gates. Tools can appear in discovery while their execution is disabled; use `mail_query` with `action: "capabilities"` to inspect the gates and the provider's supported features.

Mail text, headers, filenames, and attachment data are untrusted. See [Safety and concurrency](/docs/safety).

## Six tools, grouped by permission and risk

Angelos 0.5.0 exposes six tools for all 17 original operations plus reply-all and read-only send-status inspection. Each grouped tool has a typed `action` enum and typed argument fields. Only fields belonging to the selected action are accepted; unknown, irrelevant, missing required, and null fields are rejected before mailbox access, including explicit nulls inside message objects. There is no arbitrary command input.

| Tool | Scope in addition to `mail.read` | MCP annotations |
| --- | --- | --- |
| `mail_query` | None, except `send_status` also requires `mail.send` | Read-only, closed-world |
| `mail_create` | `mail.write` | Non-destructive, closed-world |
| `mail_modify` | `mail.write` | Destructive, closed-world |
| `mail_delete_permanently` | `mail.write` | Destructive, closed-world; separate irreversible-delete gate |
| `mail_prepare` | `mail.send` | Non-destructive, closed-world; no SMTP submission |
| `mail_send_confirmed` | `mail.send` | Destructive, open-world; actual SMTP submission |

The tool-level consent boundaries are deliberately separate. None promises idempotency through its MCP annotation. See [Migration and token budget](/docs/tool-migration) for the complete old-to-new mapping and measured size changes.

## Read operations

Call `mail_query` with one of these actions:

| Action | Arguments beyond `action` | Result |
| --- | --- | --- |
| `capabilities` | None | IMAP capabilities, discovered special folders, effective gates, Gmail label/Sent/delete constraints |
| `folders` | None | Exact folder names, hierarchy delimiters, attributes |
| `search` | Optional `search` object below, `detail` | Message summaries, UIDVALIDITY, scan size, optional next cursor |
| `read` | `reference`, optional `detail` | Text, selected headers, flags, attachment metadata, truncation warnings |
| `attachment` | `reference`, one-based `index` | Attachment metadata and complete base64-encoded bytes |
| `send_status` | `prepared_id` | Your minimal durable send receipt; never sends or claims |

`detail` accepts `summary` (default) or `full` for search/read only. Full mode returns every field in the original read/search response. Capability, folder, attachment, mutation, preparation, and dispatch results retain their previous full shapes.

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

The nested `search.folder` defaults to `INBOX`; an omitted `search` performs the default search. `query` is a plain IMAP text-search term, not a Gmail query language or arbitrary IMAP command. Optional `from`, `to`, and `subject` fields add header filters. `participant` is IMAP case-insensitive substring matching across From, Reply-To, To, or Cc (not Bcc). `message_id` is an exact case-sensitive complete Message-ID filter, verified against the original header rather than trusting IMAP substring search. `since` and `before` use `YYYY-MM-DD` IMAP internal-date boundaries; `since` is inclusive and `before` is exclusive. Optional `unread` and `flagged` booleans filter those flags. Supplied filters are combined.

```json
{
  "action": "search",
  "search": {
    "folder": "INBOX",
    "query": "invoice",
    "from": "billing@example.com",
    "since": "2026-01-01",
    "unread": true,
    "limit": 25
  }
}
```

`order` accepts `newest` (the default) or `oldest`, sorted by UID. This is mailbox arrival order, not a subject or sent-date sort. The default result limit is 25 and the maximum is 100. Each call scans at most 1000 UID values. Deleted UID gaps mean this is not necessarily 1000 messages.

Keep requesting with the returned `next_cursor`, the same filters, and the same order until the cursor is absent. An empty result page may still have a cursor. Pagination keeps the initial upper UID bound, so newly arriving messages require a new search. Changing a filter or order also requires starting a new search.

Exact-ID inputs accept modern ASCII dot-atom IDs or no-fold domain literals, with optional angle brackets and outer spaces. Obsolete quoted forms and input comments are rejected. Comments and folded whitespace around a single valid source ID are allowed, but duplicate fields, multiple IDs, case differences, and prefix/suffix collisions do not match. Candidate verification uses PEEK on only the Message-ID header, in batches of at most 16 UIDs, with a 64 KiB complete selected-header limit. Missing UIDs after a search are skipped as concurrent expunges; incomplete returned headers fail safely. False candidates do not consume the requested result quota. The same bounded UID scan and empty-page continuation rules still apply.

```json
{
  "action": "search",
  "search": {
    "folder": "INBOX",
    "message_id": "<ExactCaseID@Example.com>",
    "participant": "person@example.com"
  }
}
```

These filters combine with each other and earlier criteria by AND. Participant search may match display names or a substring of an address; it is not an exact-address operator. Message-ID case is never normalized.

### Compact results

Summary search pages hoist `folder` and `uid_validity` once to the page. Each message has `uid`, subject, addresses when present, date, flags, size, and MODSEQ when available. Construct a reference from the page's folder/UIDVALIDITY plus the row's UID. If a row contains an explicit `reference`, use it instead. `next_cursor`, `scanned_uids`, and `order` keep the same meaning. Empty address lists are omitted. Full mode restores the original per-message `reference` shape and empty fields.

Summary reads return at most 4096 UTF-8 text bytes without splitting a character. If clipped, `text_clipped: true`, `text_bytes`, and `full_text_hint` explicitly direct the client to repeat the same read with `detail: "full"`. This presentation clipping is separate from `truncated`, which still reports incomplete MIME/backend data. Full mode restores all available text within the read limits below. An unclipped summary never claims a truncated source is complete.

Exact references, flags/MODSEQ, Reply-To and other selected headers, attachment indexes, warnings, and backend truncation state are retained. Empty headers, attachments, and address lists may be omitted in summary mode. Preparation previews are always full and are never shortened; their To/Cc/Bcc arrays, complete text, and attachment hashes remain mandatory review material.

### Read limits

Reads inspect up to a 5 MiB raw-message prefix and return at most 256 KiB of text. MIME parsing is bounded to 12 nested levels and 100 parts. Plain-text alternatives are preferred; HTML-only mail uses text extraction with a warning. Extraction reads at most 1 MiB of HTML, with a 64 KiB token limit, 20,000-token limit, and 128-level stack limit. It does not render content or fetch resources. Truncation can make attachment metadata incomplete.

Attachment retrieval uses the one-based index from `mail_query` action `read`, rereads the referenced message, and returns at most 2 MiB of transfer-decoded attachment bytes. The complete enclosing message must fit the 5 MiB read limit. Text-file attachments retain their original bytes and character encoding; charset conversion applies only to displayed message text. An explicitly attached multipart container is one attachment, and its children are excluded from displayed text and inline forwards. Unsupported transfer encodings or decoding failures return an error instead of a successful partial or undecoded download. Bytes are returned as base64; the server does not open or execute files or fetch attachment URLs.

### Inspect a send receipt without sending

```json
{
  "action": "send_status",
  "prepared_id": "0123456789abcdef0123456789abcdef"
}
```

Use `mail_query` for this operation, never the dispatch tool as a status probe. It requires `mail.read`, `mail.send`, and a configured durable store. It remains available when `MAIL_ENABLE_SEND=0`; it does not claim an ID, invoke SMTP, append Sent mail, alter a record, or refresh its retention.

The minimal result contains `status`, optional `message_id`, an internal `stage` where known, original preparation `expires_at`, and a warning. It never returns the body, HTML, recipients/BCC, approval digest, owner binding, or credentials. `expires_at` is the original 15-minute approval deadline, not the receipt's retention deadline.

- `prepared` is a snapshot of an unclaimed preparation; it is not permission to send.
- `sending` or `unknown` must never cause an automatic retry or duplicate preparation.
- `accepted` means SMTP acceptance only, never verified delivery.
- `rejected` records a rejected attempt; any new message still needs its own review.
- `expired` or `unavailable` is not proof that no message was sent. Retained consumed markers can outlive the preparation deadline for seven days.

New preparations and status lookups are bound to the verified OAuth issuer, resource, and subject. Foreign IDs, missing records, and older unowned receipts all return the same `unavailable` result. Refreshing a token or changing its scopes does not change ownership; changing the issuer/resource/subject does. Legacy unowned records keep their earlier exact-ID/digest send/replay behavior until their existing expiry, but the new status lookup cannot claim an owner for them. No migration or owner adoption occurs.

## Mailbox writes

These tools require `mail.write` and `MAIL_ENABLE_WRITES=1`.

| Tool / action | Arguments beyond `action` | Behavior |
| --- | --- | --- |
| `mail_create` / `folder` | `name` | Create a folder |
| `mail_create` / `copy` | `reference`, `destination` | Copy one message into an existing folder |
| `mail_create` / `draft` | `message`, optional `folder` | Append a new composed draft |
| `mail_modify` / `flags` | `reference`, `operation`, `flags`, optional `unchanged_since` | Add or remove selected flags |
| `mail_modify` / `rename` | `old`, `new` | Rename a folder; INBOX rename is excluded |
| `mail_modify` / `move` | `reference`, `destination` | Move one message using native UID MOVE |
| `mail_modify` / `trash` | `reference` | Move into the uniquely advertised Trash folder |
| `mail_delete_permanently` (no action) | Message reference fields directly | Permanently remove exactly one UID, with an additional delete gate |

Flag operations accept `add` or `remove`, with `\Seen`, `\Answered`, `\Flagged`, `\Draft`, and permitted conservative ASCII keywords. They never replace the complete flag set or expose `\Deleted`/`\Recent` as ordinary flags. The mailbox must permit each requested flag.

Where CONDSTORE is available, read/search results include `modseq`, and the server snapshots the message's MODSEQ before applying a conditional flag change. Pass the previously observed value as `unchanged_since` to guard against changes since that read. A supplied precondition requires that capability. Without CONDSTORE, a delta can proceed with a warning that no concurrency precondition was enforced. Reread after conflicts.

Move and Trash require native MOVE support. Trash and implicit Drafts/Sent folder selection require a unique server-advertised SPECIAL-USE folder. Names are never guessed. Actual LIST role attributes are honored even without a SPECIAL-USE capability advertisement. Gmail labels overlap, and All Mail is not treated as Archive. A copy/move with server acceptance but no valid destination UID mapping returns `accepted` and a verification warning: a concurrently disappeared source can make the command an accepted no-op. Search the destination before taking another action. An append without a returned UID similarly requires a fresh search.

Draft saving creates a new message and does not replace an older draft. Its `message` uses the composition shape below. BCC is preserved in the private IMAP draft so another mail client can edit it. An omitted folder selects the discovered Drafts folder. Updating a draft is a deliberate new-save and separate old-message cleanup, with possible concurrent-client effects.

Permanent deletion additionally requires `MAIL_ENABLE_DELETE=1`, exact per-action user confirmation in the trusted client, and targeted UID EXPUNGE support. There is no ordinary mailbox-wide EXPUNGE, folder deletion, or deletion-on-close operation. An interrupted delete can leave a message marked Deleted without confirmed removal; inspect the account before retrying. Gmail/Workspace permanent deletion is unavailable even with that gate: its label UID removal does not prove account-wide deletion. The Gmail preset, known Gmail IMAP hosts, and servers advertising X-GM-EXT-1 are guarded before Deleted/EXPUNGE mutation.

## Prepare and send

All preparation and send tools require `mail.send`, `MAIL_ENABLE_SEND=1`, and the durable Redis REST store.

| Tool / action | Arguments beyond `action` | Behavior |
| --- | --- | --- |
| `mail_prepare` / `new` | `message` | Persist an immutable message and return its review payload |
| `mail_prepare` / `reply` | `reference`, `message`, optional `quote_original` | Derive omitted recipients and prepare a threaded reply |
| `mail_prepare` / `reply_all` | `reference`, `message`, optional `quote_original` | Include visible source participants, excluding configured self addresses |
| `mail_prepare` / `forward` | `reference`, `message`, optional `original_mode`, `quote_original`, `attachment_indexes` | Prepare a quoted, attached-EML, or original-omitted forward |
| `mail_send_confirmed` (no action) | `prepared_id`, `confirmed_digest`, `append_sent` | Claim once and send the exact prepared bytes |

### Composition shape

Place these fields inside `message` for all preparation actions and draft saving.

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

Optional `html` supplies an authored HTML alternative. An omitted plain body is derived from that HTML before quoting, without loading resources. Both final alternatives appear in the preparation preview. Optional attachments contain `filename`, `content_type`, and `data_base64`; valid content-type parameters such as charset are preserved. Optional `in_reply_to` and `references` contain angle-bracketed Message-IDs. Sender identity comes from `MAIL_FROM` and cannot be chosen by the tool caller.

Limits are 50 total recipients, 512 subject bytes, 1 MiB per text/HTML alternative, 20 attachments, 3 MiB of total decoded attachment bytes, and 5 MiB of complete encoded MIME. Internationalized SMTPUTF8 address mailboxes are unsupported. Infrastructure request/response limits may be lower than these application limits; base64 increases payload size.

Replies derive an omitted `message.to` from source Reply-To, then From. `reply_all` also derives an omitted `message.cc` from visible source To/Cc, excluding the sender and configured self addresses. Explicit arrays replace those fields; `[]` deliberately clears a field, while `null` is invalid. BCC is never inherited. Review the full resulting recipients before sending.

Replies quote source text with author/date attribution by default; `quote_original: false` omits the quotation. Forward `original_mode` is `quoted` by default, `eml` for an explicitly attached original, or `none` to omit it. Do not combine `quote_original` with `eml` or `none`. Source attachments are included only by explicit `attachment_indexes`, new `message.attachments`, or the explicit EML mode. Truncated source messages are rejected for reply/forward preparation. See [Natural replies and forwards](/docs/natural-messages) for exact selection, privacy, threading, and MIME behavior.

### Approval and dispatch

Preparation returns `prepared_id`, `digest`, full recipient arrays including BCC, subject, complete text and HTML, attachment hashes, Message-ID, byte size, and expiry. Source-based preparations also identify the source, threading, quotation/original mode, selected and omitted source attachments, and warnings. Review that exact content with the owner. Preparation expires after 15 minutes. Any change needs a new preparation and approval.

After approval, pass the exact ID/digest pair to `mail_send_confirmed`. Set `append_sent` deliberately: `true` requests a separate IMAP Sent-folder copy after SMTP acceptance and requires both `mail.write` and `MAIL_ENABLE_WRITES=1`; missing filing permission rejects the request before any send. Gmail SMTP saves sent mail automatically: `append_sent: true` is rejected before consuming the preparation or sending. Use `false`. Other providers may also save sent mail; enabling the copy can create duplicates. Failure to save a Sent copy does not undo sending and is not a reason to resend.

Repeated calls for a consumed ID return its recorded status without another SMTP attempt. `accepted` means SMTP acceptance only. Investigate `sending`, `unknown`, and persistence warnings before considering a new message. The host remains responsible for human confirmation; the digest is a content binding, not evidence of a human click.

## Outside the current surface

There is no server-side rule/Sieve administration, Apple Mail local-rule editing, account provisioning, sorting by subject/sent date, active HTML rendering, bulk global expunge, or folder deletion. Gmail/Workspace has server-side XOAUTH2 with owner-provisioned credentials, not an interactive consent UI. Gmail API transport, label APIs, X-GM-RAW queries, global message/thread IDs, and service-account delegation are not exposed. Other OAuth mail providers require an implementation change. See [Gmail and Google Workspace](/docs/gmail-workspace).

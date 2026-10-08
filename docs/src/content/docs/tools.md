---
title: Tool reference
description: The implemented MCP tools, input shapes, scopes, provider requirements, and limits.
summary: Read, organize, draft, prepare, and send through explicit operations.
order: 43
category: Reference
---

For task-focused examples, use the [inbox guide](/docs/inbox-guide) and [sending guide](/docs/sending-guide); this reference covers exact tool inputs, limits, and edge cases.

All tools require a valid owner token with `mail.read`. Write and send tools additionally require their scopes and deployment gates. Tools can appear in discovery while their execution is disabled; use `mail_query` with `action: "capabilities"` to inspect the gates and the provider's supported features.

Mail text, headers, filenames, and attachment data are untrusted. See [Safety and permissions](/docs/safety).

## Six tools, grouped by permission and risk

Angelos 0.8.0 exposes six tools for 25 operations, including bounded batch reading and a structured saved-draft workflow. Each grouped tool has a typed `action` enum and typed argument fields. Only fields belonging to the selected action are accepted; unknown, irrelevant, missing required, and null fields are rejected before mailbox access, including explicit nulls inside message objects. There is no arbitrary command input.

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
| `triage` | Optional `search` object below, `detail` | Unread-or-flagged summaries, page-only counts, selection explanation, optional next cursor |
| `conversation` | `reference`, optional `search` with only `folder`/`order`/`cursor`/`limit`, `detail` | Same-folder header-linked summaries, anchor, coverage explanation, optional next cursor |
| `read` | `reference`, optional `detail` | Text, selected headers, flags, attachment metadata, truncation warnings |
| `read_many` | `references`, optional `detail`, `max_response_bytes` | 1–10 distinct exact references; ordered per-item results, bounded payload, explicit continuation |
| `draft` | `reference` | Complete supported structured draft, source digest, original Message-ID, and rebuild warnings |
| `attachment` | `reference`, one-based `index` | Attachment metadata and complete base64-encoded bytes |
| `send_status` | `prepared_id` | Your minimal durable send receipt; never sends or claims |

`detail` accepts `summary` (default) or `full` for search, triage, conversation, and read. Full mode returns every field in the original message-summary or read response. Full triage/conversation rows still contain summaries, not bodies. Capability, folder, attachment, mutation, preparation, and dispatch results retain their previous full shapes.

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

The nested `search.folder` defaults to `INBOX`; an omitted `search` performs the default search. `query` is a plain IMAP text-search term, not a Gmail query language or arbitrary IMAP command. Optional `from`, `to`, and `subject` fields add header filters. `participant` is IMAP case-insensitive substring matching across From, Reply-To, To, or Cc (not Bcc). `message_id` is an exact case-sensitive complete Message-ID filter, verified against the original header rather than trusting IMAP substring search. `since` and `before` use `YYYY-MM-DD` IMAP internal-date boundaries; `since` is inclusive and `before` is exclusive. Optional `unread` and `flagged` booleans filter those flags. `attention: true` adds `(unread OR flagged)`; all other supplied filters, including explicit `unread` and `flagged` values, are combined with it by AND. Omitted or false `attention` adds no attention filter. It is a flag selection, not an urgency score.

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

### Triage

`mail_query` action `triage` applies the existing search filters and forces `attention: true`: `(unread OR flagged) AND all supplied filters`. Omit `search.attention` or set it to `true`; `false` is rejected. Explicit flag filters still narrow the selection. For example, `unread: false` selects read messages that are flagged; `flagged: false` selects unread messages that are not flagged. Ordinary `action: "search"` also accepts `attention: true`, without adding triage counts.

The result adds `selection` and `page_counts`:

- `messages`: number of returned rows
- `unread`: returned rows without `\Seen`
- `flagged`: returned rows with `\Flagged`
- `unread_and_flagged`: returned rows in both groups

These counts overlap. They describe only the rows returned in this call, not all matches in the scanned window, folder totals, pending work, or urgency. Flags can change between pages.

Triage uses one bounded search call, defaults to 25 rows, allows at most 100 rows, and scans at most 1000 UID values per call. It returns summary metadata without fetching message bodies or changing Seen or other mailbox state. Continue with the returned cursor and unchanged filters/order, even when a page is empty. The initial upper UID bound stays frozen; start a fresh query to include new arrivals. Search cursors created before the attention field existed remain valid for their unchanged, non-attention searches.

### Conversation

`mail_query` action `conversation` requires an exact anchor `reference`. Its optional `search` object accepts only `folder`, `order`, `cursor`, and `limit`. Omit or leave `folder` empty to use the anchor's folder; an explicit folder must match it exactly. Query, participant, date, flag, attention, and Message-ID filters are rejected, even when supplied as empty or false values.

The backend fetches only the anchor's Message-ID, References, and In-Reply-To headers with PEEK, then fixes that identifier set for the lookup. A candidate in the same folder matches if any complete token in its own selected headers exactly matches that fixed set. Matching is case-sensitive. There is no subject fallback, provider thread-ID lookup, or recursive expansion through newly found messages. A shared subject alone does not establish a conversation, and headers are untrusted claims rather than proof of identity.

A server-side header prefilter narrows candidates within the bounded UID window, but every returned match still passes exact local token verification. IMAP substring matches alone never establish linkage. A conservative 64 KiB encoded-query cap bounds the prefilter; queries exceeding the cap fail explicitly rather than sending an oversized command or weakening verification.

The result uses the same compact/full summary rows as search, plus the exact `anchor` and a `coverage` explanation. It does not fetch bodies. Use `read` on the exact returned references for content, including when asking for a conversation summary. The anchor need not appear on every page. Other folders, missing or malformed links, and unvisited pages are not covered; even exhausted pagination does not establish a complete account-wide thread.

Each selected-header section is limited to 64 KiB, with at most 100 IDs across its three fields and at most 1024 bytes per ID. Parsing accepts complete modern IDs and supported surrounding comments/folding. Duplicate fields and malformed identifiers are invalid: an invalid anchor or an anchor with no usable IDs fails the lookup, while invalid candidates are skipped. Oversized headers/IDs or incomplete returned header sections fail explicitly instead of returning a successful partial parse. Concurrently expunged candidates may be skipped; a missing anchor fails.

The default limit is 25, the maximum is 100 rows, and each call scans at most one 1000-UID window. `newest` (default) and `oldest` mean UID order. Follow `next_cursor` even after an empty page. A conversation cursor binds the operation, exact anchor, fixed ID-set digest, order, UIDVALIDITY, and initial upper UID bound. Do not reuse a search/triage cursor or change anchors. An altered anchor ID set or stale mailbox generation requires a fresh lookup; new arrivals require one too. Neither triage nor conversation changes flags or performs mailbox writes.

### Inbox workflow example

The following calls illustrate a read-first workflow. The reference values and reply text are examples; use the exact values and content appropriate to the returned mail.

1. Ask `mail_query` for an attention page:

```json
{
  "action": "triage",
  "search": {"folder": "INBOX", "limit": 25}
}
```

2. Choose a row and ask `mail_query` for related summaries. In compact results, combine the page's `folder` and `uid_validity` with the row's `uid`, unless the row supplies an explicit `reference`:

```json
{
  "action": "conversation",
  "reference": {"folder": "INBOX", "uid_validity": 12345, "uid": 678},
  "search": {"order": "oldest", "limit": 25}
}
```

Keep the same anchor and order for later conversation pages and place that response's `next_cursor` in `search.cursor`.

3. Read the relevant exact reference with `mail_query`; repeat for other messages needed to understand the exchange:

```json
{
  "action": "read",
  "reference": {"folder": "INBOX", "uid_validity": 12345, "uid": 678},
  "detail": "full"
}
```

4. When authorized to prepare a response, call `mail_prepare`:

```json
{
  "action": "reply",
  "reference": {"folder": "INBOX", "uid_validity": 12345, "uid": 678},
  "message": {"text": "Thanks for the update."}
}
```

Preparation requires the send scope, send gate, and durable store but does not send. Review the derived recipients, complete text/HTML, quoted source, attachments, and warnings before any separate `mail_send_confirmed` call. Nothing about triage or conversation lookup authorizes sending or marks an item handled.

### Compact results

Summary search, triage, and conversation pages hoist `folder` and `uid_validity` once to the page. Each message has `uid`, subject, addresses when present, date, flags, size, and MODSEQ when available. Construct a reference from the page's folder/UIDVALIDITY plus the row's UID. If a row contains an explicit `reference`, use it instead. `next_cursor`, `scanned_uids`, and `order` keep the same meaning. Empty address lists are omitted. Full mode restores the original per-message `reference` shape and empty fields.

Message summaries retain at most 100 flags, prioritizing standard system flags even when the server lists them after 100 custom keywords. Custom keywords may be displaced so overflow does not hide `\Seen` or `\Flagged` and corrupt triage counts.

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
| `mail_create` / `revise_draft` | `reference`, `source_digest`, `changes`, optional `folder` | Append a revision of a supported draft; preserve the original |
| `mail_modify` / `flags` | `reference`, `operation`, `flags`, optional `unchanged_since` | Add or remove selected flags |
| `mail_modify` / `rename` | `old`, `new` | Rename a folder; INBOX rename is excluded |
| `mail_modify` / `move` | `reference`, `destination` | Move one message using native UID MOVE |
| `mail_modify` / `trash` | `reference` | Move into the uniquely advertised Trash folder |
| `mail_delete_permanently` (no action) | Message reference fields directly | Permanently remove exactly one UID, with an additional delete gate |

Flag operations accept `add` or `remove`, with `\Seen`, `\Answered`, `\Flagged`, `\Draft`, and permitted conservative ASCII keywords. They never replace the complete flag set or expose `\Deleted`/`\Recent` as ordinary flags. The mailbox must permit each requested flag.

Where CONDSTORE is available, read/search results include `modseq`, and the server snapshots the message's MODSEQ before applying a conditional flag change. Pass the previously observed value as `unchanged_since` to guard against changes since that read. A supplied precondition requires that capability. Without CONDSTORE, a delta can proceed with a warning that no concurrency precondition was enforced. Reread after conflicts.

Move and Trash require native MOVE support. Trash and implicit Drafts/Sent folder selection require a unique server-advertised SPECIAL-USE folder. Names are never guessed. Actual LIST role attributes are honored even without a SPECIAL-USE capability advertisement. Gmail labels overlap, and All Mail is not treated as Archive. A copy/move with server acceptance but no valid destination UID mapping returns `accepted` and a verification warning: a concurrently disappeared source can make the command an accepted no-op. Search the destination before taking another action. An append without a returned UID similarly requires a fresh search.

Draft saving creates a new message and does not replace an older draft. Its `message` uses the composition shape below. BCC is preserved in the private IMAP draft. An omitted folder selects the discovered Drafts folder. For an existing draft, use the dedicated structured workflow below rather than reconstructing it from ordinary `read` output.

Permanent deletion additionally requires `MAIL_ENABLE_DELETE=1`, exact per-action user confirmation in the trusted client, and targeted UID EXPUNGE support. There is no ordinary mailbox-wide EXPUNGE, folder deletion, or deletion-on-close operation. An interrupted delete can leave a message marked Deleted without confirmed removal; inspect the account before retrying. Gmail/Workspace permanent deletion is unavailable even with that gate: its label UID removal does not prove account-wide deletion. The Gmail preset, known Gmail IMAP hosts, and servers advertising X-GM-EXT-1 are guarded before Deleted/EXPUNGE mutation.

## Saved draft lifecycle

1. Read a saved draft with `mail_query` action `draft` and its exact `reference`. This returns complete supported structured content (To/Cc/Bcc, subject, text/HTML, threading and attachment bytes), `source_digest`, the original Message-ID, and normalization warnings. It does not mark the message read.
2. To save changes, call `mail_create` action `revise_draft` with that reference, exact lowercase SHA-256 `source_digest`, and `changes`. Only supplied fields are replaced; omitted fields retain the source. Empty strings/lists explicitly clear the corresponding supported fields. `attachments` replaces the entire list, rather than adding to it. Text and HTML alternatives are independent: update or clear both when needed.
3. A revision appends a **new** draft to the source folder unless an explicit destination `folder` is supplied. It never changes, flags, or deletes the source. Refresh the folder listing/read the new reference before further changes.
4. To send a reviewed saved version, use `mail_prepare` action `draft` with its reference and digest. The server rereads it, checks the digest, and produces the usual immutable 15-minute preview. Review it before `mail_send_confirmed`; the original draft remains after sending.

```json
{
  "action": "revise_draft",
  "reference": { "folder": "Drafts", "uid_validity": 12345, "uid": 678 },
  "source_digest": "REPLACE_WITH_DIGEST_RETURNED_BY_DRAFT_READ",
  "changes": { "subject": "Updated project plan", "text": "Here is the revised plan.", "html": "" }
}
```

References and the digest above are placeholders, never values to infer. A stale digest requires a fresh draft read and review; do not automatically retry with a newly observed digest. The digest checks a snapshot, not a lock against another mail client. Later source edits do not change an already prepared message. IMAP APPEND can have an uncertain outcome; inspect the destination before deciding whether to save another copy.

The source must have the Draft flag and not the Deleted flag. Revision and preparation additionally require its From address to match the configured sender; draft reading can inspect a supported draft from another address. Parsing is all-or-error, limited to 5 MiB raw MIME, 1 MiB per body alternative, 20 attachments and 3 MiB total decoded attachment data, and a **1 MiB serialized structured-draft result**. Revised content is checked before APPEND, and the complete draft send preview has the same 1 MiB cap. The JSON limit includes base64 and metadata and is stricter than the parser’s raw/body/attachment limits. An otherwise parseable draft can therefore exceed the response budget and be rejected; no truncated draft is presented as editable.

Supported bodies are plain text, HTML, or an ordered plain-text/HTML alternative, optionally as the first part of a mixed message followed by named file attachments. Unsupported or duplicate headers (including Reply-To, Sender, and custom X-headers), inline/CID/related MIME, signed/encrypted mail, non-UTF-8/ASCII body charsets, and MIME preambles/epilogues are rejected. Ordinary reading may still work; use the original mail app to edit unsupported drafts.

Rebuilding preserves supported authored body content and attachment bytes, not raw MIME. An HTML-only source gains generated plaintext, disclosed in the result; an explicitly empty plaintext alternative is preserved. A source with an explicitly empty HTML alternative is rejected as unsupported instead of silently dropping that part. It normalizes headers, recipient deduplication and newlines, and regenerates sender display formatting, Date, Message-ID, and MIME boundaries. There is no in-place edit, automatic source cleanup, or blanket lossless-edit guarantee.

## Prepare and send

All preparation and send tools require `mail.send`, `MAIL_ENABLE_SEND=1`, and the durable Redis REST store.

| Tool / action | Arguments beyond `action` | Behavior |
| --- | --- | --- |
| `mail_prepare` / `new` | `message` | Persist an immutable message and return its review payload |
| `mail_prepare` / `reply` | `reference`, `message`, optional `quote_original` | Derive omitted recipients and prepare a threaded reply |
| `mail_prepare` / `reply_all` | `reference`, `message`, optional `quote_original` | Include visible source participants, excluding configured self addresses |
| `mail_prepare` / `draft` | `reference`, `source_digest` | Prepare the reviewed saved draft without changing or deleting it |
| `mail_prepare` / `forward` | `reference`, `message`, optional `original_mode`, `quote_original`, `attachment_indexes` | Prepare a quoted, attached-EML, or original-omitted forward |
| `mail_send_confirmed` (no action) | `prepared_id`, `confirmed_digest`, `append_sent` | Claim once and send the exact prepared bytes |

### Composition shape

Place these fields inside `message` for new/reply/reply-all/forward preparation and new draft saving. Saved-draft preparation instead uses only its exact reference and source digest; it does not accept `message`.

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

Replies quote source text with author/date attribution by default; `quote_original: false` omits the quotation. Forward `original_mode` is `quoted` by default, `eml` for an explicitly attached original, or `none` to omit it. Do not combine `quote_original` with `eml` or `none`. Source attachments are included only by explicit `attachment_indexes`, new `message.attachments`, or the explicit EML mode. Truncated source messages are rejected for reply/forward preparation. See [Reply and forward details](/docs/natural-messages) for exact selection, privacy, threading, and MIME behavior.

### Approval and dispatch

Preparation returns `prepared_id`, `digest`, full recipient arrays including BCC, subject, complete text and HTML, attachment hashes, Message-ID, byte size, and expiry. Source-based preparations also identify the source, threading, quotation/original mode, selected and omitted source attachments, and warnings. Review that exact content with the owner. Preparation expires after 15 minutes. Any change needs a new preparation and approval.

After approval, pass the exact ID/digest pair to `mail_send_confirmed`. Set `append_sent` deliberately: `true` requests a separate IMAP Sent-folder copy after SMTP acceptance and requires both `mail.write` and `MAIL_ENABLE_WRITES=1`; missing filing permission rejects the request before any send. Gmail SMTP saves sent mail automatically: `append_sent: true` is rejected before consuming the preparation or sending. Use `false`. Other providers may also save sent mail; enabling the copy can create duplicates. Failure to save a Sent copy does not undo sending and is not a reason to resend.

Repeated calls for a consumed ID return its recorded status without another SMTP attempt. `accepted` means SMTP acceptance only. Investigate `sending`, `unknown`, and persistence warnings before considering a new message. The host remains responsible for human confirmation; the digest is a content binding, not evidence of a human click.

## Outside the current surface

There is no server-side rule/Sieve administration, Apple Mail local-rule editing, account provisioning, sorting by subject/sent date, active HTML rendering, bulk global expunge, or folder deletion. Gmail/Workspace has server-side XOAUTH2 with owner-provisioned credentials, not an interactive consent UI. Gmail API transport, label APIs, X-GM-RAW queries, global message/thread IDs, and service-account delegation are not exposed. Other OAuth mail providers require an implementation change. See [Gmail and Google Workspace](/docs/gmail-workspace).



## Read selected messages in one call

Use `mail_query` action `read_many` after search, triage, or conversation lookup. Supply 1–10 distinct exact `references` in the desired order. It uses the same PEEK read path as `read`, never changes flags or returns attachment contents. The underlying bounded MIME read may fetch attachment bytes; explicit attachment retrieval is still separate. Single-message `read` remains unchanged.

```json
{
  "action": "read_many",
  "references": [
    {"folder": "INBOX", "uid_validity": 9, "uid": 17},
    {"folder": "INBOX", "uid_validity": 9, "uid": 18}
  ],
  "max_response_bytes": 65536
}
```

`detail` defaults to `summary`; use `full` for all available read fields. Summary clipping is still explicit through `text_clipped`, `text_bytes`, and `full_text_hint`; backend MIME incompleteness remains `truncated`.

- `items` preserves input order and every exact reference. `status: "ok"` carries `message`; `"error"` carries a classified `error`. A stale or missing item does not hide other results.
- `max_response_bytes` bounds the complete UTF-8 JSON application payload, including item metadata: default 65,536, range 4,096–131,072. `response_bytes` measures that payload. MCP transport may include both text and structured copies, so the full wire envelope is larger.
- The aggregate full-message JSON admitted for output is additionally capped at 1 MiB, reported by `admitted_message_bytes`. One read may cross this admission limit and be omitted; it does not cap total backend downloads or decoding work. Original MIME and attachment transfer limits remain in force. Full batch output retains serialized fields only, not original MIME bytes.
- On `response_limit` or `message_limit`, the fetched item is `not_returned` and later items are `not_read`. `next_index` is the zero-based first unfinished input index. Resume with `references.slice(next_index)` and a larger budget, smaller batch, or a single `read`; retrying the unchanged too-large item with the same budget will not make progress.
- Cancellation before a remaining read stops further reads with `stop_reason: "cancelled"` and `next_index`. A cancellation during the final read instead appears as that item’s error; inspect per-item status even when there is no continuation. Review completed per-item results before continuing. Reads are sequential under the existing 90-second request deadline; batching reduces MCP calls, not IMAP connections.
- Invalid, duplicate, or excessive references fail before mailbox access. If reference metadata alone cannot fit the requested response budget, split the request or raise the budget.

## Classified application errors

Errors reaching the application handler include `error_code`, `recovery`, and `retry` alongside existing `error`, `outcome`, and `retry_safe`. Codes distinguish invalid arguments, stale references, conflicts, missing messages, unsupported operations, safety limits, unavailable service, cancellation/deadline, disabled deployment capabilities, missing scope, unknown outcome, and unclassified operation failure. SDK schema/protocol validation may reject a call earlier using the SDK error format.

`retry.action` describes the next decision (for example `correct_input`, `refresh_reference`, `check_capabilities`, or `verify_outcome`); it is not automatic retry permission. `retry.transport_retry_safe` is false for mutations and unknown outcomes. Inspect `outcome` for partial changes. OAuth scope challenges retain their authentication metadata. Never automatically resend, duplicate a preparation, or bypass consent, deployment, or scope boundaries to recover from an error.

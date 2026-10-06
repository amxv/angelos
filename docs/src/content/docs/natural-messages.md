---
title: Natural replies and forwards
description: Prepare ordinary client-style mail while preserving exact approval and privacy boundaries.
summary: Reply-all selection, case-preserved threading, quotations, HTML alternatives, and explicit original attachments.
order: 65
category: Reference
---

# Natural replies and forwards

Version 0.3 keeps six MCP tool names and extends `mail_prepare`. Messages use ordinary MIME layouts and contain no Angelos `X-Mailer` header or branded MIME boundaries. Client rendering, SMTP relay headers, and other raw-message details can still differ from Apple Mail or other clients. The implementation does not impersonate another mail client.

## Reply and reply-all

```json
{
  "action": "reply_all",
  "reference": {"folder": "INBOX", "uid_validity": 7, "uid": 2500},
  "message": {"text": "Thanks, that works for me."}
}
```

- An omitted `message.to` uses the full Reply-To mailbox list when present, otherwise From. Invalid present routing metadata fails closed rather than silently choosing another address.
- An omitted `message.cc` for `reply_all` includes visible source To/Cc participants, excluding original authors and configured self addresses. A reply to one's own sent message falls back to its visible recipients.
- `MAIL_FROM`, an address-valued `MAIL_USERNAME`, and explicit `MAIL_ALIASES` identify self addresses. Alias configuration never changes sender authority.
- Explicit `to` or `cc` arrays replace that field. An empty array deliberately clears it. Do not send `null`; it is rejected to avoid confusing “clear” with “derive.” Explicit self recipients are retained.
- Deduplication is case-insensitive, with To taking precedence over Cc, then Bcc. Display names and the first address spelling are retained. Original Bcc is never inherited.

Existing callers that already provide complete recipient arrays keep replacement semantics. Check the actual final To/Cc/Bcc in every preview; inferred routing is not approval to send.

### Threading

Replies use the exact case-preserved source Message-ID in In-Reply-To. References preserves the source chain, with a single valid parent In-Reply-To used only when References is absent. The source Message-ID is appended last. Long chains keep the root and recent context within 100 IDs and 8 KiB, with an explicit warning. Header folding respects SMTP line limits.

Missing, malformed, or ambiguous parent Message-IDs require a standalone preparation instead of silently producing a reply in the wrong thread. Complete bounded raw headers are used for composition; clipped read-output headers are not used to derive participants or thread IDs.

When subject is omitted or empty, repeated `Re:` prefixes are normalized and Unicode subject text is preserved. Forward subjects similarly normalize `Fw:`/`Fwd:`. No locale-specific prefix translation is guessed.

### Quotations and HTML

Replies top-post the authored commentary, followed by a normal author/date attribution and quoted source text. The date comes from the original Date header; if unavailable, a warning is returned and the date is omitted. `quote_original: false` omits source text.

Optional `message.html` creates a text/HTML alternative. If text is omitted, a bounded readable text fallback is generated before adding quotations, so authored commentary is present in both alternatives. The full final text and HTML are reviewed and bound to the immutable prepared wire bytes.

Source HTML is never copied into outgoing quotations. Bounded, decoded source text is escaped for HTML quotes, without original scripts, tracking images, rich layout, or embedded CID images. This can lose original formatting. Authored HTML is data supplied by the caller; the server does not render it or load its resources.

## Forward modes

```json
{
  "action": "forward",
  "reference": {"folder": "INBOX", "uid_validity": 7, "uid": 2500},
  "original_mode": "quoted",
  "attachment_indexes": [1],
  "message": {"to": ["recipient@example.com"], "text": "Here is the requested document."}
}
```

- `quoted` is the default. It includes readable source text and From/Date/Subject/To/Cc attribution. `quote_original: false` is an alternative way to omit the original text.
- `none` omits source text. Explicitly selected or newly supplied attachments can still be included.
- `eml` explicitly attaches `forwarded-message.eml`. It includes original headers and attachments, with only outer Bcc and Resent-Bcc fields removed. Embedded attachments are unchanged and may contain private data. Other original transport headers are retained. The preview discloses this scope.

Do not provide `quote_original` with `eml` or `none`, even as false. Forwards start a new thread and do not inherit source In-Reply-To or References.

### Selecting original attachments

`attachment_indexes` contains unique one-based indexes from a read of that exact source reference. Angelos rereads each selected attachment under the same folder/UIDVALIDITY/UID, checks metadata and byte counts, and includes its hash in the full preparation preview. Nothing is selected by filename guessing. Path punctuation and controls in incoming filenames are removed or replaced for a safe outgoing filename.

No original attachments are included by default. Selecting EML explicitly includes the original's embedded attachments; separately selecting an index as well can intentionally include a duplicate copy. New `message.attachments` remain available for caller-supplied files.

Byte-exact text attachments keep their charset parameters. Canonical 7-bit original mail uses `message/rfc822` with identity transfer encoding. Noncanonical or 8-bit EML, and opaque multipart file attachments, use an `application/octet-stream` file fallback with a preview warning. This avoids illegal base64 encoding of `message/rfc822` or multipart entities while preserving file bytes.

The normal limits still apply: 2 MiB per fetched source attachment, 20 total outgoing attachments, 3 MiB total decoded attachment bytes, and 5 MiB encoded wire bytes. The complete original must fit the read limits. Oversized or incomplete sources fail rather than creating a misleading partial forward.

## Approval, tests, and compatibility

Preparation never sends mail. All final recipients, both body alternatives, attachment hashes, source identity, and warnings must be reviewed before `mail_send_confirmed`. The digest binds the exact wire bytes and SMTP envelope, and consumed IDs cannot send again. HTML is removed from the durable store with the rest of the full payload at the atomic send claim.

Refresh tool discovery for version 0.3. New optional preparation fields and the `reply_all` action are available under the existing six tools. The server gates, OAuth scopes, permanent-delete boundary, and send-confirmation flow are unchanged.

Automated fixtures cover MIME parsing, exact bytes, recipient selection, threading, private headers, malformed content, signed OAuth/MCP routing, and TLS IMAP preparation. They do not establish that every mail client renders identically or replace live provider validation. See [Testing](/docs/testing).

The implementation follows useful patterns in the author's Apache-2.0 [icloud-cli reply](https://github.com/amxv/icloud-cli/blob/d07385a364e95ccdfeefcdaf0cc867938ba8f9ec/internal/mail/reply.go), [forward](https://github.com/amxv/icloud-cli/blob/d07385a364e95ccdfeefcdaf0cc867938ba8f9ec/internal/mail/forward.go), and [MIME composition](https://github.com/amxv/icloud-cli/blob/d07385a364e95ccdfeefcdaf0cc867938ba8f9ec/internal/mail/send_compose.go) code, while preserving case-sensitive IDs, immutable approvals, complete source metadata, and Angelos's existing safety limits.

---
title: Migration and token budget
description: Upgrade existing MCP clients to the compact six-tool interface without losing operations or safety information.
summary: Version 0.2 groups 17 operations by permission and risk, with opt-in full read/search detail.
order: 55
category: Reference
---

# Migration and token budget

The **0.2.0** release introduced the breaking tool-name/input-layout change below. Versions **0.3.0** and **0.4.0** retain those six names and add the features described at the end of this guide. Refresh `tools/list` and update saved workflows; removed names are not registered as aliases because aliases would preserve their discovery cost. The mailbox, authentication, provider configuration, send store, and existing prepared IDs/digests are unchanged.

## Operation parity

| Previous tool | New call | Argument migration |
| --- | --- | --- |
| `mail_capabilities` | `mail_query`, `action: "capabilities"` | No other fields |
| `mail_list_folders` | `mail_query`, `action: "folders"` | No other fields |
| `mail_search` | `mail_query`, `action: "search"` | Put every previous input under `search`; add `detail: "full"` for the original result shape |
| `mail_read` | `mail_query`, `action: "read"` | Put the original fields under `reference`; add `detail: "full"` for the original result shape |
| `mail_get_attachment` | `mail_query`, `action: "attachment"` | Keep `reference` and `index` |
| `mail_create_folder` | `mail_create`, `action: "folder"` | Keep `name` |
| `mail_copy` | `mail_create`, `action: "copy"` | Keep `reference` and `destination` |
| `mail_save_draft` | `mail_create`, `action: "draft"` | Keep `message` and optional `folder` |
| `mail_set_flags` | `mail_modify`, `action: "flags"` | Keep `reference`, `operation`, `flags`, optional `unchanged_since` |
| `mail_rename_folder` | `mail_modify`, `action: "rename"` | Keep `old` and `new` |
| `mail_move` | `mail_modify`, `action: "move"` | Keep `reference` and `destination` |
| `mail_trash` | `mail_modify`, `action: "trash"` | Put the original fields under `reference` |
| `mail_delete_permanently` | Unchanged | Original direct reference fields; no action |
| `mail_prepare_send` | `mail_prepare`, `action: "new"` | Put composition fields under `message` |
| `mail_prepare_reply` | `mail_prepare`, `action: "reply"` | Keep `reference` and `message` |
| `mail_prepare_forward` | `mail_prepare`, `action: "forward"` | Keep `reference` and `message` |
| `mail_send_confirmed` | Unchanged | Same ID/digest and explicit `append_sent`; no action |

For example, the exact full read is now:

```json
{
  "action": "read",
  "reference": {"folder": "INBOX", "uid_validity": 12345, "uid": 678},
  "detail": "full"
}
```

Reference values are illustrative, not reusable mailbox identifiers.

## Discovery and response cost

The baseline is the actual `tools/list` tools array from commit `21269903054ca3e7331e80fa46fce9325bd40b65` (same Go interface as 0.1.0), captured through the real stateless MCP HTTP handler. The checked-in baseline fixture and `TestToolSchemaTokenBudget` make the comparison reproducible.

| Measurement | Before | After | Reduction |
| --- | ---: | ---: | ---: |
| Registered tools | 17 | 6 | 64.7% |
| Complete tool-definition JSON bytes | 14,886 | 8,770 | 41.1% |
| Input schemas alone, JSON bytes | 7,695 | 5,490 | 28.7% |
| Approximate discovery tokens, ceil(bytes / 4) | 3,722 | 2,193 | 41.1% |
| Representative 25-message search payload bytes | 7,567 | 6,159 | 18.6% |
| Representative 18KB-text read payload bytes | 18,501 | 4,685 | 74.7% |

These are compact UTF-8 JSON measurements, without transport framing. The discovery measurement includes descriptions, annotations, scope metadata, and input schemas, not just the input fields. The response measurements are logical JSON payloads from deterministic synthetic fixtures in `response_test.go`, not live private mail. MCP may include the same output in both text content and structured content; client context use varies.

The bytes-divided-by-four number is only a disclosed estimate, **not an actual tokenizer count or a billing prediction**. Tokenization varies with the model, language, addresses, and message content. Full-detail responses retain their original information and can still be large. Base64 attachments and exact prepared-send previews are deliberately not abbreviated.

Run the metric checks with:

```bash
go test ./internal/app -run 'TestToolSchemaTokenBudget|TestSearchSummaryLossless|TestReadSummaryPreservesSafetyAndFullText' -v
```

The discovery test enforces a ceiling of 65% of baseline size, providing room for small safety clarifications while preventing accidental return to the old overhead. Per-action requirements are concise schema descriptions plus strict server-side key checks, rather than large repeated union branches. Clients should use the declared `action` enum and only its documented fields; every call still receives typed JSON Schema validation.

## Safety and completeness

Read-only operations, non-destructive mailbox additions, destructive mailbox changes, irreversible deletion, preparation, and actual sending keep separate tool-level consent annotations. Scopes and deployment gates apply to every action. Permanent deletion and SMTP submission retain separate tools.

Compact search pages retain cursor/freshness information, UIDVALIDITY, UID, flags, and exact MODSEQ values. Compact reads retain safe headers including Reply-To, metadata, warnings, and backend truncation state. A clipped text preview points to `detail: "full"`; full mode recovers all previously available read/search fields. [The tool reference](/docs/tools) describes reconstruction and empty-field semantics.

Mutation errors retain partial outcomes and `retry_safe`; ambiguous writes and send outcomes must not be retried blindly. To/Cc/Bcc, full message text, attachment hashes, immutable digests, expiry, durable one-time claims, and the separate Sent-filing permission check are unchanged. Grouping tools does not grant permission to send or mutate mail.


## Version 0.3 preparation additions

Refresh discovery again for `mail_prepare` action `reply_all`, optional authored HTML, quotation control, selected source attachment indexes, and quoted/EML/omitted-original forward modes. The six tool names and all earlier operation routes remain available.

For replies, omitted To/Cc can now be derived from complete source metadata and configured self aliases. Explicit arrays keep replacement semantics; `[]` clears a field and `null` is rejected. Reply quotations are now included by default; set `quote_original: false` to retain an authored-body-only reply. Existing explicitly supplied recipients, full previews, approval digests, and consumed-send behavior remain intact. Review both body alternatives before sending.

See [Natural replies and forwards](/docs/natural-messages) for exact behavior and privacy limits. The version 0.2 size measurements above are historical snapshots; additional version 0.3 functionality remains covered by the repository's compact discovery regression budget.


## Version 0.4 lookup additions

Refresh discovery for `mail_query` action `send_status` (`prepared_id`), and optional search `message_id`/`participant` filters. There are six tools and 19 operations. Default searches and their existing cursor serialization are preserved; new filter values bind their cursors. Exact-ID search verifies complete case-preserved headers, while participant search is explicitly a substring operator across visible address fields.

Send-status inspection is read-only, requires `mail.read` plus `mail.send`, and works with a valid store even when sends are disabled. New records bind ownership to the verified issuer/resource/subject. Older unowned receipts remain unavailable to this new lookup; their existing exact-ID/digest send behavior and TTLs are unchanged. See the [receipt reference](/docs/tools#inspect-a-send-receipt-without-sending) and [ownership model](/docs/authentication#preparation-ownership).

---
title: Client migration and token budget
description: Upgrade saved MCP calls safely and measure the complete discovery and response cost.
summary: Durable client compatibility rules, legacy call mapping, and reproducible size checks.
order: 45
category: Reference
---

Use this page to upgrade an existing client or measure its discovery overhead. For release-by-release features, fixes, and historical measurements, read the [Changelog](/docs/changelog). New integrations should start with the [Agent playbook](/docs/agent-guide) and [tool reference](/docs/tools).

<!-- Preserve historical deep links; release notes now live in the changelog. -->
<span id="version-06-discovery-measurement"></span>
<span id="version-03-preparation-additions"></span>
<span id="version-04-lookup-additions"></span>
<span id="version-05-gmailworkspace-compatibility"></span>
<span id="version-06-inbox-workflows"></span>
<span id="version-07-bounded-reads-and-classified-errors"></span>
<span id="first-party-oauth-and-chatgpt-discovery"></span>
<span id="version-08-structured-saved-drafts"></span>
<span id="version-08-discovery-measurement"></span>
<span id="version-09-first-use-clarity-and-safe-body-edits"></span>
<span id="version-09-discovery-measurement"></span>
<span id="version-010-personal-instances-and-microsoft-graph"></span>

## Upgrade checklist

1. **Refresh `tools/list` from the deployed revision.** Update cached schemas and saved workflows. Do not infer support from an old client description or call removed tool names.
2. **Preserve exact references.** IMAP references use folder/UIDVALIDITY/UID. Microsoft Graph references contain provider/account/native IDs; preserve the complete returned object instead of inventing IMAP values. Discover folder IDs and capabilities before choosing an operation.
3. **Check scopes and gates independently.** A code upgrade does not enable mailbox writes, sending, or deletion, and cannot add scopes to an existing token or grant. A deliberate broader connection needs server configuration plus new owner consent. Provider limitations still apply.
4. **Preserve identity and durable state.** Keep the production origin, owner subject, signing key, provider token-encryption key when configured, and Redis. Changes to issuer/resource/subject affect owned preparations and receipts; follow [OAuth migration](/docs/oauth-reference#migrate-from-an-external-issuer) rather than treating inaccessible status as proof of no send.
5. **Verify without changing mail first.** Check discovery, capabilities, intended folders, and an owner-selected read. Only test mutations or sending with explicit approval and disposable content. See [testing](/docs/testing) for the verification boundary.

The server exposes six risk-separated tools for 25 operations. The breaking 0.2 regrouping removed legacy aliases; the mapping below remains useful for clients upgrading from that interface. Later release-specific action requirements belong in the [changelog](/docs/changelog), with exact current behavior in the [tool reference](/docs/tools).

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

## Behavior to preserve in saved workflows

- Use the declared `action` and only its documented fields. Unknown, irrelevant, and unsupported null inputs fail before mailbox access. Optional `search.unread` and `search.flagged` retain their documented null-as-omitted behavior.
- For derived replies, omitted recipients may be filled from source metadata; explicit arrays replace them and empty arrays clear them. Reply quotation is enabled by default. Review the complete derived message rather than assuming a prior compact read was an approval preview.
- For saved drafts, use the dedicated draft read and exact source digest. A revision appends a new draft; it does not edit the original in place. When both authored body alternatives exist, explicitly set or clear both `changes.text` and `changes.html`. Reread/review after a digest conflict.
- Treat triage counts as page-only and related-message results as bounded same-folder evidence. Follow returned continuation; never infer complete threads, mailbox totals, or message bodies from summaries.
- Use `append_sent: false` with Gmail and Microsoft Graph. Inspect actual provider capabilities before permanent deletion, conversation traversal, or conditional flags; a configured switch does not add provider support.
- Inspect send status after uncertainty. Missing, expired, or inaccessible status is not permission to prepare a replacement or resend.

## Safety and completeness

Read-only operations, non-destructive mailbox additions, destructive mailbox changes, irreversible deletion, preparation, and actual sending keep separate tool-level consent annotations. Scopes and deployment gates apply to every action. Permanent deletion and SMTP submission retain separate tools.

Compact search pages retain cursor/freshness information, UIDVALIDITY, UID, flags, and exact MODSEQ values. Compact reads retain safe headers including Reply-To, metadata, warnings, and backend truncation state. A clipped text preview points to `detail: "full"`; full mode recovers all previously available read/search fields. [The tool reference](/docs/tools) describes reconstruction and empty-field semantics.

Mutation errors retain partial outcomes and `retry_safe`; ambiguous writes and send outcomes must not be retried blindly. To/Cc/Bcc, full message text, attachment hashes, immutable digests, expiry, durable one-time claims, and the separate Sent-filing permission check are unchanged. Grouping tools does not grant permission to send or mutate mail.


## Discovery and response cost

Measure the exact revision and output shape you ship. Counting only input schemas hides descriptions, annotations, and OAuth metadata; counting tools alone hides result size and extra round trips. The complete `tools/list` tools array is the discovery fixture, without JSON-RPC transport framing.

### Reproduce the checks

From the repository root, with the declared Go toolchain:

```bash
go test ./internal/app -run 'TestToolSchemaTokenBudget|TestToolSchemaReleaseSnapshot|TestDiscoveryUsabilityAndSize|TestSearchSummaryLossless|TestReadSummaryPreservesSafetyAndFullText' -v
```

`TestToolSchemaTokenBudget` captures the real stateless MCP HTTP handler and reports complete UTF-8 JSON bytes plus input-schema bytes. `TestToolSchemaReleaseSnapshot` checks the complete current discovery output against the reviewed release fixture. Review intentional schema changes and their measured impact before updating that snapshot; never replace a baseline just to make a regression pass.

### Current comparison and budget

The maintained fixture is `tools-list-v0.10.0.json`. The strict snapshot test verifies that the current implementation matches it exactly. The original 0.1 fixture comes from [commit 2126990](https://github.com/amxv/angelos/commit/21269903054ca3e7331e80fa46fce9325bd40b65). Re-run the command above after any schema, description, or OAuth-metadata change.

| Measurement | Original 0.1 baseline | Maintained fixture |
| --- | ---: | ---: |
| Registered tools | 17 | 6 |
| Complete discovery JSON bytes | 14,886 | 11,742 |
| Input-schema JSON bytes | 7,695 | 8,293 |

The structural regression limit is 70% of the original complete baseline plus separately bounded allowances of 768 bytes for the draft lifecycle and 512 bytes for Graph references. The duplicated top-level OAuth metadata has a separate 512-byte cap. This is an explicit growth budget, not a claim that current complete discovery is below 70% of the original baseline.

The complete wire shape includes identical top-level and `_meta.securitySchemes` declarations. Do not remove one to claim a size reduction: clients may rely on either. A local `$ref`-expanded comparison is also guarded against the preserved 0.8 fixture; expanded forms and original wire bytes are different measurements.

### Interpret the results honestly

Compact UTF-8 JSON size is **not an actual tokenizer count or a billing prediction**. A bytes-divided-by-four estimate must be labeled as an estimate; tokenization varies with model, language, addresses, and content. Clients can expand references, duplicate text/structured content, or transform discovery before adding it to context.

Response tests use deterministic synthetic messages, not live private mail. Summary mode bounds selected output and links to fuller reads; it does not justify dropping warnings, truncation indicators, exact identifiers, or continuation. Full-detail responses can still be large. Attachment bytes and exact prepared-send previews are deliberately not abbreviated.

Batch reading can save round trips while increasing total response bytes because every item needs identity, status, and budget metadata. Measure both call count and complete output before claiming an improvement. Historical release-specific measurements now live in the [Changelog](/docs/changelog).

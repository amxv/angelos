---
title: Changelog
description: Release-by-release changes to Angelos, with upgrade notes and links to the source.
summary: What changed, what needs attention, and where to find migration guidance.
order: 3
category: Get started
---

The release history for Angelos. For instructions that apply across versions, use [Client migration and token budget](/docs/tool-migration); for automatic updates, use [Keep Angelos updated](/docs/keep-updated).

An **Unreleased** entry describes work being prepared, not a published release. Check [GitHub Releases](https://github.com/amxv/angelos/releases) for publication status. Earlier version entries are reconstructed from the versioned implementation and documentation linked below; release dates are omitted where publication dates have not been verified.

## 0.11.1 — Unreleased

- Fixed new assistant connections losing their authorization request when a hosted client follows redirects before opening the owner's browser. Anonymous sign-in is now rendered at the validated authorization URL, preserving the client, exact callback, state, PKCE, resource, and requested scopes through the browser handoff. Owner passkey verification and explicit consent are still required.
- Existing passkeys, sessions, grants, and client configuration remain compatible. Restart **Connect** in the assistant after updating if an earlier attempt opened a standalone sign-in page. See [OAuth authorization and recovery](/docs/oauth-reference).

## 0.11.0 — Released 2026-10-08

[Published release](https://github.com/amxv/angelos/releases/tag/v0.11.0) · [Source at v0.11.0](https://github.com/amxv/angelos/commit/95c93e2c338f99e2caab3093d6705e2e8a583eb8)

### Added and changed

- A single agent-led [Connect Your Assistant](/docs/quickstart) guide configures all supported mailbox capabilities initially, with ChatGPT and Claude.ai examples. OAuth consent and approval for each mail action remain separate.
- Optional `MCP_OAUTH_INITIAL_SCOPES` requests `mail.read mail.write mail.send` for a new connection when its corresponding write/send gates are enabled. Unset deployments keep the read-only initial request; existing tokens and grants do not gain permissions.
- Public upstream updates no longer need a separately created GitHub personal access token. Private upstream access remains an explicit optional path.
- Secret-generation instructions use an absolute owner-private location outside Git, restrictive file modes, and overwrite protection. Additional source/upload ignores and [security guidance](https://github.com/amxv/angelos/blob/main/SECURITY.md) help keep credentials out of releases.
- Release tooling pins GitHub Actions and the Vercel CLI dependency tree. Secret scanning checks fetched history with redacted output and tests against synthetic credential fixtures.
- This dedicated changelog replaces chronological feature entries in the migration/token-budget reference.
- Documentation uses native platform fonts, preserving its sans/serif/monospace layout without Google Fonts requests from visitors.

### Security and reliability

- Isolated browser, passkey, and authorization quotas by verified session, and token-exchange quotas by proven grant rather than a public client ID. Invalid PKCE attempts do not consume a valid authorization code.
- Preserved unconsumed authorization codes/refresh credentials when a valid exchange is rate-limited; refresh-token replay still revokes the grant even when its quota is exhausted.
- Removed the live ChatGPT client-metadata fetch dependency from existing grant exchanges. Disabling or removing an allowed client also denies its existing JWT access.
- Kept bounded shared limits for fresh anonymous-session admission and uncached client-metadata fetches. Abuse can still delay fresh sign-in flows; deployment-level ingress protection remains necessary. These changes are not a general denial-of-service guarantee.

### Upgrade notes

The six tool names, 25 operations, and complete 0.10.0 discovery snapshot are unchanged. Existing configuration defaults, identity, and v1 stored state remain compatible. Full access is an explicit new setup choice; upgrading code does not enable switches or broaden an existing grant. Reconnect and approve a new grant if you deliberately expand scopes.

The updater workflow changes need **reviewed manual sync** in existing personal forks before unattended updates can proceed. Preserve the production domain, runtime secrets, signing key, and Redis database. No live assistant account or second-owner automated deployment is established by passing the code tests.

## 0.10.0 — Released

[Published release](https://github.com/amxv/angelos/releases/tag/v0.10.0) · [Source at v0.10.0](https://github.com/amxv/angelos/tree/v0.10.0) · [Provider and updater implementation](https://github.com/amxv/angelos/commit/2bbdfbc3fccc891c57f581b2fe72546c97c0a8cc) · [Google consent helper](https://github.com/amxv/angelos/commit/2c67297b2572e7b01bb634454a053049535ece2b)

- Added delegated Microsoft Graph access for Outlook.com and eligible Microsoft 365 mailboxes, with account-bound native references and encrypted durable refresh-token rotation.
- Added iCloud and Yahoo app-password presets with pinned TLS endpoints.
- Added agent-led personal-instance setup, secure local Google/Microsoft grant helpers, and an opt-in daily release updater for separate owner deployments.
- Retained six tools and 25 operations. Clients must preserve Graph references in full; Graph does not support the IMAP conversation, MODSEQ, or permanent-delete operations. Gmail and Graph file Sent automatically.

Measured discovery: **11,742 complete JSON bytes**, with 8,293 input-schema bytes. The locally expanded fixture is 12,712 bytes. The schema regression budget adds a bounded 512-byte Graph-reference allowance; these are byte measurements, not token counts. See [Microsoft differences](/docs/microsoft) and [setup](/docs/quickstart).

## Earlier source milestones

The following versions identify implementation milestones in Git history, not separately published GitHub releases. Their source commits and versioned documentation establish the changes below.

### 0.9.0

[Implementation](https://github.com/amxv/angelos/commit/8bd31c9d93a172807635270618375b0ba00b1f59)

- Clarified first-use tool descriptions, optional arguments, exact references, batch continuation, draft digests, and preparation-to-send values without changing the six tools or 25 operations.
- Required explicit set/clear choices for both existing text and HTML alternatives during draft body revisions, preventing a stale alternative from surviving an edit. Subject/recipient-only changes preserve bodies.
- Improved readable extraction from HTML-only mail, including bounded untrusted HTTP(S)/mailto destinations without loading remote resources.
- Classified invalid forward options as `invalid_arguments`.

Measured complete discovery decreased **11,433 → 11,383 bytes**; the local expanded form decreased 12,299 → 12,294 bytes. These are deterministic JSON fixture sizes, not measured assistant-context savings. See [draft lifecycle](/docs/tools#saved-draft-lifecycle).

### 0.8.0

[Implementation](https://github.com/amxv/angelos/commit/a790f844c0249bd79fb90c237eff23426716c5e2) · [Draft conflict guidance fix](https://github.com/amxv/angelos/commit/89cd03b38f83fee75949bc54c0e9fe307ded1d01)

- Added three structured saved-draft actions: read a supported draft and its digest, save a new revision while preserving the original, and prepare the reviewed draft for sending.
- Rejected unsupported/lossy MIME rather than reconstructing an incomplete editable draft.
- Completed the self-hosted setup guide and kept draft-conflict recovery specific to draft actions.
- Retained six tools, now covering 25 operations.

Measured discovery was **11,433 complete bytes**: 11,004 structural bytes plus 429 for the top-level OAuth metadata mirror. The budget gained a bounded 768-byte draft allowance. See [saved draft details](/docs/tools#saved-draft-lifecycle).

### 0.7.0

[Batch-reading implementation](https://github.com/amxv/angelos/commit/fd8afe2696bf372595aec8fb68a95a0224b7f968) · [Measurement record](https://github.com/amxv/angelos/commit/a3bb698b74937ff32aefd2b55d4f8bba203f501c) · [Passkey OAuth implementation](https://github.com/amxv/angelos/commit/b36746805ced1388efb310a1d4b24dca85f9d6bf)

- Added bounded `read_many` for 1–10 selected messages with per-item outcomes, explicit budgets, and continuation. Single-message reads stayed unchanged.
- Added stable application error codes and recovery guidance, retaining SDK validation formatting.
- Added optional owner-passkey OAuth, Redis-backed sessions/grants, rotating refresh tokens, and revocation. Existing external-issuer deployments were not automatically migrated.
- Mirrored tool OAuth metadata at both the top level and `_meta` for client compatibility. Six tools covered 22 operations.

The five-message fixture reduced read calls **5 → 1**, while result JSON grew 10,760 → 11,708 bytes. Initial batch discovery was 10,341 bytes; the later OAuth mirror added 429, for 10,770 complete bytes. The structural budget became 70% of the original baseline, with a separate 512-byte OAuth-mirror cap. These changes reduced round trips, not all output sizes. See [bounded reading](/docs/tools#read-selected-messages-in-one-call) and [OAuth reference](/docs/oauth-reference).

### 0.6.0

[Implementation](https://github.com/amxv/angelos/commit/08b11a563669a3f70e179f0c493fcf9e6fbdb3e7)

- Added read-only `triage`, `conversation`, and the search `attention` filter. Triage reports overlapping counts for the returned page; conversations use exact same-folder header links without subject matching or recursive expansion.
- Preserved standard system flags within bounded summaries and corrected premature literal-drain behavior in reads and header lookups.
- Kept six tools, now covering 21 operations. Draft saving still appended a new draft.

Measured discovery: **9,661 complete bytes**, 6,457 input-schema bytes, with the then-current 65% baseline ceiling. See [inbox workflows](/docs/inbox-guide) and [conversation limits](/docs/tools#conversation).

### 0.5.0

[Implementation](https://github.com/amxv/angelos/commit/1b4a4cdd2d012ef4b6bbb3e110e343b4eed39e02)

- Added Gmail/Workspace XOAUTH2 with owner-provisioned provider credentials, separate from assistant OAuth.
- Exposed Gmail label/Sent/deletion capability information and discovered special folders without guessing All Mail as Archive.
- Blocked Gmail permanent deletion regardless of the switch and rejected duplicate Sent filing before the send claim. Gmail sends require `append_sent: false`.
- Preserved the six tools and 19 operations.

See [Gmail/Workspace requirements](/docs/gmail-workspace).

### 0.4.0

[Implementation](https://github.com/amxv/angelos/commit/0c4adf2c3b66d97932e3aac9778f4be2ad3eb36b)

- Added read-only `send_status`, exact Message-ID lookup, and visible-participant search.
- Bound new preparations and receipts to the verified issuer, resource, and subject. Legacy unowned receipts remained unavailable to the new lookup; prior exact-ID/digest dispatch behavior and retention were preserved.
- Retained six tools, now covering 19 operations.

Send-status needs `mail.read` and `mail.send`, but can inspect a configured store while sending is disabled. Missing status is not permission to retry. See [receipt inspection](/docs/tools#inspect-a-send-receipt-without-sending).

### 0.3.0

[Implementation](https://github.com/amxv/angelos/commit/ef394808a5356013992e38ab8ba84fe54412b2d7)

- Added natural reply-all, authored HTML, quotation control, selected source attachments, and quoted/EML/omitted-original forwarding.
- Derived omitted reply recipients from complete source metadata and configured own-address aliases. Explicit recipient arrays retain replacement semantics; empty arrays clear a field.
- Included reply quotations by default, with `quote_original: false` to opt out. Exact previews, approval digests, and consumed-send protections were retained.

See [reply and forward semantics](/docs/natural-messages).

### 0.2.0

[Tool regrouping](https://github.com/amxv/angelos/commit/9ee4011296966c6a283b3fd3dae3643f125d5b10) · [Ordering fix](https://github.com/amxv/angelos/commit/393c7e7b801dc2e03e5f9cd2159c52fb1008e5a6) · [MIME/attachment safeguards](https://github.com/amxv/angelos/commit/a41956643aae2a2cabb33a4aaf407bf68215fd85)

- Regrouped 17 tools into six risk-separated tools. This changed tool names and argument layout; removed names were not retained as aliases.
- Added compact search/read responses while preserving full-detail access and safety information.
- Retained mailbox authentication, provider configuration, prepared IDs/digests, and the send store.
- Preserved explicit search ordering and strengthened MIME isolation, bounded reads, and attachment-byte preservation.

Historical synthetic measurements:

| Measurement | 0.1 baseline | 0.2 snapshot |
| --- | ---: | ---: |
| Registered tools | 17 | 6 |
| Complete discovery JSON bytes | 14,886 | 8,770 |
| Input-schema JSON bytes | 7,695 | 5,490 |
| Representative 25-message search bytes | 7,567 | 6,159 |
| Representative 18KB-text read bytes | 18,501 | 4,685 |

These compact UTF-8 JSON fixtures exclude transport framing and are not tokenizer counts or billing estimates. The discovery budget initially capped growth at 65% of the baseline. Use the [legacy call mapping](/docs/tool-migration#operation-parity) when updating old clients.

### 0.1.0

[Initial toolkit](https://github.com/amxv/angelos/commit/7c79a9993b3db0cc8489e4135aa5d6729a9e0e88) · [Baseline source](https://github.com/amxv/angelos/commit/21269903054ca3e7331e80fa46fce9325bd40b65)

- Introduced a single-mailbox MCP interface over TLS IMAP/SMTP, OAuth access verification, and separate read/write/send controls.
- Added mailbox search/read/attachment access, guarded mailbox operations, draft saving, reviewed message preparation, and durable one-time send claims.
- Established exact IMAP message references, concurrency checks, MIME limits, and the rule against automatically retrying an uncertain send.

The historical discovery fixture contains 17 tools. Later versions retain the approval and provider-safety boundaries while regrouping the interface.

---
title: Run the tests
description: Run Go and documentation checks without contacting a live mailbox.
summary: Local and CI checks, plus the boundary between automated tests and live validation.
order: 90
category: Contributing
---

For first-run mailbox verification, follow [Self-host Angelos](/docs/self-hosting); this page covers contributor checks and synthetic regression tests.

Use Go 1.27.1, the toolchain requested by `go.mod` and used in CI. The module declares a Go 1.26.0 language version. For documentation checks, use Bun 1.4.2 as declared by `docs/package.json`. Keep mail credentials out of test fixtures and CI logs.

## Go checks

From the repository root:

```bash
go mod tidy
gofmt -w .
go test -race -cover ./...
go vet ./...
go build ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...
```

Review formatting, `go.mod`, and `go.sum` changes before committing. CI rejects uncommitted formatting or module-manifest changes, runs race tests, vet and build, and checks reachable known Go vulnerabilities. Review the logs for the exact commit under test.

Tests use local fixtures, fake transports, and injected dependencies where appropriate. CI also starts an ephemeral Redis container to test the actual atomic claim scripts and payload retention; these integration tests skip locally unless `ANGELOS_TEST_REDIS_ADDR` names a loopback fixture. MIME regressions cover byte-exact non-UTF-8 text attachments, unsupported and malformed transfer encodings, attached multipart isolation, and bounded parsing using synthetic messages. Unit-test success does not establish that a real provider, OAuth tenant, Redis service, or deployed MCP connection is configured correctly.

For an additional bounded MIME fuzz pass (seed cases also run in ordinary tests):

```bash
go test ./internal/mail -run '^$' -fuzz FuzzParseMessageAttachment -fuzztime=30s -parallel=2
```

Natural-composition fixtures also exercise TLS IMAP reads through signed OAuth/MCP calls, source headers longer than compact read output, reply-all routing and aliases, exact Message-ID case, text/HTML alternatives, byte-accurate EML and selected attachments, privacy, explicit-null rejection, and preparation without SMTP dispatch.

Status/search regressions cover signed OAuth principal isolation and challenges, read-only lookup with sending disabled, strict receipt projection, unchanged send retention, actual Redis GET-only status scripts and concurrent claims, exact-ID header verification and quotas, participant OR/AND semantics, sparse cursors, and no Seen mutation. Redis script/TTL tests require the configured ephemeral loopback fixture and are included in CI.

Gmail tests use synthetic Google-host TLS certificates and injected loopback transports, never real accounts or refresh grants. Coverage includes IMAP with/without SASL-IR, SMTP TLS/STARTTLS, exact XOAUTH2 payloads, challenge termination, no credential downgrade, verified TLS before credentials, token refresh expiry/cancellation/concurrency/response bounds/redaction, and generation-safe invalidation. Signed MCP fixtures verify duplicate-Sent rejection before claim, one SMTP dispatch without explicit Sent APPEND, deletion guards, localized LIST roles, native MOVE requirements, and preserved legacy-provider behavior.

## Inbox workflow regressions

The inbox test suite covers the two new query routes through signed OAuth/MCP requests as well as bounded TLS IMAP fixtures. Check these behaviors when changing triage or conversation code:

- Read-only scope enforcement, compact/full rows, exact references and MODSEQ values, and rejection of unsupported fields before mailbox access
- Attention selection as `(unread OR flagged) AND other filters`, explicit true/false flag constraints, forced triage attention, and page-only overlapping counts
- Standard system flags retained after 100 custom keywords, so overflow cannot hide Seen/Flagged or alter page counts
- Default/max row limits, one bounded UID window, sparse and empty pages, both UID orders, frozen upper bounds, and compatibility with older non-attention cursors
- Exact case-sensitive Message-ID/References/In-Reply-To linkage to a fixed anchor seed, with no subject fallback or recursive expansion
- Bounded server-side header prefilter, conservative 64 KiB encoded-query cap, and exact local verification of candidates rather than substring acceptance
- Conversation cursor binding to operation, anchor, seed, order, and UIDVALIDITY; no reuse across search and conversation
- Malformed anchors/candidates, duplicate fields, bounded ID/header lengths, incomplete provider responses, missing/expunged messages, and failure without a successful partial parse
- Premature literal-drain race regressions in ordinary read, exact-ID search, and conversation paths, run under the race detector
- Selected-header PEEK, no body fetch during triage/conversation, no Seen change, and no mailbox mutation or SMTP dispatch

Use synthetic headers, bodies, and credentials. Passing fixture tests does not validate a real provider's threading behavior or establish complete conversation coverage across folders. Current discovery cost must be measured from `TestToolSchemaTokenBudget`; the version 0.2 table in [Migration and token budget](/docs/tool-migration) is historical.

## Documentation checks

Run the required commands serially:

```bash
cd docs
bun install --frozen-lockfile
bun run check
bun run build
```

The separate documentation CI job uses the same check-then-build order. See [Improve the docs](/docs/writing-docs) for the content structure.

## Live validation

A live test is an operation against an actual account. Reading, changing flags, creating folders, saving drafts, moving messages, and sending mail have different effects; verify only the operations intended for that test account.

Begin with authentication and read-only checks from [Deploy the API](/docs/deployment). Test writes using disposable messages and folders. A successful SMTP transaction confirms server acceptance, not inbox delivery. Never repeat an uncertain send just to make a test appear successful.

When reporting verification, distinguish checks that passed, checks that failed, checks blocked by the environment, and live integration checks that have not been performed.

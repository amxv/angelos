---
title: Testing
description: Run Go and documentation checks without contacting a live mailbox.
summary: Local and CI checks, plus the boundary between automated tests and live validation.
order: 90
category: Contributing
---

# Testing

Use the Go toolchain pinned in `go.mod` and Bun version declared by `docs/package.json`. Keep mail credentials out of test fixtures and CI logs.

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

## Documentation checks

Run the required commands serially:

```bash
cd docs
bun install --frozen-lockfile
bun run check
bun run build
```

The separate documentation CI job uses the same check-then-build order. See [Writing docs](/docs/writing-docs) for the content structure.

## Live validation

A live test is an operation against an actual account. Reading, changing flags, creating folders, saving drafts, moving messages, and sending mail have different effects; verify only the operations intended for that test account.

Begin with authentication and read-only checks from [Deploy the API](/docs/deployment). Test writes using disposable messages and folders. A successful SMTP transaction confirms server acceptance, not inbox delivery. Never repeat an uncertain send just to make a test appear successful.

When reporting verification, distinguish checks that passed, checks that failed, checks blocked by the environment, and live integration checks that have not been performed.

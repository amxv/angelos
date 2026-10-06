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
```

Review `go.mod` and `go.sum` changes before committing. The CI workflow also checks formatting and uploads its module manifests for inspection.

Tests use local fixtures, fake transports, and injected dependencies where appropriate. Unit-test success does not establish that a real provider, OAuth tenant, Redis service, or deployed MCP connection is configured correctly.

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

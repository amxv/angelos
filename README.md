# Angelos

An agent-native email interface in Go. Angelos exposes a single existing IMAP/SMTP mailbox through a private, OAuth-protected remote MCP server. Your other mail clients can keep using the same account.

The repository is private while under active development and is intended to be open sourced later. Optional mailbox writes, permanent deletion, and SMTP sending are disabled by default.

## Capabilities

- Gmail/Workspace XOAUTH2 for personal/internal use, with pinned hosts and conservative Sent/delete safeguards
- Six risk-separated MCP tools cover 19 operations with compact schemas and optional full-detail read/search results
- Find exact Message-IDs or visible participants, and inspect your send receipts without sending again
- Inspect provider capabilities, discover folders, search, and read mail without marking it read
- Opt into flag changes, folder creation/rename, copying, moving, Trash, and saved drafts
- Prepare messages, natural replies/reply-all, and quoted or attached forwards with reviewed To/CC/BCC, text/HTML, and bounded attachments
- Send an immutable prepared payload with an exact digest and durable one-time dispatch claim
- Restrict access to an explicit OAuth subject allowlist and separate read/write/send scopes

Provider capabilities affect which operations are safe to perform. Angelos does not manage Apple Mail's local rules, server-side filtering rules, or mailbox account settings. Existing clients should follow the [tool migration guide](./docs/src/content/docs/tool-migration.md). See the [tool reference](./docs/src/content/docs/tools.md) for the precise surface.

## Run and test

Use the toolchain declared in [`go.mod`](./go.mod). Configure the required mailbox and OAuth environment variables from [Configuration](./docs/src/content/docs/configuration.md) and [Authentication](./docs/src/content/docs/authentication.md), then:

```bash
go mod download
go test -race -cover ./...
go vet ./...
go run .
```

Environment variables must be exported or injected by your runtime; the Go process does not automatically load `.env`. Never commit real credentials. The public server requires OAuth configuration even during development.

## Deploy

The root is a Vercel Go API project. The existing [`docs/`](./docs) site is a separate Astro/ZueDocs project published at <https://angelos.ashray.xyz>. Keep their project roots and environment variables separate. See [Deploy the API](./docs/src/content/docs/deployment.md).

## Safety boundaries

The MCP host is trusted to obtain the owner's approval. Payload digests bind content; they do not prove a human approved it. Sending additionally requires a durable Redis REST store. SMTP acceptance is not delivery, and uncertain outcomes must not be retried automatically. Read [Safety and concurrency](./docs/src/content/docs/safety.md) before enabling writes or sends.

## Documentation

```bash
cd docs
bun install --frozen-lockfile
bun run check
bun run build
bun run dev
```

Run `check` before `build`. See [Writing docs](./docs/src/content/docs/writing-docs.md) for contribution guidance.

## License

[Apache License 2.0](./LICENSE).

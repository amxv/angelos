---
title: Deploy the API
description: Deploy the Go MCP API separately from the existing static documentation site.
summary: Vercel project separation, environment setup, and post-deployment checks.
order: 23
category: Run Angelos
---

Start with [Self-host Angelos](/docs/self-hosting) to prepare your mailbox and OAuth issuer before deploying the API.

The repository contains two independent applications:

- The Go MCP API at the repository root
- The Astro/ZueDocs documentation site under `docs/`

Use separate Vercel projects. The existing documentation project and domain remain dedicated to static documentation. Do not point that project at the API root or place mailbox credentials in its build environment.

## Prerequisites

- A mailbox with IMAP and SMTP access
- An existing OAuth issuer meeting the [authentication requirements](/docs/authentication)
- A Vercel account and the official Vercel CLI
- Access to the currently private source repository
- Go 1.27.1 for local checks, matching the requested toolchain in `go.mod` and CI

Vercel's Go framework preset supports a root `main.go` server listening on `PORT`. The root `vercel.json` selects that preset and builds the API. Vercel reads the Go version/toolchain from `go.mod`. See [Vercel's Go runtime documentation](https://vercel.com/docs/functions/runtimes/go).

## Create a separate API project

Run these commands from the repository root, not from `docs/`:

```bash
vercel login
vercel link
```

Choose or create a distinct API project and confirm its root directory is the repository root. Check the project selected by the CLI before adding secrets or deploying. Keep `.vercel/` untracked.

Add each required variable from [Configuration reference](/docs/configuration) to that project's production environment. Prefer Vercel's sensitive environment settings for mailbox passwords, Google client secret/refresh token when applicable, and durable-store credentials. Gmail owners must separately complete the approved manual grant setup in [Gmail and Google Workspace](/docs/gmail-workspace); deployment does not create that grant. Enter secret values interactively instead of placing them in command history:

```bash
vercel env add MAIL_PASSWORD production
```

Use a stable production API hostname in `MCP_RESOURCE_URL`, including `/mcp`, and configure the issuer for that exact audience. An automatically generated preview URL is a different audience. See the official [CLI linking](https://vercel.com/docs/cli/link) and [environment-variable](https://vercel.com/docs/cli/env) references.

Once configuration and local/CI checks are ready, publish the API intentionally:

```bash
vercel --prod
```

Deploying code does not complete OAuth client registration, create a mailbox, configure DNS, or connect ChatGPT.

## Verify before granting write access

1. Fetch the API's `/.well-known/oauth-protected-resource` document and verify its resource URL and issuer.
2. Confirm that `/mcp` rejects an unauthenticated request with `401` and a discovery challenge.
3. Connect with an allowlisted account and verify folder names and a small read-only search.
4. Open a message and confirm that it remains unread in another client when it was unread before.
5. Enable and test optional operations only against messages and folders you intend to change.

Run checks against the actual production API URL rather than assuming a successful docs deployment means the API is running.

## Serverless limits

Keep mail operation timeouts inside the selected function duration. Do not rely on background goroutines continuing after an HTTP response. Vercel blocks outgoing SMTP port 25; authenticated submission on 465 or 587 is the intended path. See [Vercel's SMTP guidance](https://vercel.com/kb/guide/serverless-functions-and-smtp).

Durable send state must live outside a function instance. A process restart, scale-out, or deployment can discard local memory. See [Safety and permissions](/docs/safety).

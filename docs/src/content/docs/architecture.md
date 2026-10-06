---
title: Architecture
description: The Go MCP boundary, OAuth resource server, mail transports, and durable send records.
summary: How requests reach the mailbox and where state lives.
order: 10
category: Concepts
---

# Architecture

Angelos has a small, account-specific server boundary. A deployment has one configured mailbox and an explicit list of OAuth subjects allowed to access it. Multiple allowed subjects share that same mailbox; they are not separate mailbox tenants. New prepared-send records and receipt lookups are nevertheless isolated by verified OAuth issuer/resource/subject.

## Request path

1. The MCP client obtains an access token from the configured external issuer.
2. The authentication middleware verifies the JWT, owner allowlist, audience, and base `mail.read` scope.
3. A typed MCP tool validates its input and checks the operation's scope and deployment gate.
4. The mail backend opens a bounded TLS connection to the configured IMAP or SMTP server.
5. The result returns structured data, warnings, or an error to the client.

The official Go MCP SDK handles stateless Streamable HTTP with JSON responses. An MCP session is not a durable transaction or approval record. The mailbox remains the provider's source of truth.

## Packages

| Package | Responsibility |
| --- | --- |
| `internal/auth` | Protected-resource metadata, token verification, public signing-key cache, and scope checks |
| `internal/config` | Administrator-configured mailbox credentials and TLS endpoints |
| `internal/mail` | IMAP reads and guarded mutations, MIME parsing, SMTP transport, and Gmail token refresh/XOAUTH2 |
| `internal/compose` | Validated recipient envelope, MIME construction, and immutable content digest |
| `internal/dispatch` | Owner-bound preparation, atomic send claim, outcome recording, and read-only receipt projection |
| `internal/app` | MCP tool names, schemas, annotations, and operation boundaries |

The root Go service is independent of the static `docs/` workspace. Documentation builds need no mailbox access.

## State

- Mail and folder state live at the IMAP provider.
- Credentials live in the API environment.
- Public issuer signing keys have a bounded in-memory cache.
- Gmail access tokens have an expiry-bounded, credential-bound in-memory cache per backend; Google refresh credentials remain in the server environment. Concurrent connections share a refresh, without automatically retrying mail operations.
- Prepared sends and dispatch records live in an optional external Redis REST store.

Sending is disabled without that store. A configured store can still serve authorized read-only receipts while sending is disabled. Mailbox reads and ordinary mailbox writes do not require it. A function instance's memory is never used as the sole duplicate-send guard.

## Deliberate boundaries

Tools cannot choose arbitrary mail hosts or supply credentials. OAuth access to Angelos and the backend's mailbox login are separate credentials with separate purposes. Gmail OAuth uses pinned Google mail and token endpoints; Spacemail/custom transports retain their password flow. No interactive Google callback or Gmail API adapter is included.

UIDVALIDITY guards against stale message identity. Conditional flag updates use CONDSTORE where supported. Other clients can still modify the account concurrently; there is no global mailbox lock or cross-protocol transaction.

The trusted MCP client handles human confirmation. An exact payload digest ensures consistency between preparation and dispatch, while the durable claim limits a preparation to one dispatch attempt. Neither mechanism guarantees final delivery or proves human consent. See [Safety and concurrency](/docs/safety).

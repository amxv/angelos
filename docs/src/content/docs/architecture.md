---
title: Architecture
description: The Go MCP boundary, optional owner-only OAuth issuer, mail transports, and durable state.
summary: How requests reach the mailbox and where state lives.
order: 40
category: Reference
---

For everyday mailbox tasks, start with the [inbox guide](/docs/inbox-guide); this page explains the server behind those actions.

Angelos has a small, account-specific server boundary. A deployment has one configured mailbox and an explicit list of OAuth subjects allowed to access it. External-issuer mode can allow multiple subjects sharing that mailbox; they are not separate mailbox tenants. First-party mode requires exactly one owner. New prepared-send records and receipt lookups are nevertheless isolated by verified OAuth issuer/resource/subject.

## Request path

1. The MCP client obtains an access token from the configured external issuer or the opt-in first-party issuer after owner passkey sign-in and client consent.
2. The authentication middleware verifies the JWT, owner allowlist, audience, and base `mail.read` scope. First-party mode additionally checks the live Redis-backed grant, so revocation is effective for subsequent authenticated requests.
3. A typed MCP tool validates its input and checks the operation's scope and deployment gate.
4. The mail backend opens a bounded TLS connection to the configured IMAP or SMTP server.
5. The result returns structured data, warnings, or an error to the client.

The official Go MCP SDK handles stateless Streamable HTTP with JSON responses. An MCP session is not a durable transaction or approval record. The mailbox remains the provider's source of truth.

## Packages

| Package | Responsibility |
| --- | --- |
| `internal/auth` | Protected-resource metadata, token verification, public signing-key cache, and scope checks |
| `internal/oauth` | First-party authorization endpoints, passkey owner sessions/consent, stable ES256 signing, and Redis-backed OAuth state |
| `internal/config` | Administrator-configured mailbox credentials and TLS endpoints |
| `internal/mail` | IMAP reads and guarded mutations, MIME parsing, SMTP transport, and Gmail token refresh/XOAUTH2 |
| `internal/compose` | Validated recipient envelope, MIME construction, and immutable content digest |
| `internal/dispatch` | Owner-bound preparation, atomic send claim, outcome recording, and read-only receipt projection |
| `internal/app` | MCP tool names, schemas, annotations, and operation boundaries |

The root Go service is independent of the static `docs/` workspace. Documentation builds need no mailbox access.

## State

- Mail and folder state live at the IMAP provider.
- Credentials live in the API environment.
- External issuer public signing keys have a bounded in-memory cache. First-party private signing keys are stable API runtime secrets; they are never generated on function startup.
- First-party owner credentials, bootstrap consumption, challenges, browser sessions, grants, authorization codes, and refresh rotation state live in a separate OAuth Redis namespace.
- Gmail access tokens have an expiry-bounded, credential-bound in-memory cache per backend; Google refresh credentials remain in the server environment. Concurrent connections share a refresh, without automatically retrying mail operations.
- Prepared sends and dispatch records live in a Redis REST store, shared with first-party OAuth infrastructure but isolated by key namespace.

Sending is disabled without that store. A configured store can still serve authorized read-only receipts while sending is disabled. With an external issuer, mailbox reads and ordinary writes do not require it. First-party mode requires Redis for OAuth and authenticated MCP calls even with every mutation gate disabled. A function instance's memory is never used as the sole duplicate-send guard. See [OAuth state and recovery](/docs/first-party-oauth#redis-state-and-retention) for namespace, retention, and failure boundaries.

## Deliberate boundaries

Tools cannot choose arbitrary mail hosts or supply credentials. OAuth access to Angelos and the backend's mailbox login are separate credentials with separate purposes. Gmail OAuth uses pinned Google mail and token endpoints; Spacemail/custom transports retain their password flow. No interactive Google callback or Gmail API adapter is included.

UIDVALIDITY guards against stale message identity. Conditional flag updates use CONDSTORE where supported. Other clients can still modify the account concurrently; there is no global mailbox lock or cross-protocol transaction.

The trusted MCP client handles human confirmation. An exact payload digest ensures consistency between preparation and dispatch, while the durable claim limits a preparation to one dispatch attempt. Neither mechanism guarantees final delivery or proves human consent. See [Safety and permissions](/docs/safety).

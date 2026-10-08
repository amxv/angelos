---
name: setup-personal-angelos
description: Set up or resume one owner's private Angelos instance in their accounts, verify a read-only ChatGPT connection, and optionally enable the release updater. Use the canonical setup guide and secure owner handoffs.
---

# Set up personal Angelos

## Outcome

One owner's existing mailbox, personal source fork, Vercel API project, durable Upstash Redis, stable HTTPS domain, passkey identity, and working ChatGPT MCP connection. This skill is an execution checklist for [Connect Your Assistant](../../../docs/src/content/docs/quickstart.md), not another configuration specification. Read that guide and the current implementation before executing. A repository change does not provision real accounts.

## Inputs and boundaries

Collect only missing non-secret inputs: GitHub owner/repository, Vercel account/project, Upstash account/database, provider, mailbox/sender address, and desired production domain. Check source access and ChatGPT custom MCP eligibility first. Use the owner's authorized computer/tool route; honor tool access denials and platform confirmation requirements.

The owner approves hosting their mailbox data, costs, account permissions, and persistent credential access. Use secure login/secret handoff for credentials, app passwords, OAuth client secrets/refresh tokens, Redis tokens, and signing keys. Never ask for secrets in chat, print them, put them in tool output, commit them, or include them in completion notes. If the available tools cannot transfer a secret securely, have the owner enter it at the exact destination. The owner completes provider consent, passkey prompts, and ChatGPT custom-app approval. Do not accept paid provisioning or new agreements without required approval.

## Resume before creating

1. Inspect existing repository, Vercel projects/domains, and this instance's Redis association using approved tools. Keep a non-secret checkpoint of resource IDs, source revision, production domain, and completed checks.
2. Verify ownership and intended mailbox. Reuse matching resources; do not create a second project/database just because a previous step was interrupted. Do not attach another instance's Redis.
3. Check whether the production endpoint already exists, configuration is present, and owner enrollment works. Do not read out secret values to prove they exist.
4. Keep the existing domain, owner subject, signing key/key ID, Microsoft token-encryption key when configured, and Redis state. Never reset the database, regenerate identity, rotate secrets, or broaden scopes merely to rerun setup.

## Execute the canonical guide

- **Step 1:** verify permitted private source access, create/reuse the owner's fork, and import its repository root into Vercel. `docs/` is not the API root. Confirm production Git branch and stable HTTPS domain. Report policy/access blockers without publishing a private source copy.
- **Step 2:** create/reuse dedicated durable Upstash only after required approvals. Configure the REST endpoint and read/write token via the secure route. Do not use a TCP URL or read-only token.
- **Step 3:** select the actual supported provider/auth mode. Check app-password eligibility or Google's OAuth audience/scope restrictions. For Google OAuth, use the shipped local grant helper, verify Gmail API is enabled in the same project before consent, and pin the intended mailbox; the owner only handles secure secret entry and consent. For Microsoft, use the shipped secure grant helper and delegated Graph configuration, preserving the token-encryption key on renewal. Do not weaken provider security or invent an arbitrary OAuth adapter.
- **Step 4:** for a new identity only, generate and privately persist the signing key and bootstrap token/hash outside the repository. Prepare production-only environment settings from the guide. Leave writes/send/delete disabled. Redeploy and await terminal success; saved environment settings alone do not alter an existing deployment.
- **Step 5:** hand the owner the exact enrollment page. After they enroll, verify sign-in, encourage a second independent authenticator, then remove the bootstrap hash and redeploy using required approvals. Preserve consumed-enrollment state and secure signing-key backup.
- **Step 6:** give the owner the exact production `/mcp` URL and OAuth mode. They complete ChatGPT app controls and consent. Verify the app discovers tools, reads capabilities and intended folders, and reads an owner-selected message without changing its unread flag. Do not send or mutate mail as a setup test.
- **Step 7 (optional):** ask whether the owner wants daily release updates. If approved, follow [Keep Angelos updated](../../../docs/src/content/docs/keep-updated.md), including the single deployment path and secret/permission handoffs. Validate with the no-apply run before enabling automatic updates. Code availability does not mean the schedule or account integration has been tested.

## Completion evidence

Verify all of the following, or report the exact remaining blocker:

- Vercel production deployment ready on the intended stable domain.
- `/healthz` identifies Angelos and reports configured; this does not prove mailbox or Redis connectivity.
- Protected-resource and authorization-server discovery agree with the exact issuer/resource; JWKS is reachable. Anonymous `/mcp` rejects access with 401 and a `WWW-Authenticate` header.
- Owner passkey login and consent complete; authenticated tools discover the intended folders and read a selected message without marking it read.
- Optional updater status is accurate: off, configured, validation checked, or an actual release deployed. Never claim a real second-owner update was verified from unit tests alone.

Return a short receipt: repository/project identifiers, deployed revision if known, production URL, exact MCP URL, read-only capability status, checks passed, owner steps still pending, and updater status. Do not include credentials, message bodies, secret file paths, or private environment values. Keep failures safe: no authentication bypass, forced fork reset, Redis reset, duplicate send, or automatic secret rotation.

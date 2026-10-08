---
title: Keep Angelos updated
description: Let your agent enable daily, checked release updates for your personal fork and existing Vercel instance.
summary: One-time approved setup, daily release checks, and clear stops for changes that need your attention.
order: 15
category: Use your inbox
---

**Your personal instance can follow eligible Angelos releases automatically.** Ask your agent to set up the included **Personal instance updater** workflow after [Connect Your Assistant](/docs/quickstart) works. It keeps your existing Vercel project, production domain, environment variables, Redis database, signing key, and passkeys.

This is optional. Forking the repository does not enable it. Each owner authorizes access to their own repository and Vercel account; there is no shared mailbox or shared deployment. The workflow is shipped code, not proof that it has run successfully in your accounts.

> Enable the optional Angelos release updater for my personal instance. Inspect existing settings first. Keep my production domain, environment, Redis, and signing key unchanged. Use secure handoff for credentials and ask for the required access approvals. Run validation before enabling daily updates, and tell me what was actually verified.

## What the agent sets up once

Your agent checks these in order and handles the ordinary configuration work. You complete account access approvals and secure secret entry where required.

1. **Verify a working personal fork.** It must be a fork of `amxv/angelos`, use `main` for the personal production code, and stay free of per-owner code edits. Keep personal settings in Vercel. The normal public-source setup needs no separately created upstream GitHub token.
2. **Identify the existing project.** Record its Vercel organization/team ID, project ID, and exact HTTPS production origin. Do not create a new project or database for updates.
3. **Choose one deployment path.** The updater deploys explicitly to Vercel. Disconnect this project's Vercel Git integration with your approval before enabling it; leaving both paths active could trigger competing deployments. The updater checks for this and refuses to apply while a Git link remains. Initial setup may use Git integration; updates switch this same project to the explicit workflow.
4. **Enable GitHub Actions on the fork.** Inspect `.github/workflows/personal-update.yml`; enable the fork's workflows if needed. The updater is designed for forks, not the upstream repository.
5. **Configure the variables and secrets below.** The agent fills non-secret identifiers. You approve access and enter credentials using the platform's secure controls. Never paste a credential into an assistant conversation, a workflow file, or a repository variable.
6. **Run the manual workflow with `apply=false`.** Review the result before permitting deployment. A successful no-apply run with a newer eligible release validates that candidate and the project access; it is not proof of a production deployment or mailbox connection. A no-change run skips build/deployment validation because the fork already matches the release.
7. **Opt in to daily application.** Set `ANGELOS_AUTO_UPDATE=true` only after the required approvals and checks. Use the first eligible update to verify an actual release, then check your assistant connection. Until that first production run succeeds, report automatic deployment as unverified.

### Repository settings

Under the fork's **Settings → Secrets and variables → Actions**, configure:

| Type | Name | Value |
| --- | --- | --- |
| Variable | `ANGELOS_PRODUCTION_URL` | Your exact HTTPS production origin, with no path, such as `https://my-angelos.vercel.app` |
| Variable | `VERCEL_ORG_ID` | The owner/team ID for the existing Vercel project |
| Variable | `VERCEL_PROJECT_ID` | The existing API project's ID |
| Variable | `ANGELOS_AUTO_UPDATE` | `true` to opt into scheduled application; leave unset otherwise |
| Secret | `VERCEL_TOKEN` | Authorized deployment access to the intended Vercel project/account |

GitHub supplies the workflow’s built-in `GITHUB_TOKEN`; the owner does not create or save a personal access token for the normal public upstream. The workflow uses its granted fork permissions; upstream release metadata is read anonymously, so public API rate limits can pause a check safely. Only deployments that genuinely require private upstream access need the optional `ANGELOS_UPSTREAM_TOKEN`, with authorized Contents and Actions read access to `amxv/angelos`; do not add broader credentials to bypass a denied action. A Vercel token may grant broader account access than one project: inspect its real scope before authorizing it. Secret storage hides values in the UI; it does not make untrusted workflow code safe. Enabling this workflow trusts eligible upstream release code with the configured automation access.

Keep mailbox credentials and signing keys in Vercel, not in GitHub Actions. The updater does not need them as repository secrets. Keep previews free of production mailbox credentials.

## What happens each day

The workflow is scheduled at **04:23 UTC**. GitHub schedules can be delayed and only run when the fork's Actions and workflow are enabled; this is not an exact-time guarantee. You can also run it manually from **Actions → Personal instance updater → Run workflow**, choosing `apply=false` for validation or `apply=true` for an approved update.

Before applying a release, the updater checks its upstream identity, release manifest, tag/commit, successful upstream CI, and compatibility markers. It runs the repository's Go and docs validation. Only an eligible release marked for automatic updates and compatible with the current instance can proceed; a release needing new configuration or incompatible state changes must stop for review. Releases that change `.github/workflows/` also require manual review/sync: the fork’s built-in token is not granted permission to silently replace its automation.

It then stages a production-targeted Vercel deployment without assigning the production domain, waits for Vercel's ready status, and promotes it. Built-in OAuth pins the canonical domain, so a preview URL is not a valid end-to-end authentication test. After promotion, it checks the canonical `/healthz` response for the expected service, configuration, and release version, then advances the fork's `main` by fast-forward only.

The existing production configuration and durable data stay in place. No force reset, secret rotation, new Redis database, or passkey reenrollment is part of an update. OAuth consent and server capability switches remain separate from approval to send or change an email.

## Know what a green run proves

A successful **apply run that deploys a newer release** proves the release checks, build/deployment, canonical health check, and fork advancement completed. A check-only or no-change success does not prove those deployment steps ran. **Health alone does not prove Redis availability, mailbox login, or an authenticated assistant read.** After the first automated release, your agent should verify discovery and help you perform the same read-only connection check used during setup. Refresh your assistant's tool definitions when a release changes the tool surface.

This workflow has not been proven in a second owner's accounts merely because its tests pass. Account-specific Actions permissions, credential expiry, and Vercel settings still need the initial real run.

## When an update stops

Check the workflow's failed step and its run summary. Keep GitHub notification preferences appropriate for failures; installing Angelos does not configure an assistant monitor or guarantee a separate alert.

- **Upstream access or authentication failed:** check the canonical public repository, GitHub service status/rate limits, and Actions permissions. For optional private access, renew the authorized token securely. Do not create an extra personal token by default.
- **Local changes, a fork newer than the stable release, or divergent history:** stop and review the differences. A freshly forked `main` can be ahead of the latest release; wait for a compatible newer stable release rather than downgrading. The updater must not erase personal commits or force-reset the branch.
- **Workflow files changed:** have your agent review the automation changes and arrange an authorized manual sync/update. Do not add broader write credentials merely to bypass the stop.
- **Missing or incompatible release metadata:** wait for an eligible release or have your agent review the migration instructions. Do not bypass checks to make the run green.
- **Vercel Git integration still linked:** confirm the intended deployment path and disconnect the link with approval; do not allow both paths to race.
- **Deployment or post-promotion health fails:** review the live deployment before retrying. Production may already have changed even if the fork did not advance. There is no automatic rollback. A code rollback cannot undo a data migration.
- **Mail stops working after a green update:** check discovery, Redis availability, provider authentication, and the assistant’s OAuth grant. Never regenerate the signing key or clear Redis as a first troubleshooting step.

The updater can reconcile a deployment that already succeeded if its verified source metadata matches the intended release but advancing the fork previously failed. Otherwise a retry should follow investigation of the exact state, not a blind second deployment. To pause automatic application, unset `ANGELOS_AUTO_UPDATE` or set it to `false`; manual apply remains an explicit choice. To stop all scheduled runs, disable this workflow in the fork. Revoking deployment/source tokens also blocks future runs, but does not change an already-running production service.

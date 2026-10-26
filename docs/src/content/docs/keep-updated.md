---
title: Keep Angelos updated
description: Follow reviewed stable releases from a public fork or a private standalone repository without replacing your existing deployment.
summary: One-time approved setup, private-repository migration, daily release checks, and safe stops.
order: 15
category: Use your inbox
---

**Your personal instance can follow eligible Angelos releases automatically, whether its GitHub source is a public fork or a private standalone repository.** Ask your agent to set up the included **Personal instance updater** workflow after [Connect Your Assistant](/docs/quickstart) works. It keeps your existing Vercel project, production domain, environment variables, Redis database, signing key, and passkeys.

This is optional. Forking the repository does not enable it. Each owner authorizes access to their own repository and Vercel account; there is no shared mailbox or shared deployment. The workflow is shipped code, not proof that it has run successfully in your accounts.

> Enable the optional Angelos release updater for my existing instance, using my public fork or private standalone repository. Inspect existing settings first. Keep the production domain, environment, Redis, signing key, and existing assistant connections unchanged. Use secure handoff for credentials and required access approvals. Run validation before enabling daily updates, and tell me what was actually verified. Do not redeploy as part of setup.

## Which repository type?

| Repository | Release source and advancement | Owner code changes |
| --- | --- | --- |
| **Public direct fork** of `amxv/angelos` | Existing behavior: only eligible upstream releases may fast-forward the fork's `main`. | A divergent or customized `main` stops automatic updates. |
| **Private standalone repository** (`fork=false`, `private=true`) | The owner's `main` keeps the reviewed workflow. A separate `angelos-upstream` branch points to the **last successfully applied, officially tagged upstream release**. After deployment, only that branch fast-forwards. | Private `main` and its commits are preserved; per-owner code changes are **not included** in upstream release deployments. Keep personal settings in Vercel. |

The private repository does not require a personal access token for the public upstream. The workflow uses its own repository-scoped `GITHUB_TOKEN`, and optional upstream credentials remain only for an upstream that is genuinely private. Neither repository type grants unattended update permission just by existing.

## Convert an existing working fork to private without redeploying

**This is a repository and automation migration, not a new Angelos installation.** Do not create another Vercel project, Redis database, hostname, OAuth issuer, signing key, passkey, or assistant connection. No Git push, Vercel redeployment, environment edit, or ChatGPT reconnect is necessary to make the source private.

1. **Inspect and checkpoint, read-only.** Confirm which GitHub fork owns the existing Vercel project, its canonical production URL, deployed version/source revision, and whether Git integration is linked. Check `/healthz` and OAuth discovery without exposing credentials. Preserve the existing working production deployment. Do not mistake a healthy HTTP response for authenticated Redis/mail availability.
2. **Detach the fork in place.** In the fork's **GitHub → Settings → General → Danger Zone → Leave fork network**, review and confirm detachment. GitHub's [detachment procedure](https://docs.github.com/en/pull-requests/how-tos/work-with-forks/detaching-a-fork) preserves commit history, but permanently removes the fork relationship and associated GitHub social/issue/PR metadata. The in-place option requires a public fork smaller than 1 GB and no child forks. Do **not** delete/recreate the repository as a shortcut: that can lose repository settings, workflows, Actions secrets, and integrations.
3. **Make the standalone repository private.** In that same GitHub repository's **Settings → General → Danger Zone → Change repository visibility**, select **Private**. Check the API reports `fork=false`, `private=true`, `visibility=private`, and the same Git history. This does not rotate OAuth or rename the production host.
4. **Verify production has not changed.** Before touching update automation, recheck the canonical URL, release version, OAuth issuer/JWKS, and (when available) the existing assistant's read-only connection. If the site's running deployment changes, stop and investigate rather than triggering another deployment.
5. **Disconnect Vercel's Git integration before any new Git push.** For release automation, use the existing project's **Settings → Git → Disconnect**, or the [Vercel CLI `vercel git disconnect`](https://vercel.com/docs/cli/git) from a locally linked checkout. Verify the intended project IDs and domain first. Disconnecting Git prevents workflow-sync commits or updates to `angelos-upstream` from automatically deploying; the current production deployment and its configuration stay intact. Do not delete the project, remove domains, or change any environment variables. Verify the project `link` is now empty. Do this before pushing workflow or branch changes.
6. **Initialize private release tracking, without deploying.** Only after identifying the last **actually running** version and verifying it corresponds to an official upstream release tag, fetch that tag from `amxv/angelos` and create `refs/heads/angelos-upstream` pointing to its exact commit SHA. For example, a verified existing `0.11.1` deployment starts from `v0.11.1`, even if a newer upstream release exists. Preserve any divergent personal commits on private `main`. If that branch already exists, verify it rather than overwriting it. Never force-push or guess the deployed baseline.
7. **Review and sync the update controller.** Compare the updater workflow, `scripts/personal_update.py`, `scripts/upstream-askpass.sh`, `scripts/repository-push-askpass.sh`, and `.github/ci-tools/` against the intended **published** upstream release. Copy reviewed changed control files into private `main`, commit/push only after Vercel Git is disconnected, and preserve unrelated owner edits. Never blindly reset or rebase `main`. Future releases that change updater controls stop until those exact official files are manually reviewed and synced.
8. **Configure the existing updater and dry-run.** Reuse this Vercel project's IDs and existing domain in Actions variables/secrets below. Run **Personal instance updater → Run workflow → `apply=false`**. Confirm `plan` and validation pass without a deployment. **Leave `ANGELOS_AUTO_UPDATE` unset or `false` until that check succeeds and the owner permits future production updates.** Turning it on later will deploy the next eligible release at the scheduled run, which might already be available; that is separate from the no-redeployment privacy conversion.

In private mode, the exact official release commit and trusted CI remain the deploy source. A custom `vercel.json` commit retained on private `main` is **not** applied to the next official upstream release. Review differences and arrange an upstream fix or explicit manual migration if the custom behavior must be retained. Do not claim personalized runtime changes will follow the updater automatically.

## What the agent sets up once

Your agent checks these in order and handles the ordinary configuration work. You complete account access approvals and secure secret entry where required.

1. **Verify the personal source.** Use either a public direct fork of `amxv/angelos` with clean upstream history, or a detached, private standalone repository with a reviewed controller on default `main` and an initialized `angelos-upstream` branch at its last applied upstream release. Keep personal settings in Vercel. The normal public-upstream setup needs no separate upstream GitHub token.
2. **Identify the existing project.** Record its Vercel organization/team ID, project ID, and exact HTTPS production origin. Do not create a new project or database for updates.
3. **Choose one deployment path.** The updater deploys explicitly to Vercel. Disconnect this project's Vercel Git integration with your approval before enabling it; leaving both paths active could trigger competing deployments. The updater checks for this and refuses to apply while a Git link remains. Initial setup may use Git integration; updates switch this same project to the explicit workflow.
4. **Enable GitHub Actions on the personal repository.** Inspect `.github/workflows/personal-update.yml`; enable the repository's workflows if needed. The updater is not designed to run in upstream `amxv/angelos` itself.
5. **Configure the variables and secrets below.** The agent fills non-secret identifiers. You approve access and enter credentials using the platform's secure controls. Never paste a credential into an assistant conversation, a workflow file, or a repository variable.
6. **Run the manual workflow with `apply=false`.** Review the result before permitting deployment. A successful no-apply run with a newer eligible release validates that candidate and the project access; it is not proof of a production deployment or mailbox connection. A no-change run skips build/deployment validation because the tracked release already matches upstream.
7. **Opt in to daily application.** Set `ANGELOS_AUTO_UPDATE=true` only after the required approvals and checks. Use the first eligible update to verify an actual release, then check your assistant connection. Until that first production run succeeds, report automatic deployment as unverified.

### Repository settings

Under the personal repository's **Settings → Secrets and variables → Actions**, configure:

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

The workflow is scheduled at **04:23 UTC**. GitHub schedules can be delayed and only run when the personal repository's Actions and workflow are enabled; this is not an exact-time guarantee. You can also run it manually from **Actions → Personal instance updater → Run workflow**, choosing `apply=false` for validation or `apply=true` for an approved update.

Before applying a release, the updater checks its upstream identity, release manifest, tag/commit, successful upstream CI, and compatibility markers. It runs the upstream candidate's Go and docs validation. Only an eligible release marked for automatic updates and compatible with the current instance can proceed; a release needing new configuration or incompatible state changes must stop for review. A public fork stops on upstream workflow changes until a reviewed manual sync. A private repository stops if the actual updater workflow, script, or deployment-tooling files changed but are not yet reviewed and synced into its own `main`. Other workflow files on private `main` are not overwritten.

It then stages a production-targeted Vercel deployment without assigning the production domain, waits for Vercel's ready status, and promotes it. Built-in OAuth pins the canonical domain, so a preview URL is not a valid end-to-end authentication test. After promotion, it checks the canonical `/healthz` response for the expected service, configuration, and release version, then fast-forwards **the public fork's `main` or the private repository's `angelos-upstream`**, never force-updating either. A detached private repository receives the verified commit objects through a normal authenticated **non-force Git push**; it cannot advance to an unknown upstream SHA using the GitHub refs API alone. A private repo's `main` remains independent of deployed upstream release revisions.

The existing production configuration and durable data stay in place. No force reset, secret rotation, new Redis database, or passkey reenrollment is part of an update. OAuth consent and server capability switches remain separate from approval to send or change an email.

## Know what a green run proves

A successful **apply run that deploys a newer release** proves the release checks, build/deployment, canonical health check, and fork advancement completed. A check-only or no-change success does not prove those deployment steps ran. **Health alone does not prove Redis availability, mailbox login, or an authenticated assistant read.** After the first automated release, your agent should verify discovery and help you perform the same read-only connection check used during setup. Refresh your assistant's tool definitions when a release changes the tool surface.

This workflow has not been proven in a second owner's accounts merely because its tests pass. Account-specific Actions permissions, credential expiry, and Vercel settings still need the initial real run.

## When an update stops

Check the workflow's failed step and its run summary. Keep GitHub notification preferences appropriate for failures; installing Angelos does not configure an assistant monitor or guarantee a separate alert.

- **Upstream access or authentication failed:** check the canonical public repository, GitHub service status/rate limits, and Actions permissions. For optional private access, renew the authorized token securely. Do not create an extra personal token by default.
- **Local changes, a tracked release newer than the stable release, or divergent history:** stop and review the differences. A public fork's `main` can be ahead of the latest release; wait for a compatible newer stable release rather than downgrading. The updater must not erase personal commits or force-reset a branch. A private `main` may intentionally diverge; its `angelos-upstream` baseline may not.
- **Missing/invalid private baseline:** do not initialize the release branch from the newest tag by guesswork. Verify the actual production version and official tagged ancestry before creating it.
- **Updater or workflow controls changed:** have your agent review and sync the actual required automation files. Do not add broader write credentials to bypass the stop.
- **Missing or incompatible release metadata:** wait for an eligible release or have your agent review the migration instructions. Do not bypass checks to make the run green.
- **Vercel Git integration still linked:** confirm the intended deployment path and disconnect the link with approval; do not allow both paths to race.
- **Deployment or post-promotion health fails:** review the live deployment before retrying. Production may already have changed even if the release branch did not advance. There is no automatic rollback. A code rollback cannot undo a data migration.
- **Mail stops working after a green update:** check discovery, Redis availability, provider authentication, and the assistant’s OAuth grant. Never regenerate the signing key or clear Redis as a first troubleshooting step.

The updater can reconcile a deployment that already succeeded if its verified source metadata matches the intended release but advancing the release branch previously failed. Otherwise a retry should follow investigation of the exact state, not a blind second deployment. To pause automatic application, unset `ANGELOS_AUTO_UPDATE` or set it to `false`; manual apply remains an explicit choice. To stop all scheduled runs, disable this workflow in the personal repository. Revoking deployment/source tokens also blocks future runs, but does not change an already-running production service.

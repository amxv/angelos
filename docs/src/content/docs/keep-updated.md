---
title: Keep Angelos updated
description: Run Angelos from a private GitHub repository and automatically deploy verified upstream releases with GitHub Actions.
summary: One private repository, one release-tracking branch, and automatic updates to your Vercel project.
order: 15
category: Use your inbox
---

**You can keep your Angelos repository private and still receive new releases automatically.** The included **Personal instance updater** GitHub Actions workflow watches [official Angelos releases](https://github.com/amxv/angelos/releases), checks that an update is safe to apply, and deploys it to your own Vercel project.

There is one setup: create a **private standalone repository** (not a GitHub fork), deploy Angelos once, then turn on the updater. Your mailbox credentials, Redis data, OAuth configuration, passkeys, and production domain stay in your Vercel project, not in the GitHub repository.

If you're using an agent, you can give it this request:

> Set up a private standalone copy of [amxv/angelos](https://github.com/amxv/angelos) that follows official stable releases using the included Personal instance updater. Use my GitHub and Vercel accounts. Follow the steps on this page, preserve any existing project, domain, Redis data, secrets, and assistant connections, and never create a public fork. Set up the release-tracking branch, run the workflow in check-only mode first, and ask for approval before enabling automatic production updates. Never put credentials in source code or chat.

## 1. Create a private copy of an official release

Make a new **empty private repository** in your GitHub account. Copy the latest published stable Angelos release into it, rather than using GitHub's **Fork** button. This creates a standalone repository that GitHub permits you to keep private.

With [GitHub CLI](https://cli.github.com/) signed in, run these commands in a new directory, replacing the username:

```bash
OWNER=YOUR_GITHUB_USERNAME
TAG=$(gh api repos/amxv/angelos/releases/latest --jq '.tag_name')

gh repo create "$OWNER/angelos" --private
git clone --branch "$TAG" --single-branch https://github.com/amxv/angelos.git angelos-private
cd angelos-private
git switch -c main
git remote rename origin upstream
git remote add origin "https://github.com/$OWNER/angelos.git"
git push -u origin main
git push origin main:refs/heads/angelos-upstream
```

You now have two branches in your private repository:

| Branch | Purpose |
| --- | --- |
| `main` | Holds your reviewed updater workflow and its supporting files. Automatic updates do **not** overwrite it. |
| `angelos-upstream` | Records the exact official release deployed to production. The updater advances it only after successful deployment and verification. |

For a **new installation**, both branches start at the same official release. If Angelos is **already running**, reuse its existing Vercel project and have your agent set `angelos-upstream` to the *verified official release currently deployed*, not an assumed latest release. Preserve any personal commits on `main`; don't reset or force-push existing branches.

## 2. Deploy Angelos to your Vercel project

For a new installation, follow [Connect Your Assistant](/docs/quickstart) to create and configure your Vercel API project, Redis, mailbox, OAuth, and assistant connection. **Import your new private repository instead of a public fork.** Use the repository root as the Vercel Root Directory and make your initial production deployment from the official release you copied in step 1.

If you already have a working instance, **keep that same Vercel project and production domain**. Do not make another Redis database, rotate secrets, re-enroll passkeys, or reconnect your assistant just to enable updates.

Once the production instance is configured and working, open **Vercel → your project → Settings → Git → Disconnect**. The updater must be the **only** deployment mechanism: leaving Vercel's Git integration connected could deploy branch pushes without the release checks. Disconnecting Git does not delete your current deployment or environment variables.

Confirm that your production URL's `/healthz` reports Angelos as configured. A healthy response alone does not verify mailbox access; use the read-only assistant check in [Connect Your Assistant](/docs/quickstart) for that.

## 3. Configure GitHub Actions

In your **private repository**, open **Settings → Secrets and variables → Actions** and set:

| Type | Name | Value |
| --- | --- | --- |
| Variable | `ANGELOS_PRODUCTION_URL` | Your stable HTTPS origin, for example `https://my-angelos.vercel.app` (no `/mcp` or trailing path) |
| Variable | `VERCEL_ORG_ID` | The owner/team ID of your existing Vercel project |
| Variable | `VERCEL_PROJECT_ID` | That Vercel project's ID |
| Secret | `VERCEL_TOKEN` | A Vercel token authorized to deploy to that project |
| Variable | `ANGELOS_AUTO_UPDATE` | Leave unset or `false` until you finish the check-only run |

Your agent can obtain the project IDs from Vercel's project settings or its linked `.vercel/project.json`. Keep the Vercel token in **Actions secrets**, and keep mailbox passwords, signing keys, and Redis credentials in **Vercel environment variables**. Do not copy them into GitHub.

Enable GitHub Actions for the private repository and allow the included workflow its declared repository permissions, including `contents: write` for advancing `angelos-upstream`. The built-in `GITHUB_TOKEN` is sufficient; **you do not need a personal access token to read the public Angelos upstream**.

## 4. Check first, then enable automatic updates

In the private repository, go to **Actions → Personal instance updater → Run workflow**:

1. Leave **`apply=false`** and run it. This checks the official release, your tracking branch, and the updater controls without deploying anything. If a newer eligible release exists, it also checks Vercel access and validates the candidate. When you're already on the newest release, there is nothing to build or deploy, so those steps are skipped.
2. Review any errors before continuing. In particular, the workflow refuses deployment while the Vercel project still has Git integration connected.
3. When you're ready to authorize future production deployments, change the Actions variable **`ANGELOS_AUTO_UPDATE`** to **`true`**.

That's it. The workflow checks for releases **daily at 04:23 UTC** (GitHub may run scheduled jobs later). You can also run it manually with `apply=true` to apply an eligible release immediately.

## What happens when a new release is published?

The workflow fetches the latest **published stable** release from `amxv/angelos`. It verifies the official tag and commit, successful upstream CI, compatibility metadata, and whether any updater-control changes require manual review. It also runs the candidate's Go and documentation checks before any production change.

If the release qualifies, GitHub Actions builds it for your **existing Vercel project**, waits until the deployment is ready, promotes it to your production domain, and verifies the running version. **Only then** does it fast-forward `angelos-upstream`. Your private `main`, production domain, environment variables, and Redis data are not replaced by the updater.

**The deployed application comes from the official release, not from custom code on your private `main`.** If you make personal application changes, they won't be included in automatic release deployments. Upstream changes to the updater workflow or its privileged supporting files also require you to review and sync those files into `main` before automatic updates resume.

## If an update stops

Open the failed GitHub Actions run and read its summary. Common causes are a missing secret, still-connected Vercel Git integration, an incompatible release, or updater files that need review. **Do not bypass the checks or force-update a branch.** A failed deployment job may already have changed production; inspect Vercel before retrying. The workflow does not automatically roll back deployments or data migrations.

To pause scheduled deployments, set `ANGELOS_AUTO_UPDATE=false`. Manual check-only runs remain available. After the first successful automatic deployment, verify your assistant can still make an authenticated, read-only mailbox request.

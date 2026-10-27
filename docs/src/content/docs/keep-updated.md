---
title: Keep Angelos updated
description: Agent-facing CLI setup for a private Angelos repository that follows verified upstream releases automatically.
summary: One private repository, one release-tracking branch, and one controlled updater for your existing Vercel project.
order: 15
category: Use your inbox
---

This guide is for an **agent operating Git, GitHub CLI (`gh`), and Vercel CLI (`vercel`)** on the owner's behalf. The goal is a working private Angelos installation with **automatic upstream release updates enabled**. Set up a standalone private repository, preserve its existing Vercel configuration, and use the included **Personal instance updater** to deploy verified [official Angelos releases](https://github.com/amxv/angelos/releases). Do not stop after merely preparing the workflow.

Work through the CLI. Do not ask the owner to visit GitHub Actions, Secrets, or Vercel settings pages when the equivalent CLI operation exists. Browser sign-in or GitHub's **Leave fork network** operation may still require the owner's browser. Never print credentials or put them in a commit, command history, or chat.

For an agent starting from a request, use this objective:

> Set up my private standalone Angelos repository to follow published stable upstream releases through the Personal instance updater. Use Git, `gh`, and `vercel` CLI, inspect the current repository and deployed project first, and preserve all existing source changes, credentials, Redis data, OAuth configuration, passkeys, production domain, and assistant connections. Do not create a new Vercel project for an existing installation. Run a check-only update, apply the latest eligible stable release if needed, and **finish by setting `ANGELOS_AUTO_UPDATE=true` and verifying it**. My request for automatic updates authorizes this setup and initial release update; don't stop to ask for a second approval unless I explicitly restricted production changes.

## 1. Prepare the private repository

For a **new installation**, create an empty private repository and copy the latest published stable release, **not** the upstream development branch. Never use GitHub's Fork button.

```bash
REPO="YOUR_GITHUB_USERNAME/angelos"
TAG="$(gh api repos/amxv/angelos/releases/latest --jq .tag_name)"

gh repo create "$REPO" --private
git clone --branch "$TAG" --single-branch https://github.com/amxv/angelos.git angelos-private
cd angelos-private
git switch -c main
RELEASE_SHA="$(git rev-parse HEAD)"
git remote rename origin upstream
git remote add origin "https://github.com/$REPO.git"

# Upstream's docs-site deployment must not target your personal API project.
# Do this before the first push so the private repository never runs that job.
if test -f .github/workflows/docs-deploy.yml; then
  git rm .github/workflows/docs-deploy.yml
  git commit -m "ci: exclude upstream docs deployment from personal instance"
fi

git push -u origin main
git push origin "$RELEASE_SHA:refs/heads/angelos-upstream"
```

`main` is your reviewed control branch and is **never overwritten automatically**. `angelos-upstream` starts at the exact official release commit and advances only after a successful verified production update. Do not create `angelos-upstream` from a local customization commit.

For an **existing installation**, do not rerun the repository creation or cloning commands. Inspect its current GitHub identity, `main` history, source modifications, and live production deployment first. Reuse the existing repository and preserve all custom commits. Create `angelos-upstream` **only if missing**, using the official release commit for the version actually deployed, verified against Vercel, `/healthz`, and upstream Git history. Do not guess that the latest tag is live, reset `main`, force-push, or advance the tracking branch during setup. If an existing repository is still a GitHub fork, it must become a standalone repository before it can be private; complete that separate GitHub detachment safely rather than deleting and recreating it.

Check the repository via CLI:

```bash
gh api "repos/$REPO" --jq '{full_name,private,fork,default_branch}'
gh api "repos/$REPO/git/ref/heads/angelos-upstream" --jq .object.sha
```

The second command returns 404 until you have created the tracking branch. That is expected on a new setup.

## 2. Keep the existing Vercel project, and disconnect Git

For a new installation only, follow [Connect Your Assistant](/docs/quickstart) to provision your own Vercel API project and configure the mailbox, Redis, OAuth, and initial production deployment. Use `vercel project add`, `vercel link --yes --project PROJECT_NAME --scope SCOPE`, `vercel env add`, and `vercel --prod --yes` from the repository root; do not import the repository through Vercel's Git integration. Verify that your service is working before enabling updates.

For an existing installation, **do not create a project or deploy anything in this step**. Identify and link the *existing* project by name/ID, and verify its identity before changing settings:

```bash
vercel project inspect PROJECT_NAME --scope SCOPE
vercel link --yes --project PROJECT_NAME --scope SCOPE
VERCEL_ORG_ID="$(jq -er .orgId .vercel/project.json)"
VERCEL_PROJECT_ID="$(jq -er .projectId .vercel/project.json)"
vercel api "/v9/projects/$VERCEL_PROJECT_ID?teamId=$VERCEL_ORG_ID" --raw \
  | jq '{id,name,link,rootDirectory}'
```

Replace `PROJECT_NAME` and `SCOPE` with the **verified existing** project and Vercel account/team scope. Stop if the project ID, owner, or domain does not match the running instance.

If that project's `link` is non-null, disconnect its automatic Git deployments **before pushing any migration changes**:

```bash
vercel git disconnect --project "$VERCEL_PROJECT_ID" --scope SCOPE --yes
vercel api "/v9/projects/$VERCEL_PROJECT_ID?teamId=$VERCEL_ORG_ID" --raw \
  | jq -e '.link == null'
```

If Git was already disconnected, only run the verification. **`git.deploymentEnabled=false` in `vercel.json` is not a substitute for disconnecting the project**: the personal updater explicitly rejects a connected Git integration. Disconnecting does not remove the current deployment, domain, or environment variables. Confirm the original production URL still serves `/healthz` and that its deployment identity and OAuth issuer did not change.

## 3. Configure Actions using `gh`

Do this against **your private repository**, never `amxv/angelos`. Set the existing Vercel project identifiers and stable production origin, without `/mcp` or other paths:

```bash
REPO="YOUR_GITHUB_USERNAME/angelos"
PRODUCTION_URL="https://YOUR-EXISTING-ANGELOS-DOMAIN"

gh variable set ANGELOS_PRODUCTION_URL --repo "$REPO" --body "$PRODUCTION_URL"
gh variable set VERCEL_ORG_ID --repo "$REPO" --body "$VERCEL_ORG_ID"
gh variable set VERCEL_PROJECT_ID --repo "$REPO" --body "$VERCEL_PROJECT_ID"
# Keep scheduled updates off only until the initial checks and upgrade finish.
gh variable set ANGELOS_AUTO_UPDATE --repo "$REPO" --body false

# Obtain a project-authorized token through a secure credential source.
# Supply its value to gh via stdin without displaying it.
printf '%s' "$VERCEL_TOKEN" | gh secret set VERCEL_TOKEN --repo "$REPO"

gh api "repos/$REPO/actions/permissions" --jq '{enabled,allowed_actions}'
gh workflow enable personal-update.yml --repo "$REPO"
gh secret list --repo "$REPO"
gh variable list --repo "$REPO"
```

The `VERCEL_TOKEN` shell variable must already be populated securely; do not paste it into a prompt, commit it, or expose it in logs. If repository Actions are disabled, use the GitHub Actions permissions API to enable them without loosening unrelated policies. The updater has a job-scoped `contents: write` permission to advance `angelos-upstream`; no GitHub personal access token is needed to read the public upstream repository.

**Do not set up the upstream API or docs deployment workflows in your private repository.** The only production deployment mechanism for this installation should be `personal-update.yml`. In particular, remove or disable a copied `docs-deploy.yml` before supplying deployment credentials. The upstream-only `VERCEL_API_TOKEN` and `VERCEL_API_PROJECT_ID` are not required; use `VERCEL_TOKEN` and `VERCEL_PROJECT_ID` for your own existing API project.

## 4. Understand the release updater

The updater verifies the official release tag and commit, successful upstream CI, compatibility metadata, and changes to privileged updater files. For an eligible release, it validates the exact official source, builds a staged deployment for **your existing Vercel project**, waits until it is ready, promotes it, verifies the live version, and then fast-forwards `angelos-upstream` without force. It does not replace your private `main` or alter stored mailbox, OAuth, or Redis credentials.

**The deployed application comes from the official release, not custom application code on private `main`.** If you customize the application, those changes will not be included in automatic release deployments. If a release changes `.github/workflows/personal-update.yml`, `scripts/personal_update.py`, its askpass scripts, or `.github/ci-tools`, review and sync those exact trusted files into private `main` before retrying. Do not blindly sync upstream's other deployment workflows.

On failure, inspect the Actions run with `gh run view RUN_ID --repo "$REPO" --log` and inspect Vercel state through the CLI. A failed workflow may already have promoted a deployment: verify production before retrying. Do not bypass provenance checks, force-update branches, or assume a rollback occurred. After a successful update, verify an authenticated read-only mailbox request through the already-connected assistant.

## 5. Validate first, then apply the current release

```bash
gh workflow run personal-update.yml --repo "$REPO" --ref main --raw-field apply=false
gh run list --repo "$REPO" --workflow personal-update.yml --limit 5
# Inspect the run ID returned above:
gh run view RUN_ID --repo "$REPO" --log
```

An `apply=false` run checks release identity, your release-tracking branch, and the updater's trusted control files **without deploying or changing production**. If a newer eligible release exists, it also verifies the Vercel project and validates the candidate's Go and docs builds. **If the tracking branch is already on the newest release, candidate validation and Vercel checks are skipped**; separately verify the project's disconnected Git integration with the CLI command in step 2.

Once the check-only run passes, **apply the latest eligible stable release** to the existing production project. This is part of completing an automatic-update setup, not an optional task to leave for the owner. If the existing installation is already up to date, the updater may correctly have nothing to deploy.

```bash
gh workflow run personal-update.yml --repo "$REPO" --ref main --raw-field apply=true
gh run list --repo "$REPO" --workflow personal-update.yml --limit 5
gh run view APPLY_RUN_ID --repo "$REPO" --log
```

Confirm the run succeeded, `angelos-upstream` matches the deployed official release, and the live version, production domain, OAuth issuer, and MCP endpoint are correct. A successful release upgrade may change the production deployment ID, but must preserve the project, credentials, Redis data, and assistant connection. If any safety check fails, stop and report the blocker rather than enabling unattended deployment in a broken state.

## 6. Enable automatic updates (required final step)

**Do not finish this guide with `ANGELOS_AUTO_UPDATE=false`.** Setting up automatic updates means leaving them **on** after the check-only run and initial eligible release update succeed. The included workflow then checks for new published stable releases every day at **04:23 UTC** (GitHub may run it later), validates and deploys eligible updates to the same project, and verifies production. No follow-up approval is needed for the normal scheduled releases the owner requested.

**Make this the last setup action, and verify the result before reporting completion:**

```bash
gh variable set ANGELOS_AUTO_UPDATE --repo "$REPO" --body true
gh variable list --repo "$REPO" | grep -E '^ANGELOS_AUTO_UPDATE[[:space:]]+true([[:space:]]|$)'
```

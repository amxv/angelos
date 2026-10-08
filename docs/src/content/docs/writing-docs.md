---
title: Improve the docs
description: Run the docs site locally and add documentation alongside Angelos changes.
summary: The contributor workflow for keeping Angelos documentation close to the code.
order: 91
category: Contributing
---

To find a task guide, start at [Welcome to Angelos](/docs/overview); use this page when contributing documentation changes.

The documentation site is a self-contained Astro workspace under `docs/` and uses the shared `zuedocs` package for the presentation layer.

Use Bun 1.4.2 as pinned in `docs/package.json` and CI. The existing `bun.lock` uses lockfile version 2, introduced in [Bun 1.4](https://bun.com/blog/bun-v1.4). Older runtimes report an unknown lockfile version; upgrade the runtime instead of discarding or regenerating the lockfile.

## Local development

From the repository root:

```bash
cd docs
bun install --frozen-lockfile
bun run dev
```

Before committing docs changes:

```bash
cd docs
bun run check
bun run build
```

## Add a page

Create Markdown files under `docs/src/content/docs/`. Every page needs frontmatter with a title, description, order, and a category defined in `docs/src/data/docs.ts` and `docs/src/content.config.ts`.

Use `docs/src/data/docs.ts` for site-wide navigation and project metadata. Product-specific homepage copy lives in `docs/src/pages/index.astro`.

## Put the reader's task first

Choose the category by what the reader is trying to do:

- **Get started:** understand Angelos and connect a client to an existing endpoint.
- **Use your inbox:** complete a mailbox task, with ordinary-language examples and important limits at the point of use.
- Keep initial provisioning, authentication, and deployment in the single **Connect Your Assistant** guide. Describe what the agent executes and reserve owner handoffs for approvals, secrets, consent, and passkeys. Do not add competing setup guides.
- **Reference:** look up exact schemas, environment variables, permission boundaries, implementation details, or migration behavior.
- **Contributing:** change and verify the project.

Lead a guide with its outcome and prerequisites, then give ordered steps and a way to check success. Link to technical reference pages instead of making new users read implementation detail before their first task. Keep exact field names and limits in the reference so the short guides remain accurate without becoming exhaustive.

The page layout renders the frontmatter title as its H1. Start Markdown body sections at `##`; do not repeat the title as a body H1. Keep existing page routes and section anchors stable where possible. When moving material, update internal links and leave a clear route from task guides to the deeper explanation.

## Keep docs tied to behavior

When a code change introduces a new public workflow, interface, permission rule, or operational guarantee, update the relevant documentation in the same change whenever practical. Avoid documenting behavior that is only planned.

## Publish an updater-compatible release

The personal updater follows published stable releases, not raw `main`. Shipping its workflow does not publish a release or prove another owner's deployment works.

1. Update the [Changelog](/docs/changelog) under the intended version marked **Unreleased**. Summarize user-visible features, fixes, security changes, and required upgrade actions, linking the relevant references. Keep chronological notes out of the migration/token-budget guide. Bump `internal/app`'s application version, the tool-reference version, and the docs release footer coherently.
2. Review `.github/angelos-release.json`. Keep `format: 1`; set `automatic: true` only when this transition requires no owner action. Increment `config_epoch` or `state_epoch` for any required configuration or state migration, set `automatic: false`, and write explicit migration notes. The updater checks intervening manifests too, so do not mark an incompatible intermediate change safe simply because a later manifest restores an old number.
3. Run all required tests and wait for the upstream `ci.yml` workflow to succeed on the exact final `main` commit. Fixes need a new complete check on their own commit.
4. Publish a non-draft, non-prerelease GitHub release with a strict `vMAJOR.MINOR.PATCH` tag pointing at that tested commit. The tag version must equal the application's version. Do not move an existing release tag.
5. After verifying publication, mark the changelog version released and link its immutable tag/source. Add a date only from verified release publication metadata, never a guessed date or commit timestamp.
6. Distinguish publication, fixture-test success, an owner's check-only run, and an actual successful production apply. Workflow-file changes require reviewed manual sync in personal forks before unattended updates can resume.

The updater trusts the pinned upstream repository and verifies the tag's resolved commit and successful CI; it does not claim cryptographic release signing. No stable release is implied by this documentation. See [Keep Angelos updated](/docs/keep-updated) for owner setup and failure handling.

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
- **Run Angelos:** provision, authenticate, and deploy the server as its operator.
- **Reference:** look up exact schemas, environment variables, permission boundaries, implementation details, or migration behavior.
- **Contributing:** change and verify the project.

Lead a guide with its outcome and prerequisites, then give ordered steps and a way to check success. Link to technical reference pages instead of making new users read implementation detail before their first task. Keep exact field names and limits in the reference so the short guides remain accurate without becoming exhaustive.

The page layout renders the frontmatter title as its H1. Start Markdown body sections at `##`; do not repeat the title as a body H1. Keep existing page routes and section anchors stable where possible. When moving material, update internal links and leave a clear route from task guides to the deeper explanation.

## Keep docs tied to behavior

When a code change introduces a new public workflow, interface, permission rule, or operational guarantee, update the relevant documentation in the same change whenever practical. Avoid documenting behavior that is only planned.

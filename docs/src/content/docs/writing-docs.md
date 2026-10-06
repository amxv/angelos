---
title: Writing docs
description: Run the docs site locally and add documentation alongside Angelos changes.
summary: The contributor workflow for keeping Angelos documentation close to the code.
order: 3
category: Contributing
---

# Writing docs

The documentation site is a self-contained Astro workspace under `docs/` and uses the shared `zuedocs` package for the presentation layer.

## Local development

From the repository root:

```bash
cd docs
bun install
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

## Keep docs tied to behavior

When a code change introduces a new public workflow, interface, permission rule, or operational guarantee, update the relevant documentation in the same change whenever practical. Avoid documenting behavior that is only planned.

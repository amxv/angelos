# Angelos docs

The Angelos documentation site is a self-contained Astro workspace using the shared `zuedocs` package.

Use Bun 1.4.2, matching `package.json` and CI. The committed version-2 `bun.lock` requires Bun 1.4 or newer. Preserve it when installing; do not regenerate dependencies to work around an older runtime.

## Commands

```bash
bun install
bun run check
bun run build
bun run dev
```

Documentation content lives in `src/content/docs/`. Site-wide navigation and metadata live in `src/data/docs.ts`.

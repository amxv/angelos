# Agent guidance

Keep documentation close to implementation. When a code change introduces or changes a public workflow, interface, permission boundary, or operational guarantee, update `docs/` in the same change when practical.

The docs site is a self-contained Astro/ZueDocs workspace under `docs/`. New pages belong in `docs/src/content/docs/`.

Validate docs changes serially:

```bash
cd docs
bun run check
bun run build
```

Do not document planned behavior as if it is already implemented.

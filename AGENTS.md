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

## Release documentation

Maintain `docs/src/content/docs/changelog.md` for release-visible features, fixes, security changes, and upgrade requirements. Put pending changes under the intended version marked **Unreleased**. Mark a version published only after verifying its release/tag, and add a release date only from verified publication metadata; do not infer it from a commit timestamp. Link exact source revisions and the relevant setup/migration references.

Keep `tool-migration.md` focused on durable compatibility rules, legacy call mapping, and reproducible discovery/response measurements. Put chronological release notes in the changelog instead. Update the changelog and affected task/reference pages together, and validate navigation, local links, and serial docs checks before completing a release change.

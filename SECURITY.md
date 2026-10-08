# Security

Angelos is self-hosted software that can access a mailbox and send mail. The
operator is responsible for their deployment, provider permissions, backups,
and credentials. Keep the application and its dependencies current. Security
fixes target the current release; older releases have no separate maintenance
guarantee.

## Reporting a vulnerability

Please do not post credentials, mailbox contents, or exploitable private details
in a public issue, pull request, or workflow log. Use **Security → Report a
vulnerability** on the [upstream repository](https://github.com/amxv/angelos)
when that private reporting option is available. If it is unavailable, open an
issue asking the maintainer for a private reporting channel, without including
the vulnerability details. Include the affected version, impact, and a minimal
redacted reproduction in the private report. Do not test against another
person's deployment or mailbox without their permission.

If a credential is exposed, revoke or rotate it at its issuer promptly. Deleting
a file or rewriting history does not revoke a credential or erase other copies.

## Keep owner data out of source and uploads

- Store real credentials in the deployment's secret manager. Local setup output
  should live outside the checkout in an owner-only directory such as
  `$HOME/.angelos-private`.
- `.gitignore` and `.vercelignore` exclude `.angelos-private/`, `.secrets/`,
  `signing-key.pem`, `bootstrap-token.txt`, `google.env`, and `microsoft.env`, in
  addition to local `.env` files. These are guardrails, not encryption or a
  substitute for keeping secrets outside source. Already tracked files are not
  protected by ignore rules.
- Do not commit private keys, passwords, OAuth grants, Redis tokens, exported
  settings, or mailbox data. Public hostnames, OAuth client IDs, project IDs,
  example addresses, and key IDs are identifiers, not authentication secrets.
- Review the actual staged diff before committing and the deployment file list
  before uploading. Keep `.env.example` and tests synthetic.

## Secret scanning

CI's **Secret scanning** job runs the official Gitleaks **8.30.1** CLI against
all fetched Git history, including the pull-request checkout. Its archive is
SHA-256-pinned in `scripts/install-gitleaks.sh`; no scanner service receives the
source. Reports redact detected values. The scanner is a defense in depth and
does not prove the absence of every credential or sensitive piece of data.

The repository config extends the scanner's standard rules without excluding
source, docs, tests, or complete credential types. Existing obvious synthetic
fixture values, such as `synthetic-client-secret`, need no repository-specific
allowance under the pinned rules. There is no grandfathered finding baseline,
and inline `gitleaks:allow` comments are ignored. A future false positive must be
reviewed and any necessary exception limited to a specific rule, exact
synthetic value, and exact file, with a regression test showing a different
credential in the same file is still detected. Never allowlist real credentials.

To run the same scanner on Linux x86_64:

```sh
bash scripts/install-gitleaks.sh /tmp/angelos-security-tools
GITLEAKS_BIN=/tmp/angelos-security-tools/gitleaks \
  python3 -m unittest discover -s scripts -p 'test_secret_scanning.py' -v
/tmp/angelos-security-tools/gitleaks git . --log-opts="--all" \
  --config .gitleaks.toml --redact --no-banner --ignore-gitleaks-allow
```

The fixture tests are wholly offline. They verify that known synthetic values
remain usable, realistic token shapes fail in source/test/docs/example paths,
and a secret removed in a later commit still fails the history scan. When
`GITLEAKS_BIN` is absent, the ordinary Python suite skips only the CLI integration
fixtures; CI's dedicated scan job supplies the binary and runs them.

## Updater trust boundary

Public upstream releases require no personal access token. Optional
`ANGELOS_UPSTREAM_TOKEN` is for read-only access to a private upstream; never give
it write permissions. The workflow's `GITHUB_TOKEN` reads the personal fork and
can fast-forward that fork only in the deploy job. Upstream API reads are
anonymous by default; rate limiting stops the run safely until it can be retried.

The updater pins upstream repository identity, checks the exact release commit's
trusted CI, validates compatibility metadata throughout the transition, and
refuses workflow changes or divergent history. Candidate validation runs on a
separate runner without deployment/write secrets. The Vercel CLI and its full
dependency tree are pinned in `.github/ci-tools/package-lock.json`; installation
uses `npm ci --ignore-scripts` in a temporary directory before deploy tokens enter
any step. The trusted CLI survives the later candidate checkout. Actions are
pinned to reviewed commit SHAs. Changes to these pins and lockfiles require
normal source review and validation; do not replace them with floating tags or
install tools inside a token-bearing step.

For the operational setup and remaining limits, see
[`docs/src/content/docs/keep-updated.md`](docs/src/content/docs/keep-updated.md).

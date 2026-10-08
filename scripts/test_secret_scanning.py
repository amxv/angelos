"""Offline secret-scanner regressions. All credential-shaped inputs are generated."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
GITLEAKS = os.environ.get("GITLEAKS_BIN", "")


class SecurityConfigurationTests(unittest.TestCase):
    def test_actions_are_commit_pinned_and_never_use_privileged_pr_trigger(self):
        for path in (ROOT / ".github/workflows").glob("*.yml"):
            text = path.read_text()
            self.assertNotIn("pull_request_target", text)
            for action in re.findall(r"uses:\s*(\S+)", text):
                self.assertRegex(action, r"^[\w.-]+/[\w.-]+@[0-9a-f]{40}$", str(path))

    def test_scanner_has_no_blanket_allowances(self):
        # Remove comments before asserting policy to keep explanations readable.
        config = "\n".join(line.split("#", 1)[0] for line in (ROOT / ".gitleaks.toml").read_text().splitlines())
        self.assertIn("useDefault = true", config)
        for forbidden in ("allowlist", "stopwords", "paths", "disabledRules"):
            self.assertNotIn(forbidden, config)
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertIn('fetch-depth: 0', workflow)
        self.assertIn('--log-opts="--all"', workflow)
        self.assertIn('--ignore-gitleaks-allow', workflow)
        self.assertNotIn('--baseline-path', workflow)

    def test_cli_lock_pins_every_download_and_uses_official_registry(self):
        manifest = json.loads((ROOT / ".github/ci-tools/package.json").read_text())
        lock = json.loads((ROOT / ".github/ci-tools/package-lock.json").read_text())
        self.assertEqual(manifest["dependencies"], {"vercel": "62.4.0"})
        self.assertEqual(lock["packages"][""]["dependencies"], manifest["dependencies"])
        for name, package in lock["packages"].items():
            if not name:
                continue
            self.assertTrue(package["resolved"].startswith("https://registry.npmjs.org/"), name)
            self.assertTrue(package["integrity"].startswith("sha512-"), name)

    def test_sensitive_filenames_ignored_but_source_retained(self):
        sensitive = ["signing-key.pem", "bootstrap-token.txt", "google.env", "microsoft.env",
                     ".angelos-private/output", ".secrets/output", ".env", ".env.local"]
        source = [".env.example", "internal/oauth/keys.go", "internal/oauth/key.pem",
                  "scripts/google_grant.py", "scripts/test_google_grant.py", "docs/src/content/docs/quickstart.md",
                  ".github/ci-tools/package-lock.json"]
        with tempfile.TemporaryDirectory() as directory:
            subprocess.run(["git", "init", "-q", directory], check=True)
            for ignorefile in (".gitignore", ".vercelignore"):
                # Git's matcher covers these plain shared ignore-pattern forms.
                shutil.copyfile(ROOT / ignorefile, Path(directory) / ".gitignore")
                for name in sensitive:
                    result = subprocess.run(["git", "-C", directory, "check-ignore", "--no-index", name], capture_output=True)
                    self.assertEqual(result.returncode, 0, (ignorefile, name))
                if ignorefile == ".gitignore":
                    for name in source:
                        result = subprocess.run(["git", "-C", directory, "check-ignore", "--no-index", name], capture_output=True)
                        self.assertEqual(result.returncode, 1, (ignorefile, name))


@unittest.skipUnless(GITLEAKS, "GITLEAKS_BIN not set; dedicated CI secret job runs CLI fixtures")
class ScannerFixtureTests(unittest.TestCase):
    def setUp(self):
        self.assertEqual(subprocess.check_output([GITLEAKS, "version"], text=True).strip(), "8.30.1")
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()

    def token(self):
        # A provider-shaped deterministic dummy assembled only at runtime. This
        # never reaches a provider or appears as a complete token in the source.
        return "gh" + "p_" + hashlib.sha256(b"offline scanner positive fixture").hexdigest()[:36]

    def scan(self, mode="dir"):
        report = self.root / "report.json"
        command = [GITLEAKS, mode, str(self.source), "--config", str(ROOT / ".gitleaks.toml"),
                   "--redact", "--no-banner", "--ignore-gitleaks-allow", "--report-format", "json",
                   "--report-path", str(report)]
        if mode == "git":
            command.append("--log-opts=--all")
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertIn(result.returncode, (0, 1), result.stderr)
        self.assertNotIn(self.token(), result.stdout + result.stderr)
        findings = json.loads(report.read_text())
        self.assertNotIn(self.token(), report.read_text())
        return result.returncode, findings

    def test_obvious_synthetic_values_remain_usable(self):
        (self.source / "fixture.py").write_text('SECRET = "synthetic-client-secret"\nREFRESH = "synthetic-refresh-token"\nPASSWORD = "test-password"\n')
        self.assertEqual(self.scan(), (0, []))

    def test_realistic_tokens_detected_in_tests_docs_examples_and_source(self):
        paths = ["scripts/test_fixture.py", "internal/oauth/fixture_test.go", "internal/oauth/fixture.go",
                 "docs/src/content/docs/fixture.md", ".env.example"]
        for name in paths:
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('token = "' + self.token() + '"\n')
        code, findings = self.scan()
        self.assertEqual(code, 1)
        detected = {str(Path(item["File"]).relative_to(self.source)) for item in findings}
        self.assertEqual(detected, set(paths))

    def test_inline_bypass_comment_does_not_hide_a_token(self):
        (self.source / "fixture.py").write_text('token = "' + self.token() + '" # gitleaks:allow\n')
        self.assertEqual(self.scan()[0], 1)

    def test_removed_secret_still_detected_in_history(self):
        def git(*args):
            subprocess.run(["git", "-C", str(self.source), *args], check=True, capture_output=True)
        git("init", "-q")
        git("config", "user.name", "Scanner fixture")
        git("config", "user.email", "fixture@example.test")
        path = self.source / "fixture.py"
        path.write_text('token = "' + self.token() + '"\n')
        git("add", "fixture.py")
        git("commit", "-qm", "Synthetic positive fixture")
        path.write_text("# Credential removed from HEAD\n")
        git("add", "fixture.py")
        git("commit", "-qm", "Remove synthetic token")
        self.assertEqual(self.scan("git")[0], 1)


if __name__ == "__main__":
    unittest.main()

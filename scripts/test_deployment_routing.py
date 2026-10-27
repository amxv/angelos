"""Offline safeguards for independent docs and API deployment routing."""

import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent


def filters(workflow):
    """Read the two simple YAML path lists without requiring PyYAML in CI."""
    match = re.search(
        r"^            go:\n(?P<go>(?:^              - '[^']+'\n)+)"
        r"^            api:\n(?P<api>(?:^              - '[^']+'\n)+)",
        workflow,
        re.MULTILINE,
    )
    if not match:
        raise AssertionError("Go/API path filters not found")
    return {
        group: re.findall(r"^              - '([^']+)'$", match[group], re.MULTILINE)
        for group in ("go", "api")
    }


class DeploymentRoutingTests(unittest.TestCase):
    def test_via_actions_only_no_canceled_git_deployments(self):
        for path in ("vercel.json", "docs/vercel.json"):
            with self.subTest(path=path):
                config = json.loads((ROOT / path).read_text())
                self.assertIs(config["git"]["deploymentEnabled"], False)
                self.assertNotIn("ignoreCommand", config)

    def test_docs_deploy_from_docs_changes_only(self):
        workflow = (ROOT / ".github/workflows/docs-deploy.yml").read_text()
        self.assertIn('      - "docs/**"', workflow)
        self.assertNotIn('      - "internal/**"', workflow)
        self.assertIn("secrets.VERCEL_TOKEN", workflow)
        self.assertIn("vars.VERCEL_PROJECT_ID", workflow)
        self.assertNotIn("secrets.VERCEL_API_TOKEN", workflow)

    def test_go_checks_and_api_deployment_are_not_triggered_by_docs(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        filtered = filters(workflow)
        for group, paths in filtered.items():
            with self.subTest(group=group):
                self.assertIn("*.go", paths)
                self.assertIn("internal/**", paths)
                self.assertIn("go.mod", paths)
                self.assertNotIn("docs/**", paths)
                self.assertFalse(any(path.startswith("docs/") for path in paths))
        self.assertIn("scripts/**", filtered["go"])
        self.assertNotIn("scripts/**", filtered["api"])
        # Updating only the CI workflow should verify it, not redeploy the API.
        self.assertNotIn(".github/workflows/ci.yml", filtered["api"])
        self.assertNotIn(".github/ci-tools/**", filtered["api"])
        self.assertIn("needs: changes", workflow)
        self.assertIn("needs.changes.outputs.go == 'true'", workflow)
        # Docs has its own checked, path-filtered pipeline. Don't build twice.
        self.assertNotIn("  docs:\n", workflow)

    def test_api_deploy_is_production_only_after_go_success(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        deploy = workflow.split("  deploy-api:\n", 1)[1].split("  secrets:\n", 1)[0]
        self.assertIn("needs: [changes, go]", deploy)
        self.assertIn("github.event_name == 'push'", deploy)
        self.assertIn("github.repository == 'amxv/angelos'", deploy)
        self.assertIn("inputs.redeploy_api", deploy)
        self.assertIn("github.ref == 'refs/heads/main'", deploy)
        self.assertIn("needs.go.result == 'success'", deploy)
        self.assertIn("needs.changes.outputs.api == 'true'", deploy)
        self.assertIn("secrets.VERCEL_API_TOKEN", deploy)
        self.assertIn("vars.VERCEL_API_PROJECT_ID", deploy)
        self.assertNotIn("vars.VERCEL_PROJECT_ID", deploy)
        self.assertNotIn("secrets.VERCEL_TOKEN", deploy)
        self.assertIn("angelosCommit=$GITHUB_SHA", deploy)
        self.assertNotIn("Unexpected Vercel deployment URL", deploy)
        self.assertIn("git merge-base --is-ancestor", deploy)
        self.assertIn("git diff --quiet", deploy)
        self.assertIn("git diff --quiet \"$GITHUB_SHA\" origin/main", deploy)

    def test_docs_only_commits_do_not_supersede_a_pending_go_deployment(self):
        def git(root, *args):
            return subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, text=True)

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            git(root, "init", "-q")
            git(root, "config", "user.name", "Deployment test")
            git(root, "config", "user.email", "deploy@example.test")
            (root / "main.go").write_text("package main\n")
            git(root, "add", ".")
            git(root, "commit", "-qm", "API change")
            original = git(root, "rev-parse", "HEAD").stdout.strip()
            (root / "docs").mkdir()
            (root / "docs" / "guide.md").write_text("Updated docs\n")
            git(root, "add", ".")
            git(root, "commit", "-qm", "Docs only")
            # Same pathspec used by the deploy job's stale-source check.
            paths = [":(top,glob)*.go", "internal", "cmd", "pkg", "go.mod", "go.sum", "vercel.json", ".vercelignore"]
            self.assertEqual(subprocess.run(["git", "-C", temp, "diff", "--quiet", original, "HEAD", "--", *paths]).returncode, 0)
            (root / "main.go").write_text("package main\n// New code\n")
            git(root, "add", ".")
            git(root, "commit", "-qm", "Later Go change")
            self.assertEqual(subprocess.run(["git", "-C", temp, "diff", "--quiet", original, "HEAD", "--", *paths]).returncode, 1)


if __name__ == "__main__":
    unittest.main()

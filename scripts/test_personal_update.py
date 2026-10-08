"""Deterministic safety fixtures. No external accounts, credentials, or deployment."""
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import personal_update as update


class PolicyTests(unittest.TestCase):
    def test_strict_stable_tags(self):
        for tag in ("v0.9.0", "v1.20.3"):
            self.assertEqual(update.stable_release({"tag_name": tag}), tag)
        for tag in ("main", "v1.2", "v01.2.3", "v1.2.3-rc1", "v1.2.3\n", "v1.2.3;echo x"):
            with self.subTest(tag=tag), self.assertRaises(update.Stop):
                update.stable_release({"tag_name": tag})

    def test_draft_and_prerelease_blocked(self):
        for flag in ("draft", "prerelease"):
            with self.assertRaises(update.Stop):
                update.stable_release({"tag_name": "v1.2.3", flag: True})

    def test_compatibility(self):
        base = {"automatic": True, "config_epoch": 1, "state_epoch": 1}
        update.compatible(base, base)
        for change in ({"automatic": False}, {"config_epoch": 2}, {"state_epoch": 2}):
            with self.assertRaises(update.Stop):
                update.compatible(base, base | change)

    def test_manifest_requires_typed_epochs(self):
        for manifest in ({}, {"format": 1, "automatic": True, "config_epoch": True, "state_epoch": 1}):
            with patch.object(update, "git", return_value=json.dumps(manifest)), self.assertRaises(update.Stop):
                update.manifest_at("a" * 40)

    def test_project_refuses_connected_git(self):
        env = {"VERCEL_PROJECT_ID": "prj_fixture", "VERCEL_ORG_ID": "team_fixture", "VERCEL_TOKEN": "fixture"}
        with patch.dict(os.environ, env), patch.object(update, "api", return_value={
                "id": "prj_fixture", "accountId": "team_fixture", "link": {"type": "github"}}), self.assertRaisesRegex(update.Stop, "Disconnect"):
            update.project()

    def test_project_requires_owned_canonical_domain(self):
        env = {"VERCEL_PROJECT_ID": "prj_fixture", "VERCEL_ORG_ID": "team_fixture", "VERCEL_TOKEN": "fixture",
               "ANGELOS_PRODUCTION_URL": "https://mail.example.test"}
        with patch.dict(os.environ, env), patch.object(update, "api", side_effect=[
                {"id": "prj_fixture", "accountId": "team_fixture"}, {"domains": [{"name": "other.example.test"}]}]), self.assertRaisesRegex(update.Stop, "domain"):
            update.project()

    def test_finish_race_never_writes(self):
        with patch.dict(os.environ, {"GITHUB_REPOSITORY": "owner/angelos", "GH_TOKEN": "fixture"}), patch.object(update, "api", return_value={"object": {"sha": "c" * 40}}) as api, self.assertRaisesRegex(update.Stop, "changed during"):
            update.finish("a" * 40, "b" * 40)
        self.assertEqual(api.call_count, 1)

    def test_finish_non_force_and_verified(self):
        with patch.dict(os.environ, {"GITHUB_REPOSITORY": "owner/angelos", "GH_TOKEN": "fixture"}), patch.object(update, "api", side_effect=[{"object": {"sha": "a" * 40}}, {"object": {"sha": "b" * 40}}]) as api, contextlib.redirect_stdout(io.StringIO()):
            update.finish("a" * 40, "b" * 40)
        self.assertEqual(api.call_args.args[2:], ("PATCH", {"sha": "b" * 40, "force": False}))

    def test_upstream_cannot_be_mutated(self):
        with patch.dict(os.environ, {"GITHUB_REPOSITORY": update.UPSTREAM, "GH_TOKEN": "fixture"}), self.assertRaises(update.Stop):
            update.finish("a" * 40, "b" * 40)

    def test_redirects_rejected_without_forwarding_bearer(self):
        import urllib.request
        request = urllib.request.Request("https://api.github.com/test", headers={"Authorization": "Bearer fixture"})
        with self.assertRaisesRegex(update.Stop, "Redirect refused"):
            update.NoRedirect().redirect_request(request, None, 302, "Moved", {}, "https://other.example.test")

    def test_deployment_requires_exact_project_ready_and_commit(self):
        env = {"VERCEL_PROJECT_ID": "prj_fixture", "VERCEL_ORG_ID": "team_fixture", "VERCEL_TOKEN": "fixture", "EXPECTED_COMMIT": "a" * 40}
        good = {"projectId": "prj_fixture", "readyState": "READY", "target": "production", "meta": {"angelosCommit": "a" * 40}}
        for change in ({"readyState": "ERROR"}, {"projectId": "prj_other"}, {"target": "preview"}, {"meta": {}}):
            with patch.dict(os.environ, env), patch.object(update, "api", return_value=good | change), self.assertRaises(update.Stop):
                update.deployment("https://fixture.vercel.app")
        with patch.dict(os.environ, env), patch.object(update, "api", return_value=good), contextlib.redirect_stdout(io.StringIO()):
            update.deployment("https://fixture.vercel.app")

    def test_deployment_url_validation(self):
        for url in ("http://fixture.vercel.app", "https://fixture.vercel.app.evil.test", "https://user:password@fixture.vercel.app", "https://fixture.vercel.app?x=1"):
            with self.subTest(url=url), self.assertRaises(update.Stop):
                update.deployment(url)

    def test_production_newer_never_rolls_back(self):
        with patch.dict(os.environ, {"ANGELOS_PRODUCTION_URL": "https://mail.example.test"}), patch.object(update, "request_json", return_value={"service": "angelos", "configured": True, "version": "1.0.0"}), self.assertRaisesRegex(update.Stop, "newer"):
            update.production("a" * 40, "0.9.1")

    def test_production_retry_reuses_only_exact_healthy_commit(self):
        env = {"ANGELOS_PRODUCTION_URL": "https://mail.example.test", "VERCEL_ORG_ID": "team_fixture", "VERCEL_PROJECT_ID": "prj_fixture", "VERCEL_TOKEN": "fixture"}
        health = {"service": "angelos", "configured": True, "version": "0.9.1"}
        deployment = {"projectId": "prj_fixture", "readyState": "READY", "meta": {"angelosCommit": "a" * 40}}
        output = io.StringIO()
        with patch.dict(os.environ, env), patch.object(update, "request_json", return_value=health), patch.object(update, "api", side_effect=[{"projectId": "prj_fixture", "deploymentId": "dpl_fixture"}, deployment]), contextlib.redirect_stdout(output):
            update.production("a" * 40, "0.9.1")
        self.assertTrue(json.loads(output.getvalue())["current"])
        with patch.dict(os.environ, env), patch.object(update, "request_json", return_value=health), patch.object(update, "api", side_effect=[{"projectId": "prj_fixture", "deploymentId": "dpl_fixture"}, deployment]), self.assertRaisesRegex(update.Stop, "Same-version"):
            update.production("b" * 40, "0.9.1")

    def test_workflow_isolates_validation_from_deployment(self):
        workflow = (Path(__file__).resolve().parent.parent / ".github/workflows/personal-update.yml").read_text()
        validate = workflow.split("  validate:", 1)[1].split("  deploy:", 1)[0]
        self.assertNotIn("VERCEL_TOKEN", validate)
        self.assertNotIn("contents: write", validate)
        self.assertIn("persist-credentials: false", validate)
        deploy = workflow.split("  deploy:", 1)[1].split("  report:", 1)[0]
        self.assertIn("needs: [plan, validate]", deploy)
        self.assertLess(deploy.index("VALIDATED_TARGET"), deploy.index("vercel deploy"))
        self.assertLess(deploy.index("--require-current"), deploy.index(" finish --base"))
        self.assertIn("--skip-domain", deploy)
        self.assertIn('cp scripts/upstream-askpass.sh "$RUNNER_TEMP/angelos-askpass"', deploy)


class ReleaseFixtureTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.old_dir = os.getcwd()
        os.chdir(self.directory.name)
        subprocess.run(["git", "init", "-q"], check=True)
        update.git("config", "user.email", "fixture@example.test")
        update.git("config", "user.name", "Fixture")
        Path(".github").mkdir()
        self.manifest = {"format": 1, "automatic": True, "config_epoch": 1, "state_epoch": 1}
        Path(update.MANIFEST).write_text(json.dumps(self.manifest))
        Path("internal/app").mkdir(parents=True)
        Path("internal/app/app.go").write_text('const Version = "0.9.0"')
        self.base = self.commit("base")
        Path("internal/app/app.go").write_text('const Version = "0.9.1"')
        self.target = self.commit("release")
        update.git("checkout", "--detach", self.base)
        self.release = {"tag_name": "v0.9.1", "draft": False, "prerelease": False}
        self.runs = [{"id": 10, "head_sha": self.target, "event": "push", "head_repository": {"full_name": update.UPSTREAM}, "conclusion": "success"}]
        self.remote = self.base
        self.env = patch.dict(os.environ, {"GITHUB_REPOSITORY": "owner/angelos", "GITHUB_REF": "refs/heads/main", "GH_TOKEN": "fixture", "ANGELOS_UPSTREAM_TOKEN": "fixture", "ANGELOS_AUTO_UPDATE": "true"}, clear=True)
        self.env.start()
        self.real_git = update.git

    def tearDown(self):
        self.env.stop()
        os.chdir(self.old_dir)
        self.directory.cleanup()

    def commit(self, message):
        update.git("add", ".")
        update.git("commit", "-qm", message)
        return update.git("rev-parse", "HEAD")

    def api(self, path, token):
        if path == "/repos/owner/angelos":
            return {"fork": True, "parent": {"full_name": update.UPSTREAM}, "default_branch": "main"}
        if path.endswith("/git/ref/heads/main"):
            return {"object": {"sha": self.remote}}
        if path == "/repos/" + update.UPSTREAM:
            return {"id": update.UPSTREAM_ID, "full_name": update.UPSTREAM}
        if path.endswith("/releases/latest"):
            return self.release
        if "/git/ref/tags/" in path:
            return {"object": {"sha": self.target, "type": "commit"}}
        if "/actions/" in path:
            return {"workflow_runs": self.runs}
        self.fail("Unexpected API call: " + path)

    def git(self, *args):
        if "fetch" in args:
            Path(".git/FETCH_HEAD").write_text(self.target + "\n")
            return ""
        return self.real_git(*args)

    def plan(self):
        output = io.StringIO()
        with patch.object(update, "git", side_effect=self.git), patch.object(update, "api", side_effect=self.api), contextlib.redirect_stdout(output):
            update.plan()
        return json.loads(output.getvalue())

    def test_eligible_release(self):
        result = self.plan()
        self.assertTrue(result["changed"])
        self.assertEqual(result["target"], self.target)
        self.assertEqual(self.real_git("rev-parse", "HEAD"), self.base)  # plan never advances source

    def test_no_change(self):
        self.real_git("checkout", "--detach", self.target)
        self.remote = self.target
        self.assertFalse(self.plan()["changed"])

    def test_dirty_tree(self):
        Path("owner-settings.env").write_text("not a real secret")
        with self.assertRaisesRegex(update.Stop, "local changes"):
            self.plan()

    def test_divergent_fork(self):
        Path("owner-customization").write_text("local change")
        self.remote = self.commit("fork change")
        with self.assertRaisesRegex(update.Stop, "diverged"):
            self.plan()

    def test_old_release_cannot_roll_back(self):
        self.real_git("checkout", "--detach", self.target)
        self.remote = self.target
        self.target = self.base
        with self.assertRaisesRegex(update.Stop, "older"):
            self.plan()

    def test_latest_failed_ci_blocks_old_success(self):
        self.runs.append(self.runs[0] | {"id": 11, "conclusion": "failure"})
        with self.assertRaisesRegex(update.Stop, "has not passed"):
            self.plan()

    def test_pull_request_ci_is_not_release_evidence(self):
        self.runs[0]["event"] = "pull_request"
        with self.assertRaises(update.Stop):
            self.plan()

    def test_mismatched_release_version(self):
        self.release["tag_name"] = "v0.9.2"
        with self.assertRaisesRegex(update.Stop, "version disagree"):
            self.plan()

    def test_manual_transition_cannot_be_skipped(self):
        self.real_git("checkout", "--detach", self.target)
        Path(update.MANIFEST).write_text(json.dumps(self.manifest | {"automatic": False}))
        self.commit("manual migration")
        Path(update.MANIFEST).write_text(json.dumps(self.manifest))
        self.target = self.commit("automatic again")
        self.runs[0]["head_sha"] = self.target
        self.real_git("checkout", "--detach", self.base)
        with self.assertRaisesRegex(update.Stop, "manual-only"):
            self.plan()

    def test_workflow_changes_require_manual_sync(self):
        self.real_git("checkout", "--detach", self.target)
        Path(".github/workflows").mkdir()
        Path(".github/workflows/example.yml").write_text("name: changed")
        self.target = self.commit("workflow change")
        self.runs[0]["head_sha"] = self.target
        self.real_git("checkout", "--detach", self.base)
        with self.assertRaisesRegex(update.Stop, "changes workflows"):
            self.plan()

    def test_descendant_semver_downgrade(self):
        self.real_git("checkout", "--detach", self.target)
        Path("internal/app/app.go").write_text('const Version = "0.8.0"')
        self.target = self.commit("bad lower version")
        self.runs[0]["head_sha"] = self.target
        self.release["tag_name"] = "v0.8.0"
        self.real_git("checkout", "--detach", self.base)
        with self.assertRaisesRegex(update.Stop, "version must increase"):
            self.plan()

    def test_manual_check_does_not_require_schedule_opt_in(self):
        os.environ["ANGELOS_AUTO_UPDATE"] = "false"
        os.environ["GITHUB_EVENT_NAME"] = "workflow_dispatch"
        self.assertTrue(self.plan()["changed"])

    def test_scheduled_run_requires_opt_in(self):
        os.environ["ANGELOS_AUTO_UPDATE"] = "false"
        os.environ["GITHUB_EVENT_NAME"] = "schedule"
        with self.assertRaisesRegex(update.Stop, "opt-in"):
            self.plan()

    def test_upstream_identity_change(self):
        original = self.api
        def changed(path, token):
            if path == "/repos/" + update.UPSTREAM:
                return {"id": 1, "full_name": update.UPSTREAM}
            return original(path, token)
        self.api = changed
        with self.assertRaisesRegex(update.Stop, "identity changed"):
            self.plan()

    def test_moved_tag(self):
        original = self.api
        def moved(path, token):
            if "/git/ref/tags/" in path:
                return {"object": {"sha": self.base, "type": "commit"}}
            return original(path, token)
        self.api = moved
        with self.assertRaisesRegex(update.Stop, "moved"):
            self.plan()


if __name__ == "__main__":
    unittest.main()

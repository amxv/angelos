#!/usr/bin/env python3
"""Fail-closed personal-fork release updater. Never writes application settings."""
import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

UPSTREAM = "amxv/angelos"
UPSTREAM_ID = 1407020355
MANIFEST = ".github/angelos-release.json"
TAG = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")
SHA = re.compile(r"[0-9a-f]{40}\Z")


class Stop(RuntimeError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Stop("Redirect refused; verify the configured service identity.")


def request_json(request):
    with urllib.request.build_opener(NoRedirect()).open(request, timeout=45) as response:
        raw = response.read(4 * 1024 * 1024 + 1)
        require(len(raw) <= 4 * 1024 * 1024, "Service response exceeded the safety limit.")
        value = json.loads(raw)
        require(isinstance(value, dict), "Service returned an unexpected response shape.")
        return value


def require(condition, message):
    if not condition:
        raise Stop(message)


def env(name):
    value = os.environ.get(name, "")
    require(value, f"Missing {name}; finish owner setup first.")
    return value


def api(path, token, method="GET", body=None, base="https://api.github.com"):
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(base + path, data=data, method=method,
        headers={"Authorization": "Bearer " + token, "Accept": "application/json",
                 "Content-Type": "application/json", "User-Agent": "angelos-personal-updater"})
    try:
        return request_json(request)
    except urllib.error.HTTPError as error:
        if error.code == 404 and path.endswith("/releases/latest"):
            raise Stop("No accessible published stable upstream release is available; verify private access or wait for the first tested release.") from None
        raise Stop(f"Service request failed ({error.code}); check access and Actions logs. No settings changed.") from None
    except (OSError, ValueError):
        raise Stop("Service unavailable or returned invalid JSON; no credentials were logged.") from None


def git(*args):
    result = subprocess.run(["git", *args], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    require(result.returncode == 0, "Git safety check failed; inspect your fork locally. No force reset is performed.")
    return result.stdout.strip()


def ancestor(old, new):
    return subprocess.run(["git", "merge-base", "--is-ancestor", old, new],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def manifest_at(sha):
    try:
        result = json.loads(git("show", f"{sha}:{MANIFEST}"))
    except (ValueError, Stop):
        raise Stop("Release metadata missing or invalid; follow the manual setup/update guide.") from None
    require(result.get("format") == 1 and type(result.get("automatic")) is bool,
            "Unsupported release metadata; manual review required.")
    for key in ("config_epoch", "state_epoch"):
        require(type(result.get(key)) is int and result[key] > 0, "Invalid compatibility epoch.")
    return result


def compatible(current, target):
    require(target["automatic"], "Maintainer marked this release manual-only; read its release notes.")
    require(all(current[key] == target[key] for key in ("config_epoch", "state_epoch")),
            "Configuration or data compatibility changed; manual migration required. No automatic rollback.")


def stable_release(release):
    require(not release.get("draft") and not release.get("prerelease"), "Only published stable releases are eligible.")
    require(TAG.fullmatch(release.get("tag_name", "")), "Release tag must be strict vMAJOR.MINOR.PATCH.")
    return release["tag_name"]


def write_output(values):
    print(json.dumps(values, sort_keys=True))
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a") as stream:
            for key, value in values.items():
                stream.write(f"{key}={str(value).lower() if isinstance(value, bool) else value}\n")


def plan():
    repository = env("GITHUB_REPOSITORY")
    require(repository != UPSTREAM, "Updater runs only in an opted-in personal fork.")
    require(os.environ.get("ANGELOS_AUTO_UPDATE") == "true" or os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch", "Owner opt-in is absent.")
    own = api(f"/repos/{repository}", env("GH_TOKEN"))
    require(own.get("fork") and own.get("parent", {}).get("full_name") == UPSTREAM,
            "Repository must be a direct fork of the pinned amxv/angelos upstream.")
    require(own.get("default_branch") == "main" and env("GITHUB_REF") == "refs/heads/main",
            "Run on the fork's main default branch only.")
    require(not git("status", "--porcelain"), "Working tree has local changes; refusing to overwrite them.")
    base = git("rev-parse", "HEAD")
    current = api(f"/repos/{repository}/git/ref/heads/main", env("GH_TOKEN"))["object"]["sha"]
    require(base == current, "Fork changed since checkout; rerun on current main.")
    token = env("ANGELOS_UPSTREAM_TOKEN")
    identity = api(f"/repos/{UPSTREAM}", token)
    require(identity.get("id") == UPSTREAM_ID and identity.get("full_name") == UPSTREAM, "Upstream repository identity changed; manual review required.")
    release = api(f"/repos/{UPSTREAM}/releases/latest", token)
    tag = stable_release(release)
    # Resolve the release's tag via Git, not mutable target_commitish in release JSON.
    # GIT_ASKPASS is supplied by the workflow; the token never enters a URL or log.
    git("-c", "http.followRedirects=false", "fetch", "--no-tags", f"https://github.com/{UPSTREAM}.git", f"refs/tags/{tag}")
    target = git("rev-parse", "FETCH_HEAD^{commit}")
    require(SHA.fullmatch(target), "Invalid upstream commit.")
    remote_tag = api(f"/repos/{UPSTREAM}/git/ref/tags/{tag}", token)["object"]
    for _ in range(5):
        if remote_tag["type"] == "commit":
            break
        require(remote_tag["type"] == "tag", "Unsupported release tag type.")
        remote_tag = api(f"/repos/{UPSTREAM}/git/tags/{remote_tag['sha']}", token)["object"]
    require(remote_tag.get("type") == "commit" and remote_tag["sha"] == target,
            "Release tag moved or could not be verified; stop and ask the maintainer.")
    require(ancestor(base, target), "Release is older than this fork or histories diverged; manual review required.")
    require(not git("diff", "--name-only", base, target, "--", ".github/workflows"),
            "This release changes workflows. Review and manually sync it with workflow-authorized credentials before resuming automatic updates.")
    compatible(manifest_at(base), manifest_at(target))
    # Every intervening metadata state must permit unattended transitions.
    for commit in git("rev-list", "--full-history", f"{base}..{target}", "--", MANIFEST).splitlines():
        compatible(manifest_at(base), manifest_at(commit))
    runs = api(f"/repos/{UPSTREAM}/actions/workflows/ci.yml/runs?head_sha={target}&per_page=100", token)["workflow_runs"]
    trusted = [run for run in runs if run.get("head_sha") == target and run.get("event") in ("push", "workflow_dispatch")
               and run.get("head_repository", {}).get("full_name") == UPSTREAM]
    require(trusted and max(trusted, key=lambda run: run["id"]).get("conclusion") == "success",
            "Latest trusted upstream CI run for this exact release commit has not passed.")
    old_version = re.search(r'const Version = "([0-9]+\.[0-9]+\.[0-9]+)"', git("show", f"{base}:internal/app/app.go"))
    require(old_version, "Current application version is unknown; manual review required.")
    if base != target:
        require(tuple(map(int, tag[1:].split("."))) > tuple(map(int, old_version[1].split("."))), "Release version must increase; refusing a version rollback or same-version replacement.")
    version_source = git("show", f"{target}:internal/app/app.go")
    require(f'const Version = "{tag[1:]}"' in version_source, "Release tag and application version disagree.")
    write_output({"changed": base != target, "base": base, "target": target, "tag": tag, "version": tag[1:]})


def project():
    project_id, org_id = env("VERCEL_PROJECT_ID"), env("VERCEL_ORG_ID")
    query = "?teamId=" + urllib.parse.quote(org_id, safe="")
    result = api("/v9/projects/" + urllib.parse.quote(project_id, safe="") + query,
                 env("VERCEL_TOKEN"), base="https://api.vercel.com")
    require(result.get("id") == project_id and result.get("accountId") == org_id, "Vercel project ownership mismatch.")
    require(not result.get("link"), "Disconnect this personal project's Vercel Git integration before enabling updates; it can deploy before validation.")
    url = urllib.parse.urlsplit(env("ANGELOS_PRODUCTION_URL"))
    require(url.scheme == "https" and url.hostname and not url.username and not url.password and not url.query
            and not url.fragment and url.path in ("", "/"), "Production URL must be a plain HTTPS origin.")
    domains = api("/v9/projects/" + urllib.parse.quote(project_id, safe="") + "/domains" + query,
                  env("VERCEL_TOKEN"), base="https://api.vercel.com").get("domains", [])
    require(any(domain.get("name") == url.netloc for domain in domains), "Canonical domain does not belong to the selected Vercel project.")
    print("Verified existing project, canonical domain, and disconnected Git integration.")


def deployment(url):
    parsed = urllib.parse.urlsplit(url)
    require(parsed.scheme == "https" and parsed.hostname and parsed.hostname.endswith(".vercel.app")
            and not parsed.port and not parsed.username and not parsed.password and not parsed.query and not parsed.fragment
            and parsed.path in ("", "/"), "Invalid Vercel deployment URL.")
    info = api("/v13/deployments/" + parsed.hostname + "?teamId=" + urllib.parse.quote(env("VERCEL_ORG_ID"), safe=""),
               env("VERCEL_TOKEN"), base="https://api.vercel.com")
    require(info.get("projectId") == env("VERCEL_PROJECT_ID") and info.get("readyState") == "READY"
            and info.get("target") == "production", "Deployment is not READY in the selected production project.")
    require(info.get("meta", {}).get("angelosCommit") == env("EXPECTED_COMMIT"), "Deployment source identity mismatch.")
    print("Verified staged production deployment READY and source commit identity.")


def production(target, version, require_current=False):
    origin = env("ANGELOS_PRODUCTION_URL").rstrip("/")
    result = request_json(urllib.request.Request(origin + "/healthz", headers={"Cache-Control": "no-cache"}))
    require(result.get("service") == "angelos" and result.get("configured") is True, "Existing production is not healthy/configured; investigate before updating.")
    current = result.get("version", "")
    require(TAG.fullmatch("v" + current), "Existing production version is unknown; manual review required.")
    require(tuple(map(int, current.split("."))) <= tuple(map(int, version.split("."))), "Production is newer than the candidate; refusing rollback while fork source lags.")
    if current == version:
        hostname = urllib.parse.urlsplit(origin).hostname
        query = "?teamId=" + urllib.parse.quote(env("VERCEL_ORG_ID"), safe="")
        alias = api("/v4/aliases/" + hostname + query, env("VERCEL_TOKEN"), base="https://api.vercel.com")
        require(alias.get("projectId") == env("VERCEL_PROJECT_ID") and not alias.get("redirect")
                and alias.get("deploymentId"), "Canonical alias is not a direct deployment of the selected project.")
        deployment_id = urllib.parse.quote(alias["deploymentId"], safe="")
        info = api("/v13/deployments/" + deployment_id + query, env("VERCEL_TOKEN"), base="https://api.vercel.com")
        require(info.get("projectId") == env("VERCEL_PROJECT_ID") and info.get("readyState") == "READY"
                and info.get("meta", {}).get("angelosCommit") == target,
                "Same-version production cannot be matched to this release. Reconcile it manually; no replacement attempted.")
    require(not require_current or current == version, "Canonical production has not reached the expected release.")
    write_output({"current": current == version})


def health(version):
    url = env("ANGELOS_PRODUCTION_URL").rstrip("/") + "/healthz"
    for _ in range(12):
        try:
            result = request_json(urllib.request.Request(url, headers={"Cache-Control": "no-cache"}))
            if result.get("service") == "angelos" and result.get("configured") is True and result.get("version") == version:
                print("Canonical health check passed (configuration readiness only; not a mailbox or Redis round trip).")
                return
        except (OSError, ValueError):
            pass
        time.sleep(10)
    raise Stop("Production health verification failed. Inspect the deployment; no automatic rollback or source advance was attempted.")


def finish(base, target):
    require(SHA.fullmatch(base) and SHA.fullmatch(target), "Invalid update commit.")
    repo, token = env("GITHUB_REPOSITORY"), env("GH_TOKEN")
    require(repo != UPSTREAM, "Never advance upstream from this workflow.")
    current = api(f"/repos/{repo}/git/ref/heads/main", token)["object"]["sha"]
    require(current == base, "Fork changed during deployment; reconcile manually. Production may already be updated.")
    result = api(f"/repos/{repo}/git/refs/heads/main", token, "PATCH", {"sha": target, "force": False})
    require(result.get("object", {}).get("sha") == target, "Fork advancement could not be verified.")
    print("Verified fast-forward to the tested release. Existing settings and data were not modified.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("plan", "project", "deployment", "production", "health", "finish"))
    parser.add_argument("--version")
    parser.add_argument("--url")
    parser.add_argument("--require-current", action="store_true")
    parser.add_argument("--base")
    parser.add_argument("--target")
    args = parser.parse_args()
    try:
        {"plan": plan, "project": project, "deployment": lambda: deployment(args.url), "production": lambda: production(args.target, args.version, args.require_current), "health": lambda: health(args.version),
         "finish": lambda: finish(args.base, args.target)}[args.command]()
    except (Stop, KeyError, TypeError, OSError) as error:
        print(f"Update stopped: {error}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

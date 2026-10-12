"""Plan semantic releases and preserve the exact artifacts across publishing retries."""

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import urlopen

VERSION = re.compile(r"^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
LEVELS = {"patch": 0, "minor": 1, "major": 2}


def command(*args: str) -> str:
    return subprocess.check_output(args, text=True).strip()


def api(endpoint: str, *, missing_ok: bool = False, **fields: object) -> object:
    args = ["gh", "api", endpoint]
    if fields:
        args += ["--method", "POST", "--input", "-"]
    result = subprocess.run(
        args, input=json.dumps(fields) if fields else None, text=True, capture_output=True
    )
    if result.returncode:
        if missing_ok and "HTTP 404" in result.stderr:
            return None
        raise RuntimeError(result.stderr.strip())
    return json.loads(result.stdout)


def bump_level(messages: list[str], labels: list[str]) -> str:
    overrides = {label.removeprefix("release:") for label in labels if label.startswith("release:")}
    if overrides - LEVELS.keys():
        raise ValueError("Unknown release label; use release:patch, release:minor or release:major")
    if len(overrides) > 1:
        raise ValueError("Conflicting release labels on a pull request")
    if overrides:
        return overrides.pop()
    if any(re.search(r"(?m)^BREAKING[ -]CHANGE:\s*\S|^[a-z]+(?:\([^\n)]*\))?!:", m) for m in messages):
        return "major"
    if any(re.search(r"(?m)^feat(?:\([^\n)]*\))?:", message) for message in messages):
        return "minor"
    return "patch"


def changes_level(changes: list[tuple[str, list[dict]]]) -> str:
    """Apply each PR's override to all of its commits, then take the largest bump."""
    groups = {}
    levels = []
    for message, pulls in changes:
        merged = [pr for pr in pulls if pr.get("merged_at") and pr["base"]["ref"] == "main"]
        if not merged:
            levels.append(bump_level([message], []))
        for pr in merged:
            if pr["number"] not in groups:
                groups[pr["number"]] = (
                    [pr["title"], pr.get("body") or ""],
                    [label["name"] for label in pr["labels"]],
                )
            groups[pr["number"]][0].append(message)
    levels.extend(bump_level(messages, labels) for messages, labels in groups.values())
    return max(levels, key=LEVELS.get, default="patch")


def select_version(tags: dict[str, str], sha: str, level: str) -> tuple[str, bool]:
    stable = {tag: tuple(map(int, VERSION.fullmatch(tag).groups())) for tag in tags if VERSION.fullmatch(tag)}
    matches = [tag for tag in stable if tags[tag] == sha]
    if len(matches) > 1:
        raise ValueError("Multiple release versions point to this commit")
    if matches:
        return matches[0][1:], True
    if not stable:
        return "0.1.0", False
    major, minor, patch = max(stable.values())
    if level == "major":
        major, minor, patch = major + 1, 0, 0
    elif level == "minor":
        minor, patch = minor + 1, 0
    elif level == "patch":
        patch += 1
    else:
        raise ValueError(f"Unknown bump: {level}")
    return f"{major}.{minor}.{patch}", False


def successful_ci(run: dict, sha: str, repository: str) -> bool:
    return (
        run.get("path") == ".github/workflows/ci.yml"
        and run.get("event") in {"push", "workflow_dispatch"}
        and run.get("head_branch") == "main"
        and run.get("head_sha") == sha
        and run.get("head_repository", {}).get("full_name") == repository
        and run.get("conclusion") == "success"
    )


def output(**values: str) -> None:
    print(json.dumps(values, indent=2))
    if destination := os.environ.get("GITHUB_OUTPUT"):
        with open(destination, "a") as stream:
            for key, value in values.items():
                stream.write(f"{key}={value}\n")


def find_release(repository: str, tag: str) -> dict | None:
    """The by-tag endpoint excludes drafts; list releases with write access instead."""
    page = 1
    while True:
        releases = api(f"repos/{repository}/releases?per_page=100&page={page}")
        matches = [item for item in releases if item["tag_name"] == tag]
        if len(matches) > 1:
            raise ValueError("Multiple GitHub releases use the same tag")
        if matches:
            return matches[0]
        if len(releases) < 100:
            return None
        page += 1


def require_main_ci(repository: str, sha: str, run_id: int | None = None) -> None:
    runs = (
        [api(f"repos/{repository}/actions/runs/{run_id}")]
        if run_id
        else api(f"repos/{repository}/actions/workflows/ci.yml/runs?head_sha={sha}&per_page=100")[
            "workflow_runs"
        ]
    )
    if not any(successful_ci(run, sha, repository) for run in runs):
        raise ValueError("Publishing requires successful main CI for this exact repository and commit")


def plan(dry_run: bool) -> None:
    repository = os.environ["GITHUB_REPOSITORY"]
    sha = os.environ.get("TARGET_SHA") or command("git", "rev-parse", "HEAD")
    if not dry_run:
        if os.environ.get("RELEASE_ENABLED") != "true":
            raise ValueError("Set the RELEASE_ENABLED repository variable to true after configuring PyPI")
        subprocess.run(["git", "merge-base", "--is-ancestor", sha, "origin/main"], check=True)
        event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
        run_id = event["workflow_run"]["id"] if os.environ["GITHUB_EVENT_NAME"] == "workflow_run" else None
        require_main_ci(repository, sha, run_id)
    tags = {
        tag: command("git", "rev-list", "-n", "1", tag)
        for tag in command("git", "tag", "--list", "v*").splitlines()
        if VERSION.fullmatch(tag)
    }
    latest = max(tags, key=lambda tag: tuple(map(int, VERSION.fullmatch(tag).groups()))) if tags else None
    reuse = sha in tags.values()
    if latest and not reuse:
        subprocess.run(["git", "merge-base", "--is-ancestor", tags[latest], sha], check=True)
        # This endpoint deliberately checks publication, not draft visibility.
        previous = api(f"repos/{repository}/releases/tags/{latest}", missing_ok=True)
        if previous is None or previous["draft"]:
            sha = tags[latest]
            if not dry_run:
                require_main_ci(repository, sha)
            output(version=latest[1:], tag=latest, sha=sha, bump="resume", reused="true")
            return
    revision = f"{latest}..{sha}" if latest else sha
    changes = []
    for commit in command("git", "rev-list", revision).splitlines():
        message = command("git", "show", "-s", "--format=%B", commit)
        pulls = api(f"repos/{repository}/commits/{commit}/pulls")
        changes.append((message, pulls))
    level = changes_level(changes)
    version, reused = select_version(tags, sha, level)
    output(version=version, tag=f"v{version}", sha=sha, bump=level, reused=str(reused).lower())


def artifacts(directory: Path, version: str) -> dict[str, str]:
    expected = {f"openavt-{version}-py3-none-any.whl", f"openavt-{version}.tar.gz"}
    paths = list(directory.iterdir())
    names = {path.name for path in paths}
    attestations = {f"{name}.publish.attestation" for name in expected}
    if not expected.issubset(names) or names - expected - attestations:
        raise ValueError("Expected exactly the selected version's wheel and source archive")
    return {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in paths if path.name in expected
    }


def verify_files(local: dict[str, str], remote: list[dict], complete: bool) -> None:
    published = {file["filename"]: file["digests"]["sha256"] for file in remote}
    if any(local.get(name) != digest for name, digest in published.items()):
        raise ValueError("PyPI already contains different artifacts; never overwrite or silently skip them")
    if complete and published != local:
        raise ValueError("PyPI is missing expected release artifacts")


def pypi(version: str, complete: bool) -> None:
    try:
        with urlopen(f"https://pypi.org/pypi/openavt/{version}/json", timeout=30) as response:
            files = json.load(response)["urls"]
    except HTTPError as error:
        if error.code != 404:
            raise
        files = []
    verify_files(artifacts(Path("dist"), version), files, complete)
    print(f"PyPI artifact hashes verified ({len(files)}/2 present).")


def stage(version: str, sha: str) -> None:
    """Create a draft release; keep its files immutable so retries reuse identical bytes."""
    repository = os.environ["GITHUB_REPOSITORY"]
    tag = f"v{version}"
    # Also reject malicious or accidental externally-created tags on a different commit.
    refs = api(f"repos/{repository}/git/matching-refs/tags/{tag}")
    exact = [ref for ref in refs if ref["ref"] == f"refs/tags/{tag}"]
    if exact:
        obj = exact[0]["object"]
        while obj["type"] == "tag":
            obj = api(f"repos/{repository}/git/tags/{obj['sha']}")["object"]
        if obj["type"] != "commit" or obj["sha"] != sha:
            raise ValueError("Release tag points to a different commit")
    else:
        api(f"repos/{repository}/git/refs", ref=f"refs/tags/{tag}", sha=sha)
    release = find_release(repository, tag)
    if release is None:
        # Use the create response directly: draft listing can lag behind creation.
        release = api(
            f"repos/{repository}/releases",
            tag_name=tag,
            target_commitish=sha,
            name=f"OpenAVT {version}",
            draft=True,
            generate_release_notes=True,
        )
    expected = artifacts(Path("dist"), version)
    remote_names = {asset["name"] for asset in release["assets"]}
    if remote_names - expected.keys():
        raise ValueError("GitHub release contains unexpected assets")
    # Existing files are canonical, including a partial upload from an interrupted run.
    with tempfile.TemporaryDirectory() as temporary:
        if remote_names:
            subprocess.run(["gh", "release", "download", tag, "--dir", temporary], check=True)
        for name in expected:
            if name in remote_names:
                Path("dist", name).write_bytes(Path(temporary, name).read_bytes())
            else:
                subprocess.run(
                    [
                        "gh",
                        "api",
                        "--method",
                        "POST",
                        "--header",
                        "Content-Type: application/octet-stream",
                        "--input",
                        str(Path("dist", name)),
                        f"https://uploads.github.com/repos/{repository}/releases/{release['id']}/assets?name={name}",
                    ],
                    check=True,
                    stdout=subprocess.DEVNULL,
                )
    output(release_id=str(release["id"]))
    print(f"Staged immutable release artifacts for {tag} at {sha}.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    actions.add_parser("plan").add_argument("--dry-run", action="store_true")
    staging = actions.add_parser("stage")
    staging.add_argument("version")
    staging.add_argument("sha")
    verification = actions.add_parser("verify-pypi")
    verification.add_argument("version")
    verification.add_argument("--complete", action="store_true")
    args = parser.parse_args()
    if args.action == "plan":
        plan(args.dry_run)
    elif args.action == "stage":
        stage(args.version, args.sha)
    else:
        pypi(args.version, args.complete)


if __name__ == "__main__":
    main()

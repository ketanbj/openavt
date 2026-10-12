"""Release policy tests: compatibility, trusted CI, retry identity and PyPI immutability."""

import importlib.util
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location("release", Path(__file__).parents[1] / "scripts/release.py")
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


@pytest.mark.parametrize(
    ("messages", "labels", "expected"),
    [
        (["fix: recover dropped frames"], [], "patch"),
        (["docs: clarify trust boundaries"], [], "patch"),
        (["refactor(transport): simplify buffering"], [], "patch"),
        (["feat(authority): add domain enrollment"], [], "minor"),
        (["feat!: require new request format"], [], "major"),
        (["fix(tls)!: drop old certificate format"], [], "major"),
        (["Change framing\n\nBREAKING CHANGE: old peers cannot connect"], [], "major"),
        (["feat: new endpoint\n\nBREAKING-CHANGE: remove old endpoint"], [], "major"),
        (["Rewrite thousands of documentation lines"], [], "patch"),
        (["feat: internal change"], ["release:patch"], "patch"),
        (["Add support for new providers"], ["release:minor", "enhancement"], "minor"),
        (["Change transport"], ["release:major"], "major"),
    ],
)
def test_compatibility_bump(messages, labels, expected):
    assert release.bump_level(messages, labels) == expected


@pytest.mark.parametrize("labels", [["release:major", "release:patch"], ["release:banana"]])
def test_invalid_overrides_fail_closed(labels):
    with pytest.raises(ValueError):
        release.bump_level([], labels)


def pull(number, *, title="Improve transport", labels=()):
    return {
        "number": number,
        "title": title,
        "body": "",
        "merged_at": "2026-10-11",
        "base": {"ref": "main"},
        "labels": [{"name": label} for label in labels],
    }


def test_inner_pr_commits_can_detect_features_and_breaking_changes():
    pr = pull(1)
    assert release.changes_level([("Merge PR", [pr]), ("feat(audio): add modem", [pr])]) == "minor"
    assert release.changes_level([("Merge PR", [pr]), ("fix(audio)!: new frames", [pr])]) == "major"


def test_pr_override_applies_to_all_its_commits():
    pr = pull(1, labels=["release:patch"])
    assert release.changes_level([("Merge PR", [pr]), ("feat!: internal change", [pr])]) == "patch"


def test_largest_pending_pr_change_wins():
    changes = [("fix: retries", [pull(1)]), ("feat: audio", [pull(2)]), ("feat!: framing", [pull(3)])]
    assert release.changes_level(changes) == "major"
    assert release.changes_level(changes[:2]) == "minor"


def test_direct_main_commits_still_select_a_version():
    assert release.changes_level([("feat: enrollment", []), ("docs: guide", [])]) == "minor"


@pytest.mark.parametrize(
    ("tags", "level", "expected"),
    [
        ({}, "major", "0.1.0"),
        ({"v0.1.0": "old"}, "patch", "0.1.1"),
        ({"v0.1.9": "old"}, "minor", "0.2.0"),
        ({"v0.1.9": "old"}, "major", "1.0.0"),
        ({"v1.9.0": "old", "v1.10.0": "newer", "v2.0.0rc1": "beta"}, "patch", "1.10.1"),
    ],
)
def test_version_selection(tags, level, expected):
    assert release.select_version(tags, "current", level) == (expected, False)


def test_retry_reuses_version_even_after_newer_releases():
    assert release.select_version({"v0.1.0": "current", "v0.1.1": "newer"}, "current", "major") == (
        "0.1.0",
        True,
    )


def test_ambiguous_release_tags_fail_closed():
    with pytest.raises(ValueError, match="Multiple"):
        release.select_version({"v0.1.0": "current", "v0.1.1": "current"}, "current", "patch")


def trusted_run():
    return {
        "path": ".github/workflows/ci.yml",
        "event": "push",
        "head_branch": "main",
        "head_sha": "good",
        "head_repository": {"full_name": "ketanbj/openavt"},
        "conclusion": "success",
    }


def test_successful_main_ci():
    assert release.successful_ci(trusted_run(), "good", "ketanbj/openavt")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("event", "pull_request"),
        ("head_branch", "feature"),
        ("head_sha", "untested"),
        ("conclusion", "failure"),
        ("path", ".github/workflows/release.yml"),
        ("head_repository", {"full_name": "fork/openavt"}),
    ],
)
def test_untrusted_or_failed_ci_cannot_publish(field, value):
    run = trusted_run() | {field: value}
    assert not release.successful_ci(run, "good", "ketanbj/openavt")


def remote(name, digest):
    return {"filename": name, "digests": {"sha256": digest}}


def test_partial_publication_can_resume_with_identical_files():
    local = {"wheel": "abc", "source": "def"}
    release.verify_files(local, [], complete=False)
    release.verify_files(local, [remote("wheel", "abc")], complete=False)
    release.verify_files(local, [remote("wheel", "abc"), remote("source", "def")], complete=True)


@pytest.mark.parametrize("files", [[remote("wheel", "different")], [remote("unexpected", "abc")]])
def test_retry_never_skips_conflicting_pypi_artifacts(files):
    with pytest.raises(ValueError, match="different artifacts"):
        release.verify_files({"wheel": "abc"}, files, complete=False)


def test_release_cannot_complete_with_missing_artifacts():
    with pytest.raises(ValueError, match="missing"):
        release.verify_files({"wheel": "abc", "source": "def"}, [remote("wheel", "abc")], complete=True)


def test_post_upload_verification_allows_only_expected_attestation_sidecars(tmp_path):
    names = ["openavt-0.1.0-py3-none-any.whl", "openavt-0.1.0.tar.gz"]
    for name in names:
        (tmp_path / name).write_bytes(b"archive")
    before = release.artifacts(tmp_path, "0.1.0")
    for name in names:
        (tmp_path / f"{name}.publish.attestation").write_text("{}")
    assert release.artifacts(tmp_path, "0.1.0") == before
    (tmp_path / "unexpected.publish.attestation").write_text("{}")
    with pytest.raises(ValueError):
        release.artifacts(tmp_path, "0.1.0")


def test_attestation_sidecar_cannot_replace_a_missing_distribution(tmp_path):
    (tmp_path / "openavt-0.1.0-py3-none-any.whl").write_bytes(b"archive")
    (tmp_path / "openavt-0.1.0.tar.gz.publish.attestation").write_text("{}")
    with pytest.raises(ValueError):
        release.artifacts(tmp_path, "0.1.0")


def stage_fixture(tmp_path, monkeypatch, *, existing=False):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GITHUB_REPOSITORY", "ketanbj/openavt")
    directory = tmp_path / "dist"
    directory.mkdir()
    names = ["openavt-0.1.0-py3-none-any.whl", "openavt-0.1.0.tar.gz"]
    for name in names:
        (directory / name).write_bytes(b"new build")
    state = {
        "tag": existing,
        "release": existing,
        "list_calls": 0,
        "assets": {names[0]: b"canonical wheel"} if existing else {},
    }
    calls = []

    def api(endpoint, **fields):
        if "matching-refs" in endpoint:
            return (
                [{"ref": "refs/tags/v0.1.0", "object": {"type": "commit", "sha": "good"}}]
                if state["tag"]
                else []
            )
        if endpoint.endswith("git/refs"):
            assert fields == {"ref": "refs/tags/v0.1.0", "sha": "good"}
            state["tag"] = True
            return {}
        if endpoint.endswith("/releases") and fields:
            assert fields == {
                "tag_name": "v0.1.0",
                "target_commitish": "good",
                "name": "OpenAVT 0.1.0",
                "draft": True,
                "generate_release_notes": True,
            }
            state["release"] = True
            return {"id": 123, "tag_name": "v0.1.0", "draft": True, "assets": []}
        if "/releases?" in endpoint:
            state["list_calls"] += 1
            # Simulate stale draft listings even after the create API succeeded.
            return (
                [
                    {
                        "id": 123,
                        "tag_name": "v0.1.0",
                        "draft": True,
                        "assets": [{"name": name} for name in state["assets"]],
                    }
                ]
                if existing
                else []
            )
        raise AssertionError(endpoint)

    def run(args, **kwargs):
        calls.append(args)
        if args[:2] == ["gh", "release"] and args[2] == "download":
            destination = Path(args[args.index("--dir") + 1])
            for name, data in state["assets"].items():
                (destination / name).write_bytes(data)
        elif args[:2] == ["gh", "api"]:
            assert args[-1].startswith(
                "https://uploads.github.com/repos/ketanbj/openavt/releases/123/assets?name="
            )
            source = Path(args[args.index("--input") + 1])
            assert source.name not in state["assets"]
            state["assets"][source.name] = source.read_bytes()
        else:
            raise AssertionError(args)

    monkeypatch.setattr(release, "api", api)
    monkeypatch.setattr(release.subprocess, "run", run)
    return directory, state, calls


def test_first_publication_creates_draft_and_freezes_both_artifacts(tmp_path, monkeypatch):
    directory, state, calls = stage_fixture(tmp_path, monkeypatch)
    release.stage("0.1.0", "good")
    assert state["tag"] and state["release"]
    assert set(state["assets"]) == {path.name for path in directory.iterdir()}
    assert [call[1] for call in calls] == ["api", "api"]
    assert state["list_calls"] == 1


def test_partial_github_upload_recovers_canonical_bytes_without_replacing_them(tmp_path, monkeypatch):
    directory, state, calls = stage_fixture(tmp_path, monkeypatch, existing=True)
    release.stage("0.1.0", "good")
    assert (directory / "openavt-0.1.0-py3-none-any.whl").read_bytes() == b"canonical wheel"
    assert len(state["assets"]) == 2
    assert [call[1] for call in calls] == ["release", "api"]
    # A complete retry downloads the same bytes and performs no further uploads.
    calls.clear()
    release.stage("0.1.0", "good")
    assert [call[2] for call in calls] == ["download"]


def test_existing_tag_on_different_commit_cannot_publish(tmp_path, monkeypatch):
    stage_fixture(tmp_path, monkeypatch, existing=True)
    with pytest.raises(ValueError, match="different commit"):
        release.stage("0.1.0", "evil")


def test_draft_lookup_uses_paginated_listing_not_published_tag_endpoint(monkeypatch):
    calls = []

    def api(endpoint, **fields):
        calls.append(endpoint)
        assert "releases/tags" not in endpoint
        if endpoint.endswith("&page=1"):
            return [{"tag_name": f"v9.0.{n}"} for n in range(100)]
        return [{"tag_name": "v0.1.0", "draft": True, "id": 410055240}]

    monkeypatch.setattr(release, "api", api)
    assert release.find_release("ketanbj/openavt", "v0.1.0")["id"] == 410055240
    assert len(calls) == 2


def test_resume_reserved_version_preserves_original_source_and_checks_its_ci(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_REPOSITORY", "ketanbj/openavt")
    monkeypatch.setenv("RELEASE_ENABLED", "true")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "workflow_dispatch")
    monkeypatch.setenv("TARGET_SHA", "new-main")
    event = tmp_path / "event.json"
    event.write_text("{}")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event))

    def command(*args):
        if args[:3] == ("git", "tag", "--list"):
            return "v0.1.0"
        if args[:2] == ("git", "rev-list"):
            return "reserved-source"
        raise AssertionError(args)

    verified = []
    output = []
    monkeypatch.setattr(release, "command", command)
    monkeypatch.setattr(release.subprocess, "run", lambda *args, **kwargs: None)
    monkeypatch.setattr(release, "api", lambda *args, **kwargs: None)
    monkeypatch.setattr(release, "require_main_ci", lambda repo, sha, *args: verified.append(sha))
    monkeypatch.setattr(release, "output", lambda **values: output.append(values))
    release.plan(dry_run=False)
    assert verified == ["new-main", "reserved-source"]
    assert output == [
        {"version": "0.1.0", "tag": "v0.1.0", "sha": "reserved-source", "bump": "resume", "reused": "true"}
    ]


def test_create_api_preserves_json_boolean_types(monkeypatch):
    import json
    from types import SimpleNamespace

    captured = {}

    def run(args, **kwargs):
        captured.update(kwargs)
        assert args[-2:] == ["--input", "-"]
        return SimpleNamespace(returncode=0, stdout='{"id": 123}', stderr="")

    monkeypatch.setattr(release.subprocess, "run", run)
    assert release.api("repos/ketanbj/openavt/releases", draft=True, generate_release_notes=True) == {
        "id": 123
    }
    assert json.loads(captured["input"]) == {"draft": True, "generate_release_notes": True}


def test_complete_publication_waits_for_metadata_visibility(monkeypatch):
    import io
    import json

    local = {"wheel": "abc", "source": "def"}
    responses = iter([[], [remote("wheel", "abc")], [remote("wheel", "abc"), remote("source", "def")]])
    sleeps = []
    monkeypatch.setattr(release, "artifacts", lambda *args: local)
    monkeypatch.setattr(
        release, "urlopen", lambda *args, **kwargs: io.BytesIO(json.dumps({"urls": next(responses)}).encode())
    )
    monkeypatch.setattr(release.time, "sleep", sleeps.append)
    release.pypi("0.1.0", complete=True)
    assert sleeps == [2, 4]


def test_conflicting_artifact_is_never_retried(monkeypatch):
    import io
    import json

    sleeps = []
    monkeypatch.setattr(release, "artifacts", lambda *args: {"wheel": "abc"})
    monkeypatch.setattr(
        release,
        "urlopen",
        lambda *args, **kwargs: io.BytesIO(json.dumps({"urls": [remote("wheel", "wrong")]}).encode()),
    )
    monkeypatch.setattr(release.time, "sleep", sleeps.append)
    with pytest.raises(ValueError, match="different artifacts"):
        release.pypi("0.1.0", complete=True)
    assert sleeps == []


def test_metadata_visibility_wait_is_bounded(monkeypatch):
    import io

    sleeps = []
    monkeypatch.setattr(release, "artifacts", lambda *args: {"wheel": "abc"})
    monkeypatch.setattr(release, "urlopen", lambda *args, **kwargs: io.BytesIO(b'{"urls": []}'))
    monkeypatch.setattr(release.time, "sleep", sleeps.append)
    with pytest.raises(release.IncompletePublication):
        release.pypi("0.1.0", complete=True)
    assert sum(sleeps) == 50

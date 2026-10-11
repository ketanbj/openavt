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
        if "releases/tags" in endpoint:
            return (
                {"tag_name": "v0.1.0", "assets": [{"name": name} for name in state["assets"]]}
                if state["release"]
                else None
            )
        raise AssertionError(endpoint)

    def run(args, **kwargs):
        calls.append(args)
        assert args[:2] == ["gh", "release"]
        if args[2] == "create":
            assert "--draft" in args and "--verify-tag" in args
            assert not state["release"]
            state["release"] = True
        elif args[2] == "download":
            destination = Path(args[args.index("--dir") + 1])
            for name, data in state["assets"].items():
                (destination / name).write_bytes(data)
        elif args[2] == "upload":
            source = Path(args[-1])
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
    assert [call[2] for call in calls] == ["create", "upload", "upload"]


def test_partial_github_upload_recovers_canonical_bytes_without_replacing_them(tmp_path, monkeypatch):
    directory, state, calls = stage_fixture(tmp_path, monkeypatch, existing=True)
    release.stage("0.1.0", "good")
    assert (directory / "openavt-0.1.0-py3-none-any.whl").read_bytes() == b"canonical wheel"
    assert len(state["assets"]) == 2
    assert [call[2] for call in calls] == ["download", "upload"]
    # A complete retry downloads the same bytes and performs no further uploads.
    calls.clear()
    release.stage("0.1.0", "good")
    assert [call[2] for call in calls] == ["download"]


def test_existing_tag_on_different_commit_cannot_publish(tmp_path, monkeypatch):
    stage_fixture(tmp_path, monkeypatch, existing=True)
    with pytest.raises(ValueError, match="different commit"):
        release.stage("0.1.0", "evil")

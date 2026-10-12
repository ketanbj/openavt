# Releasing OpenAVT

[README](../README.md) · [Verification](verification.md) · [Changelog](../CHANGELOG.md)

After successful `main` CI, [`release.yml`](../.github/workflows/release.yml)
selects a version, tests and builds the package, publishes it to PyPI, then
publishes a GitHub release with the same wheel and source archive.
Publishing stays disabled until the one-time setup below is complete.

## Automatic versions

The first release is **0.1.0**. Later releases use PR titles, descriptions,
commit messages and an optional PR label:

| Change | PR title or commit | Optional override | From 0.1.3 |
| --- | --- | --- | --- |
| Fix, docs, maintenance; default | `fix: recover lost audio frames` | `release:patch` | 0.1.4 |
| New compatible functionality | `feat(ava): add domain enrollment` | `release:minor` | 0.2.0 |
| Breaking compatibility | `feat!: change request format` or `BREAKING CHANGE:` in the description | `release:major` | 1.0.0 |

A label overrides detection for that PR; use at most one release label. The
largest bump wins when several changes are pending. Size in lines is deliberately
not a version signal. Breaking changes increment the major version even during
0.x; an intentional pre-1.0 exception can use `release:minor`.

Versions are generated from Git tags by `setuptools-scm`; development checkouts
have a `.dev` version. Release builds use the selected version, and the matching
tag points to the tested `main` commit. No version-bump commits or release loops.
Only successful CI in this repository for that exact main commit can publish.
Runs are serialized and up to 100 can queue. An older commit cannot supersede
an already released descendant. If a tag has been reserved but publication failed,
the next run resumes that exact version and source before selecting another version.

## One-time setup

1. In [GitHub Environments](https://github.com/ketanbj/openavt/settings/environments),
   create **`pypi`**. Restrict deployment branches to **`main`**. Leave required
   reviewers and wait timers unset for unattended publishing.
2. In your [PyPI account's Publishing settings](https://pypi.org/manage/account/publishing/),
   add a **pending GitHub Trusted Publisher**:

   | Field | Value |
   | --- | --- |
   | PyPI project name | `openavt` |
   | Owner | `ketanbj` |
   | Repository name | `openavt` |
   | Workflow filename | `release.yml` |
   | Environment name | `pypi` |

3. In [GitHub Actions variables](https://github.com/ketanbj/openavt/settings/variables/actions),
   add a **repository variable**, not a secret: **`RELEASE_ENABLED` = `true`**.
4. Run **Actions → Release → Run workflow**, choose **`main`**, and uncheck
   **Build and test without creating tags or publishing** to publish the current
   main commit. Later merges publish automatically after CI passes.

**No PyPI API token or GitHub repository secret is needed.** The workflow's
`pypi` job uses OIDC Trusted Publishing and the built-in `GITHUB_TOKEN`.
The pending publisher creates the project on first upload; it does not reserve
its name. [PyPI's setup guide](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/).

## Test without publishing

Run **Actions → Release → Run workflow** with the default dry-run checkbox set.
This works before PyPI setup, including on an implementation branch, and makes
no tags, releases or uploads to PyPI. It runs lint, all tests, source/wheel checks,
a clean core-wheel TLS loopback, and installed-wheel live WebRTC and delegation
demos. Download `distributions` and inspect the run summary for version and hashes.

To validate locally, start with an empty `dist/` and run:

```sh
uv run --locked --extra webrtc --extra authority pytest -q
uv run --locked --extra webrtc --extra authority ruff check src tests scripts
uv run --locked --extra webrtc --extra authority ruff format --check src tests scripts
uv run --locked --extra webrtc --extra authority python -m build
uv run --locked --extra webrtc --extra authority twine check --strict dist/*
uv run --locked --extra webrtc --extra authority python scripts/check_dist.py
uv run --locked --extra webrtc --extra authority python scripts/smoke_wheel.py
```

## Recover and verify

If publishing fails, **rerun failed jobs** in Actions, or start a new Release run
on `main` with dry-run disabled. A new run uses the current workflow helpers to
recover a pending older release without moving its tag. A tag and draft GitHub
release preserve the reserved version and exact artifact bytes. Rerunning the
whole workflow for the same commit also reuses them. Do not delete or move a
release tag to force a retry. Existing PyPI files must have matching SHA-256
hashes; partial uploads resume, conflicting uploads fail. After uploading, the
verifier waits up to 50 seconds for both files to appear in PyPI metadata; a hash
mismatch fails immediately. The GitHub release is
published only after both files are verified on PyPI. A failed publish leaves a
draft, not a successful public release.

To pause future releases, set `RELEASE_ENABLED` to `false`. After a release,
install its version in a fresh environment and verify a protected request:

```sh
python -m pip install 'openavt[webrtc,authority]==0.1.0'
openavt --version
openavt delegation-demo
```

Use the actual released version in place of `0.1.0`. Changelog entries remain
reviewed documentation; GitHub release notes are generated from merged PRs.

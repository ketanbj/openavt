# Releasing OpenAVT

Source is hosted at [ketanbj/openavt](https://github.com/ketanbj/openavt).
PyPI publication is pending; the package and release workflows are prepared.
`openavt` returned 404 from the PyPI project API when checked; availability is not a
reservation. Confirm the name remains available before publishing.

## Review and build locally

```sh
uv sync --locked --extra agents --extra authority
uv run --locked --extra agents --extra authority pytest -q
uv run --locked --extra agents --extra authority ruff check src tests scripts
uv run --locked --extra agents --extra authority ruff format --check src tests scripts
uv run --locked --extra agents --extra authority python -m build
uv run --locked --extra agents --extra authority twine check --strict dist/*
uv run --locked --extra agents --extra authority python scripts/check_dist.py
uv run --locked --extra agents --extra authority python scripts/smoke_wheel.py
```

The build produces `dist/openavt-0.1.0.tar.gz` and
`dist/openavt-0.1.0-py3-none-any.whl`. The standard build command builds its wheel
from the source archive, so omitted source files are caught. Clean out older
release files before building another version; archive checks expect exactly one
wheel and one source archive.

`smoke_wheel.py` installs the core wheel into a fresh virtual environment, checks
that optional integrations are absent, checks the missing-extra error, and
completes a real mutual TLS WAV request from outside the checkout. CI also runs
live transport-only WebRTC and delegated-access calls with the installed wheel; it never needs an
OpenAI key.

## GitHub repository

The repository is `ketanbj/openavt`; `main` is the default branch. Push reviewed
changes to `main` and wait for CI before creating a release. The repository URLs
are configured under `[project.urls]` in `pyproject.toml`.

CI covers Python 3.11 and 3.13 on Linux plus Python 3.13 on macOS. It builds both
archives, validates metadata and README rendering, checks a clean core
installation, and exercises live WebRTC on Linux without OpenAI API credits.

## PyPI Trusted Publisher

Sign in to your PyPI account and create a
[pending Trusted Publisher](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/)
under [account publishing](https://pypi.org/manage/account/publishing/):

| Field | Value |
| --- | --- |
| PyPI project name | `openavt` |
| GitHub owner | `ketanbj` |
| Repository name | `openavt` |
| Workflow filename | `release.yml` |
| Environment name | `pypi` |

Create the repository's GitHub Environment named `pypi`. You may configure a
required reviewer there if you want a manual release checkpoint. The workflow
uses OIDC, not a stored PyPI API token. A pending publisher creates the PyPI
project on first successful publication and does not reserve the package name.
See the [PyPA workflow guide](https://packaging.python.org/en/latest/guides/publishing-package-distribution-releases-using-github-actions-ci-cd-workflows/).

## Publish v0.1.0

1. Set the release version in `src/openavt/__init__.py` (the single version source).
2. Update `CHANGELOG.md` and remove the README's unpublished status.
3. Run local checks, commit, and push; wait for CI.
4. Create a tag and GitHub release:

   ```sh
   git tag -a v0.1.0 -m "OpenAVT v0.1.0"
   git push origin v0.1.0
   gh release create v0.1.0 --repo ketanbj/openavt --title "OpenAVT v0.1.0" --notes-file CHANGELOG.md
   ```

Publishing a GitHub release triggers `release.yml`. It checks tag/version
agreement, tests, builds and checks archives, verifies wheel installation and
live WebRTC, then publishes the same artifacts to PyPI and attaches them to the
GitHub release. Configure the pending publisher before triggering this workflow.
If either publishing step fails, inspect the workflow jobs before retrying.
PyPI versions cannot be overwritten; use a new version for changed artifacts.

Verify the release with a fresh environment:

```sh
python -m pip install 'openavt[agents]==0.1.0'
openavt --version
openavt loopback --scenario valid
openavt live --transport-only
```

An actual two-agent call additionally requires your local `OPENAI_API_KEY`.

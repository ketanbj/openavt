# Releasing OpenAVT

[README](../README.md) · [Verification](verification.md) · [Changelog](../CHANGELOG.md)

The repository is [ketanbj/openavt](https://github.com/ketanbj/openavt).
PyPI publication is pending. Configure Trusted Publishing before creating a release.

## Validate

From a checkout with no older-version archives in `dist/`:

```sh
uv run --locked --extra webrtc --extra authority pytest -q
uv run --locked --extra webrtc --extra authority ruff check src tests scripts
uv run --locked --extra webrtc --extra authority ruff format --check src tests scripts
uv run --locked --extra webrtc --extra authority python -m build
uv run --locked --extra webrtc --extra authority twine check --strict dist/*
uv run --locked --extra webrtc --extra authority python scripts/check_dist.py
uv run --locked --extra webrtc --extra authority python scripts/smoke_wheel.py
```

This builds a wheel and source archive, checks names/metadata/license and private
artifact exclusions, then verifies a fresh core-wheel TLS loopback. CI additionally
tests the installed wheel over live WebRTC and delegated audio requests.

## Configure PyPI once

Create a [pending Trusted Publisher](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/)
in your PyPI account, and a GitHub Environment named `pypi`:

| Field | Value |
| --- | --- |
| PyPI project | `openavt` |
| GitHub owner / repository | `ketanbj` / `openavt` |
| Workflow | `release.yml` |
| Environment | `pypi` |

The workflow uses OIDC. A pending publisher does not reserve the project name;
confirm availability before publication. [PyPA publishing guide](https://packaging.python.org/en/latest/guides/publishing-package-distribution-releases-using-github-actions-ci-cd-workflows/).

## Publish

1. Set the version in `src/openavt/__init__.py` and update `CHANGELOG.md` and the README's publication status.
2. Run validation, push reviewed changes to `main`, and wait for CI.
3. Tag and create the release (the current configured version is `0.1.0`):

   ```sh
   git tag -a v0.1.0 -m "OpenAVT v0.1.0"
   git push origin v0.1.0
   gh release create v0.1.0 --repo ketanbj/openavt --title "OpenAVT v0.1.0" --notes-file CHANGELOG.md
   ```

[`release.yml`](../.github/workflows/release.yml) validates the tag, tests and
builds the package, checks wheel calls, then publishes to PyPI and attaches the
same artifacts to GitHub. Inspect failed jobs before retrying; PyPI versions
cannot be overwritten.

Verify in a fresh environment with `python -m pip install 'openavt[webrtc,authority]==0.1.0'`,
then run `openavt --version` and `openavt delegation-demo`.

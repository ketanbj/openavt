# Develop OpenAVT

Run commands from **this repository root**. Python 3.11+ and `uv` are required.
The core WAV/older live demos also use the `openssl` executable. OpenAVT has its
own lockfile/environment; the other modalities use a separate shared-core package.

## Setup and routine commands

```sh
make install
make help
make demo
make check
```

`make install` runs `uv sync --locked --all-extras`. The demo starts local SDK
peers without a model API. `make check` runs lint, formatting, documentation-link
checks and tests. `UV=/path/to/uv` selects an explicit executable. Equivalent
commands without Make are:

```sh
uv sync --locked --all-extras
uv run --locked --all-extras openavt sdk-demo
uv run --locked --all-extras pytest -q
uv run --locked --all-extras ruff check src tests scripts
uv run --locked --all-extras ruff format --check src tests scripts
uv run --locked --all-extras python scripts/check_docs.py
```

Use the [quickstart](quickstart.md) for a smaller runtime-only installation and
[code map](code-map.md) to locate the owning module and closest tests. Model
modes and real provider calls are separate opt-in workflows, with their own
credentials and possible usage charges. Routine checks require neither.

## Match verification to the change

| Changed area | Useful checks |
|---|---|
| Documentation/navigation | `make check-docs`; review examples and local links |
| Protocol, permissions or transport | Closest tests, then `make check` and the relevant local demo |
| Public SDK or CLI | SDK/CLI tests and `make demo` |
| Dependency metadata or package contents | `make build`, strict distribution checks and installed-wheel smoke below |
| Evidence/manuscript | Preserve old reports and use the publication workflow below |

Focused tests, for example:

```sh
uv run --locked --all-extras pytest -q tests/test_security.py tests/test_authority.py
```

Library code belongs in `src/openavt/`; demos own orchestration and fixture
provisioning. Keep optional imports lazy. Update `uv.lock` deliberately with a
dependency change; normal checks use `--locked` and should not rewrite it.

## New measurements

```sh
make benchmark RUNS=5 OUT=output/handshake-new-run
```

The output directory must not already exist. The run creates fresh local calls
and writes timing/environment information there. It does not update tracked
historical results. The [authority experiment](authority-experiment.md) has its
own method, schedules and output requirements. These experimental scripts are
not production application APIs.

Report the exact revision, environment, channel and timing/effect boundary.
Retain failures and controls. A successful expected-outcome assertion in the
revocation study includes deliberate limitations; it is not a claim that all
effects respected current authority.

## Local package validation

Build and validate in a fresh output directory, preserving earlier artifacts:

```sh
make check-package DIST=output/package-validation/dist
```

This builds the source/wheel pair, checks strict metadata/archive contents and
runs the installed-wheel smoke workflow outside the source checkout. The chosen
directory must contain only that pair. Use a new path for a later version rather
than mixing older archives or deleting them implicitly.

For individual steps, `make build DIST=...` selects the build directory, and both
`scripts/check_dist.py` and `scripts/smoke_wheel.py` accept `--dist PATH`.
Their no-argument behavior remains `dist/` for existing CI/release workflows.
These commands build/check locally and do not publish. The separate
[release guide](releasing.md) describes actual publication automation.

## Manuscript and generated artifacts

The [paper guide](../paper/README.md) lists editable sections, recorded report
inputs and the table extractor. `make paper TECTONIC=/path/to/tectonic` regenerates
the measurement table and compiles the draft under `output/pdf/`. It does not
refresh the reviewed `paper/openavt.pdf` or its hash/review record automatically.
For an intentional publication update, inspect the compiled pages, update the
reviewed copy and provenance consistently, and review the complete diff.
Documentation-only work needs no paper or benchmark regeneration.

## Common problems

| Symptom | Check |
|---|---|
| Missing optional dependency | Use the matching extra or the locked developer environment |
| Existing-output error | Choose an unused output directory; SDK demos otherwise choose their own directories |
| Slow FSK handshake | Select PCM only when the unchanged digital PCMU channel assumptions hold |
| Unknown result after a disconnect | Follow application recovery; do not blindly retry a write |
| Historical count differs from current tests | Keep dated evidence intact; report the new revision's actual result separately |

See [AGENTS.md](../AGENTS.md) for a compact coding checklist.

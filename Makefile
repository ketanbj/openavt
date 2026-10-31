UV ?= uv
DIST ?= dist
RUN = $(UV) run --locked --all-extras
RUNS ?= 5
OUT ?= output/handshake-benchmark
TECTONIC ?= tectonic
UV_FOR_CHILD = $(if $(findstring /,$(UV)),$(abspath $(UV)),$(UV))

.PHONY: help install demo test lint check-docs check benchmark build check-package paper
.DEFAULT_GOAL := help

help:
	@printf '%s\n' 'Run from the voice repository root; uv uses the checked-in lockfile:' '  make install      Install locked runtime extras and development tools' '  make demo         Run local independent SDK peers (no model API)' '  make test         Run the voice test suite' '  make lint         Check Python lint and formatting' '  make check-docs   Check local Markdown links and headings' '  make check        Run lint, docs and tests' '  make benchmark    New local audio calls (RUNS=5); OUT must not already exist' '  make build        Build locally (DIST=dist; choose a fresh output for comparisons)' '  make check-package  Build and smoke-check the selected archive pair' '  make paper        Build the research draft (requires TECTONIC)' 'Set UV=/path/to/uv if needed. Paid model/provider integrations are separate opt-in workflows.'

install:
	$(UV) sync --locked --all-extras

demo:
	$(RUN) openavt sdk-demo

test:
	$(RUN) pytest -q

lint:
	$(RUN) ruff check src tests scripts
	$(RUN) ruff format --check src tests scripts

check-docs:
	$(RUN) python scripts/check_docs.py

check: lint check-docs test

benchmark:
	$(RUN) python scripts/benchmark_handshake.py --runs "$(RUNS)" --profile pcm --output "$(OUT)"

build:
	$(RUN) python -m build --outdir "$(DIST)"

check-package: build
	$(RUN) twine check --strict "$(DIST)"/*
	$(RUN) python scripts/check_dist.py --dist "$(DIST)"
	$(RUN) python scripts/smoke_wheel.py --dist "$(DIST)"

paper:
	$(MAKE) -C paper pdf PYTHON="$(UV_FOR_CHILD) run --locked --all-extras python" TECTONIC="$(TECTONIC)"

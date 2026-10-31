# openavt agent guide

OpenAVT carries protected structured requests through audio using TLS or QUIC,
with separate delegated permission. Ordinary speech remains outside the inner
protected channel. Core/SDK modules must stay independent of demos and model APIs.

## Read first

`README.md` -> `docs/README.md` -> `docs/architecture.md` -> `docs/code-map.md`.

## Commands

Run from this repository root. Use the checked-in `uv.lock`:

```sh
make install    # uv sync --locked --all-extras
make help
make demo       # local SDK peers, no model API
make test
make lint
make check-docs
```

`UV=/path/to/uv` selects an explicit executable. Focused tests can use
`uv run --locked --all-extras pytest -q tests/test_security.py`.
`make check-package DIST=output/fresh/dist` validates a new source/wheel pair
without mixing earlier artifacts. `make benchmark` uses fresh local audio calls and requires an unused `OUT` path.
Paid model modes and real provider calls are opt-in; do not use them for routine
verification. See `docs/development.md` for package and evidence workflows.

## Change map

| Change | Start with | Closest tests |
|---|---|---|
| Public session/requests | `src/openavt/session.py`, `gateway.py` | `tests/test_sdk.py` |
| Transport framing/recovery | `channel.py`, `protocol.py`, `modem.py`, `pcm.py` | `test_streaming.py`, `test_pcm.py`, `test_security.py` |
| QUIC/datagrams | `quic.py`, `datagram.py` | `tests/test_quic.py` |
| Enrollment/grants | `authority/` | `tests/test_authority.py` |
| PAP operation binding | `pap/` | `tests/test_pap.py` |
| Risk/provider ingress | `risk.py`, `transports/twilio.py` | `test_risk.py`, `test_twilio.py` |
| CLI/package/release helpers | `cli.py`, `scripts/` | `test_cli.py`, `test_dist.py`, `test_release.py` |

## Important boundaries

Keep certificate identity, customer grants and speech separate. The gateway checks
authority before an application handler; it cannot make a remote/physical handler
effect atomic. RequestOutcomeUnknown requires explicit recovery, not blind write
retries. Preserve audio-only carriage, explicit trust roots, parser bounds,
redaction and independent optional imports. Never edit generated `_version.py`.

## Working rules

- Read the task guide and closest code/tests before editing; use `rg` to navigate.
- Keep changes within the requested behavior. Explain changed guarantees in the
  architecture/threat model and cover them with relevant protocol tests.
- Preserve the separation between observations, verified claims and permission.
  Never promote a fresh signature to location, or a contact report to consent.
- Recorded benchmarks and publication artifacts are evidence. Do not hand-edit
  numeric results or overwrite historical reports to hide a mismatch. Exploratory
  benchmarks go in ignored `output/`; docs-only changes need no benchmark rerun.
- New or changed relative Markdown links should pass `make check-docs`.
- Keep keys, grants, credentials, recordings and databases out of commits. Public fixtures
  must be explicitly synthetic or have documented rights; public verification
  keys are distinct from private signing credentials.
- Publishing a package, running paid/provider integrations and submitting papers
  are separate tasks; the local demo and normal checks require none of them.

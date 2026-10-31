# Verification

[README](../README.md) · [Performance](performance.md) · [Authority](authority.md)

This page records historical milestones and their evidence. For a new checkout,
use its actual test output and exact-commit CI.

The SDK/provider-adapter milestone recorded **155 automated tests passing locally**
on macOS/Python 3.13. The current CI matrix runs the checked-out suite on
Linux/Python 3.11, Linux/Python 3.13 and macOS/Python 3.13.

The older [October 11 main CI run](https://github.com/ketanbj/openavt/actions/runs/38150046644)
verified the preceding 75-test release; it does not attest to these new changes.

## QUIC milestone (October 30, 2026)

**226 tests passed locally** on macOS/Python 3.13, including QUIC mutual authentication,
lossy independent WebRTC/provider calls, PAP/risk checks and shutdown behavior.
The 1 kbps FSK SDK call also passed all eight probes (35.681 s client handshake).
These are local results, separate from the historical TLS benchmarks below.
[QUIC guide](quic.md) · [Recorded reports and environment](quic-verification.json).

## Evidence

| Check | Result | Details |
| --- | --- | --- |
| Two independent OpenAI SDK processes, WebRTC | **0.620 s**; eight cases pass, one handler execution | [SDK evidence](sdk-verification.json) |
| Same OpenAI SDK application, Twilio emulation | **0.523 s**; eight cases pass, one handler execution | [SDK evidence](sdk-verification.json) |
| Real Twilio/carrier call | Deferred until account configuration | [Configuration](integration.md#configure-a-later-real-twilio-call) |
| Five fresh PCM audio calls in CI | All full mTLS handshakes below one second | [Timings and environment](performance/pcm-ci-main.json) |
| Two OpenAI agents with AVA | 0.623 s handshake; all eight authorization cases verified | [Public report](authority-verification.json) |
| Fresh installed wheel, AVA without OpenAI | 0.582 s handshake; all eight cases verified locally | [Public report](authority-verification.json) |
| Package checks | Builds, strict metadata validation and clean core-wheel installation | [Release checks](releasing.md#test-without-publishing) |

CI also exercises the installed wheel over live WebRTC audio and runs the
five-call handshake threshold. It also runs the SDK in independent processes over
WebRTC and emulated Twilio, including installed-wheel checks. It needs no OpenAI key. The OpenAI demo is a
separate opt-in local run using two independent GPT-6.1 Sol contexts.

## What the tests cover

- Streaming frame acquisition, chunk boundaries, corruption recovery and native PCMU preservation.
- TLS certificate rejection, missing client certificates, ciphertext tampering and replay.
- Audio retry and deduplication after a damaged waveform and dropped ACK.
- Enrollment key proof, account isolation, renewal and explicit root trust.
- Customer/resource permissions, grant signatures, scope, expiry and revocation.
- Concurrent single-use enforcement and persistent replay state.
- HTTP/CLI bounds, overload handling and sanitized transport failures.
- Mandatory gateway authorization, handler allowlists, schema rejection and unavailable policies.
- Request cancellation, ambiguous outcomes after disconnect and bounded buffers.
- Modem/speech scheduling, μ-law round trips, provider metadata and playback marks.
- Signed HTTP/WebSocket ingress, tampering, proxy Host spoofing and duplicate streams.
- Installed CLI, optional dependency errors and distribution contents.

## Run locally

The counts above describe dated milestones. Use the current test output and
exact-commit CI for the checkout being reviewed; do not treat a historical count
as a live assertion. See the [development guide](development.md) for setup.

```sh
uv run --locked --all-extras pytest -q
uv run --locked --all-extras ruff check src tests scripts
uv run --locked --all-extras ruff format --check src tests scripts
```

Use the [quickstart](quickstart.md) for calls and [performance guide](performance.md#reproduce)
for a fresh benchmark. Real OpenAI runs incur API usage.

## Interpretation

Live demos use two local peers and a digital PCMU path. Timing conditions are
defined in [performance](performance.md#timing-and-scope). These tests establish
the measured prototype behavior; they are not a production security audit or
verification of Internet/PSTN interoperability.

Public JSON omits credentials, delegation tokens and transcripts. Raw reports
and recordings stay in ignored `output/`; capture hashes identify those local
artifacts but do not make them independently inspectable.

## PAP and risk profile

[Local HTTPS/audio evidence](pap-verification.json) covers PAP draft 0.1 sessions,
PKCE, DPoP nonce handling, audio authorization, operations confirmation/recovery,
risk blocking and sign-out. `tests/test_pap.py` uses a separate PyJWT wire verifier
and checks tampering, replay, scope, ownership, expiry and extension negotiation.
`tests/test_risk.py` checks bounded observation, outage behavior and authority
separation. Run `openavt pap-demo` to reproduce. This is a local reference profile;
external PAP providers and fraud vendor integrations have not been certified.

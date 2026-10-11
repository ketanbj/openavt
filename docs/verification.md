# Verification

[README](../README.md) · [Performance](performance.md) · [Authority](authority.md)

**75 automated tests passed** on Linux/Python 3.11, Linux/Python 3.13 and
macOS/Python 3.13 in the October 11, 2026
[`main` CI run](https://github.com/ketanbj/openavt/actions/runs/38150046644).

## Evidence

| Check | Result | Details |
| --- | --- | --- |
| Five fresh PCM audio calls in CI | All full mTLS handshakes below one second | [Timings and environment](performance/pcm-ci-main.json) |
| Two OpenAI agents with AVA | 0.623 s handshake; all eight authorization cases verified | [Public report](authority-verification.json) |
| Fresh installed wheel, AVA without OpenAI | 0.582 s handshake; all eight cases verified locally | [Public report](authority-verification.json) |
| Package checks | Builds, strict metadata validation and clean core-wheel installation | [Release checks](releasing.md#validate) |

CI also exercises the installed wheel over live WebRTC audio and runs the
five-call handshake threshold. It needs no OpenAI key. The OpenAI demo is a
separate opt-in local run using two independent GPT-6.1 Sol contexts.

## What the tests cover

- Streaming frame acquisition, chunk boundaries, corruption recovery and native PCMU preservation.
- TLS certificate rejection, missing client certificates, ciphertext tampering and replay.
- Audio retry and deduplication after a damaged waveform and dropped ACK.
- Enrollment key proof, account isolation, renewal and explicit root trust.
- Customer/resource permissions, grant signatures, scope, expiry and revocation.
- Concurrent single-use enforcement and persistent replay state.
- HTTP/CLI bounds, overload handling and sanitized transport failures.
- Installed CLI, optional dependency errors and distribution contents.

## Run locally

```sh
uv run --locked --extra webrtc --extra authority pytest -q
uv run --locked --extra webrtc --extra authority ruff check src tests scripts
uv run --locked --extra webrtc --extra authority ruff format --check src tests scripts
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

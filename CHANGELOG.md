# OpenAVT changelog

## Unreleased

- Add optional PAP draft 0.1 HTTPS sessions, DPoP, direct/device/mediated sign-in,
  account refresh/revocation, and operations v1 confirmation/recovery.
- Bridge PAP authority to single-use grants bound to the voice certificate,
  live challenge and exact request; recheck permissions before execution.
- Add vendor-neutral fraud hooks for unsupported callers and authenticated
  requests, bounded observation and explicit outage behavior.
- Add `openavt pap-demo`, local HTTPS/audio evidence and negative wire tests.

- Add framework-neutral `Identity`, `VoiceSession` and business `Gateway`, with
  explicit trust, schema validation, authorization, bounded waits and safe failures.
- Add separate-process WebRTC and configurable Twilio audio adapters, signed
  ingress, playback marks and a shared modem/speech scheduler.
- Add `openavt sdk-demo`, two independent OpenAI workers, provider emulation,
  optional live-call configuration, regression tests and installed-wheel checks.

- Fix draft-release lookup and recover reserved versions using current workflow
  helpers without moving tags or changing their artifacts.
- Verify PyPI artifact hashes while accepting the publishing action's attestation
  sidecars, and document installation from PyPI.

## 0.1.0 — October 11, 2026

- Add CI-gated automatic GitHub/PyPI releases, semantic version selection,
  dry-run validation, and immutable artifact recovery through Trusted Publishing.

- Add the optional `authority` extra and `openavt ava` local service/client:
  accounts, CSR/key-proof enrollment, renewal and authenticated revocation.
- Add a separate business consent signer with certificate-bound, short-lived,
  single-use delegation, customer/resource checks and persistent replay defense.
- Add `openavt delegation-demo`, including optional real OpenAI agents and eight
  authorization scenarios over actual audio TLS; redact delegation tokens in traces.

- Add an opt-in digital G.711 PCM modem with 56 kbps raw data in a 64 kbps
  audio stream, larger frames and low-delay buffering for sub-second cold mTLS.
- Add repeatable handshake benchmarking, per-flight metrics, and PCM security,
  codec preservation and live-call tests.
- Package the working prototype under `src/openavt`, with core framing and TLS,
  streaming audio, WebRTC transport, OpenAI agents, and runnable demos.
- Add `openavt loopback` and `openavt live`, plus `python -m openavt`.
- Separate optional `audio`, `webrtc`, and `agents` dependencies.
- Preserve real mutual TLS 1.3 over tones, fixed backend grants, recordings,
  metrics, loss recovery, and certificate rejection scenarios.
- Add Apache-2.0 licensing, tests, wheel/source builds, CI, and Trusted Publishing.
- Adopt OpenAVT (Open Agent Voice TLS) throughout the package, CLI, docs, and release configuration.

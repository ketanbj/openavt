# OpenAVT changelog

## 0.1.0 — unreleased

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

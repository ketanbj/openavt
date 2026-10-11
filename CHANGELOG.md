# OpenAVT changelog

## 0.1.0 — unreleased

- Package the working prototype under `src/openavt`, with core framing and TLS,
  streaming audio, WebRTC transport, OpenAI agents, and runnable demos.
- Add `openavt loopback` and `openavt live`, plus `python -m openavt`.
- Separate optional `audio`, `webrtc`, and `agents` dependencies.
- Preserve real mutual TLS 1.3 over tones, fixed backend grants, recordings,
  metrics, loss recovery, and certificate rejection scenarios.
- Add Apache-2.0 licensing, tests, wheel/source builds, CI, and Trusted Publishing.
- Adopt OpenAVT (Open Agent Voice TLS) throughout the package, CLI, docs, and release configuration.

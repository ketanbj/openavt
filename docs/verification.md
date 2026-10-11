# OpenAVT verification results

The pre-packaging implementation completed real local WebRTC calls with two
OpenAI GPT-6.1 Sol agents. Each had its own Responses context and tools, transcribed
received RTP audio, and used synthesized speech. The codec was G.711/PCMU and the
inner authenticated transport was OpenSSL mutual TLS 1.3 over audible FSK.

| Run | TLS handshake | Protected request/response | Outcome |
| --- | ---: | ---: | --- |
| Two-agent order inquiry | 32.164 s | 5.417 s | Allowed; order shipped |
| Two-agent address change | 32.203 s | 5.217 s | Denied by read-only fixture grant |

Both runs had zero retransmissions and zero bad modem frames. Each made five LLM
requests, four TTS requests, and three transcriptions across both agents. The
request/response metric includes desk ASR and LLM time and ends upon receipt of
the protected response, excluding the later spoken reply and goodbye.

Transport-only runs also verified recovery from one deliberately damaged
waveform plus one dropped audio ACK (two retries, one duplicate suppressed), and
rejection of an untrusted agent certificate before an application request was
delivered. They did not invoke LLMs.

The original eight automated tests covered unknown sample offsets and chunk
boundaries, noise/gain, corrupt-frame resynchronization, backend grants,
ciphertext tampering despite a valid CRC, record replay, and missing client
certificates. Packaging adds installed command-line and artifact checks. CI
uses no OpenAI key; new live OpenAI runs are opt-in and incur API usage.

Measurements used an ephemeral P-256 demo CA and P-256 key exchange on this
machine. Different chain sizes, codecs, sample clocks, networks, and key-exchange
groups may change both performance and reliability. This is not a PSTN or
production-security verification.

Original reports and recordings remain in the local ignored `output/` directory.
They are intentionally not included in PyPI distributions or the public source
repository. This document summarizes the measured values without exposing
credentials or call transcripts.

## Packaged-wheel verification

The reorganized v0.1.0 wheel was installed with its `agents` extra into a fresh
virtual environment and run from outside the checkout, with the working-directory
configuration passed explicitly through `--env-file`. Both real GPT-6.1 Sol
agents completed the audio call: a **32.466 s** mutual TLS handshake and a
**6.016 s** protected order-status request/response, with zero retries and zero
bad modem frames. The wheel's transport-only loss scenario also passed with two
retries and one duplicate suppressed. Local evidence is in
`output/package-agents/` and `output/package-recovery/`.

All **13 tests** passed, Ruff lint/format checks passed, both workflows passed
`actionlint`, and the core wheel completed a mutual TLS loopback in a clean
environment with no optional pip dependencies. Wheel/source metadata passed
`twine check --strict`; archive contents exclude local/private run artifacts.
GitHub's Linux/macOS matrix runs on source pushes; PyPI publication uses the
separate release workflow.

## OpenAVT release-name verification

The renamed OpenAVT v0.1.0 wheel was installed with `agents` in a fresh virtual
environment and run outside the checkout. The environment exposes `openavt` and
its CLI, with no previous package namespace installed. Two real GPT-6.1 Sol
agents completed the live PCMU audio call with a **32.003 s** mutual TLS handshake
and a **5.957 s** protected order-status request/response. Both endpoints had zero
retries and zero bad modem frames. Evidence remains local in
`output/openavt-agents/`.

All 13 tests passed after the rename. Both GitHub workflows passed actionlint.
The clean core wheel completed its mutual TLS loopback without optional pip
dependencies. Release checks verify the `openavt` filename, metadata, import
namespace, CLI entry point, extras, Apache-2.0 license, and README title. Both
archives contain no previous package name or local/private run artifacts.
Source is hosted at [ketanbj/openavt](https://github.com/ketanbj/openavt);
PyPI publication is pending.

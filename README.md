# OpenAVT

[![CI](https://github.com/ketanbj/openavt/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/ketanbj/openavt/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](pyproject.toml)
[![Apache 2.0](https://img.shields.io/github/license/ketanbj/openavt)](LICENSE)
[![Experimental](https://img.shields.io/badge/Status-Experimental-orange.svg)](#scope)

**TLS over voice. Built for agents.**

OpenAVT (**Open Agent Voice TLS**) carries real mutual TLS 1.3 records through
audio. An agent can authenticate its key and send a protected request during a
voice call; the business checks its permission before returning a result.

- **Transport:** TLS requests and responses travel through audio-only WebRTC.
- **Identity:** AVA (Agent Voice Authority) enrolls, renews and revokes agent certificates.
- **Permission:** a separate business signer issues customer grants for specific actions and resources.

## Try the complete demo

Requires Python 3.11+, `uv` and the `openssl` executable. No OpenAI key needed.
Install the released package from [PyPI](https://pypi.org/project/openavt/):

```sh
python -m pip install 'openavt[webrtc,authority]'
openavt delegation-demo
```

Or run from a GitHub checkout:

```sh
git clone https://github.com/ketanbj/openavt.git
cd openavt
uv run --locked --extra webrtc --extra authority openavt delegation-demo
```

The demo enrolls an agent, issues customer consent, and establishes a live local
audio call. It accepts one authorized request and rejects seven misuse cases,
including scope escalation, replay and revocation. It saves a report and audio
under `output/`.

To use **two real OpenAI voice agents**, copy `.env.example` to `.env`, set
`OPENAI_API_KEY` locally, then run:

```sh
uv run --locked --extra agents --extra authority openavt delegation-demo --agents
```

[More demos and installation options →](docs/quickstart.md)

## Sub-second handshakes

Measured on an established local **64 kbps G.711 PCMU** audio call:

| Run | Full mutual TLS handshake | Evidence |
| --- | ---: | --- |
| `main` CI, 5 fresh calls, October 11, 2026 | **0.561 s median · 0.581 s max** | [Benchmark](docs/performance/pcm-ci-main.json) |
| Two OpenAI agents with AVA and customer delegation | **0.623 s** | [Demo results](docs/authority-verification.json) |

The timer includes both authenticated endpoints and the final audio ACK. It
excludes certificate creation, call setup and LLM/speech time. The fast PCM
profile requires an unchanged digital PCMU path; transcoding or audio processing
can break it. [Measurements and reproduction →](docs/performance.md)

## Scope

This is an **experimental local prototype**. Both peers run on one machine;
public Internet, carrier/PSTN and microphone paths have not been verified.
Ordinary speech is outside the inner TLS session. There is no WebRTC data channel
carrying the protected requests.

Certificates prove registered account/key control. Customer authentication uses
demo credentials; provider verification, real customer login and production CA
operations remain future work. The backend enforces grants outside the LLM.
[Trust boundaries →](docs/authority.md#trust-boundaries)

## Documentation

| Goal | Guide |
| --- | --- |
| Install and choose a demo | [Quickstart](docs/quickstart.md) |
| Understand certificates and customer consent | [Authority and delegation](docs/authority.md) |
| Run a persistent authority | [AVA CLI walkthrough](docs/authority-cli.md) |
| Integrate the transport | [Architecture and library usage](docs/architecture.md) |
| Reproduce the timings | [Performance](docs/performance.md) |
| Inspect tests and evidence | [Verification](docs/verification.md) |
| Build and publish the package | [Releasing](docs/releasing.md) |

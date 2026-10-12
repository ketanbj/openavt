# OpenAVT

[![CI](https://github.com/ketanbj/openavt/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/ketanbj/openavt/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/openavt.svg)](https://pypi.org/project/openavt/)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](pyproject.toml)
[![Apache 2.0](https://img.shields.io/github/license/ketanbj/openavt)](LICENSE)
[![Experimental](https://img.shields.io/badge/Status-Experimental-orange.svg)](#scope)

**Closing the Voice-to-Business trust gap. TLS over voice, built for agents.**

A personal AI agent calls a bank, utility or store on your behalf. The business
needs to verify the agent, the customer it represents and the actions that
customer authorized. Conversation alone cannot establish those permissions.

OpenAVT (**Open Agent Voice TLS**) carries cryptographic identity, encrypted
requests and signed customer permissions through the call's actual audio.
Participating businesses check identity and permission before acting.

**For business teams:** [the problem, value and adoption path](docs/business.md).
**For developers:** [run the demo](#try-the-demo) or [explore the architecture](docs/architecture.md).

## The trust gap

| Risk | OpenAVT's approach |
| --- | --- |
| **Audio prompt injection and hijacking:** an IVR or counterparty's speech can try to redirect an agent or extract data. | Use protected structured requests and enforce signed permissions outside the LLM. Speech cannot expand a grant. |
| **Missing cryptographic identity:** a voice, caller ID or spoken passcode does not prove an agent's key or customer authority. | Mutual TLS authenticates both endpoints; customer grants travel inside TLS rather than being spoken aloud. |
| **Scope creep:** a request to read data can become a request to change an account. | Bind each grant to the agent certificate, customer, business, action and resource; check expiry, revocation and single-use state. |

TLS does not make an LLM immune to prompt injection. These checks constrain
requests at the participating backend; preventing leaks through speech or other
tools still requires controls in the calling agent.

## How it works

1. **Enroll:** the Agent Voice Authority (AVA) issues an agent certificate after key proof.
2. **Delegate:** a separate business signer issues a scoped customer grant.
3. **Call:** mutual TLS 1.3 authenticates the peers through audio and protects requests and responses.
4. **Enforce:** the business checks the grant against the authenticated peer before executing the permitted action.

The current demo allows **reading Alice's order**, then denies an address change
under the same read-only scope. Keys and grant credentials stay out of model inputs.
[Identity and permission details →](docs/authority.md)

## Try the demo

Requires Python 3.11+ and the `openssl` executable. No OpenAI key needed.

```sh
python -m pip install 'openavt[webrtc,authority]'
openavt delegation-demo
```

The demo enrolls an agent, issues customer consent, and establishes a live local
audio call. It accepts one authorized request and rejects seven misuse cases,
including scope escalation, replay and revocation. It saves a report and audio
under `output/`.

For **two real OpenAI voice agents**, [configure `OPENAI_API_KEY` locally](docs/quickstart.md#add-two-openai-voice-agents), then run:

```sh
python -m pip install 'openavt[agents,authority]'
openavt delegation-demo --agents
```

[More demos and installation options →](docs/quickstart.md)

## Sub-second handshakes

Measured on an established local **64 kbps G.711 PCMU** audio call:

| Run | Full mutual TLS handshake | Evidence |
| --- | ---: | --- |
| `main` CI, 5 fresh calls, October 11, 2026 | **0.561 s median · 0.581 s max** | [Benchmark](docs/performance/pcm-ci-main.json) |
| Two OpenAI agents with AVA and customer delegation | **0.623 s** | [Demo results](docs/authority-verification.json) |

The timer includes both authenticated endpoints and the final audio ACK. It
excludes certificate creation, call setup and LLM/speech time. These local results
are not a carrier or Internet latency guarantee. The fast PCM
profile requires an unchanged digital PCMU path; transcoding or audio processing
can break it. [Measurements and reproduction →](docs/performance.md)

## Scope

This is an **experimental local prototype**. Both peers run on one machine;
public Internet, carrier/PSTN and microphone paths have not been verified.
Ordinary speech is outside the inner TLS session. There is no WebRTC data channel
carrying the protected requests.

Certificates prove registered account/key control. Customer authentication uses
demo credentials; provider verification, real customer login and production CA
operations remain future work. Banking, payments and utility integrations are
target use cases; the implemented demo returns a fixed read-only order result.
[Trust boundaries →](docs/authority.md#trust-boundaries)

## Documentation

| Goal | Guide |
| --- | --- |
| Evaluate the business case and adoption path | [Voice-to-Business trust gap](docs/business.md) |
| Install and choose a demo | [Quickstart](docs/quickstart.md) |
| Understand certificates and customer consent | [Authority and delegation](docs/authority.md) |
| Run a persistent authority | [AVA CLI walkthrough](docs/authority-cli.md) |
| Integrate the transport | [Architecture and library usage](docs/architecture.md) |
| Reproduce the timings | [Performance](docs/performance.md) |
| Inspect tests and evidence | [Verification](docs/verification.md) |
| Build and publish the package | [Releasing](docs/releasing.md) |

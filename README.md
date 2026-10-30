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

Requires Python 3.11+. No OpenAI key needed.

```sh
python -m pip install 'openavt[webrtc,authority]'
openavt sdk-demo
```

The demo enrolls an agent, issues customer consent, and establishes a live local
audio call. It accepts one authorized request and rejects seven misuse cases,
including scope escalation, replay and revocation. The peers run in separate Python processes and save a report under `output/`.

For **two real OpenAI voice agents**, [configure `OPENAI_API_KEY` locally](docs/quickstart.md#add-two-openai-voice-agents), then run:

```sh
python -m pip install 'openavt[agents,authority]'
openavt sdk-demo --agents
```

[Integrate a voice agent or configure Twilio →](docs/integration.md) · [More demos →](docs/quickstart.md)

## PAP sessions and fraud monitoring

OpenAVT works **alongside Personal Agent Protocol (PAP/Poppy)**: PAP supplies
HTTPS discovery, sign-in and account permissions; OpenAVT binds those permissions
to an authenticated audio call and exact requests. The optional adapter targets
PAP draft 0.1 with a negotiated custom voice extension.

```sh
python -m pip install 'openavt[pap,webrtc]'
openavt pap-demo
```

This local demo reads an order over audio, proposes an exchange, and confirms it
through PAP's HTTPS operations endpoint exactly once. It also verifies fraud
blocking and sign-out before execution. [Integration and supported profile →](docs/pap.md)

A vendor-neutral [fraud adapter](docs/risk.md) supports unsupported callers and
suspicious authenticated requests. It can restrict execution without expanding
permissions. Provider-specific integrations and external PAP interoperability
still require validation with those providers.

## QUIC over voice

The optional QUIC path reuses the audio modems, call adapters and authorization
SDK, with QUIC providing packet loss recovery and mutually authenticated TLS 1.3.
From this checkout:

```sh
python -m pip install -e '.[quic,webrtc,authority]'
openavt sdk-demo --protocol quic --loss
```

This runs two independent processes with dropped, damaged and duplicated audio
bursts. [QUIC integration, PAP, G.711 provider emulation and limits →](docs/quic.md)

## Sub-second handshakes

Measured on an established local **64 kbps G.711 PCMU** audio call:

| Run | Full mutual TLS handshake | Evidence |
| --- | ---: | --- |
| `main` CI, 5 fresh calls, October 11, 2026 | **0.561 s median · 0.581 s max** | [Benchmark](docs/performance/pcm-ci-main.json) |
| Two independent OpenAI SDK processes, WebRTC | **0.620 s** | [SDK results](docs/sdk-verification.json) |

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
demo credentials; verified provider identities, real customer login and production CA
operations remain future work. Banking, payments and utility integrations are
target use cases; the standalone demo returns a fixed order result, and the PAP demo adds a
simulated exchange with explicit HTTPS confirmation.
[Trust boundaries →](docs/authority.md#trust-boundaries)

## Documentation

| Goal | Guide |
| --- | --- |
| Evaluate the business case and adoption path | [Voice-to-Business trust gap](docs/business.md) |
| Install and choose a demo | [Quickstart](docs/quickstart.md) |
| Understand certificates and customer consent | [Authority and delegation](docs/authority.md) |
| Run a persistent authority | [AVA CLI walkthrough](docs/authority-cli.md) |
| Add a personal agent, business gateway or Twilio call | [SDK integration](docs/integration.md) |
| Connect PAP sessions and voice authorization | [PAP adapter](docs/pap.md) |
| Add voice detection and fraud monitoring | [Fraud adapters](docs/risk.md) |
| Understand the transport | [Architecture](docs/architecture.md) |
| Run QUIC over lossy audio | [QUIC over voice](docs/quic.md) |
| Reproduce the timings | [Performance](docs/performance.md) |
| Inspect tests and evidence | [Verification](docs/verification.md) |
| Build and publish the package | [Releasing](docs/releasing.md) |

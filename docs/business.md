# Addressing the Voice-to-Business trust gap

[README](../README.md) · [Technical architecture](architecture.md) · [Try the demo](quickstart.md)

## The pitch

**When your customer's AI agent calls, verify its identity and its permission to
act.** OpenAVT carries mutual TLS and signed customer grants through actual call
audio, giving participating businesses a protected request channel with explicit
limits. Customers delegate a specific task; businesses enforce its boundaries.
The agent can converse naturally while the backend checks each requested action.

## Why this matters

A customer asks their personal agent to check an account, resolve a utility bill
or contact a store. The business needs to establish three things: which agent is
calling, which customer it represents, and what that customer authorized.

Recognizing a synthetic voice answers a different question. Pindrop's
[analysis of personal agents calling contact centers](https://www.pindrop.com/resources/article/inside-the-detection-of-meta-muse)
highlights the distinction between detecting an AI voice and establishing
customer identity and authority.

Three risks motivate OpenAVT:

- **Audio prompt injection and hijacking.** A malicious counterparty or compromised
  IVR can put instructions into the audio an agent hears, trying to redirect it
  or extract information. [Research demonstrates audio prompt injection](https://arxiv.org/abs/2607.28165).
- **Missing cryptographic identity.** Spoken credentials can be recorded or replayed;
  an agent's voice does not prove possession of an authorized private key.
- **Scope creep and misuse.** A read-only task needs an enforceable boundary so
  a confused or manipulated agent cannot turn it into an account change.

## What OpenAVT provides

| Capability | Business value | Current proof |
| --- | --- | --- |
| Mutual TLS through audio | Verify endpoint key possession and protect structured requests without speaking credentials. | Full TLS 1.3 handshake and protected request over local audio-only WebRTC. |
| Agent Voice Authority | Issue, renew and withdraw agent credentials. | Local enrollment with key proof and certificate revocation. |
| Signed customer grants | Restrict access to a specific customer, agent, business, action and resource. | Short-lived grants, checked by the backend outside the LLM. |
| Per-request enforcement | Reject stale, revoked, reused or out-of-scope authority. | One allowed order read and seven denied misuse cases. |

Cryptography protects the grant from forgery; backend checks enforce its limits.
Existing standards already support scoped authorization and
[certificate-bound tokens](https://www.rfc-editor.org/rfc/rfc8705.html#section-3).
OpenAVT brings these building blocks into an audio-carried agent session.

## A concrete customer journey

1. Alice authorizes her agent to read one order at a store.
2. The store issues a grant tied to Alice, that order and the agent's certificate.
3. The agent calls; both endpoints authenticate through audio TLS.
4. The backend verifies the protected request and grant, then returns the result.
5. If the agent requests an address change, the backend rejects it because the
   grant permits only reading the order.

The demo implements this read-only journey with simulated customer consent.
The same boundary could distinguish checking a balance from making a wire
transfer, once a bank integrates its login and backend policy. Bank, utility and
payment integrations are future applications.

## Where it fits

The intended integration attaches OpenAVT to the audio boundary of a personal
agent and a business voice system, then connects verified requests to the
business's existing authorization and tools. The business endpoint can be a
gateway serving an AI agent, IVR or human representative. The framework-neutral
SDK and business gateway are implemented; connecting a production contact center
still requires its audio adapter and customer authorization integration. Both sides need participating OpenAVT endpoints.

The emerging [Personal Agent Protocol](https://personalagentprotocol.org/docs/spec)
already defines discovery, sign-in and permissions for digital business
interfaces. Connecting those sessions to OpenAVT calls is a proposed integration,
not implemented interoperability. Voice detection and fraud monitoring remain
useful for unsupported callers and suspicious authenticated behavior.

## Evaluate it today

Run the [independent-process SDK demo](integration.md) and inspect the
[authorization outcomes and handshake evidence](verification.md). A sensible
first pilot would expose one read-only action, integrate real customer consent,
and measure the chosen audio path before enabling sensitive operations.

OpenAVT is an experimental prototype. Public Internet and telephone-network
interoperability are unverified; the sub-second profile needs an unchanged PCMU
path. Certificates currently establish registered account/key control, not
verified provider or human identity. Real customer login, production CA operations,
availability and transactional write recovery remain work to do.

TLS authenticates an endpoint, not the truth or safety of its speech. OpenAVT
does not stop prompt injection into the LLM or prevent leaks through other tools
or ordinary speech. Agent-side permission and data-release controls are still
needed. See the [trust boundaries](authority.md#trust-boundaries).

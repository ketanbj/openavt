# OpenAVT novelty audit

Research date: October 30, 2026. Code inspected: paper branch at
`3c83975cd93eb55e6d7a8911ba78e8235e1d1e82`, containing implementation baseline
`033f8bfbc69c4bfa44163f8fa4a680a004400f75`.

## Assessment

The current implementation demonstrates useful integration and local feasibility.
This review does **not** establish a strong research novelty claim for it yet.
Neither cryptographic exchange over voice, automatic voice-related certificate
issuance, agent certificates, scoped grants, nor execution gates is individually
new. Calling the authority “Let's Encrypt for agents” does not resolve that issue.

A more promising hypothesis is a deployable control infrastructure for preserving
customer-delegated authority across constrained voice workflows, with explicit
issuer assurance, channel/session binding, transfers, and revocation semantics.
That conjunction needs to be specified and evaluated against composed baselines;
it must not be presented as an established literature gap merely because no one
source uses our terminology.

This audit supplements the current manuscript. Its initial related-work coverage
missed several close predecessors and must be expanded before submission. The
existing PDF has not been rewritten to claim the proposed research direction.

## Closest precedents and the claims they constrain

| Candidate claim | Closest evidence | Assessment |
| --- | --- | --- |
| Cryptographic authentication entirely through audio | AuthLoop, USENIX Security 2016 | Established prior work. Reusing modern TLS does not erase the overlap. |
| Automatic certificate enrollment proving control of a voice endpoint | AuthentiCall, USENIX Security 2017, Section 4.1 | Direct prior work, including automated reverification. |
| ACME-style automated telephone identity certificates | RFC 9447 and RFC 9448 | Standardized authority-token and telephone-provider profiles already exist. |
| Automatically issued short-lived workload credentials | SPIFFE/SPIRE; Sigstore Fulcio | Established identity infrastructure, with different identity assertions and purposes. |
| Customer-authorized agent actions with key-bound evidence | OAuth possession binding/RAR; AP2; Verifiable Intent | Existing standards and implemented specifications cover much of this layer. |
| Offline, attenuated, principal-bound agent delegation | AIP preprint; WIMSE-related individual drafts | Active overlapping work. Drafts/preprints are evidence of competing ideas, not established security guarantees. |
| Privacy-preserving caller credentials with a public infrastructure and call binding | UCBlocker, USENIX Security 2023 | Privacy or pre-call credential acquisition alone would not establish novelty. |
| Binding a higher-level authorization to a secure session | RFC 9266 and general channel-binding work | Use these primitives; do not claim channel binding itself as new. |
| A constrained authorization channel | ACE-OAuth and EDHOC | Required baselines, even though adapting them to audio would require engineering. |
| Authority continuity across voice transfers under a stated proof/availability budget | No exact equivalent established by this review | A research hypothesis with substantial adjacent work, not a verified first. |

### Secure telephony: closer than just a modem

[AuthLoop](https://www.usenix.org/system/files/conference/usenixsecurity16/sec16_paper_reaves.pdf)
provides an in-audio authentication protocol and a codec-aware reliable link.
Its certificate caching and selective block retransmission also constrain claims
about reducing on-call proof transmission or improving a simple stop-and-wait
baseline. It should be a central comparison, not a peripheral citation.

[AuthentiCall](https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-reaves_paper.pdf)
adds mutual identity authentication and content-integrity mechanisms using a data
channel. Crucially for the infrastructure hypothesis, its enrollment procedure
combines a network nonce, a voice-delivered nonce, and a signature under the
requester's key before certificate issuance. It discusses automatic periodic
reverification. Thus, “a CA that automatically issues a certificate after an audio
challenge” is already anticipated by an implemented peer-reviewed system. Its
phone-number binding is not customer permission to execute an account operation.

[UCBlocker](https://www.usenix.org/conference/usenixsecurity23/presentation/du)
uses anonymous credentials, recipient policies, a public ledger, and a verification
code connecting authentication to later call initiation. Its architecture avoids
a call-time data channel. It is a necessary comparison for a privacy-preserving
or pre-issued agent/caller admission infrastructure.

### Automated issuance: ACME is extensible already

[RFC 8555](https://www.rfc-editor.org/rfc/rfc8555.html) automates certificate
validation and management. [RFC 9447](https://www.rfc-editor.org/rfc/rfc9447.html)
specifies ACME challenges backed by an external authority token.
[RFC 9448](https://www.rfc-editor.org/rfc/rfc9448.html) profiles that mechanism for
telephone-provider STI credentials. [RFC 9060](https://www.rfc-editor.org/rfc/rfc9060.html)
addresses delegation of telephone-number authority. These are strong counters
to a broad “automated telephony PKI” novelty claim; they do not define a customer's
business-action consent.

[SPIRE](https://spiffe.io/docs/latest/spire-about/spire-concepts/) attests nodes and
workloads and issues their identity credentials. Its federation specifications
also address exchanges across trust domains. [Fulcio's specification](https://github.com/sigstore/architecture-docs/blob/main/fulcio-spec.md)
describes short-lived signing certificates based on OIDC identity and key
possession, including transparency logging. Their certificate purposes and
trust models differ; neither should be treated as a drop-in voice-agent protocol.
They nonetheless make generic automated issuance an unconvincing novelty claim.

### Agent authorization is a crowded area

[AIMS, draft-ietf-wimse-aims-00](https://datatracker.ietf.org/doc/html/draft-ietf-wimse-aims-00)
describes applying existing workload identity and OAuth mechanisms to agent
authentication and authorization, including limitations of transport identity
through intermediaries. It is a September 2026 working-group draft, not an RFC.

Two particularly relevant individual drafts are
[cross-organizational delegation requirements, revision 02](https://www.ietf.org/archive/id/draft-reece-wimse-cross-org-delegation-02.html)
and [Agent Delegation Chain, revision 03](https://www.ietf.org/ietf-ftp/internet-drafts/draft-asor-wimse-agent-delegation-chain-03.html).
They address principal binding, attenuation, offline verification and revocation;
the former also identifies execution-time human authorization. The latter was
published October 27, 2026. Neither is an adopted standard simply because it is
hosted by the IETF.

The [AIP preprint](https://arxiv.org/abs/2603.24775) proposes invocation-bound
capability chains and MCP/A2A/HTTP bindings. The
[AIC individual draft](https://datatracker.ietf.org/doc/html/draft-wei-aic-identity-cert-02)
proposes an X.509 extension binding an agent to a principal. These are additional
overlap signals. This audit does not adopt their broad criticisms of competing
standards or independently validate their reported benchmarks.

[AP2's agent authorization framework](https://ap2-protocol.org/ap2/agent_authorization/)
already separates user-approved mandates from verifier-challenged action
authorization. [Verifiable Intent](https://github.com/agent-intent/verifiable-intent)
defines cryptographic evidence linking delegated authority and agent commerce.
The [OAuth Transaction Authorization Challenge individual draft](https://www.ietf.org/archive/id/draft-rosomakho-oauth-txn-challenge-00.html)
also describes a resource challenging for operation-specific authorization,
with approval obtained through an authorization server. Merely signing a
customer's exact action or using a challenge is therefore insufficient.

The [Authorization Evidence Challenge individual draft](https://www.ietf.org/archive/id/draft-schrock-ae-challenge-03.html)
explicitly defines a transport-neutral challenge for missing or stale evidence.
It is relevant to retry and gateway transitions, but a proposal is not a deployed
solution to every handoff or admission-consistency problem.

Recent AP2 security preprints also study the gap between valid signatures and
the decisions preceding them: [Beyond the Mandate](https://arxiv.org/abs/2608.23858)
and [Signing the Transaction but Not the Decision](https://arxiv.org/abs/2609.11757).
“Signed actions do not imply faithful user intent” is not an unexplored thesis.
Their voice applicability and results require independent investigation.

## What the Let's Encrypt analogy actually requires

Let's Encrypt's [CCS 2019 paper](https://doi.org/10.1145/3319535.3363192)
reports a certificate authority, protocol, operational ecosystem and deployment
measurements. This is a useful example that infrastructure can be a research
contribution without new cryptographic primitives. It is not evidence that
renaming a small enrollment server constitutes equivalent work.

The crucial design question is the assertion being automated:

| Assertion | Who can credibly validate it? | Consequence for OpenAVT |
| --- | --- | --- |
| Possession of a new private key | Any challenge verifier | Already implemented; does not identify a provider or customer. |
| Control of an agent-provider namespace | A validated domain/organization authority | Requires a real validation and naming policy; currently absent. |
| Which running workload holds the key | A workload/platform attestation mechanism | Requires an explicit attestation trust model; currently absent. |
| Which customer delegated an action | The business/account authorization service or a trusted user credential | Cannot be inferred from provider-domain control. |
| Which remote endpoint participates in this protected session | The authenticated channel protocol and its binding evidence | Does not establish ownership of every spoken statement. |
| A person is physically present or a speaker is local | Additional trusted sensing/presence assumptions | Not provided by a CA, nonce, or blind live relay. |

An open CA can automate evidence collection for an accurately limited claim.
It cannot turn key possession into verified human identity, honest agent
behavior, or customer consent. Issuance policy, trust distribution, key
compromise response, issuer accountability, and relying-party acceptance are
part of the system, not details that follow automatically from a certificate.

There is also a practical distinction between inspiration and reuse:
[Let's Encrypt's published transition](https://letsencrypt.org/2025/05/14/ending-tls-client-authentication)
removed its client-authentication issuance profile in July 2026. Its normal
HTTPS server certificates are not a substitute for OpenAVT's client identity
credentials. ACME can be used by other issuers; issuer discovery services can
still use conventional HTTPS.

## What exists in this repository

The current AVA:

- Creates a local root and random pseudonymous account identifiers.
- Accepts a P-256 CSR and verifies a fresh, account/order/CSR-bound key proof.
- Issues a 24-hour client certificate for a server-constructed agent URN.
- Supports account-scoped revocation and checks active certificate state.
- Deliberately reports `pseudonymous-key-control` assurance.

This supports key control and issuer-maintained account continuity. It does not
validate a provider domain, a real person's identity, a telephone number, or a
running workload. There is no public trust federation, domain challenge,
transparency infrastructure, or shared issuer-assurance policy. Calling it
“ACME-inspired” is accurate; calling it an ACME implementation or a deployed
public agent CA is not. See `src/openavt/authority/ca.py` and `docs/authority.md`.

The PAP bridge is the strongest existing authorization binding: it checks the
voice-certificate fingerprint, a fresh challenge, request ID, action, resource,
customer and argument digest, and rechecks current session permission. However,
the nonce is maintained in application state rather than bound to a TLS exporter;
the code does not implement transfer epochs or federated issuer acceptance.
Its current-session lookup is a runtime callback, so it is not an offline
authorization-verification design. A nonce is useful protection and should not
be described as no binding at all; the missing session/transfer properties are
specific additional claims that would need a specification.

## Best research hypothesis to test

**Authority continuity for delegated agents over constrained voice paths.**

Proposed question: Can independently administered agent and business systems
establish accurately scoped customer authority through a codec-constrained voice
path, preserve or narrow it across legitimate endpoint changes, and reject stale
or misbound authority within a stated freshness and availability budget?

This is a systems/protocol-composition hypothesis. It is not a new cipher, a
new certificate format, or a claim that channel binding was invented here.
[RFC 9266](https://www.rfc-editor.org/rfc/rfc9266.html) already defines a TLS 1.3
channel binding. [ACE-OAuth](https://www.rfc-editor.org/rfc/rfc9200.html) and
[EDHOC](https://www.rfc-editor.org/rfc/rfc9528.html) supply important constrained
authorization and authenticated-key-exchange building blocks.

An experimental design could separate three layers:

1. **Issuer and enrollment layer:** reuse established issuance/federation protocols;
   state exactly which namespace, account or workload evidence each issuer attests.
   Do not put mutable business permissions into a broadly trusted identity claim.
2. **Delegation layer:** reuse a suitable mandate/capability format to express
   customer, business, action, resource, exact argument constraints, expiry and key
   possession. Preserve the difference between consent and a model's proposal.
3. **Voice-session layer:** bind presentation to the protected interaction and a
   defined transition epoch. A transfer must either retain the same relevant
   authenticated principals under a justified rule or obtain narrowed, fresh
   authorization. A random call ID alone is not cryptographic binding.

Possible measurable contributions are:

- A demonstrated class of authority-confusion failures at voice/API/transfer
  boundaries which strong composed baselines do not already prevent.
- A precise continuity invariant and a protocol enforcing it, including
  concurrent-call, replay, reconnect, revocation, and transfer semantics.
- A measured tradeoff between on-call proof bytes, latency, cached trust,
  revocation staleness, and third-party availability on realistic voice paths.
- An interoperable implementation with independent issuer/verifier components
  and a substantially lower deployment burden than an equally secure baseline.

Every item is prospective. A blind live relay still does not demonstrate physical
presence. Offline verification cannot promise instantaneous knowledge of remote
revocation without a fresh information source. A fresh certificate does not make
an in-scope malicious action benign.

## Experiments that decide whether the hypothesis survives

### 1. Compose the strongest simple baseline first

Build ordinary workload identity or mTLS plus OAuth possession binding, rich
authorization details, and standard channel binding where applicable. Compare
the same customer intent and executor checks over:

- AuthLoop-style authentication with a delegated-operation layer;
- ordinary authenticated HTTPS with a well-specified call correlation mechanism;
- OpenAVT TLS and QUIC;
- an ACE/COSE/EDHOC-based audio adaptation, if transport efficiency is claimed;
- a pre-call credential/code approach inspired by UCBlocker, if offline admission
  or low on-call overhead is claimed.

An insecure bearer-token baseline is insufficient. If the well-composed existing
baseline satisfies the same security properties with comparable operational cost,
we should report a standards profile/integration result rather than a new
authorization mechanism.

### 2. Use two independent domains and real transition state

Construct at least two issuers, two receiving gateways, concurrent calls sharing
an agent identity, key rotation, and an actual endpoint transfer. Attempt
cross-customer, cross-business, cross-call and stale-epoch substitution; exercise
revocation during risk assessment and transfer. Count actual backend effects and
information release, not just rejected HTTP or JSON messages.

Separate expected failures from newly demonstrated attacks. Generic grant replay
or scope checks already handled by OAuth/capability systems are regression tests,
not novel attack discoveries. Any claimed transfer attack must be reproduced
against a clearly specified baseline, not inferred from absent fields alone.

### 3. Measure authority proof cost under realistic channels

At 500 bit/s, serializing one 1200-byte packet alone takes 19.2 seconds before
framing or retries. This arithmetic explains why an Internet-oriented QUIC Initial
can be costly; it does not demonstrate a protocol improvement. Compare proof and
certificate caching fairly with AuthLoop, and compact protected messages with
ACE/EDHOC. Do not compare the exact-sample 56 kbps PCM result to a robust
codec-transcoding result as if they used equivalent channels.

Sweep actual G.711 and speech-codec transformations, loss units, clock drift,
cache hits, issuer reachability and explicit freshness bounds. Report supported
paths, all failures, tail latency, useful proof bytes, airtime and revocation
reaction. Bound stale status explicitly and fail closed when the bound is crossed.
The generic offline-revocation tension is known; any contribution must be in the
demonstrated voice workflow, protocol, or measured operating frontier.

### 4. Test the infrastructure claim as infrastructure

Evaluate independently implemented issuance and verification, root/issuer
discovery, enrollment abuse controls, renewal, key compromise, and outage recovery.
Measure configuration and integration effort in addition to latency. Do not
publish per-customer grants or call destinations to a public transparency log by
default; auditability needs a privacy model. Public trust or production adoption
requires actual external relying parties, not just two components sharing our root.

## Recommendation and stop conditions

Continue OpenAVT as an engineering and experimentation platform. Do not rewrite
the paper around an already-established claim such as “automated agent CA” or
“cryptographic user delegation.” Prioritize the composed baseline and transition
attack harness before adding more infrastructure.

For a USENIX Security paper, the strongest route would be a concrete security
failure at an authorization boundary, a justified mechanism, and adversarial
evaluation against appropriate defenses. For SIGCOMM, the stronger route would
be a substantive transport/control adaptation with a realistic codec and workload
study. A Let's Encrypt-style systems/experience contribution would need credible
deployment, ecosystem and operational evidence.

If the composed baseline already covers the transition properties, or if an
ordinary authenticated API is consistently simpler at the same trust boundary,
retain the software and pursue a standards profile or practical integration
publication. That is useful work, but it should not be inflated into a new
cryptographic architecture.

## Search scope and remaining uncertainty

This review examined peer-reviewed secure-telephony and infrastructure papers,
relevant RFCs, official workload-identity and commerce specifications, current
IETF drafts and selected agent-security preprints. English-language public
material was screened as of October 30, 2026. It is a targeted novelty assessment,
not an exhaustive claim of absence. Individual Internet-Drafts, preprints, and
vendor product descriptions have different evidentiary status from peer-reviewed
evaluations and deployed standards. Their strong marketing or novelty claims were
not accepted without qualification.

Search snapshots are kept under the ignored `output/novelty-research/` directory;
the accompanying source index preserves identifiers and URLs without redistributing
the papers. The current paper's transport, authorization, and evaluation claims
should be revised against this audit before any submission.

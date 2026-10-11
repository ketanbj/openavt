# AVA: Agent Voice Authority and delegated voice requests

AVA is a runnable **local prototype** of automated agent certificate issuance
and business-issued customer consent. It uses standard X.509 client certificates,
TLS 1.3 and Ed25519-signed compact JWS grants. It is inspired by ACME's account,
order, challenge and issuance flow; it is **not ACME wire-compatible** and is not
a publicly trusted CA. No roots are installed in system trust.

## What the certificate means

Anyone using the local service can register a pseudonymous account, generate a
P-256 key locally, submit a signed CSR and answer an order-specific challenge
with that key. The service assigns an identity:

```text
urn:openavt:agent:<random-account-id>:<agent-label>
```

It issues a client-authentication-only leaf lasting at most 24 hours. Requested
CSR subjects, domains and CA extensions are ignored; they cannot create a
provider identity or server certificate. `assistant` or `muse` is merely a label
within the account's namespace. Identifying a specific provider requires an
additional trusted registration/attestation process; naming an agent does not
establish that it uses a particular LLM.

The certificate proves registered account/key control. It supplies no customer
identity, account ownership or business permission. A separate business signer
issues consent only after validating its customer credential and resource policy.
For this milestone, customer identity is explicitly **operator-provisioned demo
identity**, rather than a real login or identity-proofing integration.

## Complete voice demo

Two real GPT-6.1 Sol agents completed the flow with a **0.623 s** full mutual
TLS handshake and all eight authorization cases verified. [Public verification
evidence](authority-verification.json) records the results and model counters
without tokens, customer credentials or speech transcripts.
All **75 automated tests** passed locally. A fresh non-editable wheel environment
also completed all eight cases without an OpenAI dependency installed; the
authority-only installation was checked without audio dependencies.

```sh
uv sync --locked --extra webrtc --extra authority
uv run --locked --extra webrtc --extra authority openavt delegation-demo

# With OPENAI_API_KEY configured locally:
uv sync --locked --extra agents --extra authority
uv run --locked --extra agents --extra authority openavt delegation-demo --agents
```

The demo starts a temporary loopback authority service, registers an agent over
HTTP, enrolls and renews its certificate, and establishes a real audio-only PCMU
WebRTC connection. Full mutual TLS authenticates the enrolled agent and service.
The business sends a fresh challenge through audio TLS; the agent returns the
challenge and customer consent with its structured request, also through audio TLS.
The backend checks and returns a protected decision. There is no data channel.

| Case | Required outcome |
| --- | --- |
| Alice consents to reading her demo order | Allowed; fixed status returned |
| Consent expires | Denied |
| Bob's consent is used for Alice's account | Denied |
| Read consent is used for an address change | Denied |
| Already-used consent is submitted with a fresh challenge | Denied |
| Alice withdraws consent | Denied |
| Consent for another enrolled agent is used | Denied |
| Agent certificate is revoked after TLS establishment | Denied by backend |

The optional OpenAI mode uses two independent GPT-6.1 Sol contexts with actual
received speech transcription and synthesized voices. The first allowed request
comes from the caller's tool invocation. Backend decisions stay outside the LLM;
delegation tokens are omitted from model inputs and redacted in channel traces.
The seven denial cases are deterministic probes, not LLM-selected attacks.
Reports and recordings stay in ignored `output/`; temporary CA, agent and
business private keys, credentials and SQLite stores are deleted after the run.

## Persistent local service

Initialize two distinct authorities and provision a demo customer:

```sh
openavt ava init --state output/ava
openavt ava business-init --state output/business --ava-state output/ava
openavt ava customer --state output/business --ava-state output/ava \
  --customer alice --resource demo-order-1234 \
  --credentials output/alice.credentials.json

openavt ava serve --state output/ava --business-state output/business \
  --host 127.0.0.1 --port 8400
```

In another terminal, register and enroll an agent. Obtain `root.pem` from the
operator over a trusted channel; the client does not trust a root downloaded
from the enrollment service automatically.

```sh
openavt ava account --url http://127.0.0.1:8400 \
  --credentials output/agent.credentials.json
openavt ava enroll --url http://127.0.0.1:8400 \
  --credentials output/agent.credentials.json --agent assistant \
  --root output/ava/root.pem --output output/enrolled-agent

# Renew into a new bundle; reusing the local private key is supported.
openavt ava renew --url http://127.0.0.1:8400 \
  --credentials output/agent.credentials.json --agent assistant \
  --root output/ava/root.pem --key output/enrolled-agent/agent.key \
  --output output/renewed-agent
```

Enrollment credentials authenticate issuance and certificate revocation. They
cannot issue a customer grant. A customer approves a scoped grant by invoking:

```sh
openavt ava consent --url http://127.0.0.1:8400 \
  --credentials output/alice.credentials.json \
  --agent-cert output/enrolled-agent/agent.pem \
  --action order.read --resource demo-order-1234 --ttl 300 \
  --output output/alice.grant.json
```

Grant metadata is printed; the actual token is written only to the mode-0600
grant file. Credential files are likewise mode 0600. The client never uploads
its private key, and commands refuse to overwrite existing bundles or secret
files. Renewal is a CLI operation suitable for external scheduling; no renewal
daemon is included. A renewed certificate needs fresh consent because grants
bind to the exact certificate fingerprint, including when the key is reused.

Use the printed grant ID or certificate serial to revoke:

```sh
openavt ava withdraw-consent --url http://127.0.0.1:8400 \
  --credentials output/alice.credentials.json --grant-id GRANT_ID
openavt ava revoke --url http://127.0.0.1:8400 \
  --credentials output/agent.credentials.json --serial CERTIFICATE_SERIAL
```

The operator may also use `revoke-grant --state output/business --ava-state
output/ava --grant-id GRANT_ID`. Operator initialization, customer provisioning
and service certificate issuance are not public API endpoints. Enrollment and
consent requests require JSON with bounded fields; their endpoint definitions
are in `authority/service.py`. HTTPS is required when binding off loopback, with
`--https-cert` and `--https-key`. Clients use normal HTTPS validation and refuse
redirects. Remote hosting and Internet exposure have not been verified.

At worker capacity the HTTP service rejects new connections with 503; a client
still uploading may instead encounter a closed socket. The client reports that
transport failure as `authority_unavailable` (status 503) and does not retry
automatically. HTTPS overload closes the connection before its TLS handshake.

## Trust and CIA boundaries

| Property | Implemented here | Remaining boundary |
| --- | --- | --- |
| Confidentiality | TLS protects structured audio requests; SRTP protects the WebRTC audio leg; HTTPS is required for remote APIs; file permissions protect local secrets | Local loopback API is HTTP; ordinary speech is outside inner TLS; keys and SQLite state are not encrypted at rest |
| Integrity | TLS records, pinned Ed25519 grant signatures, strict algorithms/claims, certificate fingerprint binding | A compromised endpoint or business issuer can act with its legitimate credentials |
| Availability | Eight API workers, bounded backlog/body/timeout, enrollment rate and storage caps, audio retry and CRC recovery | No distributed DoS protection, high availability, storage-quota or operational recovery guarantee |
| Agent identity | CSR signature and one-time proof, explicit root trust, registry and expiry checks | Pseudonymous account/key control, without verified provider or human identity |
| Authorization | Separate customer credential, business resource policy, scoped five-minute maximum grant, fresh challenge, persistent atomic single-use consumption and revocation | Customer login/consent is a fixture; production business policy and transaction handling are not implemented |

Grants pin the issuer and business audience, include the customer and action/
resource, and use `cnf.x5t#S256` to bind to the client certificate. The verifier
uses a configured public key and one fixed algorithm/token type, never a key
URL or algorithm selected by a token. Used and revoked grants survive process
restart. Consumption of a grant and challenge is atomic within the business
SQLite store, so concurrent uses have only one winner. Invalid requests fail
closed. This is a signed JWS profile using the certificate-binding mechanism
from RFC 8705, not a complete OAuth authorization server.

The backend must obtain the certificate from its verified TLS session, rather
than from a request field. The local demo follows this pattern:

```python
peer_der = desk.endpoint.tls.getpeercert(binary_form=True)
nonce = business.challenge(peer_der)
await desk.send_json({"type": "authorization_challenge", "nonce": nonce})
request = await desk.receive_json()
await desk.send_json(business.decide(peer_der, request, nonce))
```

Certificate revocation is checked by the backend against the AVA registry on
each request, including established TLS sessions. **OpenSSL does not consult
this registry automatically.** This milestone has no CRL/OCSP distribution and
no remote signed status protocol. A production integration must preserve the
status check; checks are point-in-time and do not cancel work already underway.
Single-use grants do not implement transactional side-effect idempotency or
recovery after a lost response; this demo performs a fixed read-only operation.

The CA uses one online root protected by local file permissions. A deployable
authority needs offline root/intermediate separation, key isolation, issuer
rotation, real customer authentication and consent UX, provider registration,
auditing, remote status checking, and operational availability controls.
The demo orchestrator holds customer credentials to simulate consent; neither
voice-agent context receives those credentials. All components run locally in
one process, so this is a protocol demonstration rather than process isolation.

References: [ACME, RFC 8555](https://www.rfc-editor.org/rfc/rfc8555.html),
[certificate-bound access tokens, RFC 8705](https://www.rfc-editor.org/rfc/rfc8705.html#section-3),
and [JWT best practices, RFC 8725](https://www.rfc-editor.org/rfc/rfc8725.html).

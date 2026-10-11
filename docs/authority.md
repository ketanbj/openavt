# Agent Voice Authority and customer delegation

[README](../README.md) · [Quickstart](quickstart.md) · [AVA CLI](authority-cli.md)

**AVA gives an agent a certificate. A separate business signer gives it customer
permission. The business checks both before acting.**

AVA is a local, ACME-inspired enrollment service using X.509 client certificates.
It is not ACME-compatible or publicly trusted. No root is installed in system trust.

## How it works

1. **Enroll:** the agent registers an account, creates a P-256 key locally and
   proves possession through a signed CSR and one-time challenge. AVA issues a
   client certificate valid for at most 24 hours.
2. **Delegate:** a demo customer credential authorizes the business to issue a
   signed grant for one agent certificate, customer, business, action and resource.
   Grants last at most five minutes and are single-use.
3. **Call:** mutual TLS authenticates both peers through audio. The business sends
   a fresh challenge; the agent returns its grant and request through that channel.
4. **Enforce:** the backend checks the certificate, grant, account ownership,
   scope, expiry, revocation and replay state before returning the fixed read-only result.

The agent identity is `urn:openavt:agent:<account-id>:<agent-label>`. Requested
CSR subjects, domains and CA extensions cannot grant provider identity or CA powers.
Enrollment credentials cannot authorize access to a customer's account.

## Try it

```sh
uv run --locked --extra webrtc --extra authority openavt delegation-demo
```

Add `--agents` and use the `agents` extra for two real OpenAI voice agents; see
[setup](quickstart.md#add-two-openai-voice-agents). The OpenAI run measured a
**0.623 s** handshake with all eight cases verified. [Evidence](authority-verification.json).

### Demo cases

| Request | Result |
| --- | --- |
| Alice reads her order with valid consent | Allowed |
| Expired consent | Denied |
| Another customer's grant | Denied |
| Address change under read-only consent | Denied |
| Reuse of a consumed grant | Denied |
| Withdrawn consent | Denied |
| Grant bound to another agent certificate | Denied |
| Certificate revoked after TLS establishment | Denied |

The allowed request is agent-driven in OpenAI mode. Denial probes are deterministic.
Credentials and tokens stay out of model inputs; channel traces redact tokens.

## Backend integration

Obtain the peer certificate from the verified TLS session. Use it to check a
business challenge and grant; an identity supplied in request JSON is insufficient.

```python
peer_der = desk.endpoint.tls.getpeercert(binary_form=True)
nonce = business.challenge(peer_der)
await desk.send_json({"type": "authorization_challenge", "nonce": nonce})
request = await desk.receive_json()
await desk.send_json(business.decide(peer_der, request, nonce))
```

Ed25519 signatures use a pinned business public key and fixed token algorithm/type.
Grants bind to the exact certificate fingerprint with `cnf.x5t#S256`. SQLite
atomically consumes the grant and challenge, preserving replay and revocation
state across restarts. Certificate status is checked on each request, including
existing TLS sessions. **OpenSSL does not consult the AVA registry automatically.**

## Trust boundaries

| Layer | Implemented | Remaining work |
| --- | --- | --- |
| Agent identity | Registered account/key control | Verified provider, organization or human identity |
| Customer permission | Operator-provisioned demo accounts and scoped grants | Real customer login and consent integration |
| Confidentiality and integrity | TLS requests, signed grants, outer WebRTC SRTP | Ordinary speech is outside inner TLS; local HTTP and stored keys are unencrypted |
| Revocation | Per-request local registry checks | CRL/OCSP or remote signed status; cancellation of work already underway |
| Availability | Eight workers, bounded requests/timeouts, rate/storage caps | High availability, DoS protection and recovery |

The prototype has one online root protected by file permissions. Production use
needs key isolation, root/intermediate separation, issuer rotation and auditing.
Single-use grants do not provide transactional write recovery; the demo performs
a fixed read. All demo components share one process, with the orchestrator
simulating customer consent. It is not a production security audit.

[Persistent service commands](authority-cli.md) ·
[ACME](https://www.rfc-editor.org/rfc/rfc8555.html) ·
[Certificate-bound tokens](https://www.rfc-editor.org/rfc/rfc8705.html#section-3) ·
[JWT guidance](https://www.rfc-editor.org/rfc/rfc8725.html)

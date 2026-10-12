# PAP sessions → OpenAVT calls

OpenAVT works **alongside Personal Agent Protocol (PAP/Poppy)**. PAP handles
HTTPS discovery, sign-in and account permissions. OpenAVT binds that authority to
an authenticated audio endpoint and exact requests. Either integration is optional;
standalone OpenAVT callers keep their existing authorization policy.

This adapter targets [PAP draft 0.1, updated October 9, 2026](https://personalagentprotocol.org/docs/spec)
and [operations v1](https://personalagentprotocol.org/docs/extensions/operations).
The bridge is a custom extension, not a standard PAP audio transport.

## Try the complete flow

```sh
python -m pip install 'openavt[pap,webrtc]'
openavt pap-demo
```

A local HTTPS reference company verifies JWTs independently with PyJWT. The demo
performs simulated user sign-in with PKCE, then uses a real WebRTC audio call to:

1. Read an authorized order through TLS over audio.
2. Propose an exchange through audio; no business change occurs yet.
3. Confirm the same operation ID through PAP HTTPS. Repeating confirmation and
   reading status cause exactly one simulated business effect.
4. Block an authenticated request through the fraud interface.
5. Sign out after issuing a grant and reject it before execution.

`output/pap-demo/report.json` contains timings and results, without credentials.
[Checked-in evidence](pap-verification.json) records this local profile, **not
interoperability certification against another PAP provider**. User login/approval
and the order backend are simulations. The reference service is not a production
OAuth provider.

## Agent integration

Install `openavt[pap]` for HTTPS only; add an audio transport extra for calls.
Host client metadata and public JWKS on HTTPS URLs under the same hostname. Keep
assertion, DPoP and voice private keys local and separate. Persist keys across runs;
`SigningKey.generate()` is for initial provisioning, not every request.

```python
from pathlib import Path
from openavt.pap import PAPClient, PAPVoiceGrant, UserIDs
from openavt.pap.crypto import SigningKey

namespace = "your-domain.example/openavt-voice"  # replace with a domain you control
pap = PAPClient(
    client_id="https://agent.example/client.json",
    signing_key=SigningKey.load(Path("assertion.key"), kid="assertion-1"),
    dpop_key=SigningKey.load(Path("dpop.key")),
    user_ids=UserIDs(Path("private-user-state/ids.sqlite3")),
    redirect_uris=("https://agent.example/callback",),
    extensions={namespace: {"version": "1"}, "operations": {"version": "1"}},
)
# Publish pap.metadata("https://agent.example/jwks.json", name="My agent")
# and pap.signing_key.jwks at those URLs.
await pap.discover("https://company.example")
await pap.start_session()
flow = pap.begin_direct("poppy:read", pap.redirect_uris[0])
# Open flow.url in the user's browser; receive the registered HTTPS callback.
await pap.finish_direct(callback_url)

# With an already established OpenAVT VoiceSession and enrolled Identity:
result = await call.request(
    "order.read", resource="order-1", customer="company-account-id",
    grant=PAPVoiceGrant(pap, identity, namespace=namespace),
)
await pap.close()
```

The callback runs after the business's protected challenge arrives. It signs the
challenge and intent with the voice certificate's key, authenticates the grant
request with the current DPoP Session Token, and returns a separate ≤30-second
voice grant. PAP access/account credentials remain on HTTPS and outside model
inputs. Ordinary speech remains outside OpenAVT's inner TLS.

## Business integration

Implement `SessionBackend` using your existing PAP authorization server:

| Method | Required behavior |
| --- | --- |
| `authenticate(...)` | Resolve the opaque token; verify current session, expiry, resource audience and DPoP signature, key binding, `ath`, HTTP method/URL, time, nonce and replay. Return `VerifiedSession`. |
| `current(credential_id)` | Recheck the same credential's current account, scopes, expiry, sign-out, withdrawal and invalidation before execution. Return `None` when unavailable authority is invalid. |
| `supports_extension(...)` | Check the client's verified HTTPS metadata for the matching extension version. |

Never construct `VerifiedSession` from a caller's unverified JSON or merely decode
an access token. Transport failure must raise; it must not create valid authority.

Initialize `VoiceAuthority` once with an AVA, that backend and a mandatory async
`authorize_intent(session, action, resource, arguments)` callback. The callback must
check business ownership and permissions for the exact arguments; `poppy:read`
and `poppy:write` are independent permissions. Use that authority as `Gateway`'s
policy. Mount `VoiceBridge(authority, endpoint=..., namespace=...).application()`
behind verified HTTPS, and advertise `extension(namespace, endpoint, audience)` in
`poppy.json`. Share the authority's persistent SQLite state between the grant
service and gateway processes on one host; distributed issuance is not implemented.
Private business signing keys are separate from the AVA certificate key.
The business backend must still check permissions atomically with durable effects;
no network-level check can eliminate a revocation race with a separate backend.

A grant binds audience, customer, client/user/session, access-credential reference,
certificate, live nonce, request ID, action, resource and canonical arguments hash.
The gateway checks current permission, rechecks after fraud assessment, and atomically consumes the grant/challenge
before invoking a registered, schema-validated handler. Replay cannot execute it twice.

For consequential actions, the audio handler **only proposes** an operation. Store
one durable operation ID across channels. Show its current summary and terms in the
personal interface, obtain real user approval where required, then call
`pap.operation(id, revision=revision, approved_by="user")` over HTTPS. On uncertain
outcomes, read that same ID with `pap.operation(id)`; never create another operation
as a recovery shortcut. The company owns durable revision checks, state and exactly
once effects. The adapter does not infer user approval from an LLM response;
`approved_by` itself is an agent statement, not cryptographic proof of human consent.

## Supported interoperability profile

| Capability | Implemented |
| --- | --- |
| Discovery | HTTPS-only redirects; original host and issuer-domain binding; cache headers; unsupported major refusal, unknown minor fields ignored |
| Identity/session | HTTPS metadata/JWKS publishing helpers; private-key JWT; stable random per-user/per-issuer IDs; signed-out creation/renewal |
| HTTP token use | Separate ES256 DPoP key; `ath`, fresh `jti`, method/URL binding; nonce challenge retry; bounded responses/timeouts; Retry-After for authenticated requests |
| Sign-in | Direct PKCE/state/issuer/redirect checks; device polling/presentation; mediated fields and code step |
| Account authority | Refresh, scope narrowing, optional resource, account-token rotation, revocation and local sign-out |
| Operations | Mutually advertised v1; GET, explicit revision confirmation and cancellation over HTTPS |
| Voice bridge | Mutually advertised custom extension; certificate key proof; exact intent, expiry and atomic replay checks; current authorization |
| Other PAP features | Browser-session bootstrap, native conversations, direct conversations and MCP/Bearer transport are outside this adapter's profile |

Publish a custom extension under a domain **you control**. The name and endpoints
are configurable; `example.test/openavt-voice` is a reserved local demo namespace.
No domain has been selected or registered for a public OpenAVT PAP extension.
Unknown extensions/fields do not prevent standard PAP use. A caller lacking this
extension can still use the company's existing PAP HTTPS interfaces; an unsupported
voice caller goes through existing identity/login and fraud monitoring workflows.

[Fraud adapter integration →](risk.md) · [Standalone SDK and Twilio →](integration.md)

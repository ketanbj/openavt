# Add OpenAVT to a voice agent

[README](../README.md) · [Quickstart](quickstart.md) · [Authority](authority.md)

Use **`VoiceSession` on the personal agent and `Gateway` on the business**.
The LLM proposes an action; the SDK transports it through audio TLS, and the
business policy decides whether its handler may run. No agent framework is required.

For lossy audio, install the `quic` extra and pass `protocol="quic"` to both
sessions. The same Gateway, identities and policies apply. See the
[QUIC guide](quic.md) for end-to-end demos and modem requirements.

## Run the complete application

From a checkout, with no credentials:

```sh
uv run --locked --extra webrtc --extra authority openavt sdk-demo
uv run --locked --extra twilio --extra authority openavt sdk-demo --transport twilio-emulated
```

Each command launches **two separate Python processes**, enrolls an agent with
a temporary AVA service, and exercises one permitted read plus seven denials.
WebRTC signaling carries only SDP; the provider fixture carries only audio and
playback marks. Protected requests and grants travel inside the audio payload.
Reports include worker PIDs, handshake time, handler execution count and results.

Add independent OpenAI contexts, speech synthesis and transcription:

```sh
uv run --locked --extra agents --extra authority openavt sdk-demo --agents
uv run --locked --extra agents --extra twilio --extra authority openavt sdk-demo --agents --transport twilio-emulated
```

Configure `OPENAI_API_KEY` in `.env` first; these runs use paid API calls.
Both modes use the **same SDK and business handler**. Emulation verifies the
provider format locally; it does not verify Twilio or a telephone network.

## Personal-agent tool

After your call adapter has connected, make a protected request:

```python
from openavt import Identity, VoiceSession

async def check_order(audio, grant):
    async with VoiceSession(
        audio=audio,
        identity=Identity.load("agent-identity"),
        trust="trusted-business-root.pem",
        expected_peer="desk.demo",
    ) as call:
        return await call.request(
            "order.read",
            resource="demo-order-1234",
            customer="alice",
            grant=grant,
        )
```

`agent-identity/` contains `agent.pem` and `agent.key`. You may also construct
`Identity(certificate=Path(...), private_key=Path(...))` for existing certificates.
Trust roots and the expected business hostname must come from trusted configuration.
Fetch customer consent through a separate authenticated workflow; the LLM should
receive a narrow tool, not the credential or grant that implements it.

Entering the session completes mutual TLS. Requests are serialized, use a fresh
business challenge and correlate each response to its request. A timeout or
connection loss after submission raises **`RequestOutcomeUnknown`** and closes
the session. Resolve that outcome through your backend before retrying a write.
There is no automatic retry of application actions or downgrade to speech.

## Business tool boundary

```python
from pathlib import Path
from openavt import Gateway, Identity, VoiceSession
from openavt.authority.ca import AgentAuthority
from openavt.authority.delegation import BusinessAuthority
from openavt.authority.policy import AVAPolicy

async def serve_call(audio, order_backend):
    policy = AVAPolicy(BusinessAuthority(
        Path("business-state"), AgentAuthority(Path("ava-state"))
    ))
    gateway = Gateway(policy=policy)

    def validate(request):
        if request.arguments:
            raise ValueError("order.read accepts no additional arguments")

    async def read_order(request, verified_claims):
        return await order_backend.read(request.customer, request.resource)

    gateway.register("order.read", validate=validate, handler=read_order)
    async with VoiceSession(
        audio=audio,
        identity=Identity.load("business-identity", name="desk"),
        trust="trusted-agent-root.pem",
        server=True,
    ) as call:
        await gateway.serve(call)
```

The gateway requires a policy and an explicit handler allowlist. It validates the
request, checks permission against the actual TLS peer certificate, then invokes
the handler. Unknown actions, invalid arguments and rejected grants never invoke
it. Unavailable authorization produces a protected error; it cannot permit an action.

`AVAPolicy` implements the existing local, certificate-bound, single-use
`order.read` grants. For another business, implement the `AuthorizationPolicy`
interface: issue a challenge and return verified claims from `authorize`, or
raise `PermissionError`. Enforce customer, audience, action, resource, argument
constraints, expiry, revocation and replay before returning. A permissive policy
would defeat this boundary. Enrollment certificates alone are not customer consent.

See [the persistent AVA setup](authority-cli.md) for identities, service certificates
and consent. The complete executable wiring lives in
[`sdk_worker.py`](../src/openavt/demos/sdk_worker.py).

## Connect an existing call

| Call | Adapter | Setup |
| --- | --- | --- |
| WebRTC | `transports.peer.WebRTCAdapter` | Exchange `offer()`, `answer(offer)` and `accept(answer)` through your signaling service |
| Twilio bidirectional Media Streams | `transports.twilio.TwilioAdapter` | Accept a signed stream with `TwilioIngress`, then supply the socket and account SID |
| Another provider | Implement `transports.base.AudioAdapter` | Receive and play 8 kHz mono signed 16-bit PCM |

The adapter implements `start(receive, disconnected)`, async
`send(samples, kind="modem")` and async `close()`, plus a matching `profile`.
Receive callbacks supply at most two seconds of audio per chunk. Disconnects
must notify the session so pending operations fail promptly.

Route **all TTS playback through the adapter** (`call.send_speech`, or its
`send(..., "speech")` callback). Its bounded scheduler reserves complete modem
bursts and pauses speech at packet boundaries. Mixing speech into modem audio
corrupts the fast profile. `on_speech` receives chunks outside detected modem
bursts for an ASR integration; it is not a security filter for prompt injection.

The fast `pcm` profile requires an unchanged digital 8 kHz PCMU path. WebRTC pins
PCMU and rejects data channels. Existing Opus, denoising, gain processing or
transcoding paths need adaptation and verification. `voiceband` is an explicit
slower profile, not an automatic fallback or a verified PSTN solution.

## Configure a later real Twilio call

Install the `twilio,authority` extras (also `agents` for LLMs). Set these locally:

| Variable | Value |
| --- | --- |
| `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN` | Your Twilio account credentials |
| `TWILIO_CALLER_NUMBER` | An E.164 number owned by that account |
| `TWILIO_BUSINESS_NUMBER` | A different E.164 number owned by that account |
| `TWILIO_PUBLIC_BASE_URL` | Public HTTPS origin, such as `https://your-tunnel.example` |
| `TWILIO_LISTEN_PORT` | Local ingress port; defaults to `8080` |

Forward that public HTTPS/WSS origin to `127.0.0.1:8080`, preserving the paths
and `X-Twilio-Signature` header. On the **business number**, configure its voice
webhook as `POST https://your-tunnel.example/voice/desk`.
The caller leg uses `/voice/agent`; both return bidirectional `<Connect><Stream>`.

```sh
uv run --locked --extra twilio --extra authority openavt sdk-demo --transport twilio-live
# Add --extra agents and --agents for the two LLM workers.
```

This command verifies account ownership of both numbers, creates **one outbound
call** between them with a 180-second limit, and attempts to end it during cleanup.
Twilio charges apply. It will not modify your number configuration or
repeat an ambiguous call-creation request. Inspect the provider console before
retrying a failed call setup.

Ingress validates Twilio signatures against the configured public HTTPS/WSS URLs,
not proxy Host headers. The adapter checks account, stream, sequence and codec,
decodes μ-law audio, and waits for playback marks. It never sends `clear`, which
would turn mark acknowledgments into ambiguous playback results. Twilio signatures
identify provider ingress; **inner mutual TLS still identifies the agent**.

**Real Twilio/carrier verification is pending.** The local fixture and signature
checks do not establish carrier codec preservation, latency, mixing behavior or
interoperability. Run the live mode after configuring your account and inspect its
report before making those claims. [Verification evidence](sdk-verification.json).

## Boundaries

Both verified demo peers currently run on one host, in separate processes. That
is process separation, not filesystem sandboxing. The parent provisions demo
identities and grants and uses local authority state shared by the workers.
Production identity verification, user login, public discovery, remote signaling,
CA availability and durable transaction reconciliation remain separate work.
Ordinary speech is outside inner TLS and remains untrusted. Protect other agent
tools and speech output as well as the business gateway.

## PAP and fraud integrations

Use the optional [PAP session bridge](pap.md) to carry existing digital account
authority into a call. Attach a [fraud adapter](risk.md) for authenticated behavior
checks, or use it directly for unsupported callers. Core OpenAVT remains standalone.

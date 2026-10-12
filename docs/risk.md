# Voice detection and fraud adapters

Cryptographic identity and permissions do not replace fraud monitoring. OpenAVT
exposes an optional vendor-neutral interface for unsupported callers and suspicious
authenticated behavior. A solution such as Pindrop can be connected using its
supported SDK/API. No Pindrop-specific API integration or vendor validation is
claimed by this package.

```python
from openavt.risk import CallbackFraudAdapter, RiskAssessment, RiskMonitor, RiskOutcome

async def observe(context, pcm):
    # Send through your vendor's supported integration, subject to your policy.
    await detector.observe(context.call_id, pcm)

async def assess(context, request):
    verdict = await detector.assess(context.call_id)
    return RiskAssessment(RiskOutcome.BLOCK if verdict.block else RiskOutcome.CONTINUE)

monitor = RiskMonitor(
    CallbackFraudAdapter(observe=observe, assess=assess),
    required=True, timeout=2,
)
# Pass monitor=monitor to the receiving VoiceSession.
```

`observe` receives 8 kHz mono little-endian signed int16 PCM, which may contain
speech and modem tones. `CallContext` includes a call ID, whether TLS has verified
the peer and its certificate fingerprint. Configure audio observation explicitly;
the library does not upload recordings to a vendor by default.

After schema validation and cryptographic authorization, `Gateway` calls `assess`
with only request ID, action, resource and customer. It never passes grants,
arguments, tokens or model context. `continue` permits the existing authorization
path to proceed; it cannot override denied permission. `block`, `step_up` and
`review` stop execution with a protected denial. Your surrounding application owns
the user verification/review flow and a fresh authorized request afterward.

Observation uses a 32-chunk queue with chunks capped at 32,000 bytes. Assessments
wait for queued audio under a bounded deadline. Provider exceptions, invalid
results, timeouts and dropped audio block when `required=True`. Setting
`required=False` explicitly permits continuing during monitor failure; inspect
`monitor.unavailable` and `dropped_chunks` for operational reporting. Provider
exception text and reasons are not reflected in protected responses.

For callers without OpenAVT, use the monitor directly:

```python
from openavt.risk import CallContext

context = CallContext(call_id="provider-call-id")  # authenticated=False
monitor.start()
monitor.feed(context, pcm_chunk)
assessment = await monitor.assess(context)
await monitor.close()
```

A fraud result does not authenticate an unsupported caller or grant account
permissions. Retain the business's existing login, consent and recovery controls.
[PAP integration →](pap.md) · [SDK integration →](integration.md)

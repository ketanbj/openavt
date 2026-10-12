"""Risk adapters observe bounded audio and can restrict, never authorize, tools."""

import asyncio
from types import SimpleNamespace

import pytest

from openavt.gateway import Gateway
from openavt.risk import (
    CallbackFraudAdapter,
    CallContext,
    RequestSignal,
    RiskAssessment,
    RiskMonitor,
    RiskOutcome,
)


@pytest.mark.parametrize("outcome", list(RiskOutcome))
def test_risk_is_enforced_after_authority_with_one_response(outcome):
    async def scenario():
        called = []
        responses = []
        checked = []

        async def assess(context, signal):
            checked.append((context, signal))
            assert not hasattr(signal, "grant") and not hasattr(signal, "arguments")
            return RiskAssessment(outcome, "provider-secret-not-reflected")

        monitor = RiskMonitor(CallbackFraudAdapter(assess=assess))
        messages = iter(
            [
                {"v": 1, "type": "challenge", "id": "r"},
                {
                    "v": 1,
                    "type": "request",
                    "id": "r",
                    "action": "read",
                    "resource": "order-1",
                    "customer": "alice",
                    "arguments": {},
                    "nonce": "n",
                    "grant": "private-grant",
                },
            ]
        )

        async def receive():
            return next(messages)

        async def send(message):
            responses.append(message)

        class Policy:
            async def challenge(self, peer):
                return "n"

            async def authorize(self, peer, request):
                return {"scope": ["read"]}

        gateway = Gateway(Policy())

        async def handler(request, claims):
            called.append(request.id)
            return {}

        gateway.register("read", validate=lambda request: None, handler=handler)
        session = SimpleNamespace(
            server=True,
            peer_certificate=b"certificate",
            monitor=monitor,
            risk_context=CallContext("call", True, "fingerprint"),
            channel=SimpleNamespace(receive_json=receive, send_json=send),
        )
        await gateway.serve(session, limit=1)
        assert len(responses) == 2 and len(checked) == 1
        assert called == (["r"] if outcome == RiskOutcome.CONTINUE else [])
        assert responses[1]["reason"] == ("authorized" if called else "risk_" + outcome.value)
        assert "provider-secret" not in str(responses)
        await monitor.close()

    asyncio.run(scenario())


@pytest.mark.parametrize("required", [True, False])
@pytest.mark.parametrize("failure", ["exception", "timeout", "invalid", "observation"])
def test_risk_outage_policy_is_explicit_and_audio_errors_fail_closed(required, failure):
    async def scenario():
        async def assess(context, signal):
            if failure == "exception":
                raise RuntimeError("private vendor message")
            if failure == "timeout":
                await asyncio.sleep(1)
            if failure == "invalid":
                return "allow"
            return RiskAssessment(RiskOutcome.CONTINUE)

        async def observe(context, pcm):
            if failure == "observation":
                raise RuntimeError("private")

        monitor = RiskMonitor(
            CallbackFraudAdapter(assess=assess, observe=observe), required=required, timeout=0.02
        )
        monitor.start()
        monitor.feed(CallContext("legacy"), b"\0\0" * 80)
        result = await monitor.assess(CallContext("legacy"))
        assert result == RiskAssessment(
            RiskOutcome.BLOCK if required else RiskOutcome.CONTINUE, "unavailable"
        )
        await monitor.close()
        assert monitor.task.done() and monitor.queue.empty()

    asyncio.run(scenario())


def test_unsupported_audio_order_and_capacity_are_bounded():
    async def scenario():
        observed = []

        async def observe(context, pcm):
            observed.append(pcm)

        async def assess(context, request):
            assert not context.authenticated and context.peer_fingerprint is None
            assert observed == [b"\1\0", b"\2\0"]
            return RiskAssessment(RiskOutcome.REVIEW)

        monitor = RiskMonitor(CallbackFraudAdapter(observe=observe, assess=assess))
        monitor.start()
        context = CallContext("unsupported")
        monitor.feed(context, b"\1\0")
        monitor.feed(context, b"\2\0")
        assert (await monitor.assess(context)).outcome == RiskOutcome.REVIEW
        for invalid in (b"", b"\0", b"\0" * 32002, "not bytes"):
            with pytest.raises(ValueError):
                monitor.feed(context, invalid)
        await monitor.close()
        overflow = RiskMonitor(CallbackFraudAdapter(assess=assess))
        for _ in range(33):
            overflow.feed(context, b"\0\0")
        assert overflow.queue.qsize() == 32 and overflow.dropped_chunks == 1
        assert (await overflow.assess(context)).outcome == RiskOutcome.BLOCK
        await overflow.close()

    asyncio.run(scenario())


def test_fraud_continue_does_not_bypass_permission_failure():
    async def scenario():
        checks = []
        sent = []

        async def assess(context, request):
            checks.append(request)
            return RiskAssessment(RiskOutcome.CONTINUE)

        monitor = RiskMonitor(CallbackFraudAdapter(assess=assess))

        class Policy:
            async def challenge(self, peer):
                return "n"

            async def authorize(self, peer, request):
                raise PermissionError()

        messages = iter(
            [
                {"v": 1, "type": "challenge", "id": "r"},
                {
                    "v": 1,
                    "type": "request",
                    "id": "r",
                    "nonce": "n",
                    "action": "read",
                    "resource": "r",
                    "customer": "c",
                    "arguments": {},
                    "grant": "g",
                },
            ]
        )

        async def receive():
            return next(messages)

        async def send(message):
            sent.append(message)

        async def handler(request, claims):
            raise AssertionError("must not execute")

        gateway = Gateway(Policy())
        gateway.register("read", validate=lambda r: None, handler=handler)
        session = SimpleNamespace(
            server=True,
            peer_certificate=b"peer",
            monitor=monitor,
            risk_context=CallContext("c", True),
            channel=SimpleNamespace(receive_json=receive, send_json=send),
        )
        await gateway.serve(session, limit=1)
        assert not checks and sent[-1]["result"] == "denied" and gateway.executions == 0
        await monitor.close()

    asyncio.run(scenario())


def test_request_signal_has_no_credential_fields():
    assert set(RequestSignal.__dataclass_fields__) == {"request_id", "action", "resource", "customer"}

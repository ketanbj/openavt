"""Public SDK trust boundaries and two independently running audio peers."""

import asyncio
import ssl
from contextlib import asynccontextmanager
from types import SimpleNamespace

import numpy as np
import pytest

from openavt import Gateway, Identity, VoiceSession
from openavt.channel import AudioTLS
from openavt.demos.sdk import CASES, run
from openavt.gateway import Request
from openavt.pki import issue_certificates
from openavt.session import ProtocolError, RequestOutcomeUnknown
from openavt.transports.audio import AudioScheduler
from openavt.transports.peer import WebRTCAdapter


class Policy:
    def __init__(self, failure=None, phase="authorize"):
        self.failure, self.phase = failure, phase
        self.used = set()

    async def challenge(self, peer):
        assert peer
        if self.phase == "challenge" and self.failure:
            raise self.failure
        return "fresh-nonce"

    async def authorize(self, peer, request):
        assert peer
        if self.failure:
            raise self.failure
        if request.action != "order.read" or request.grant in self.used:
            raise PermissionError()
        self.used.add(request.grant)
        return {"scope": ["order.read"]}


@asynccontextmanager
async def sessions(bundle, expected="desk.demo"):
    a, b = WebRTCAdapter(), WebRTCAdapter()
    try:
        await a.accept(await b.answer(await a.offer()))
        caller = VoiceSession(
            audio=a,
            identity=Identity.load(bundle),
            trust=bundle / "root.pem",
            expected_peer=expected,
            handshake_timeout=3,
        )
        desk = VoiceSession(
            audio=b,
            identity=Identity.load(bundle, name="desk"),
            trust=bundle / "root.pem",
            server=True,
            handshake_timeout=3,
        )
        results = await asyncio.gather(caller.__aenter__(), desk.__aenter__(), return_exceptions=True)
        if any(isinstance(r, BaseException) for r in results):
            await asyncio.gather(caller.close(), desk.close())
            raise next(r for r in results if isinstance(r, BaseException))
        try:
            yield caller, desk
        finally:
            await asyncio.gather(caller.close(), desk.close())
    finally:
        await asyncio.gather(a.close(), b.close())


@pytest.fixture
def bundle(tmp_path):
    issue_certificates(tmp_path, rogue=False)
    return tmp_path


def register(gateway, executed):
    def validate(request):
        if request.arguments:
            raise ValueError("no parameters permitted")

    async def handler(request, claims):
        executed.append(request.id)
        assert claims["scope"] == ["order.read"]
        return {"status": "shipped"}

    gateway.register("order.read", validate=validate, handler=handler)


def test_mutual_tls_sdk_enforces_allowlist_schema_scope_and_replay(bundle):
    async def scenario():
        async with sessions(bundle) as (caller, desk):
            executed, gateway = [], Gateway(Policy())
            register(gateway, executed)
            server = asyncio.create_task(gateway.serve(desk, limit=4))
            options = {"resource": "order-1", "customer": "alice", "grant": "secret-grant"}
            assert (await caller.request("order.read", **options))["data"] == {"status": "shipped"}
            assert (await caller.request("order.read", **options))["result"] == "denied"
            assert (await caller.request("payment.create", **options))["reason"] == "unsupported_action"
            assert (await caller.request("order.read", **options, arguments={"override": True}))[
                "reason"
            ] == "invalid_arguments"
            await server
            assert gateway.summary() == {"requests": 4, "handler_executions": 1, "denials": 3}
            assert len(executed) == 1
            assert caller.peer_certificate and caller.summary()["tls_version"] == "TLSv1.3"
            assert not caller.summary()["session_reused"]
            assert not caller.audio.summary()["data_channel"]

    asyncio.run(scenario())


@pytest.mark.parametrize("phase", ["challenge", "authorize"])
@pytest.mark.parametrize(
    "failure,expected", [(PermissionError("secret"), "denied"), (RuntimeError("backend secret"), "error")]
)
def test_policy_failure_never_invokes_handler_or_reflects_secrets(bundle, phase, failure, expected):
    async def scenario():
        async with sessions(bundle) as (caller, desk):
            gateway, executed = Gateway(Policy(failure, phase)), []
            register(gateway, executed)
            server = asyncio.create_task(gateway.serve(desk, limit=1))
            response = await caller.request("order.read", resource="r", customer="c", grant="private")
            await server
            assert response["result"] == expected
            assert "secret" not in str(response)
            assert executed == []

    asyncio.run(scenario())


def test_wrong_service_name_closes_session_before_any_request(bundle):
    async def scenario():
        with pytest.raises((ssl.SSLError, TimeoutError)):
            async with sessions(bundle, expected="attacker.example"):
                pytest.fail("incorrect peer identity was accepted")

    asyncio.run(scenario())


@pytest.mark.parametrize("transport", ["webrtc", "twilio-emulated"])
def test_independent_workers_deliver_all_probes_over_audio(tmp_path, transport):
    report = asyncio.run(run(tmp_path, transport=transport))
    assert report["verified"] and not report["provider_network_verified"]
    assert report["caller"]["pid"] != report["business"]["pid"]
    assert tuple(r["case"] for r in report["caller"]["results"]) == CASES
    assert all(r["verified"] for r in report["caller"]["results"])
    assert report["business"]["gateway"] == {"requests": 8, "handler_executions": 1, "denials": 7}
    assert report["protected_request_delivery"] == "audio only"
    assert all(r["sdk"]["modem_bad_frames"] == 0 for r in (report["caller"], report["business"]))


@pytest.mark.parametrize("submitted", [False, True])
def test_disconnect_classifies_ambiguous_execution_and_closes(bundle, submitted):
    async def scenario():
        adapter = SimpleNamespace(profile="pcm", send=lambda *a: None)
        session = VoiceSession(
            audio=adapter,
            identity=Identity.load(bundle),
            trust=bundle / "root.pem",
            expected_peer="desk.demo",
        )
        session.state = "verified"
        sent = []

        async def send(message):
            sent.append(message)

        async def receive():
            if len(sent) == 1 and submitted:
                return {"v": 1, "type": "challenge", "id": sent[0]["id"], "nonce": "n"}
            raise ConnectionError("disconnected")

        async def close():
            session.state = "closed"

        session.channel.send_json, session.channel.receive_json, session.close = send, receive, close
        with pytest.raises(RequestOutcomeUnknown if submitted else ConnectionError):
            await session.request("order.read", resource="r", customer="c", grant="g")
        assert len(sent) == (2 if submitted else 1)
        assert session.state == "closed"

    asyncio.run(scenario())


def test_challenge_cannot_pretend_an_action_was_executed(bundle):
    async def scenario():
        adapter = SimpleNamespace(profile="pcm", send=lambda *a: None)
        session = VoiceSession(
            audio=adapter,
            identity=Identity.load(bundle),
            trust=bundle / "root.pem",
            expected_peer="desk.demo",
        )
        session.state = "verified"
        sent = []

        async def send(message):
            sent.append(message)

        async def receive():
            return {
                "v": 1,
                "type": "response",
                "id": sent[0]["id"],
                "result": "allowed",
                "reason": "pretend",
                "data": {},
            }

        async def close():
            session.state = "closed"

        session.channel.send_json, session.channel.receive_json, session.close = send, receive, close
        with pytest.raises(ProtocolError):
            await session.request("order.read", resource="r", customer="c", grant="g")
        assert len(sent) == 1 and session.state == "closed"

    asyncio.run(scenario())


def test_modem_bursts_preempt_speech_without_mixing_and_cancel_cleanly():
    async def scenario():
        scheduler = AudioScheduler()
        speech = asyncio.create_task(scheduler.send(np.full(480, 1000, np.int16), "speech"))
        await asyncio.sleep(0)
        assert np.all(scheduler.take()[0] == 1000)
        bursts = [
            asyncio.create_task(scheduler.send(np.full(320, v, np.int16), "modem")) for v in (2000, 3000)
        ]
        await asyncio.sleep(0)
        heard = []
        for _ in range(8):
            pcm, done = scheduler.take()
            heard.append(int(pcm[0]))
            scheduler.delivered(done)
            await asyncio.sleep(0.001)
        await asyncio.gather(speech, *bursts)
        assert heard[:4] == [2000, 2000, 3000, 3000]
        assert heard[4:6] == [1000, 1000]
        pending = asyncio.create_task(scheduler.send(np.ones(320, np.int16)))
        await asyncio.sleep(0)
        pending.cancel()
        await asyncio.gather(pending, return_exceptions=True)
        assert not scheduler.pending["speech"] and not scheduler.futures
        scheduler.close()

    asyncio.run(scenario())


def test_sdk_logs_omit_application_contents(bundle):
    events = []
    session = VoiceSession(
        audio=SimpleNamespace(profile="pcm", send=lambda *a: None),
        identity=Identity.load(bundle),
        trust=bundle / "root.pem",
        expected_peer="desk.demo",
        log=lambda *a, **k: events.append(k),
    )
    session._safe_log(
        "protected_message_tx", message={"grant": "secret", "data": "private"}, reason="secret", bytes=2
    )
    assert events == [{"bytes": 2}]


def test_policy_is_required_and_wire_versions_are_strict():
    with pytest.raises(ValueError):
        Gateway(None)
    with pytest.raises(ProtocolError):
        Request.parse(
            {
                "v": True,
                "type": "request",
                "id": "r",
                "action": "a",
                "resource": "r",
                "customer": "c",
                "arguments": {},
                "nonce": "n",
                "grant": "g",
            }
        )


def test_queued_response_survives_disconnect_but_future_reads_fail_promptly():
    async def scenario():
        channel = AudioTLS(SimpleNamespace(), lambda *a: None, lambda *a, **k: None)
        channel.messages.put_nowait({"result": "allowed"})
        channel.fail(ConnectionError("closed"))
        assert await channel.receive_json() == {"result": "allowed"}
        for _ in range(2):
            with pytest.raises(ConnectionError):
                await asyncio.wait_for(channel.receive_json(), 0.1)
        full = AudioTLS(SimpleNamespace(), lambda *a: None, lambda *a, **k: None)
        for _ in range(32):
            full.messages.put_nowait({})
        full.fail(ConnectionError("overload"))
        with pytest.raises(ConnectionError):
            await asyncio.wait_for(full.receive_json(), 0.1)

    asyncio.run(scenario())


def test_audio_input_capacity_fails_before_ack_or_unbounded_buffer():
    incoming = SimpleNamespace(pending=65536)
    channel = AudioTLS(SimpleNamespace(incoming=incoming), lambda *a: None, lambda *a, **k: None)
    from openavt import protocol

    channel.receive_frame(0, protocol.DATA, b"oversize")
    assert isinstance(channel.error, ValueError)
    assert not channel.ack_tasks


def test_request_cancellation_closes_and_never_retries(bundle):
    async def scenario():
        session = VoiceSession(
            audio=SimpleNamespace(profile="pcm", send=lambda *a: None),
            identity=Identity.load(bundle),
            trust=bundle / "root.pem",
            expected_peer="desk.demo",
        )
        session.state = "verified"
        blocked = asyncio.Event()

        async def send(message):
            blocked.set()
            await asyncio.Future()

        async def close():
            session.state = "closed"

        session.channel.send_json, session.close = send, close
        task = asyncio.create_task(session.request("order.read", resource="r", customer="c", grant="g"))
        await blocked.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert session.state == "closed"

    asyncio.run(scenario())

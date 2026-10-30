"""Real QUIC over modem samples, lossy calls and the existing authorization SDK."""

import asyncio
import ssl
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

import numpy as np
import pytest

pytest.importorskip("aioquic")

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtendedKeyUsageOID

from openavt import Gateway, Identity, VoiceSession, pcm, protocol
from openavt.datagram import FRAGMENT, MTU, AudioDatagrams
from openavt.demos.sdk import CASES, run
from openavt.pki import issue_certificates
from openavt.quic import ALPN, AudioQUIC
from openavt.session import RequestOutcomeUnknown
from openavt.transports.impaired import ImpairedAudio


class MemoryAudio:
    """Only samples cross this boundary; exercise the session's real decoder."""

    def __init__(self, profile):
        self.profile, self.started = profile, asyncio.Event()
        self.closed = False
        self.tamper = False
        self.tampered = 0
        self.gate = None
        self.wire = bytearray()

    async def start(self, receive, disconnected):
        self.receive, self.disconnected = receive, disconnected
        self.started.set()

    async def send(self, samples, kind="modem"):
        await self.peer.started.wait()
        if self.closed:
            raise ConnectionError("audio closed")
        if self.gate:
            await self.gate.wait()
        if self.profile == "pcm" and kind == "modem":
            frames = pcm.StreamDecoder().feed(samples)
            assert len(frames) <= 1
            if frames:
                sequence, frame_kind, payload = frames[0]
                assert frame_kind == protocol.QUIC  # No stop-and-wait DATA / ACK frames.
                self.wire.extend(payload)
            if self.tamper and frames:
                self.tamper = False
                self.tampered += 1
                # Modify ciphertext, then recompute a valid audio CRC. QUIC's
                # packet protection must detect this independently of framing.
                damaged = payload[:-1] + bytes([payload[-1] ^ 1])
                samples = pcm.encode(protocol.frame(sequence, frame_kind, damaged))
        for start in range(0, len(samples), 211):
            self.peer.receive(np.asarray(samples[start : start + 211], dtype=np.int16))
            await asyncio.sleep(0)

    async def close(self):
        self.closed = True

    def summary(self):
        return {"data_channel": False}


@pytest.fixture
def bundle(tmp_path):
    issue_certificates(tmp_path, rogue=False)
    return tmp_path


@asynccontextmanager
async def sessions(bundle, *, profile="pcm", loss=False, fault=None):
    if fault in {"expired_client", "expired_server", "server_purpose"}:
        name = "agent" if fault == "expired_client" else "desk"
        certificate = x509.load_pem_x509_certificate((bundle / f"{name}.pem").read_bytes())
        root = x509.load_pem_x509_certificate((bundle / "root.pem").read_bytes())
        key = serialization.load_pem_private_key((bundle / "root.key").read_bytes(), None)
        now = datetime.now(timezone.utc)
        builder = (
            x509.CertificateBuilder()
            .subject_name(certificate.subject)
            .issuer_name(root.subject)
            .public_key(certificate.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=2))
            .not_valid_after(
                now - timedelta(days=1) if fault.startswith("expired") else now + timedelta(days=1)
            )
        )
        for extension in certificate.extensions:
            value = extension.value
            if fault == "server_purpose" and isinstance(value, x509.ExtendedKeyUsage):
                value = x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH])
            builder = builder.add_extension(value, critical=extension.critical)
        (bundle / f"{name}.pem").write_bytes(
            builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)
        )
    a, b = MemoryAudio(profile), MemoryAudio(profile)
    a.peer, b.peer = b, a
    caller = VoiceSession(
        audio=ImpairedAudio(a) if loss else a,
        identity=Identity.load(bundle, name="desk" if fault == "client_purpose" else "agent"),
        trust=bundle / "root.pem",
        expected_peer="attacker.example" if fault == "hostname" else "desk.demo",
        protocol="quic",
        profile=profile,
        handshake_timeout=5,
    )
    desk = VoiceSession(
        audio=b,
        identity=Identity.load(bundle, name="desk"),
        trust=bundle / "root.pem",
        protocol="quic",
        profile=profile,
        server=True,
        handshake_timeout=5,
    )
    if fault == "missing_client":
        caller.channel.configuration.certificate = None
    if fault == "client_key_proof":
        caller.channel.configuration.private_key = desk.channel.configuration.private_key
    try:
        results = await asyncio.gather(caller.__aenter__(), desk.__aenter__(), return_exceptions=True)
        if any(isinstance(r, BaseException) for r in results):
            assert caller.state != "verified"
            raise next(r for r in results if isinstance(r, BaseException))
        yield caller, desk, a, b
    finally:
        await asyncio.gather(caller.close(), desk.close())


class Policy:
    def __init__(self):
        self.used = set()

    async def challenge(self, peer):
        assert peer
        return "fresh-challenge"

    async def authorize(self, peer, request):
        assert peer
        if request.action != "order.read" or request.grant in self.used:
            raise PermissionError()
        self.used.add(request.grant)
        return {"scope": ["order.read"]}


def gateway():
    result = Gateway(Policy())

    def validate(request):
        if request.arguments:
            raise ValueError()

    async def read(request, claims):
        assert claims["scope"] == ["order.read"]
        return {"status": "shipped"}

    result.register("order.read", validate=validate, handler=read)
    return result


@pytest.mark.parametrize("profile,loss", [("pcm", False), ("pcm", True), ("voiceband", False)])
def test_authenticated_requests_and_policy_survive_audio_loss(bundle, profile, loss):
    async def scenario():
        async with sessions(bundle, profile=profile, loss=loss) as (caller, desk, a, _b):
            business = gateway()
            serving = asyncio.create_task(business.serve(desk, limit=3))
            options = dict(resource="order-1", customer="alice", grant="never-spoken-private-grant")
            assert (await caller.request("order.read", **options))["data"] == {"status": "shipped"}
            assert (await caller.request("order.read", **options))["result"] == "denied"
            assert (await caller.request("payment.create", **options))["reason"] == "unsupported_action"
            await serving
            assert business.summary() == {"requests": 3, "handler_executions": 1, "denials": 2}
            assert caller.peer_certificate and desk.peer_certificate
            assert caller.summary()["protocol"] == "quic"
            assert caller.summary()["alpn"] == ALPN
            assert not caller.summary()["link_acknowledgments"]
            assert not caller.summary()["session_reused"]
            assert desk.risk_context.authenticated
            assert b"never-spoken-private-grant" not in a.wire
            if loss:
                assert caller.audio.dropped and caller.audio.corrupted and caller.audio.duplicated
                assert desk.decoder.bad_frames > 0
                assert caller.summary()["quic_timer_firings"] > 0

    asyncio.run(scenario())


def test_valid_audio_crc_does_not_hide_ciphertext_tampering(bundle):
    async def scenario():
        async with sessions(bundle) as (caller, desk, a, _b):
            a.tamper = True
            business = gateway()
            serving = asyncio.create_task(business.serve(desk, limit=1))
            response = await caller.request("order.read", resource="r", customer="c", grant="secret")
            await serving
            assert response["result"] == "allowed" and business.executions == 1
            assert a.tampered == 1 and desk.decoder.bad_frames == 0
            assert caller.summary()["quic_timer_firings"] > 0

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "fault",
    [
        "hostname",
        "missing_client",
        "client_purpose",
        "client_key_proof",
        "expired_client",
        "expired_server",
        "server_purpose",
    ],
)
def test_mutual_authentication_rejects_invalid_peers_before_client_ready(bundle, fault):
    async def scenario():
        with pytest.raises((ssl.SSLError, ConnectionError, TimeoutError)):
            async with sessions(bundle, fault=fault):
                pytest.fail("invalid peer was accepted")

    asyncio.run(scenario())


def test_self_signed_client_is_rejected(tmp_path):
    issue_certificates(tmp_path, rogue=True)

    async def scenario():
        with pytest.raises((ssl.SSLError, ConnectionError, TimeoutError)):
            async with sessions(tmp_path):
                pytest.fail("untrusted client was accepted")

    asyncio.run(scenario())


def test_mismatched_local_private_key_fails_before_call(bundle):
    with pytest.raises(ValueError, match="do not match"):
        AudioQUIC(
            Identity(bundle / "agent.pem", bundle / "desk.key"),
            bundle / "root.pem",
            lambda *_: None,
            lambda *_: None,
            server_hostname="desk.demo",
        )


def test_datagram_reassembly_accepts_reordering_duplicates_and_sequence_gaps():
    sender, receiver = AudioDatagrams(256), AudioDatagrams(256)
    first, second = bytes(range(256)) * 4, b"next independent datagram"
    frames = [protocol.unframe(f) for f in sender.frame(first)]
    assert receiver.receive(*frames[2]) is None
    assert receiver.receive(*frames[2]) is None
    # An incomplete earlier datagram cannot block the next one.
    assert receiver.receive(*protocol.unframe(sender.frame(second)[0])) == second
    complete = [receiver.receive(*frame) for frame in (frames[3], frames[0], frames[1], frames[4])]
    assert complete[-1] == first


def test_reassembly_is_bounded_expires_and_rejects_invalid_fragments(monkeypatch):
    now = [0.0]
    monkeypatch.setattr("openavt.datagram.time.monotonic", lambda: now[0])
    sender, receiver = AudioDatagrams(256), AudioDatagrams(256, lifetime=5)
    for _ in range(100):
        receiver.receive(*protocol.unframe(sender.frame(b"x" * MTU)[0]))
    assert len(receiver.pending) == 16 and receiver.discarded == 84
    now[0] = 6
    receiver.receive(0, protocol.ACK, b"")
    assert not receiver.pending
    for header in ((0, 0, 1200), (0, 1, 1201), (5, 5, 1200), (0, 5, 1200)):
        assert receiver.receive(42, protocol.QUIC, FRAGMENT.pack(*header) + b"x") is None
    assert not receiver.pending
    for data in (b"", b"x" * (MTU + 1)):
        with pytest.raises(ValueError):
            sender.frame(data)


@pytest.mark.parametrize("transport,loss", [("webrtc", False), ("webrtc", True), ("twilio-emulated", True)])
def test_independent_quic_workers_over_real_audio(tmp_path, transport, loss):
    report = asyncio.run(run(tmp_path, transport=transport, protocol="quic", loss=loss))
    assert report["verified"] and not report["provider_network_verified"]
    assert report["caller"]["pid"] != report["business"]["pid"]
    assert tuple(r["case"] for r in report["caller"]["results"]) == CASES
    assert report["business"]["gateway"] == {"requests": 8, "handler_executions": 1, "denials": 7}
    for role in ("caller", "business"):
        assert report[role]["sdk"]["state"] == "verified"
        assert report[role]["sdk"]["error"] is None
        assert report[role]["sdk"]["protocol"] == "quic"
        assert report[role]["sdk"]["link_acknowledgments"] is False
        if transport == "webrtc":
            assert report[role]["audio"]["data_channel"] is False
        else:
            assert report[role]["audio"]["transport"] == "twilio-media-streams"
        if loss:
            assert report[role]["audio"]["impairment"]["dropped"] > 0


def test_disconnect_after_submission_keeps_outcome_unknown(bundle):
    async def scenario():
        async with sessions(bundle) as (caller, desk, _a, _b):
            serving = asyncio.create_task(gateway().serve(desk, limit=1))
            send = desk.channel.send_json

            async def disconnect(message):
                if message["type"] == "response":
                    caller._disconnected(ConnectionError("call lost after execution"))
                    return
                await send(message)

            desk.channel.send_json = disconnect
            with pytest.raises(RequestOutcomeUnknown):
                await caller.request("order.read", resource="r", customer="c", grant="secret")
            await serving
            assert caller.state == "closed"

    asyncio.run(scenario())


def test_large_messages_obey_flow_control_and_send_buffer_bounds(bundle):
    async def scenario():
        async with sessions(bundle) as (caller, desk, _a, _b):
            message = {"data": "x" * 65000}
            for _ in range(2):
                _, received = await asyncio.gather(
                    caller.channel.send_json(message),
                    desk.channel.receive_json(),
                )
                assert received == message
            assert caller.channel.connection.stream_bytes_acked > 130000
            with pytest.raises(ValueError, match="size limit"):
                await caller.channel.send_json({"data": "x" * 65536})

    asyncio.run(scenario())


def test_authenticated_non_object_and_oversized_input_fail_closed(bundle):
    async def scenario(raw):
        async with sessions(bundle) as (caller, desk, _a, _b):
            caller.channel.connection.send_stream_data(0, raw)
            caller.channel.new_data.set()
            with pytest.raises(ValueError):
                await desk.channel.receive_json()
            assert desk.channel.error and not desk.risk_context.authenticated

    asyncio.run(scenario(b"[]\n"))
    asyncio.run(scenario(b"x" * 65536))


def test_pap_permissions_and_risk_monitor_over_lossy_quic(tmp_path):
    from openavt.demos.pap import run as pap_run

    report = asyncio.run(pap_run(tmp_path, protocol="quic", loss=True))
    assert report["verified"] and report["protocol"] == "quic"
    assert report["audio_session"]["link_acknowledgments"] is False
    assert report["authenticated_risk_block"] and report["signed_out_grant_denied"]
    assert report["https_confirmation_effects"] == 1


def test_drain_waits_for_final_audio_ack_playback(bundle):
    async def scenario():
        async with sessions(bundle) as (caller, desk, a, _b):
            await asyncio.gather(caller.channel.send_json({"open": True}), desk.channel.receive_json())
            await asyncio.gather(caller.channel.drain(), desk.channel.drain())
            a.gate = asyncio.Event()
            sending = asyncio.create_task(desk.channel.send_json({"final": "response"}))
            assert await caller.channel.receive_json() == {"final": "response"}
            draining = asyncio.create_task(caller.channel.drain())
            await asyncio.sleep(0.05)
            assert not draining.done() and not sending.done()
            a.gate.set()
            await asyncio.wait_for(asyncio.gather(draining, sending), 2)

    asyncio.run(scenario())

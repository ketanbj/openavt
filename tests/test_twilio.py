"""Provider wire format, signed ingress, playback and failure boundaries."""

import asyncio
import base64
from types import SimpleNamespace
from unittest.mock import Mock

import numpy as np
import pytest
from aiohttp import ClientSession, WSServerHandshakeError, web
from twilio.request_validator import RequestValidator

from openavt import pcm, protocol
from openavt.demos.twilio_bridge import ProviderBridge
from openavt.transports.twilio import TwilioAdapter, TwilioConfig, TwilioIngress, decode_mulaw, encode_mulaw

ACCOUNT = "AC" + "0" * 32
STREAM = "MZ" + "1" * 32


def config():
    return TwilioConfig(ACCOUNT, "private-token", "+12025550101", "+12025550102", "https://voice.example")


def start(sequence=1):
    return {
        "event": "start",
        "sequenceNumber": str(sequence),
        "streamSid": STREAM,
        "start": {
            "accountSid": ACCOUNT,
            "streamSid": STREAM,
            "callSid": "CA" + "2" * 32,
            "tracks": ["inbound"],
            "mediaFormat": {"encoding": "audio/x-mulaw", "sampleRate": 8000, "channels": 1},
        },
    }


def test_pcm_modem_survives_mulaw_encoding_at_arbitrary_packet_boundaries():
    wire = protocol.frame(7, protocol.DATA, bytes(range(256)))
    audio = np.concatenate((np.zeros(137, np.int16), pcm.encode(wire), np.zeros(320, np.int16)))
    decoded = decode_mulaw(encode_mulaw(audio))
    decoder, frames = pcm.StreamDecoder(), []
    for i in range(0, len(decoded), 73):
        frames += decoder.feed(decoded[i : i + 73])
    assert frames == [(7, protocol.DATA, bytes(range(256)))]
    assert decoder.bad_frames == 0
    assert base64.b64decode(encode_mulaw(np.array([0, 32124, -32124], np.int16))) == bytes([255, 128, 0])


@pytest.mark.parametrize("payload", ["", "!!!", "A" * 22001, base64.b64encode(b"x" * 16001).decode()])
def test_invalid_or_oversized_audio_is_rejected(payload):
    with pytest.raises(ValueError):
        decode_mulaw(payload)


@pytest.mark.parametrize(
    "field,value",
    [
        ("accountSid", "AC" + "3" * 32),
        ("tracks", ["outbound"]),
        ("streamSid", "MZ" + "4" * 32),
        ("mediaFormat", {"encoding": "audio/opus", "sampleRate": 48000, "channels": 1}),
    ],
)
def test_wrong_account_stream_track_or_codec_is_rejected(field, value):
    adapter = TwilioAdapter(None, account_sid=ACCOUNT)
    event = start()
    event["start"][field] = value
    with pytest.raises(ValueError):
        adapter.event(event)
    assert not adapter.started.is_set()


def test_audio_timeline_sequence_and_stream_are_checked():
    adapter = TwilioAdapter(None, account_sid=ACCOUNT)
    samples = []
    adapter.receive = samples.append
    adapter.event(start())
    message = {
        "event": "media",
        "sequenceNumber": "2",
        "streamSid": STREAM,
        "media": {"track": "inbound", "timestamp": "20", "payload": encode_mulaw(np.ones(160, np.int16))},
    }
    adapter.event(message)
    assert [len(x) for x in samples] == [160, 160]
    with pytest.raises(ValueError):
        adapter.event(message)
    with pytest.raises(ValueError):
        adapter.event({**message, "sequenceNumber": "3", "streamSid": "other"})
    with pytest.raises(ValueError):
        adapter.event({**message, "sequenceNumber": "4", "media": {**message["media"], "timestamp": "0"}})


def test_playback_mark_completes_only_its_waveform_and_stop_releases_waiters():
    async def scenario():
        adapter = TwilioAdapter(None, account_sid=ACCOUNT)
        adapter.event(start())
        send = asyncio.create_task(adapter.send(np.ones(160, np.int16)))
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        _, future = adapter.scheduler.take()
        adapter.marks["my-mark"] = future
        adapter.event(
            {"event": "mark", "sequenceNumber": "2", "streamSid": STREAM, "mark": {"name": "unrelated"}}
        )
        assert not send.done()
        adapter.event(
            {"event": "mark", "sequenceNumber": "3", "streamSid": STREAM, "mark": {"name": "my-mark"}}
        )
        await send
        assert adapter.mark_acks == 1
        pending = asyncio.create_task(adapter.send(np.ones(160, np.int16)))
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        adapter.event({"event": "stop", "sequenceNumber": "4", "streamSid": STREAM})
        with pytest.raises(ConnectionError):
            await asyncio.wait_for(pending, 0.2)

    asyncio.run(scenario())


def test_missing_playback_ack_fails_closed():
    async def scenario():
        adapter = TwilioAdapter(None, account_sid=ACCOUNT, playback_timeout=0.01)
        adapter.event(start())
        with pytest.raises(TimeoutError):
            await adapter.send(np.ones(1, np.int16))
        assert adapter.error and adapter.scheduler.closed
        with pytest.raises(ConnectionError):
            await adapter.send(np.ones(1, np.int16))

    asyncio.run(scenario())


def test_http_and_websocket_ingress_require_signatures_for_configured_origin():
    async def scenario():
        cfg = config()
        entered = asyncio.Event()

        async def on_stream(role, ws):
            assert role == "agent"
            entered.set()
            async for _ in ws:
                pass

        ingress = TwilioIngress(cfg, on_stream)
        runner = web.AppRunner(ingress.application())
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        base = f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}"
        signer = RequestValidator(cfg.auth_token)
        try:
            async with ClientSession() as client:
                params = {"AccountSid": ACCOUNT, "CallSid": "CA" + "2" * 32, "FutureField": "preserved"}
                signature = signer.compute_signature(cfg.url("/voice/agent"), params)
                headers = {"X-Twilio-Signature": signature, "Host": "attacker.example"}
                response = await client.post(base + "/voice/agent", data=params, headers=headers)
                assert response.status == 200
                assert "wss://voice.example/stream/agent" in await response.text()
                for path, data, hdrs in [
                    ("/voice/agent", {**params, "FutureField": "tampered"}, headers),
                    ("/voice/agent?x=1", params, headers),
                    ("/voice/agent", params, {}),
                ]:
                    assert (await client.post(base + path, data=data, headers=hdrs)).status == 403
                with pytest.raises(WSServerHandshakeError) as failed:
                    await client.ws_connect(base + "/stream/agent")
                assert failed.value.status == 403
                ws_signature = signer.compute_signature(cfg.url("/stream/agent", websocket=True), {})
                ws_headers = {"X-Twilio-Signature": ws_signature}
                async with client.ws_connect(base + "/stream/agent", headers=ws_headers):
                    await asyncio.wait_for(entered.wait(), 1)
                    with pytest.raises(WSServerHandshakeError) as duplicate:
                        await client.ws_connect(base + "/stream/agent", headers=ws_headers)
                    assert duplicate.value.status == 409
                await asyncio.sleep(0.05)
                assert not ingress.active
        finally:
            await runner.cleanup()

    asyncio.run(scenario())


def test_configuration_is_optional_and_never_prints_token(monkeypatch):
    for name in (
        "TWILIO_ACCOUNT_SID",
        "TWILIO_AUTH_TOKEN",
        "TWILIO_CALLER_NUMBER",
        "TWILIO_BUSINESS_NUMBER",
        "TWILIO_PUBLIC_BASE_URL",
    ):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(ValueError, match="TWILIO_ACCOUNT_SID"):
        TwilioConfig.from_env()
    assert "private-token" not in repr(config())
    assert config().url("/stream/desk", websocket=True).startswith("wss://")
    with pytest.raises(ValueError):
        TwilioConfig(ACCOUNT, "secret", "+12025550101", "+12025550102", "http://voice.example")


def test_live_call_only_dials_owned_numbers_once_and_uses_bounded_duration(monkeypatch):
    client = Mock()
    client.incoming_phone_numbers.list.return_value = [
        SimpleNamespace(voice_url=config().url("/voice/desk"), voice_method="POST")
    ]
    factory = Mock(return_value=client)
    monkeypatch.setattr("twilio.rest.Client", factory)
    bridge = ProviderBridge()
    bridge.config = config()
    bridge._place_owned_call()
    call_options = client.calls.create.call_args.kwargs
    assert call_options["record"] is False and call_options["time_limit"] == 180
    assert client.calls.create.call_count == 1
    client.calls.create.side_effect = RuntimeError("secret-provider-failure")
    with pytest.raises(RuntimeError, match="provider console") as error:
        bridge._place_owned_call()
    assert "secret" not in str(error.value)
    assert client.calls.create.call_count == 2
    client.incoming_phone_numbers.list.return_value = []
    with pytest.raises(ValueError, match="owned"):
        bridge._place_owned_call()
    assert client.calls.create.call_count == 2

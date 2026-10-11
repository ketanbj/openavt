"""Digital G.711 preservation, stream recovery, and unchanged TLS security."""

import asyncio
import ssl
from fractions import Fraction

import av
import numpy as np
import pytest
from aiortc.codecs.g711 import PcmuDecoder, PcmuEncoder
from aiortc.jitterbuffer import JitterFrame

from openavt import pcm, pki, protocol
from openavt.demos.live import run
from openavt.tls import Endpoint
from openavt.transports.webrtc import AudioCall


def decode_audio(audio, chunk=73):
    decoder = pcm.StreamDecoder()
    frames = []
    for offset in range(0, len(audio), chunk):
        frames.extend(decoder.feed(audio[offset : offset + chunk]))
    return decoder, frames


@pytest.mark.parametrize("offset,chunk", [(1, 1), (137, 160), (999, 211)])
def test_pcm_arbitrary_boundaries_and_maximum_frame(offset, chunk):
    payload = bytes(range(256)) * 16
    audio = np.concatenate(
        (np.zeros(offset, dtype=np.int16), pcm.encode(protocol.frame(4, protocol.DATA, payload)))
    )
    decoder, frames = decode_audio(audio, chunk)
    assert frames == [(4, protocol.DATA, payload)]
    assert decoder.bad_frames == 0
    # The voice-band parser still enforces its original smaller limit.
    with pytest.raises(protocol.FrameError):
        protocol.unframe(protocol.frame(4, protocol.DATA, payload))


def test_native_g711_preserves_every_modem_level_and_frame():
    payload = bytes(range(256)) * 16
    waveform = pcm.encode(protocol.frame(1, protocol.DATA, payload))
    samples = np.concatenate((pcm.LEVELS, np.zeros(35, dtype=np.int16), waveform))
    samples = np.pad(samples, (0, (-len(samples)) % 160))
    encoder, decoder = PcmuEncoder(), PcmuDecoder()
    received = []
    for offset in range(0, len(samples), 160):
        frame = av.AudioFrame(format="s16", layout="mono", samples=160)
        frame.planes[0].update(samples[offset : offset + 160].astype("<i2").tobytes())
        frame.sample_rate, frame.pts, frame.time_base = 8000, offset, Fraction(1, 8000)
        packets, timestamp = encoder.encode(frame)
        assert len(packets) == 1 and len(packets[0]) == 160  # 64 kbps codec payload
        for packet in packets:
            received.extend(
                pcm.to_ndarray().reshape(-1) for pcm in decoder.decode(JitterFrame(packet, timestamp))
            )
    received = np.concatenate(received)
    assert np.array_equal(received, samples)
    assert decode_audio(received)[1] == [(1, protocol.DATA, payload)]


@pytest.mark.parametrize("damage", ["level", "crc", "length"])
def test_pcm_rejects_damage_and_resynchronizes(damage):
    raw = bytearray(protocol.frame(0, protocol.DATA, b"damaged"))
    if damage == "crc":
        raw[-1] ^= 1
    elif damage == "length":
        raw[len(protocol.PREAMBLE) + 5 : len(protocol.PREAMBLE) + 7] = b"\xff\xff"
    audio = pcm.encode(bytes(raw))
    if damage == "level":
        audio[len(pcm.PREFIX) + pcm._sample_count(pcm.HEADER_BYTES) + 2] = 0
    audio = np.concatenate((audio, pcm.encode(protocol.frame(0, protocol.DATA, b"retry"))))
    decoder, frames = decode_audio(audio)
    assert frames == [(0, protocol.DATA, b"retry")]
    assert decoder.bad_frames >= 1


def test_pcm_rejects_silence_noise_and_processed_samples():
    random = np.random.default_rng(18)
    audio = np.concatenate(
        (
            np.zeros(4000),
            random.integers(-32768, 32768, 4000),
            pcm.encode(protocol.frame(0, protocol.DATA, b"data")) * 0.6,
        )
    )
    decoder, frames = decode_audio(audio)
    assert frames == []
    assert len(decoder.buffer) < len(pcm.PREFIX)


def deliver(sender, receiver, wire=None):
    wire = sender.outgoing.read() if wire is None else wire
    if wire:
        frames = decode_audio(pcm.encode(protocol.frame(0, protocol.DATA, wire)))[1]
        assert len(frames) == 1
        receiver.incoming.write(frames[0][2])


@pytest.mark.parametrize("attack", ["tamper", "replay"])
def test_tls_rejects_attacks_even_with_valid_pcm_crc(tmp_path, attack):
    pki.issue_certificates(tmp_path, rogue=False)
    agent, desk = pki.endpoints(tmp_path)
    for _ in range(10):
        for sender, receiver in ((agent, desk), (desk, agent)):
            if not sender.ready:
                try:
                    sender.tls.do_handshake()
                    sender.ready = True
                except ssl.SSLWantReadError:
                    pass
            deliver(sender, receiver)
        if agent.ready and desk.ready:
            break
    assert agent.ready and desk.ready
    assert not agent.tls.session_reused and not desk.tls.session_reused
    assert desk.tls.getpeercert()["subjectAltName"] == (("URI", "urn:demo:agent:assistant"),)
    agent.tls.write(b"protected request")
    wire = agent.outgoing.read()
    if attack == "tamper":
        wire = wire[:-1] + bytes([wire[-1] ^ 1])
    else:
        deliver(agent, desk, wire)
        assert desk.tls.read(16384) == b"protected request"
    deliver(agent, desk, wire)
    with pytest.raises(ssl.SSLError):
        desk.tls.read(16384)


@pytest.mark.parametrize("scenario", ["valid", "scope", "loss", "untrusted"])
def test_live_pcm_scenarios(tmp_path, scenario):
    report = asyncio.run(run(tmp_path, scenario, True, "PCMU", "pcm"))
    assert report["verified"]
    assert not report["llm_agents_executed"]
    assert all(not item["session_reused"] for item in report["tls"].values())
    if scenario == "loss":
        assert report["tls"]["agent"]["retries"] == 2
        assert report["tls"]["desk"]["duplicates_suppressed"] == 1
    elif scenario == "untrusted":
        assert report["tls"]["desk"]["error"] == "SSLCertVerificationError"
        assert report["tls"]["desk"]["messages_rx"] == 0
    else:
        assert all(item["retries"] == 0 for item in report["tls"].values())


def test_pcm_refuses_lossy_codec(tmp_path):
    with pytest.raises(ValueError, match="PCMU"):
        AudioCall(tmp_path, lambda *args, **kwargs: None, "opus", profile="pcm")


def test_live_pcm_client_without_certificate_is_rejected(tmp_path, monkeypatch):
    from openavt.demos import live

    def anonymous_endpoints(directory):
        _, desk = pki.endpoints(directory)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.load_verify_locations(str(directory / "root.pem"))
        context.set_ecdh_curve("prime256v1")
        return Endpoint("agent", context, server_hostname="desk.demo"), desk

    monkeypatch.setattr(live, "endpoints", anonymous_endpoints)
    with pytest.raises(ssl.SSLError):
        asyncio.run(asyncio.wait_for(run(tmp_path, "valid", True, "PCMU", "pcm"), 10))
    import json

    report = json.loads((tmp_path / "report.json").read_text())
    assert not report["verified"]
    assert report["tls"]["desk"]["error"] == "SSLError"
    assert report["tls"]["desk"]["messages_rx"] == 0

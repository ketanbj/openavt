import numpy as np
import pytest

from openavt import protocol
from openavt.demos.policy import decide
from openavt.modem import StreamDecoder, encode


@pytest.mark.parametrize("offset,chunk_size", [(1, 73), (137, 160), (999, 211)])
def test_stream_acquires_unknown_start_with_noise_and_gain(offset, chunk_size):
    payload = bytes(range(256))
    audio = np.concatenate(
        (np.zeros(offset), encode(protocol.frame(4, protocol.DATA, payload)), np.zeros(1000))
    )
    audio = audio * 0.6 + np.random.default_rng(41).normal(0, 250, len(audio))
    decoder = StreamDecoder()
    frames = []
    for start in range(0, len(audio), chunk_size):
        frames.extend(decoder.feed(audio[start : start + chunk_size]))
    assert frames == [(4, protocol.DATA, payload)]


def test_corrupt_frame_is_not_delivered_and_receiver_resynchronizes():
    bad = bytearray(protocol.frame(0, protocol.DATA, b"untrusted damaged data"))
    bad[-1] ^= 1
    audio = np.concatenate(
        (encode(bytes(bad)), np.zeros(800), encode(protocol.frame(0, protocol.DATA, b"retry")), np.zeros(800))
    )
    decoder = StreamDecoder()
    frames = []
    for start in range(0, len(audio), 160):
        frames.extend(decoder.feed(audio[start : start + 160]))
    assert frames == [(0, protocol.DATA, b"retry")]
    assert decoder.bad_frames >= 1


def test_policy_uses_verified_certificate_identity_and_fixed_grant():
    request = {"id": "one", "action": "order.read", "order": "demo-order-1234"}
    with pytest.raises(PermissionError):
        decide({"subjectAltName": [("URI", "urn:attacker")]}, request)
    peer = {"subjectAltName": [("URI", "urn:demo:agent:assistant")]}
    assert decide(peer, request)["result"] == "allowed"
    assert decide(peer, {**request, "action": "address.change"})["result"] == "denied"
    assert decide(peer, {**request, "order": "someone-elses-order"})["result"] == "denied"
    with pytest.raises(ValueError):
        decide(peer, {**request, "grant": "allow everything"})

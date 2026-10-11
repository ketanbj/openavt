"""Voice-band FSK waveform, framing, and PCM WAV helpers (standard library only)."""

from __future__ import annotations

import array
import math
import struct
import sys
import wave
import zlib
from pathlib import Path

RATE = 8000
BAUD = 1000
SAMPLES_PER_BIT = RATE // BAUD
PREAMBLE = b"\x55" * 12 + b"TOV1"
HEADER = struct.Struct("!IBH")  # sequence, kind, payload length
DATA, ACK = 1, 2
MAX_PAYLOAD = 256
TONES = tuple(
    tuple(int(14000 * math.sin(2 * math.pi * frequency * n / RATE)) for n in range(SAMPLES_PER_BIT))
    for frequency in (1000, 2000)
)


class FrameError(ValueError):
    pass


def frame(sequence: int, kind: int, payload: bytes = b"") -> bytes:
    body = HEADER.pack(sequence, kind, len(payload)) + payload
    return PREAMBLE + body + struct.pack("!I", zlib.crc32(body))


def unframe(raw: bytes) -> tuple[int, int, bytes]:
    if not raw.startswith(PREAMBLE):
        raise FrameError("preamble mismatch")
    body = raw[len(PREAMBLE) : -4]
    if len(body) < HEADER.size or len(raw) < len(PREAMBLE) + HEADER.size + 4:
        raise FrameError("truncated frame")
    if struct.pack("!I", zlib.crc32(body)) != raw[-4:]:
        raise FrameError("CRC mismatch")
    sequence, kind, length = HEADER.unpack(body[: HEADER.size])
    payload = body[HEADER.size :]
    if length != len(payload) or length > MAX_PAYLOAD or kind not in (DATA, ACK):
        raise FrameError("invalid frame header")
    if kind == ACK and payload:
        raise FrameError("ACK contains payload")
    return sequence, kind, payload


def modulate(raw: bytes) -> array.array:
    samples = array.array("h")
    for byte in raw:
        for bit in range(7, -1, -1):
            samples.extend(TONES[(byte >> bit) & 1])
    return samples


def demodulate(samples: array.array) -> bytes:
    if len(samples) % (8 * SAMPLES_PER_BIT):
        raise FrameError("incomplete audio byte")
    raw = bytearray()
    value = 0
    for start in range(0, len(samples), SAMPLES_PER_BIT):
        symbol = samples[start : start + SAMPLES_PER_BIT]
        scores = [sum(x * reference for x, reference in zip(symbol, tone)) for tone in TONES]
        value = (value << 1) | (scores[1] > scores[0])
        if (start // SAMPLES_PER_BIT) % 8 == 7:
            raw.append(value)
            value = 0
    return bytes(raw)


def write_wav(path: Path, samples: array.array) -> None:
    pcm = array.array("h", samples)
    if sys.byteorder != "little":
        pcm.byteswap()
    with wave.open(str(path), "wb") as output:
        output.setparams((1, 2, RATE, 0, "NONE", "not compressed"))
        output.writeframes(pcm.tobytes())


def read_wav(path: Path) -> array.array:
    with wave.open(str(path), "rb") as source:
        if (source.getnchannels(), source.getsampwidth(), source.getframerate()) != (1, 2, RATE):
            raise FrameError("unexpected WAV format")
        samples = array.array("h", source.readframes(source.getnframes()))
    if sys.byteorder != "little":
        samples.byteswap()
    return samples

"""56 kbps PCM modem for an unchanged, digital 64 kbps G.711 mu-law path.

Seven bits select one of 128 mu-law reconstruction levels per 8 kHz sample.
This profile requires sample preservation, not merely telephone bandwidth.
CRC validates link frames; TLS authenticates recovered bytes.
"""

from __future__ import annotations

import numpy as np

from openavt import protocol

RATE = 8000
BITS_PER_SAMPLE = 7
BITRATE = RATE * BITS_PER_SAMPLE
MAX_PAYLOAD = 4096


def _mulaw(code: int) -> int:
    value = (~code) & 255
    magnitude = (((value & 15) << 3) + 132) << ((value >> 4) & 7)
    return 132 - magnitude if value & 128 else magnitude - 132


# Avoid the duplicate zero level and the loudest quantization segments.
LEVELS = np.array([_mulaw(c) for c in (*range(32, 96), *range(160, 224))], dtype=np.int16)
LOOKUP = np.full(65536, -1, dtype=np.int16)
LOOKUP[LEVELS.astype(np.int32) + 32768] = np.arange(128)
PREFIX = LEVELS[
    [
        74,
        5,
        55,
        38,
        57,
        64,
        43,
        82,
        72,
        0,
        89,
        62,
        126,
        1,
        47,
        98,
        125,
        108,
        7,
        79,
        33,
        112,
        17,
        119,
        103,
        37,
        3,
        29,
        14,
        86,
        31,
        26,
    ]
]
HEADER_BYTES = len(protocol.PREAMBLE) + protocol.HEADER.size


def _sample_count(length: int) -> int:
    return (length * 8 + BITS_PER_SAMPLE - 1) // BITS_PER_SAMPLE


def encode(raw: bytes) -> np.ndarray:
    bits = np.unpackbits(np.frombuffer(raw, dtype=np.uint8))
    bits = np.pad(bits, (0, (-len(bits)) % BITS_PER_SAMPLE)).reshape(-1, BITS_PER_SAMPLE)
    symbols = bits @ (1 << np.arange(BITS_PER_SAMPLE - 1, -1, -1))
    return np.concatenate((PREFIX, LEVELS[symbols], np.zeros(32, dtype=np.int16)))


def _decode(samples: np.ndarray) -> bytes:
    symbols = LOOKUP[samples.astype(np.int32) + 32768]
    if np.any(symbols < 0):
        raise protocol.FrameError("PCM reconstruction level was modified")
    bits = (symbols[:, None] >> np.arange(BITS_PER_SAMPLE - 1, -1, -1)) & 1
    return np.packbits(bits.reshape(-1)).tobytes()


class StreamDecoder:
    """Acquire frames at unknown packet/sample offsets; bound candidate size."""

    def __init__(self):
        self.buffer = np.empty(0, dtype=np.int16)
        self.acquired = False
        self.frame_samples: int | None = None
        self.length = 0
        self.good_frames = self.bad_frames = self.acquisitions = 0

    def feed(self, samples: np.ndarray) -> list[tuple[int, int, bytes]]:
        self.buffer = np.concatenate((self.buffer, np.asarray(samples, dtype=np.int16)))
        frames = []
        while True:
            if not self.acquired:
                if len(self.buffer) < len(PREFIX):
                    break
                candidates = np.flatnonzero(self.buffer[: len(self.buffer) - len(PREFIX) + 1] == PREFIX[0])
                index = next(
                    (int(i) for i in candidates if np.array_equal(self.buffer[i : i + len(PREFIX)], PREFIX)),
                    None,
                )
                if index is None:
                    self.buffer = self.buffer[-(len(PREFIX) - 1) :]
                    break
                self.buffer = self.buffer[index:]
                self.acquired = True
                self.acquisitions += 1
            header_end = len(PREFIX) + _sample_count(HEADER_BYTES)
            if len(self.buffer) < header_end:
                break
            if self.frame_samples is None:
                try:
                    header = _decode(self.buffer[len(PREFIX) : header_end])
                    _, kind, length = protocol.HEADER.unpack(header[len(protocol.PREAMBLE) : HEADER_BYTES])
                    if not header.startswith(protocol.PREAMBLE) or kind not in (protocol.DATA, protocol.ACK):
                        raise protocol.FrameError("invalid PCM header")
                    if length > MAX_PAYLOAD or (kind == protocol.ACK and length):
                        raise protocol.FrameError("invalid PCM payload length")
                    self.length = HEADER_BYTES + length + 4
                    self.frame_samples = len(PREFIX) + _sample_count(self.length)
                except protocol.FrameError:
                    self.bad_frames += 1
                    self.buffer = self.buffer[1:]
                    self.acquired = False
                    continue
            if len(self.buffer) < self.frame_samples:
                break
            try:
                raw = _decode(self.buffer[len(PREFIX) : self.frame_samples])[: self.length]
                frames.append(protocol.unframe(raw, max_payload=MAX_PAYLOAD))
                self.good_frames += 1
            except protocol.FrameError:
                self.bad_frames += 1
            self.buffer = self.buffer[self.frame_samples :]
            self.acquired = False
            self.frame_samples = None
        return frames

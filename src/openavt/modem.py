"""Streaming, voice-band FSK framing. No TLS or network shortcuts."""

from __future__ import annotations

import numpy as np
from scipy.signal import correlate

from openavt import protocol

RATE = protocol.RATE
SAMPLES_PER_BIT = protocol.SAMPLES_PER_BIT
PREFIX_SAMPLES = len(protocol.PREAMBLE) * 8 * SAMPLES_PER_BIT
MAX_FRAME_SAMPLES = (
    (len(protocol.PREAMBLE) + protocol.HEADER.size + protocol.MAX_PAYLOAD + 4) * 8 * SAMPLES_PER_BIT
)
REFERENCE = np.asarray(protocol.modulate(protocol.PREAMBLE), dtype=np.float32)
REFERENCE_ENERGY = float(REFERENCE @ REFERENCE)
PHASE = np.arange(SAMPLES_PER_BIT)
SIN = np.asarray([np.sin(2 * np.pi * f * PHASE / RATE) for f in (1000, 2000)])
COS = np.asarray([np.cos(2 * np.pi * f * PHASE / RATE) for f in (1000, 2000)])


def encode(raw: bytes) -> np.ndarray:
    return np.asarray(protocol.modulate(raw), dtype=np.int16)


def decode(samples: np.ndarray) -> bytes:
    symbols = samples.astype(np.float64).reshape(-1, SAMPLES_PER_BIT)
    energy = (symbols @ SIN.T) ** 2 + (symbols @ COS.T) ** 2
    bits = (energy[:, 1] > energy[:, 0]).astype(np.uint8)
    return np.packbits(bits).tobytes()


class StreamDecoder:
    """Acquire a preamble from arbitrary chunks, then verify complete frames.

    Correlation supplies sample alignment, not packet timestamps or a side
    channel. This first receiver assumes no clock drift within a frame.
    """

    def __init__(self):
        self.buffer = np.empty(0, dtype=np.float32)
        self.acquired = False
        self.frame_samples: int | None = None
        self.good_frames = 0
        self.bad_frames = 0
        self.acquisitions = 0

    def feed(self, samples: np.ndarray) -> list[tuple[int, int, bytes]]:
        self.buffer = np.concatenate((self.buffer, samples.astype(np.float32)))
        frames = []
        while True:
            if not self.acquired:
                if len(self.buffer) < PREFIX_SAMPLES:
                    break
                scores = correlate(self.buffer, REFERENCE, mode="valid", method="fft")
                energies = np.convolve(self.buffer**2, np.ones(PREFIX_SAMPLES), mode="valid")
                normalized = np.abs(scores) / np.sqrt(np.maximum(energies * REFERENCE_ENERGY, 1))
                index = int(np.argmax(normalized))
                candidate = self.buffer[index : index + PREFIX_SAMPLES]
                if normalized[index] < 0.86 or decode(candidate) != protocol.PREAMBLE:
                    self.buffer = self.buffer[-(PREFIX_SAMPLES - 1) :]
                    break
                self.buffer = self.buffer[index:]
                self.acquired = True
                self.acquisitions += 1

            header_samples = PREFIX_SAMPLES + protocol.HEADER.size * 8 * SAMPLES_PER_BIT
            if len(self.buffer) < header_samples:
                break
            if self.frame_samples is None:
                raw_header = decode(self.buffer[PREFIX_SAMPLES:header_samples])
                _, kind, length = protocol.HEADER.unpack(raw_header)
                if (
                    kind not in (protocol.DATA, protocol.ACK, protocol.QUIC)
                    or length > protocol.MAX_PAYLOAD
                    or (kind == protocol.ACK and length)
                ):
                    self.bad_frames += 1
                    self.buffer = self.buffer[SAMPLES_PER_BIT:]
                    self.acquired = False
                    continue
                self.frame_samples = header_samples + (length + 4) * 8 * SAMPLES_PER_BIT
            if len(self.buffer) < self.frame_samples:
                break
            raw = decode(self.buffer[: self.frame_samples])
            try:
                frames.append(protocol.unframe(raw))
                self.good_frames += 1
            except protocol.FrameError:
                self.bad_frames += 1
            self.buffer = self.buffer[self.frame_samples :]
            self.acquired = False
            self.frame_samples = None
        return frames

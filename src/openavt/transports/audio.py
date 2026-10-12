"""Bounded audio scheduling and speech collection shared by call adapters."""

from __future__ import annotations

import asyncio
from collections import deque

import numpy as np

RATE = 8000
PACKET_SAMPLES = 160


class AudioScheduler:
    """Reserve complete modem bursts; pause speech at packet boundaries.

    Two modem waveforms never interleave. Speech is never summed into a modem
    waveform. This scheduler owns playback, including application TTS output.
    """

    def __init__(self):
        self.pending = {"modem": deque(), "speech": deque()}
        self.locks = {kind: asyncio.Lock() for kind in self.pending}
        self.closed = False
        self.futures: set[asyncio.Future] = set()

    async def send(self, samples, kind: str = "speech") -> None:
        if kind not in self.pending or self.closed:
            raise ConnectionError("audio scheduler unavailable")
        samples = np.asarray(samples, dtype=np.int16)
        if samples.ndim != 1 or not 0 < len(samples) <= RATE * 60:
            raise ValueError("invalid audio waveform size")
        async with self.locks[kind]:
            if self.closed:
                raise ConnectionError("audio scheduler closed")
            future = asyncio.get_running_loop().create_future()
            self.futures.add(future)
            item = [samples, 0, future]
            self.pending[kind].append(item)
            try:
                await asyncio.wait_for(future, timeout=len(samples) / RATE + 10)
            finally:
                self.futures.discard(future)
                if any(p is item for p in self.pending[kind]):
                    # Identity comparison avoids numpy's ambiguous array equality.
                    self.pending[kind] = deque(p for p in self.pending[kind] if p is not item)

    def take(self) -> tuple[np.ndarray, asyncio.Future | None]:
        samples = np.zeros(PACKET_SAMPLES, dtype=np.int16)
        queue = self.pending["modem"] or self.pending["speech"]
        if not queue:
            return samples, None
        waveform, offset, future = item = queue[0]
        count = min(PACKET_SAMPLES, len(waveform) - offset)
        samples[:count] = waveform[offset : offset + count]
        item[1] += count
        if item[1] == len(waveform):
            queue.popleft()
            return samples, future
        return samples, None

    @staticmethod
    def delivered(future: asyncio.Future | None) -> None:
        if future is not None and not future.done():
            future.set_result(None)

    def close(self) -> None:
        self.closed = True
        for future in self.futures:
            if not future.done():
                future.set_exception(ConnectionError("audio scheduler closed"))
        for queue in self.pending.values():
            for _, _, future in queue:
                if not future.done():
                    future.set_exception(ConnectionError("audio scheduler closed"))
            queue.clear()


class SpeechInbox:
    """Collect utterances for an ASR adapter without exposing modem frames."""

    def __init__(self):
        self.utterances: asyncio.Queue = asyncio.Queue(maxsize=4)
        self.parts: list[np.ndarray] = []
        self.silence = self.voiced = 0
        self.total = 0

    def feed(self, samples: np.ndarray) -> None:
        rms = float(np.sqrt(np.mean(samples.astype(np.float64) ** 2))) if len(samples) else 0
        if rms > 250:
            self.voiced += len(samples)
            self.silence = 0
        elif self.parts:
            self.silence += len(samples)
        if self.voiced:
            self.parts.append(samples.copy())
            self.total += len(samples)
        if self.total > RATE * 60:
            self.parts.clear()
            self.voiced = self.silence = 0
            self.total = 0
            return
        if self.silence >= int(0.8 * RATE):
            if self.voiced >= RATE // 4 and not self.utterances.full():
                self.utterances.put_nowait(np.concatenate(self.parts))
            self.parts.clear()
            self.voiced = self.silence = 0
            self.total = 0

"""Deterministic audio faults for local, reproducible transport verification."""

from __future__ import annotations

import numpy as np

from openavt.transports.base import AudioAdapter


class ImpairedAudio:
    """Drop, damage and duplicate complete modem bursts before call playback.

    Speech passes unchanged. Faults are fixed by burst number, not by decoded
    protocol contents. This tests recovery without a hidden data channel.
    """

    def __init__(self, audio: AudioAdapter):
        self.audio, self.profile = audio, audio.profile
        self.bursts = self.dropped = self.corrupted = self.duplicated = 0

    async def start(self, receive, disconnected):
        await self.audio.start(receive, disconnected)

    async def send(self, samples, kind="modem"):
        if kind == "modem":
            self.bursts += 1
            if self.bursts in {1, 12}:
                self.dropped += 1
                return
            if self.bursts == 4:
                self.corrupted += 1
                samples = np.asarray(samples, dtype=np.int16).copy()
                start = len(samples) // 2
                samples[start : start + 160] = 0
            if self.bursts == 7:
                self.duplicated += 1
                await self.audio.send(samples, kind)
        await self.audio.send(samples, kind)

    async def close(self):
        await self.audio.close()

    def summary(self):
        return {
            **self.audio.summary(),
            "impairment": {
                "modem_bursts": self.bursts,
                "dropped": self.dropped,
                "corrupted": self.corrupted,
                "duplicated": self.duplicated,
            },
        }

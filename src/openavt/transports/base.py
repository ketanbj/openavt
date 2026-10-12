"""The audio boundary implemented by call adapters."""

from __future__ import annotations

from typing import Callable, Protocol


class AudioAdapter(Protocol):
    profile: str

    async def start(self, receive: Callable, disconnected: Callable) -> None:
        """Deliver 8 kHz mono int16 samples; report terminal transport failures."""

    async def send(self, samples, kind: str = "modem") -> None:
        """Deliver samples in order, preserving modem bursts from speech mixing."""

    async def close(self) -> None:
        """Release owned media resources and unblock pending sends."""

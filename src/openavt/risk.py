"""Vendor-neutral risk signals. A risk result can restrict, never grant authority."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from enum import Enum
from typing import Awaitable, Callable, Protocol


class RiskOutcome(str, Enum):
    CONTINUE = "continue"
    BLOCK = "block"
    STEP_UP = "step_up"
    REVIEW = "review"


@dataclass(frozen=True)
class CallContext:
    call_id: str
    authenticated: bool = False
    peer_fingerprint: str | None = None


@dataclass(frozen=True)
class RequestSignal:
    request_id: str
    action: str
    resource: str
    customer: str


@dataclass(frozen=True)
class RiskAssessment:
    outcome: RiskOutcome
    reason: str = "assessed"


class FraudAdapter(Protocol):
    async def observe(self, context: CallContext, pcm: bytes) -> None:
        """8 kHz mono signed little-endian 16-bit PCM; may include ordinary speech."""

    async def assess(self, context: CallContext, request: RequestSignal | None) -> RiskAssessment: ...


class CallbackFraudAdapter:
    """Connect a supported vendor SDK without coupling OpenAVT to that vendor."""

    def __init__(self, *, assess: Callable[..., Awaitable[RiskAssessment]], observe: Callable | None = None):
        self.assessor, self.observer = assess, observe

    async def observe(self, context: CallContext, pcm: bytes) -> None:
        if self.observer:
            await self.observer(context, pcm)

    async def assess(self, context: CallContext, request: RequestSignal | None) -> RiskAssessment:
        return await self.assessor(context, request)


class RiskMonitor:
    """Bounded per-call audio observation and explicit failure policy.

    Use directly for unsupported callers, or attach to VoiceSession. Never pass
    credentials, delegation tokens or model context to an adapter.
    """

    def __init__(self, adapter: FraudAdapter, *, required: bool = True, timeout: float = 2):
        if not 0 < timeout <= 30:
            raise ValueError("risk timeout must be between zero and 30 seconds")
        self.adapter, self.required, self.timeout = adapter, required, timeout
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=32)
        self.task: asyncio.Task | None = None
        self.unavailable = False
        self.closed = False
        self.dropped_chunks = 0
        self.lock = asyncio.Lock()

    def start(self) -> None:
        if self.closed or self.task:
            raise RuntimeError("a monitor belongs to one call")
        self.task = asyncio.create_task(self._consume())

    def feed(self, context: CallContext, pcm: bytes) -> None:
        if self.closed:
            return
        if not isinstance(pcm, bytes) or not 0 < len(pcm) <= 32000 or len(pcm) % 2:
            raise ValueError("invalid risk audio chunk")
        try:
            self.queue.put_nowait((context, pcm))
        except asyncio.QueueFull:
            self.dropped_chunks += 1
            self.unavailable = True

    async def _consume(self):
        while True:
            context, pcm = await self.queue.get()
            try:
                async with self.lock, asyncio.timeout(self.timeout):
                    await self.adapter.observe(context, pcm)
            except Exception:
                self.unavailable = True
            finally:
                self.queue.task_done()

    async def assess(self, context: CallContext, request: RequestSignal | None = None) -> RiskAssessment:
        try:
            if self.closed or self.unavailable:
                raise ConnectionError()
            async with asyncio.timeout(self.timeout):
                # Assess only after the audio received so far has been observed.
                await self.queue.join()
                if self.unavailable:
                    raise ConnectionError()
                async with self.lock:
                    result = await self.adapter.assess(context, request)
            if not isinstance(result, RiskAssessment) or not isinstance(result.outcome, RiskOutcome):
                raise ValueError()
            return result
        except Exception:
            return RiskAssessment(RiskOutcome.BLOCK if self.required else RiskOutcome.CONTINUE, "unavailable")

    async def close(self) -> None:
        self.closed = True
        if self.task:
            self.task.cancel()
            await asyncio.gather(self.task, return_exceptions=True)
        while not self.queue.empty():
            self.queue.get_nowait()
            self.queue.task_done()

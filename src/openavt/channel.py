"""Reliable framed audio carrying a normal OpenSSL TLS byte stream."""

from __future__ import annotations

import asyncio
import json
import ssl
import time
from typing import Awaitable, Callable

from openavt import protocol
from openavt.modem import encode
from openavt.tls import Endpoint


class AudioTLS:
    def __init__(
        self,
        endpoint: Endpoint,
        send_audio: Callable[..., Awaitable],
        log: Callable,
        scenario: str = "valid",
        *,
        profile: str = "voiceband",
    ):
        if profile not in ("voiceband", "pcm"):
            raise ValueError(f"unknown modem profile: {profile}")
        self.profile = profile
        self.encode = encode
        self.max_payload = protocol.MAX_PAYLOAD
        self.rate = protocol.RATE
        if profile == "pcm":
            from openavt import pcm

            self.encode = pcm.encode
            self.max_payload = pcm.MAX_PAYLOAD
        self.flights = []
        self.tls_cpu_seconds = 0.0
        self.endpoint = endpoint
        self.send_audio = send_audio
        self.log = log
        self.scenario = scenario
        self.next_tx = 0
        self.next_rx = 0
        self.acks: dict[int, asyncio.Event] = {}
        self.new_data = asyncio.Event()
        self.ready = asyncio.Event()
        self.flush_lock = asyncio.Lock()
        self.messages: asyncio.Queue = asyncio.Queue(maxsize=32)
        self.pending_json = bytearray()
        self.error: BaseException | None = None
        self.started_at: float | None = None
        self.ready_at: float | None = None
        self.retries = 0
        self.duplicates = 0
        self.tls_bytes_rx = 0
        self.tls_bytes_tx = 0
        self.corrupted = False
        self.dropped_ack = False
        self.ack_tasks: set[asyncio.Task] = set()
        self.stats = {"data_frames_rx": 0, "ack_frames_rx": 0, "messages_rx": 0}

    def receive_frame(self, sequence: int, kind: int, payload: bytes) -> None:
        if self.error:
            return
        if kind == protocol.ACK:
            self.stats["ack_frames_rx"] += 1
            if sequence in self.acks:
                self.acks[sequence].set()
            return
        self.stats["data_frames_rx"] += 1
        notify = False
        if sequence == self.next_rx:
            if self.endpoint.incoming.pending + len(payload) > 65536:
                self.fail(ValueError("TLS input exceeds buffer limit"))
                return
            if self.started_at is None:
                self.started_at = time.monotonic()
            self.endpoint.incoming.write(payload)
            self.tls_bytes_rx += len(payload)
            self.next_rx += 1
            notify = True
        elif sequence == self.next_rx - 1:
            self.duplicates += 1
        else:
            return
        if len(self.ack_tasks) >= 16:
            self.fail(ValueError("audio ACK capacity exceeded"))
            return
        task = asyncio.create_task(self._ack(sequence, notify))
        self.ack_tasks.add(task)
        task.add_done_callback(self._ack_done)

    def _ack_done(self, task: asyncio.Task) -> None:
        self.ack_tasks.discard(task)
        if not task.cancelled() and (error := task.exception()):
            self.fail(error)

    def fail(self, error: BaseException) -> None:
        if self.error:
            return
        self.error = error
        self.ready.set()
        self.new_data.set()
        # Fail promptly even when a peer has filled the application queue.
        if self.messages.full():
            while not self.messages.empty():
                self.messages.get_nowait()
        self.messages.put_nowait(error)
        for event in self.acks.values():
            event.set()

    async def _ack(self, sequence: int, notify: bool) -> None:
        try:
            if self.scenario == "loss" and self.endpoint.name == "desk" and not self.dropped_ack:
                self.dropped_ack = True
                self.log("audio_ack_dropped", sequence=sequence)
                return
            await self.send_audio(self.encode(protocol.frame(sequence, protocol.ACK)), "modem")
        finally:
            # An ACK must be scheduled ahead of a TLS response flight; otherwise
            # the sender can time out while that flight occupies the audio track.
            if notify:
                self.new_data.set()

    async def _send_frame(self, payload: bytes) -> None:
        sequence = self.next_tx
        event = self.acks[sequence] = asyncio.Event()
        raw = protocol.frame(sequence, protocol.DATA, payload)
        try:
            for attempt in range(4):
                audio = self.encode(raw)
                if self.scenario == "loss" and self.endpoint.name == "agent" and not self.corrupted:
                    self.corrupted = True
                    if self.profile == "pcm":
                        from openavt import pcm

                        audio[len(pcm.PREFIX) + pcm._sample_count(pcm.HEADER_BYTES) + 5] = 0
                    else:
                        start = (len(protocol.PREAMBLE) + protocol.HEADER.size) * 8 * protocol.SAMPLES_PER_BIT
                        bit = (raw[len(protocol.PREAMBLE) + protocol.HEADER.size] >> 7) & 1
                        audio[start : start + protocol.SAMPLES_PER_BIT] = protocol.TONES[1 - bit]
                    self.log("audio_waveform_corrupted", sequence=sequence)
                self.log(
                    "audio_frame_tx",
                    sequence=sequence,
                    attempt=attempt,
                    payload_bytes=len(payload),
                    audio_seconds=round(len(audio) / self.rate, 6),
                )
                await self.send_audio(audio, "modem")
                try:
                    await asyncio.wait_for(event.wait(), timeout=0.75 if self.profile == "pcm" else 3.5)
                    if self.error:
                        raise self.error
                    self.next_tx += 1
                    self.tls_bytes_tx += len(payload)
                    return
                except TimeoutError:
                    self.retries += 1
                    self.log("audio_retry", sequence=sequence)
            raise TimeoutError(f"audio frame {sequence} was not acknowledged")
        finally:
            self.acks.pop(sequence, None)

    async def flush(self) -> None:
        async with self.flush_lock:
            while self.endpoint.outgoing.pending:
                wire = self.endpoint.outgoing.read()
                flight = {
                    "phase": "handshake" if self.ready_at is None else "application",
                    "bytes": len(wire),
                }
                started = time.monotonic()
                self.log("tls_flight", **flight)
                for start in range(0, len(wire), self.max_payload):
                    await self._send_frame(wire[start : start + self.max_payload])
                flight["delivery_seconds"] = round(time.monotonic() - started, 6)
                self.flights.append(flight)

    async def run(self, initiate: bool = False) -> None:
        try:
            if initiate:
                self.started_at = time.monotonic()
                self.log("tls_handshake_started")
            else:
                await self.new_data.wait()
                self.log("tls_handshake_started")
            while True:
                if self.error:
                    raise self.error
                self.new_data.clear()
                if not self.endpoint.ready:
                    cpu_start = time.perf_counter()
                    try:
                        self.endpoint.tls.do_handshake()
                        self.endpoint.ready = True
                    except ssl.SSLWantReadError:
                        pass
                    finally:
                        self.tls_cpu_seconds += time.perf_counter() - cpu_start
                    await self.flush()
                    if self.endpoint.ready:
                        self.ready_at = time.monotonic()
                        self.ready.set()
                        self.log(
                            "tls_authenticated",
                            version=self.endpoint.tls.version(),
                            handshake_seconds=round(self.ready_at - self.started_at, 3),
                            peer=self.endpoint.tls.getpeercert().get("subjectAltName", ()),
                        )
                if self.endpoint.ready:
                    while True:
                        try:
                            plaintext = self.endpoint.tls.read(16384)
                        except ssl.SSLWantReadError:
                            break
                        if not plaintext:
                            raise ConnectionError("TLS peer closed")
                        self.pending_json.extend(plaintext)
                        if len(self.pending_json) > 65536:
                            raise ValueError("application message exceeds size limit")
                        while b"\n" in self.pending_json:
                            line, _, remainder = self.pending_json.partition(b"\n")
                            self.pending_json = bytearray(remainder)
                            message = json.loads(line)
                            if not isinstance(message, dict):
                                raise ValueError("application message must be an object")
                            self.stats["messages_rx"] += 1
                            self.log(
                                "protected_message_rx",
                                message={
                                    k: "[redacted]" if k == "delegation" else v for k, v in message.items()
                                },
                            )
                            self.messages.put_nowait(message)
                    await self.flush()
                if not self.new_data.is_set():
                    await self.new_data.wait()
        except asyncio.CancelledError:
            raise
        except Exception as error:
            self.fail(error)
            self.log("tls_error", error_type=type(error).__name__, reason=str(error))

    async def wait_ready(self) -> None:
        await asyncio.wait_for(self.ready.wait(), timeout=150)
        if self.error:
            raise self.error

    async def send_json(self, message: dict) -> None:
        await self.wait_ready()
        wire = json.dumps(message, separators=(",", ":")).encode() + b"\n"
        if len(wire) > 65536:
            raise ValueError("application message exceeds size limit")
        while wire:
            consumed = self.endpoint.tls.write(wire)
            wire = wire[consumed:]
            await self.flush()
        self.log(
            "protected_message_tx",
            message={k: "[redacted]" if k == "delegation" else v for k, v in message.items()},
        )

    async def receive_json(self) -> dict:
        if self.error and self.messages.empty():
            raise self.error
        message = await asyncio.wait_for(self.messages.get(), timeout=150)
        if isinstance(message, BaseException):
            raise message
        return message

    def summary(self) -> dict:
        return {
            **self.stats,
            "tls_bytes_rx": self.tls_bytes_rx,
            "tls_bytes_tx": self.tls_bytes_tx,
            "retries": self.retries,
            "duplicates_suppressed": self.duplicates,
            "profile": self.profile,
            "flights": self.flights,
            "tls_handshake_cpu_seconds": round(self.tls_cpu_seconds, 6),
            "session_reused": self.endpoint.tls.session_reused,
            "tls_version": self.endpoint.tls.version(),
            "handshake_seconds": round(self.ready_at - self.started_at, 3) if self.ready_at else None,
            "error": type(self.error).__name__ if self.error else None,
        }

    async def close(self) -> None:
        for task in list(self.ack_tasks):
            task.cancel()
        await asyncio.gather(*self.ack_tasks, return_exceptions=True)

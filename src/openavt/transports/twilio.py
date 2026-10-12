"""Twilio bidirectional Media Streams: G.711 audio, marks and signed ingress.

HTTP/WebSocket JSON is the provider's audio envelope. Protected OpenAVT
requests exist only inside the audio payload, never a provider side channel.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import os
import re
import time
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urlsplit
from xml.sax.saxutils import quoteattr

import numpy as np
from aiohttp import WSMsgType, web
from twilio.request_validator import RequestValidator

from openavt.pcm import _mulaw
from openavt.transports.audio import PACKET_SAMPLES, RATE, AudioScheduler

MULAW_TO_PCM = np.array([_mulaw(code) for code in range(256)], dtype=np.int16)


def decode_mulaw(payload: str) -> np.ndarray:
    if not isinstance(payload, str) or not 1 <= len(payload) <= 22000:
        raise ValueError("invalid media payload size")
    try:
        raw = base64.b64decode(payload, validate=True)
    except (ValueError, binascii.Error):
        raise ValueError("invalid media encoding") from None
    if not 0 < len(raw) <= 16000:
        raise ValueError("invalid media packet size")
    return MULAW_TO_PCM[np.frombuffer(raw, dtype=np.uint8)]


def encode_mulaw(samples: np.ndarray) -> str:
    values = np.asarray(samples, dtype=np.int16).astype(np.int32)
    signs = np.where(values < 0, 128, 0)
    magnitude = np.minimum(np.abs(values), 32635) + 132
    exponent = np.clip(np.floor(np.log2(magnitude)).astype(np.int32) - 7, 0, 7)
    mantissa = (magnitude >> (exponent + 3)) & 15
    codes = (~(signs | (exponent << 4) | mantissa) & 255).astype(np.uint8)
    return base64.b64encode(codes.tobytes()).decode("ascii")


@dataclass(frozen=True)
class TwilioConfig:
    account_sid: str
    auth_token: str = field(repr=False)
    caller_number: str
    business_number: str
    public_base_url: str

    @classmethod
    def from_env(cls) -> TwilioConfig:
        names = (
            "TWILIO_ACCOUNT_SID",
            "TWILIO_AUTH_TOKEN",
            "TWILIO_CALLER_NUMBER",
            "TWILIO_BUSINESS_NUMBER",
            "TWILIO_PUBLIC_BASE_URL",
        )
        missing = [name for name in names if not os.getenv(name)]
        if missing:
            raise ValueError("Configure: " + ", ".join(missing))
        return cls(*(os.environ[name] for name in names))

    def __post_init__(self):
        if not re.fullmatch(r"AC[0-9a-fA-F]{32}", self.account_sid) or not self.auth_token:
            raise ValueError("invalid Twilio account configuration")
        if any(
            not re.fullmatch(r"\+[1-9][0-9]{7,14}", n) for n in (self.caller_number, self.business_number)
        ):
            raise ValueError("configure two owned E.164 telephone numbers")
        if self.caller_number == self.business_number:
            raise ValueError("caller and business numbers must be different")
        parsed = urlsplit(self.public_base_url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("public base URL must be an HTTPS origin")

    def url(self, path: str, *, websocket: bool = False) -> str:
        origin = self.public_base_url.rstrip("/")
        return (origin.replace("https://", "wss://", 1) if websocket else origin) + path


class TwilioAdapter:
    def __init__(self, websocket, *, account_sid: str, profile: str = "pcm", playback_timeout: float = 5):
        if profile not in {"pcm", "voiceband"} or not 0 < playback_timeout <= 30:
            raise ValueError("invalid Twilio audio configuration")
        self.websocket, self.account_sid, self.profile = websocket, account_sid, profile
        self.playback_timeout = playback_timeout
        self.scheduler = AudioScheduler()
        self.stream_sid: str | None = None
        self.started = asyncio.Event()
        self.sequence = 0
        self.timestamp = 0
        self.marks: dict[str, asyncio.Future] = {}
        self.mark_counter = 0
        self.receive: Callable = lambda _samples: None
        self.disconnected: Callable = lambda _error: None
        self.reader: asyncio.Task | None = None
        self.writer: asyncio.Task | None = None
        self.error: Exception | None = None
        self.closed = False
        self.samples_rx = self.samples_tx = self.mark_acks = 0

    async def start(self, receive: Callable, disconnected: Callable) -> None:
        self.receive, self.disconnected = receive, disconnected
        self.reader = asyncio.create_task(self._consume())
        await asyncio.wait_for(self.started.wait(), 60)
        if self.error:
            raise self.error
        self.writer = asyncio.create_task(self._output())

    def _fail(self, error: Exception) -> None:
        if not self.error and not self.closed:
            self.error = error
            self.started.set()
            self.scheduler.close()
            for future in self.marks.values():
                if not future.done():
                    future.set_exception(error)
            self.disconnected(error)

    async def _consume(self) -> None:
        try:
            async for message in self.websocket:
                if message.type != WSMsgType.TEXT:
                    raise ConnectionError("provider audio stream ended")
                if len(message.data) > 32768:
                    raise ValueError("provider event exceeds size limit")
                self.event(message.json())
            raise ConnectionError("provider audio stream ended")
        except asyncio.CancelledError:
            raise
        except Exception:
            self._fail(ConnectionError("invalid or disconnected provider audio stream"))

    def event(self, message: dict) -> None:
        if not isinstance(message, dict):
            raise ValueError("invalid provider event")
        kind = message.get("event")
        if kind == "connected":
            if self.stream_sid or message.get("protocol") != "Call" or message.get("version") != "1.0.0":
                raise ValueError("unsupported provider protocol")
            return
        sequence = message.get("sequenceNumber")
        if not isinstance(sequence, str) or not sequence.isdecimal() or int(sequence) <= self.sequence:
            raise ValueError("invalid provider sequence")
        self.sequence = int(sequence)
        if kind == "start":
            start = message.get("start", {})
            stream_sid = message.get("streamSid")
            if (
                self.stream_sid is not None
                or not isinstance(stream_sid, str)
                or not re.fullmatch(r"MZ[0-9a-fA-F]{32}", stream_sid)
                or start.get("streamSid") != stream_sid
                or start.get("accountSid") != self.account_sid
                or not re.fullmatch(r"CA[0-9a-fA-F]{32}", start.get("callSid", ""))
                or start.get("tracks") != ["inbound"]
                or start.get("mediaFormat")
                != {"encoding": "audio/x-mulaw", "sampleRate": 8000, "channels": 1}
            ):
                raise ValueError("unsupported provider media format or stream")
            self.stream_sid = stream_sid
            self.started.set()
            return
        if not self.stream_sid or message.get("streamSid") != self.stream_sid:
            raise ValueError("event belongs to another stream")
        if kind == "media":
            media = message.get("media", {})
            stamp = media.get("timestamp")
            if media.get("track") != "inbound" or not isinstance(stamp, str) or not stamp.isdecimal():
                raise ValueError("invalid inbound media")
            samples = decode_mulaw(media.get("payload"))
            offset = int(stamp) * (RATE // 1000)
            if offset < self.timestamp or offset - self.timestamp > RATE * 2:
                raise ValueError("invalid media timeline")
            if offset > self.timestamp:
                self.receive(np.zeros(offset - self.timestamp, dtype=np.int16))
            self.timestamp = offset + len(samples)
            self.samples_rx += len(samples)
            self.receive(samples)
        elif kind == "mark":
            name = message.get("mark", {}).get("name")
            if not isinstance(name, str):
                raise ValueError("invalid playback mark")
            future = self.marks.pop(name, None)
            if future is not None:
                self.mark_acks += 1
                self.scheduler.delivered(future)
        elif kind == "stop":
            self._fail(ConnectionError("provider stopped the call"))
        elif kind != "dtmf":
            raise ValueError("unsupported provider event")

    async def _output(self) -> None:
        origin, packets = time.monotonic(), 0
        try:
            while not self.closed and not self.error:
                await asyncio.sleep(max(0, origin + packets * PACKET_SAMPLES / RATE - time.monotonic()))
                samples, future = self.scheduler.take()
                await self.websocket.send_json(
                    {
                        "event": "media",
                        "streamSid": self.stream_sid,
                        "media": {"payload": encode_mulaw(samples)},
                    }
                )
                self.samples_tx += len(samples)
                packets += 1
                if future is not None:
                    self.mark_counter += 1
                    name = f"openavt-{self.mark_counter}"
                    self.marks[name] = future
                    await self.websocket.send_json(
                        {"event": "mark", "streamSid": self.stream_sid, "mark": {"name": name}}
                    )
        except asyncio.CancelledError:
            raise
        except Exception:
            self._fail(ConnectionError("provider playback failed"))

    async def send(self, samples, kind: str = "modem") -> None:
        if self.error or self.closed:
            raise ConnectionError("provider audio unavailable")
        try:
            await asyncio.wait_for(
                self.scheduler.send(samples, kind), len(samples) / RATE + self.playback_timeout
            )
        except TimeoutError:
            self._fail(ConnectionError("provider playback acknowledgement timed out"))
            raise

    async def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        self.scheduler.close()
        for future in self.marks.values():
            if not future.done():
                future.cancel()
        for task in (self.reader, self.writer):
            if task:
                task.cancel()
        await asyncio.gather(*(t for t in (self.reader, self.writer) if t), return_exceptions=True)
        await self.websocket.close()

    def summary(self) -> dict:
        return {
            "transport": "twilio-media-streams",
            "profile": self.profile,
            "codec": "PCMU",
            "audio_samples_rx": self.samples_rx,
            "audio_samples_tx": self.samples_tx,
            "playback_marks_acknowledged": self.mark_acks,
        }


class TwilioIngress:
    """Validate provider ingress before exposing an audio stream to an application.

    The configured public origin is authoritative; never trust proxy Host headers
    when constructing the signed URL. The inner mutual TLS supplies agent identity.
    """

    def __init__(self, config: TwilioConfig, on_stream: Callable):
        self.config, self.on_stream = config, on_stream
        self.validator = RequestValidator(config.auth_token)
        self.active: set[str] = set()

    def application(self) -> web.Application:
        app = web.Application(client_max_size=16384)
        app.router.add_post("/voice/{role}", self.voice)
        app.router.add_get("/stream/{role}", self.stream)
        return app

    async def voice(self, request: web.Request) -> web.Response:
        role = request.match_info["role"]
        if role not in {"agent", "desk"}:
            raise web.HTTPNotFound()
        params = await request.post()
        if (
            request.query_string
            or params.get("AccountSid") != self.config.account_sid
            or not self.validator.validate(
                self.config.url(request.path), params, request.headers.get("X-Twilio-Signature", "")
            )
        ):
            raise web.HTTPForbidden()
        url = self.config.url(f"/stream/{role}", websocket=True)
        return web.Response(
            text=f"<Response><Connect><Stream url={quoteattr(url)}/></Connect></Response>",
            content_type="application/xml",
        )

    async def stream(self, request: web.Request) -> web.WebSocketResponse:
        role = request.match_info["role"]
        if role not in {"agent", "desk"}:
            raise web.HTTPNotFound()
        signature = request.headers.get("X-Twilio-Signature", "")
        url = self.config.url(request.path, websocket=True)
        if request.query_string or not self.validator.validate(url, {}, signature):
            raise web.HTTPForbidden()
        if role in self.active:
            raise web.HTTPConflict()
        self.active.add(role)
        ws = web.WebSocketResponse(max_msg_size=32768, heartbeat=10)
        try:
            await ws.prepare(request)
            await self.on_stream(role, ws)
        finally:
            self.active.discard(role)
            await ws.close()
        return ws

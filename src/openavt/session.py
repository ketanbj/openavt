"""Framework-neutral authenticated requests over an existing audio call."""

from __future__ import annotations

import asyncio
import hashlib
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import numpy as np

from openavt.channel import AudioTLS
from openavt.identity import Identity
from openavt.risk import CallContext, RiskMonitor
from openavt.tls import Endpoint
from openavt.transports.base import AudioAdapter


@dataclass(frozen=True)
class GrantRequest:
    request_id: str
    nonce: str
    action: str
    resource: str
    customer: str
    arguments: dict


class ProtocolError(ValueError):
    """An authenticated peer sent an unexpected application message."""


class RequestOutcomeUnknown(TimeoutError):
    """A submitted request has no confirmed result. Do not blindly retry writes."""


def identifier(value: object, field: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 256:
        raise ProtocolError(f"invalid {field}")
    return value


def protected_response(response: dict, request_id: str) -> dict:
    if (
        set(response) != {"v", "type", "id", "result", "reason", "data"}
        or type(response["v"]) is not int
        or response["v"] != 1
        or response["type"] != "response"
        or response["id"] != request_id
        or response["result"] not in ("allowed", "denied", "error")
        or not isinstance(response["reason"], str)
        or not isinstance(response["data"], dict)
    ):
        raise ProtocolError("unexpected protected response")
    return response


class VoiceSession:
    """Own a call adapter, authenticate both ends, and serialize protected requests.

    The adapter carries only audio. Signaling and enrollment are separate.
    Ordinary speech is unauthenticated by this inner TLS session.
    """

    def __init__(
        self,
        *,
        audio: AudioAdapter,
        identity: Identity,
        trust: str | Path,
        expected_peer: str | None = None,
        server: bool = False,
        profile: str = "pcm",
        protocol: str = "tls",
        handshake_timeout: float = 15,
        request_timeout: float = 15,
        on_speech: Callable | None = None,
        log: Callable | None = None,
        monitor: RiskMonitor | None = None,
    ):
        if not server and not expected_peer:
            raise ValueError("a client must specify the expected service hostname")
        if profile not in {"pcm", "voiceband"} or audio.profile != profile:
            raise ValueError("session and audio adapter must use the same supported profile")
        if protocol not in {"tls", "quic"}:
            raise ValueError("session protocol must be tls or quic")
        if not 0 < handshake_timeout <= 150 or not 0 < request_timeout <= 150:
            raise ValueError("timeouts must be between zero and 150 seconds")
        self.audio, self.server, self.profile = audio, server, profile
        self.handshake_timeout, self.request_timeout = handshake_timeout, request_timeout
        self.on_speech = on_speech
        self.log = log or (lambda *_args, **_fields: None)
        self.state = "new"
        self.monitor = monitor
        self.call_id = uuid.uuid4().hex
        self._task: asyncio.Task | None = None
        self._lock = asyncio.Lock()
        self._suppress_until = 0.0
        self._handshake_seconds: float | None = None
        if protocol == "quic":
            from openavt.quic import AudioQUIC

            self.channel = AudioQUIC(
                identity,
                trust,
                audio.send,
                self._safe_log,
                server=server,
                server_hostname=expected_peer,
                profile=profile,
            )
        else:
            endpoint = Endpoint(
                "desk" if server else "agent",
                identity.context(trust, server=server),
                server=server,
                server_hostname=expected_peer,
            )
            self.channel = AudioTLS(endpoint, audio.send, self._safe_log, profile=profile)
        if profile == "pcm":
            from openavt.pcm import StreamDecoder
        else:
            from openavt.modem import StreamDecoder
        self.decoder = StreamDecoder()

    def _safe_log(self, event: str, **fields) -> None:
        # Applications may put secrets in any JSON field, not just "delegation".
        fields.pop("message", None)
        fields.pop("reason", None)
        self.log(event, **fields)

    def _receive_audio(self, samples) -> None:
        if self.state in {"closed", "failed"}:
            return
        samples = np.asarray(samples, dtype=np.int16)
        if samples.ndim != 1 or len(samples) > 16000:
            self.channel.fail(ProtocolError("invalid audio chunk"))
            return
        if self.monitor and len(samples):
            self.monitor.feed(self.risk_context, samples.astype("<i2").tobytes())
        frames = self.decoder.feed(samples)
        for sequence, kind, payload in frames:
            self.channel.receive_frame(sequence, kind, payload)
        if self.decoder.acquired or frames:
            self._suppress_until = time.monotonic() + 0.2
        elif self.on_speech and time.monotonic() > self._suppress_until:
            self.on_speech(samples)

    def _disconnected(self, error: BaseException) -> None:
        if self.state != "closed":
            self.state = "failed"
        self.channel.fail(error)

    async def __aenter__(self) -> VoiceSession:
        if self.state != "new":
            raise RuntimeError("a session cannot be reopened")
        self.state = "authenticating"
        try:
            if self.monitor:
                self.monitor.start()
            await asyncio.wait_for(
                self.audio.start(self._receive_audio, self._disconnected), self.handshake_timeout
            )
            started = time.monotonic()
            self._task = asyncio.create_task(self.channel.run(initiate=not self.server))
            await asyncio.wait_for(self.channel.wait_ready(), self.handshake_timeout)
            self._handshake_seconds = time.monotonic() - started
            self.state = "verified"
            return self
        except BaseException:
            await self.close()
            raise

    async def __aexit__(self, *_args) -> None:
        await self.close()

    @property
    def risk_context(self) -> CallContext:
        verified = self.state == "verified" and not self.channel.error
        fingerprint = hashlib.sha256(self.peer_certificate).hexdigest() if verified else None
        return CallContext(self.call_id, verified, fingerprint)

    @property
    def peer_certificate(self) -> bytes:
        if self.state != "verified" or self.channel.error:
            raise ConnectionError("the session is not verified")
        return self.channel.peer_certificate

    async def send_speech(self, samples) -> None:
        if self.state != "verified" or self.channel.error:
            raise ConnectionError("the session is not verified")
        await self.audio.send(samples, "speech")

    async def request(
        self,
        action: str,
        *,
        resource: str,
        customer: str,
        grant: str | Callable,
        arguments: dict | None = None,
        timeout: float | None = None,
    ) -> dict:
        if self.server:
            raise RuntimeError("requests are initiated by the client")
        for field, value in (("action", action), ("resource", resource), ("customer", customer)):
            identifier(value, field)
        if not callable(grant) and (not isinstance(grant, str) or not 1 <= len(grant) <= 4096):
            raise ValueError("invalid grant")
        if arguments is not None and not isinstance(arguments, dict):
            raise ValueError("arguments must be an object")
        deadline = self.request_timeout if timeout is None else timeout
        if not 0 < deadline <= 150:
            raise ValueError("timeout must be between zero and 150 seconds")
        async with self._lock:
            if self.state != "verified" or self.channel.error:
                raise ConnectionError("the session is not verified")
            request_id, submitted = uuid.uuid4().hex, False
            try:
                async with asyncio.timeout(deadline):
                    await self.channel.send_json({"v": 1, "type": "challenge", "id": request_id})
                    challenge = await self.channel.receive_json()
                    if challenge.get("type") == "response":
                        response = protected_response(challenge, request_id)
                        if response["result"] == "allowed":
                            raise ProtocolError("a challenge cannot authorize an action")
                        return response
                    if (
                        set(challenge) != {"v", "type", "id", "nonce"}
                        or type(challenge["v"]) is not int
                        or challenge["v"] != 1
                        or challenge["type"] != "challenge"
                        or challenge["id"] != request_id
                    ):
                        raise ProtocolError("unexpected authorization challenge")
                    nonce = identifier(challenge["nonce"], "nonce")
                    credential = (
                        await grant(
                            GrantRequest(request_id, nonce, action, resource, customer, arguments or {})
                        )
                        if callable(grant)
                        else grant
                    )
                    if not isinstance(credential, str) or not 1 <= len(credential) <= 4096:
                        raise ProtocolError("invalid issued voice grant")
                    message = {
                        "v": 1,
                        "type": "request",
                        "id": request_id,
                        "action": action,
                        "resource": resource,
                        "customer": customer,
                        "nonce": nonce,
                        "grant": credential,
                        "arguments": arguments or {},
                    }
                    submitted = True
                    await self.channel.send_json(message)
                    response = await self.channel.receive_json()
                    return protected_response(response, request_id)
            except (TimeoutError, ConnectionError) as error:
                await self.close()
                if submitted:
                    raise RequestOutcomeUnknown("request submitted without a confirmed result") from error
                raise
            except BaseException:
                await self.close()
                raise

    def summary(self) -> dict:
        return {
            "state": self.state,
            "handshake_wall_seconds": self._handshake_seconds,
            **self.channel.summary(),
            "modem_good_frames": self.decoder.good_frames,
            "modem_bad_frames": self.decoder.bad_frames,
        }

    async def close(self) -> None:
        if self.state == "closed":
            return
        if self.state == "verified" and not self.channel.error:
            # Let outstanding audio ACKs drain before tearing down RTP/playback.
            try:
                await asyncio.wait_for(self.channel.drain(), 10 if self.profile == "voiceband" else 1)
                await asyncio.sleep(0.15)
            except (Exception, asyncio.CancelledError):
                pass
        self.state = "closed"
        self.channel.fail(ConnectionError("session closed"))
        if self._task:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
        try:
            await self.channel.close()
            await self.audio.close()
        finally:
            if self.monitor:
                await self.monitor.close()

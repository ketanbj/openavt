"""Mutually authenticated QUIC streams carried exclusively by lossy call audio.

aioquic owns encryption, congestion control, acknowledgments and retransmission.
The audio link only fragments datagrams and discards CRC failures. No UDP socket
or WebRTC data channel is created by this module.
"""

from __future__ import annotations

import asyncio
import json
import ssl
import time
from pathlib import Path
from typing import Awaitable, Callable

from aioquic import tls
from aioquic.buffer import Buffer
from aioquic.quic import events
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.logger import QuicLogger, QuicLoggerTrace
from aioquic.quic.packet import QuicPacketType, QuicProtocolVersion, pull_quic_header
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtendedKeyUsageOID

from openavt import protocol
from openavt.datagram import MTU, AudioDatagrams
from openavt.identity import Identity

ALPN = "openavt/1"
AUTHENTICATED = b'{"v":1,"type":"authenticated"}\n'
# A single audio call has exactly one peer. These are opaque routing tokens for
# the sans-I/O engine, never addresses to which the implementation sends UDP.
PEER = ("127.0.0.1", 4433)
MAX_MESSAGE = 65536


class _MutualQuicConnection(QuicConnection):
    """Isolate the private aioquic 1.3.0 hooks, covered by handshake tests.

    Upstream does not expose required client certificates or peer DER in its public
    QUIC API. CertificateVerify still proves key possession in upstream TLS; we
    validate the chain, purpose and identity before exposing any application data.
    """

    def _initialize(self, peer_cid: bytes) -> None:
        super()._initialize(peer_cid)
        if not self.configuration.is_client:
            self.tls._request_client_certificate = True

    def verified_peer(self) -> bytes:
        certificate = self.tls._peer_certificate
        try:
            if certificate is None:
                raise ValueError("peer certificate required")
            tls.verify_certificate(
                certificate,
                chain=self.tls._peer_certificate_chain,
                cadata=self.configuration.cadata,
                server_name=self.configuration.server_name if self.configuration.is_client else None,
            )
            purpose = (
                ExtendedKeyUsageOID.SERVER_AUTH
                if self.configuration.is_client
                else ExtendedKeyUsageOID.CLIENT_AUTH
            )
            if purpose not in certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value:
                raise ValueError("incorrect certificate purpose")
            if certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                raise ValueError("a CA certificate cannot be an endpoint")
            if not certificate.extensions.get_extension_for_class(x509.KeyUsage).value.digital_signature:
                raise ValueError("certificate cannot sign")
        except (tls.Alert, ValueError, x509.ExtensionNotFound) as error:
            raise ssl.SSLCertVerificationError("QUIC peer certificate rejected") from error
        return certificate.public_bytes(Encoding.DER)

    @property
    def stream_bytes_acked(self) -> int:
        stream = self._streams.get(0)
        return stream.sender._buffer_start if stream else 0

    @property
    def acks_pending(self) -> bool:
        return any(space.ack_at is not None for space in self._spaces.values())


class _Counters(QuicLoggerTrace):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.packets_lost = 0

    def log_event(self, *, category: str, event: str, data: dict) -> None:
        # Retain counts only: no unbounded qlog or application/identity contents.
        self.packets_lost += int(category == "recovery" and event == "packet_lost")


class _Logger(QuicLogger):
    def start_trace(self, *, is_client: bool, odcid: bytes) -> _Counters:
        trace = _Counters(is_client=is_client, odcid=odcid)
        self._traces.append(trace)
        return trace


class AudioQUIC:
    def __init__(
        self,
        identity: Identity,
        trust: str | Path,
        send_audio: Callable[..., Awaitable],
        log: Callable,
        *,
        server: bool = False,
        server_hostname: str | None = None,
        profile: str = "pcm",
    ):
        if profile not in {"pcm", "voiceband"}:
            raise ValueError("unsupported audio profile")
        if not server and not server_hostname:
            raise ValueError("an expected service hostname is required")
        if profile == "pcm":
            from openavt import pcm as modem

            max_payload = modem.MAX_PAYLOAD
        else:
            from openavt import modem

            max_payload = protocol.MAX_PAYLOAD
        self.profile, self.server = profile, server
        self.encode, self.send_audio, self.log = modem.encode, send_audio, log
        self.datagrams = AudioDatagrams(max_payload, lifetime=60 if profile == "voiceband" else 5)
        self.logger = _Logger()
        self.configuration = QuicConfiguration(
            is_client=not server,
            alpn_protocols=[ALPN],
            server_name=server_hostname,
            cadata=Path(trust).read_bytes(),
            verify_mode=ssl.CERT_REQUIRED,
            max_datagram_size=MTU,
            max_data=MAX_MESSAGE,
            max_stream_data=MAX_MESSAGE,
            initial_rtt=0.5 if profile == "pcm" else 25,
            idle_timeout=150,
            supported_versions=[QuicProtocolVersion.VERSION_1],
            quic_logger=self.logger,
        )
        self.configuration.load_cert_chain(identity.certificate, identity.private_key)
        if self.configuration.certificate.public_key() != self.configuration.private_key.public_key():
            raise ValueError("certificate and private key do not match")
        self.connection: _MutualQuicConnection | None = None
        self.ready = asyncio.Event()
        self.new_data = asyncio.Event()
        self.progress = asyncio.Event()
        self.incoming: asyncio.Queue = asyncio.Queue(maxsize=32)
        self.outgoing: asyncio.Queue = asyncio.Queue(maxsize=128)
        self.messages: asyncio.Queue = asyncio.Queue(maxsize=32)
        self.pending_json = bytearray()
        self.pending_auth = bytearray()
        self.peer_certificate: bytes | None = None
        self.error: BaseException | None = None
        self.started_at: float | None = None
        self.ready_at: float | None = None
        self._sender: asyncio.Task | None = None
        self._tx_pending = self._stream_sent = 0
        self._send_lock = asyncio.Lock()
        self._closed = False
        self.stats = dict(
            quic_datagrams_tx=0,
            quic_datagrams_rx=0,
            quic_bytes_tx=0,
            quic_bytes_rx=0,
            quic_timer_firings=0,
            audio_frames_tx=0,
            messages_rx=0,
        )

    def receive_frame(self, sequence: int, kind: int, payload: bytes) -> None:
        if self.error:
            return
        if data := self.datagrams.receive(sequence, kind, payload):
            try:
                self.incoming.put_nowait(data)
                self.new_data.set()
            except asyncio.QueueFull:
                # A full unreliable link drops packets, preserving its bound.
                self.datagrams.discarded += 1

    def fail(self, error: BaseException) -> None:
        if self.error:
            return
        self.error = error
        self.ready.set()
        self.new_data.set()
        self.progress.set()
        while not self.messages.empty():
            self.messages.get_nowait()
        self.messages.put_nowait(error)

    async def _send_datagram(self, data: bytes) -> None:
        for raw in self.datagrams.frame(data):
            await self.send_audio(self.encode(raw), "modem")
            self.stats["audio_frames_tx"] += 1
        self.stats["quic_datagrams_tx"] += 1
        self.stats["quic_bytes_tx"] += len(data)

    async def _send_loop(self) -> None:
        try:
            while True:
                data = await self.outgoing.get()
                await self._send_datagram(data)
                self._tx_pending -= 1
                self.new_data.set()
        except asyncio.CancelledError:
            raise
        except Exception as error:
            self.fail(error)

    def _mark_ready(self) -> None:
        self.ready_at = time.monotonic()
        self.ready.set()
        self.log("quic_authenticated", version="TLSv1.3", alpn=ALPN)

    def _events(self) -> None:
        while (event := self.connection.next_event()) is not None:
            if isinstance(event, events.ConnectionTerminated):
                raise ConnectionError(f"QUIC connection terminated ({event.error_code})")
            if isinstance(event, events.HandshakeCompleted):
                if event.alpn_protocol != ALPN or event.early_data_accepted or event.session_resumed:
                    raise ssl.SSLError("unexpected QUIC handshake parameters")
                self.peer_certificate = self.connection.verified_peer()
                if self.server:
                    # A client waits for this encrypted confirmation before it
                    # can send grants: the server has now verified its identity.
                    self.connection.send_stream_data(3, AUTHENTICATED, end_stream=True)
                    self._mark_ready()
            elif isinstance(event, events.StreamDataReceived):
                if event.stream_id == 3 and not self.server and not self.ready_at:
                    if not self.peer_certificate:
                        raise ssl.SSLError("confirmation before certificate verification")
                    self.pending_auth.extend(event.data)
                    if len(self.pending_auth) > len(AUTHENTICATED):
                        raise ssl.SSLError("invalid mutual authentication confirmation")
                    if event.end_stream:
                        if self.pending_auth != AUTHENTICATED:
                            raise ssl.SSLError("invalid mutual authentication confirmation")
                        self.pending_auth.clear()
                        self._mark_ready()
                    continue
                if event.stream_id != 0 or event.end_stream or not self.peer_certificate:
                    raise ValueError("unexpected QUIC application stream")
                self.pending_json.extend(event.data)
                while b"\n" in self.pending_json:
                    line, _, remainder = self.pending_json.partition(b"\n")
                    if len(line) + 1 > MAX_MESSAGE:
                        raise ValueError("application message exceeds size limit")
                    self.pending_json = bytearray(remainder)
                    if not self.ready_at:
                        raise ssl.SSLError("application data before authentication")
                    message = json.loads(line)
                    if not isinstance(message, dict):
                        raise ValueError("application message must be an object")
                    self.messages.put_nowait(message)
                    self.stats["messages_rx"] += 1
                    self.log("protected_message_rx")
                if len(self.pending_json) >= MAX_MESSAGE:
                    raise ValueError("application message exceeds size limit")
            elif isinstance(event, (events.StreamReset, events.StopSendingReceived)):
                raise ConnectionError("QUIC application stream was reset")

    async def run(self, initiate: bool = False) -> None:
        try:
            if initiate != (not self.server):
                raise ValueError("incorrect QUIC endpoint role")
            self._sender = asyncio.create_task(self._send_loop())
            if initiate:
                self.started_at = time.monotonic()
                self.connection = _MutualQuicConnection(configuration=self.configuration)
                self.connection.connect(PEER, now=self.started_at)
            while not self.error:
                self.new_data.clear()
                while not self.incoming.empty():
                    data = self.incoming.get_nowait()
                    if self.connection is None:
                        # Ignore damaged or unrelated traffic before allocating
                        # server handshake state, just like a QUIC UDP listener.
                        try:
                            header = pull_quic_header(Buffer(data=data), host_cid_length=8)
                        except ValueError:
                            continue
                        if (
                            len(data) < MTU
                            or header.packet_type != QuicPacketType.INITIAL
                            or header.version != QuicProtocolVersion.VERSION_1
                        ):
                            continue
                        self.started_at = time.monotonic()
                        self.connection = _MutualQuicConnection(
                            configuration=self.configuration,
                            original_destination_connection_id=header.destination_cid,
                        )
                    self.stats["quic_datagrams_rx"] += 1
                    self.stats["quic_bytes_rx"] += len(data)
                    self.connection.receive_datagram(data, PEER, now=time.monotonic())
                    self._events()
                timer = None
                if self.connection is not None and not self._tx_pending:
                    now = time.monotonic()
                    deadline = self.connection.get_timer()
                    if deadline is not None and deadline <= now:
                        self.connection.handle_timer(now=now)
                        self.stats["quic_timer_firings"] += 1
                        self._events()
                    packets = self.connection.datagrams_to_send(now=time.monotonic())
                    # QUIC's initial congestion window bounds each burst. Never
                    # build more while audio from the previous burst is queued.
                    for data, _address in packets:
                        self.outgoing.put_nowait(data)
                        self._tx_pending += 1
                    if not self._tx_pending:
                        timer = self.connection.get_timer()
                self.progress.set()
                if self.error:
                    break
                try:
                    delay = max(0, timer - time.monotonic()) if timer is not None else None
                    await asyncio.wait_for(self.new_data.wait(), timeout=delay)
                except TimeoutError:
                    pass
        except asyncio.CancelledError:
            raise
        except Exception as error:
            self.fail(error)
            self.log("quic_error", error_type=type(error).__name__)
            await self.close(error_code=1)

    async def wait_ready(self) -> None:
        await asyncio.wait_for(self.ready.wait(), 150)
        if self.error:
            raise self.error

    async def _wait_acked(self, target: int) -> None:
        while True:
            self.progress.clear()
            if self.error:
                raise self.error
            if self.connection.stream_bytes_acked >= target:
                return
            await self.progress.wait()

    async def send_json(self, message: dict) -> None:
        await self.wait_ready()
        if not isinstance(message, dict):
            raise ValueError("application message must be an object")
        wire = json.dumps(message, separators=(",", ":"), allow_nan=False).encode() + b"\n"
        if len(wire) > MAX_MESSAGE:
            raise ValueError("application message exceeds size limit")
        async with self._send_lock:
            if self.error:
                raise self.error
            self.connection.send_stream_data(0, wire)
            self._stream_sent += len(wire)
            self.new_data.set()
            await asyncio.wait_for(self._wait_acked(self._stream_sent), 150)
        self.log("protected_message_tx")

    async def receive_json(self) -> dict:
        if self.error:
            raise self.error
        message = await asyncio.wait_for(self.messages.get(), 150)
        if isinstance(message, BaseException):
            raise message
        return message

    async def drain(self) -> None:
        # Receiving a response can finish before our delayed ACK has even been
        # built. Keep the engine alive until that ACK finishes audio playback.
        self.new_data.set()
        while True:
            self.progress.clear()
            if self.error:
                raise self.error
            if (
                self.connection.stream_bytes_acked >= self._stream_sent
                and not self._tx_pending
                and not self.connection.acks_pending
            ):
                return
            await self.progress.wait()

    async def close(self, *, error_code: int = 0) -> None:
        if self._closed:
            return
        self._closed = True
        if self._sender:
            self._sender.cancel()
            await asyncio.gather(self._sender, return_exceptions=True)
        if self.connection is not None:
            self.connection.close(error_code=error_code)
            try:
                for data, _address in self.connection.datagrams_to_send(now=time.monotonic()):
                    await asyncio.wait_for(self._send_datagram(data), 1 if self.profile == "pcm" else 3)
            except (Exception, asyncio.CancelledError):
                pass
        self.fail(ConnectionError("QUIC channel closed"))

    def summary(self) -> dict:
        return {
            **self.stats,
            "protocol": "quic",
            "profile": self.profile,
            "quic_version": "1",
            "tls_version": "TLSv1.3" if self.peer_certificate else None,
            "session_reused": False,
            "alpn": ALPN if self.peer_certificate else None,
            "link_acknowledgments": False,
            "quic_packets_lost": sum(t.packets_lost for t in self.logger._traces),
            "discarded_audio_datagrams": self.datagrams.discarded,
            "handshake_seconds": round(self.ready_at - self.started_at, 3) if self.ready_at else None,
            "error": type(self.error).__name__ if self.error else None,
        }

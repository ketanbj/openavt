"""One independently signaled, audio-only WebRTC endpoint."""

from __future__ import annotations

import asyncio
import time
from fractions import Fraction
from typing import Callable

import av
import numpy as np
from aiortc import AudioStreamTrack, RTCConfiguration, RTCPeerConnection, RTCRtpSender, RTCSessionDescription

from openavt.transports.audio import PACKET_SAMPLES, RATE, AudioScheduler


class ScheduledAudio(AudioStreamTrack):
    def __init__(self):
        super().__init__()
        self.scheduler = AudioScheduler()
        self.started: float | None = None
        self.pts = 0

    async def recv(self):
        now = time.monotonic()
        if self.started is None:
            self.started = now
        await asyncio.sleep(max(0, self.started + self.pts / RATE - now))
        samples, future = self.scheduler.take()
        frame = av.AudioFrame(format="s16", layout="mono", samples=PACKET_SAMPLES)
        frame.planes[0].update(samples.astype("<i2").tobytes())
        frame.sample_rate, frame.pts, frame.time_base = RATE, self.pts, Fraction(1, RATE)
        self.pts += PACKET_SAMPLES
        self.scheduler.delivered(future)
        return frame

    def stop(self):
        self.scheduler.close()
        super().stop()


class WebRTCAdapter:
    """Offer/answer are signaling only. Application bytes never use signaling.

    Default ICE configuration is local. Supply ICE servers for a remote route;
    TURN, public Internet and transcoding compatibility require separate tests.
    """

    def __init__(self, *, profile: str = "pcm", ice_servers: list | None = None):
        if profile not in {"pcm", "voiceband"}:
            raise ValueError("unsupported audio profile")
        self.profile = profile
        self.pc = RTCPeerConnection(RTCConfiguration(iceServers=ice_servers or []))
        self.output = ScheduledAudio()
        self.pc.addTrack(self.output)
        transceiver = self.pc.getTransceivers()[0]
        codecs = [c for c in RTCRtpSender.getCapabilities("audio").codecs if c.mimeType == "audio/PCMU"]
        if not codecs:
            raise RuntimeError("PCMU is unavailable")
        transceiver.setCodecPreferences(codecs)
        if profile == "pcm":
            # Same pinned aiortc 1.15 buffering setting as the measured prototype.
            from openavt.transports.webrtc import _low_delay_audio

            _low_delay_audio(transceiver.receiver)
        self.connected = asyncio.Event()
        self.track_ready = asyncio.Event()
        self.receive: Callable = lambda _samples: None
        self.disconnected: Callable = lambda _error: None
        self.input = None
        self.consumer: asyncio.Task | None = None
        self.closed = False
        self.samples_rx = self.samples_tx = 0

        @self.pc.on("track")
        def track_received(track):
            if track.kind != "audio" or self.input is not None:
                self.disconnected(ConnectionError("unexpected WebRTC track"))
                return
            self.input = track
            self.track_ready.set()

        @self.pc.on("connectionstatechange")
        def state_changed():
            if self.pc.connectionState == "connected":
                self.connected.set()
            elif self.pc.connectionState in {"failed", "closed"} and not self.closed:
                self.disconnected(ConnectionError("WebRTC connection ended"))

    @staticmethod
    def _description(message: dict, kind: str) -> RTCSessionDescription:
        if (
            set(message) != {"sdp", "type"}
            or message["type"] != kind
            or not isinstance(message["sdp"], str)
            or len(message["sdp"]) > 65536
        ):
            raise ValueError("invalid WebRTC signaling description")
        if "m=application" in message["sdp"] or "m=video" in message["sdp"]:
            raise ValueError("only an audio media section is accepted")
        return RTCSessionDescription(**message)

    async def offer(self) -> dict:
        await self.pc.setLocalDescription(await self.pc.createOffer())
        return {"sdp": self.pc.localDescription.sdp, "type": self.pc.localDescription.type}

    async def answer(self, offer: dict) -> dict:
        await self.pc.setRemoteDescription(self._description(offer, "offer"))
        await self.pc.setLocalDescription(await self.pc.createAnswer())
        return {"sdp": self.pc.localDescription.sdp, "type": self.pc.localDescription.type}

    async def accept(self, answer: dict) -> None:
        await self.pc.setRemoteDescription(self._description(answer, "answer"))

    async def start(self, receive: Callable, disconnected: Callable) -> None:
        self.receive, self.disconnected = receive, disconnected
        await asyncio.wait_for(asyncio.gather(self.connected.wait(), self.track_ready.wait()), 15)
        if self.pc.sctp is not None:
            raise RuntimeError("an OpenAVT audio call cannot carry a data channel")
        # Drain pre-connection silence and stabilize the first RTP flight.
        self.consumer = asyncio.create_task(self._consume())
        await asyncio.sleep(0.1)

    async def _consume(self) -> None:
        resampler = av.AudioResampler(format="s16", layout="mono", rate=RATE)
        try:
            while True:
                frame = await self.input.recv()
                for pcm in resampler.resample(frame):
                    samples = pcm.to_ndarray().reshape(-1).astype(np.int16)
                    self.samples_rx += len(samples)
                    self.receive(samples)
        except asyncio.CancelledError:
            raise
        except Exception:
            if not self.closed:
                self.disconnected(ConnectionError("WebRTC audio ended"))

    async def send(self, samples, kind: str = "modem") -> None:
        self.samples_tx += len(samples)
        await self.output.scheduler.send(samples, kind)

    async def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        self.output.stop()
        if self.consumer:
            self.consumer.cancel()
            await asyncio.gather(self.consumer, return_exceptions=True)
        await self.pc.close()

    def summary(self) -> dict:
        return {
            "transport": "webrtc",
            "profile": self.profile,
            "codec": "PCMU",
            "audio_samples_rx": self.samples_rx,
            "audio_samples_tx": self.samples_tx,
            "data_channel": self.pc.sctp is not None,
        }

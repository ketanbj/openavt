"""Two live audio-only WebRTC endpoints; modem input is decoded RTP audio."""

from __future__ import annotations

import asyncio
import time
import wave
from collections import deque
from fractions import Fraction
from pathlib import Path

import av
import numpy as np
from aiortc import AudioStreamTrack, RTCConfiguration, RTCPeerConnection, RTCRtpSender
from aiortc.mediastreams import MediaStreamError

from openavt.modem import RATE, StreamDecoder

PACKET_SAMPLES = RATE // 50


def stereo_recording(directory: Path) -> None:
    """Combine already-received audio for listening, never for TLS delivery."""
    channels = []
    for name in ("desk", "agent"):  # caller on the left, service desk on the right
        with wave.open(str(directory / f"{name}-received.wav"), "rb") as source:
            channels.append(np.frombuffer(source.readframes(source.getnframes()), dtype="<i2"))
    length = max(map(len, channels))
    samples = np.zeros((length, 2), dtype="<i2")
    for index, channel in enumerate(channels):
        samples[: len(channel), index] = channel
    with wave.open(str(directory / "call-stereo.wav"), "wb") as output:
        output.setparams((2, 2, RATE, 0, "NONE", "not compressed"))
        output.writeframes(samples.tobytes())


class OutgoingAudio(AudioStreamTrack):
    def __init__(self, profile: str = "voiceband"):
        super().__init__()
        self.profile = profile
        self.pending = deque()
        self.pts = 0
        self.started: float | None = None
        self.lock = asyncio.Lock()
        self.sent_samples = 0

    async def send(self, samples: np.ndarray, kind: str = "speech") -> None:
        async with self.lock:
            future = asyncio.get_running_loop().create_future()
            self.pending.append([np.asarray(samples, dtype=np.int16), 0, future])
            await asyncio.wait_for(future, timeout=len(samples) / RATE + 10)
            # Leave a small turnaround/speech gap on the actual audio stream.
            if kind == "speech" or self.profile == "voiceband":
                await asyncio.sleep(0.08)

    async def recv(self):
        now = time.monotonic()
        if self.started is None:
            self.started = now
        await asyncio.sleep(max(0, self.started + self.pts / RATE - now))
        samples = np.zeros(PACKET_SAMPLES, dtype=np.int16)
        if self.pending:
            pending = self.pending[0]
            waveform, offset, future = pending
            amount = min(PACKET_SAMPLES, len(waveform) - offset)
            samples[:amount] = waveform[offset : offset + amount]
            pending[1] += amount
            self.sent_samples += amount
            if pending[1] == len(waveform):
                self.pending.popleft()
                if not future.done():
                    future.set_result(None)
        frame = av.AudioFrame(format="s16", layout="mono", samples=PACKET_SAMPLES)
        frame.planes[0].update(samples.astype("<i2").tobytes())
        frame.sample_rate = RATE
        frame.pts = self.pts
        frame.time_base = Fraction(1, RATE)
        self.pts += PACKET_SAMPLES
        return frame

    def stop(self):
        for _, _, future in self.pending:
            if not future.done():
                future.cancel()
        self.pending.clear()
        super().stop()


class SpeechDetector:
    def __init__(self):
        self.active = False
        self.parts = []
        self.silent_samples = 0
        self.voiced_samples = 0

    def clear(self):
        self.active = False
        self.parts = []
        self.silent_samples = 0
        self.voiced_samples = 0

    def feed(self, samples: np.ndarray) -> np.ndarray | None:
        rms = float(np.sqrt(np.mean(samples.astype(np.float64) ** 2)))
        if rms > 250:
            self.active = True
            self.silent_samples = 0
            self.voiced_samples += len(samples)
        elif self.active:
            self.silent_samples += len(samples)
        if not self.active:
            return None
        self.parts.append(samples.copy())
        if self.silent_samples >= int(0.8 * RATE):
            utterance = np.concatenate(self.parts) if self.voiced_samples >= RATE // 4 else None
            self.clear()
            return utterance
        if sum(map(len, self.parts)) > 30 * RATE:
            self.clear()
        return None


class AudioReceiver:
    def __init__(self, name: str, path: Path, log, profile: str = "voiceband"):
        self.name = name
        self.log = log
        if profile == "pcm":
            from openavt.pcm import StreamDecoder as PCMDecoder

            self.decoder = PCMDecoder()
        else:
            self.decoder = StreamDecoder()
        self.speech = SpeechDetector()
        self.utterances: asyncio.Queue[np.ndarray] = asyncio.Queue()
        self.on_frame = lambda *args: None
        self.packets = 0
        self.samples = 0
        self.suppress_until = 0.0
        self.file = wave.open(str(path), "wb")
        self.file.setparams((1, 2, RATE, 0, "NONE", "not compressed"))
        self.task: asyncio.Task | None = None

    async def consume(self, track):
        resampler = av.AudioResampler(format="s16", layout="mono", rate=RATE)
        try:
            while True:
                frame = await track.recv()
                self.packets += 1
                for pcm in resampler.resample(frame):
                    samples = pcm.to_ndarray().reshape(-1).astype(np.int16)
                    self.samples += len(samples)
                    self.file.writeframesraw(samples.astype("<i2").tobytes())
                    frames = self.decoder.feed(samples)
                    for sequence, kind, payload in frames:
                        self.log("audio_frame_rx", sequence=sequence, kind=kind, payload_bytes=len(payload))
                        self.on_frame(sequence, kind, payload)
                    if self.decoder.acquired or frames:
                        self.speech.clear()
                        self.suppress_until = time.monotonic() + 0.2
                    elif time.monotonic() > self.suppress_until:
                        utterance = self.speech.feed(samples)
                        if utterance is not None:
                            self.log("speech_received", duration_seconds=round(len(utterance) / RATE, 3))
                            await self.utterances.put(utterance)
        except (MediaStreamError, asyncio.CancelledError):
            pass
        except Exception as error:
            self.log("audio_receiver_error", error_type=type(error).__name__, reason=str(error))
            raise

    async def close(self):
        if self.task:
            self.task.cancel()
            await asyncio.gather(self.task, return_exceptions=True)
        self.file.close()

    def summary(self):
        return {
            "audio_packets_rx": self.packets,
            "audio_samples_rx": self.samples,
            "modem_good_frames": self.decoder.good_frames,
            "modem_bad_frames": self.decoder.bad_frames,
            "preamble_acquisitions": self.decoder.acquisitions,
        }


def _low_delay_audio(receiver) -> None:
    """aiortc 1.15 adapter: one 20 ms frame of prefetch for the local demo.

    No public jitter-buffer setting exists. Fail closed if its layout changes;
    this alters buffering only, never RTP audio bytes or the decoded samples.
    """
    from aiortc.jitterbuffer import JitterBuffer

    jitter = getattr(receiver, "_RTCRtpReceiver__jitter_buffer", None)
    if not isinstance(jitter, JitterBuffer) or jitter.capacity != 16 or jitter._prefetch != 4:
        raise RuntimeError("unsupported aiortc audio jitter-buffer layout")
    jitter._prefetch = 1


class AudioCall:
    def __init__(self, directory: Path, log, codec: str = "PCMU", *, profile: str = "voiceband"):
        if profile not in ("voiceband", "pcm"):
            raise ValueError(f"unknown modem profile: {profile}")
        if profile == "pcm" and codec != "PCMU":
            raise ValueError("PCM profile requires an unchanged 64 kbps PCMU audio path")
        self.profile = profile
        self.codec = codec
        self.peers = {}
        self.outputs = {}
        self.inputs = {}
        self.connected = {}
        self.log = log
        for name in ("agent", "desk"):
            pc = RTCPeerConnection(RTCConfiguration(iceServers=[]))
            outgoing = OutgoingAudio(profile)
            receiver = AudioReceiver(
                name,
                directory / f"{name}-received.wav",
                lambda event, name=name, **fields: log(name, event, **fields),
                profile,
            )
            connected = asyncio.Event()
            self.peers[name], self.outputs[name], self.inputs[name], self.connected[name] = (
                pc,
                outgoing,
                receiver,
                connected,
            )
            pc.addTrack(outgoing)
            if profile == "pcm":
                _low_delay_audio(pc.getTransceivers()[0].receiver)
            preferences = [
                c
                for c in RTCRtpSender.getCapabilities("audio").codecs
                if c.mimeType.lower() == f"audio/{codec}".lower()
            ]
            if not preferences:
                raise ValueError(f"unsupported audio codec: {codec}")
            pc.getTransceivers()[0].setCodecPreferences(preferences)

            @pc.on("track")
            def on_track(track, receiver=receiver):
                if track.kind != "audio":
                    raise RuntimeError("only audio tracks are allowed")
                receiver.task = asyncio.create_task(receiver.consume(track))

            @pc.on("connectionstatechange")
            def on_state(pc=pc, connected=connected, name=name):
                log(name, "webrtc_state", state=pc.connectionState)
                if pc.connectionState == "connected":
                    connected.set()

    async def connect(self):
        agent, desk = self.peers["agent"], self.peers["desk"]
        await agent.setLocalDescription(await agent.createOffer())
        await desk.setRemoteDescription(agent.localDescription)
        await desk.setLocalDescription(await desk.createAnswer())
        await agent.setRemoteDescription(desk.localDescription)
        # SDP is the only out-of-band peer exchange; there is no data channel.
        if any(pc.sctp is not None for pc in self.peers.values()):
            raise RuntimeError("unexpected WebRTC data channel")
        await asyncio.wait_for(asyncio.gather(*(e.wait() for e in self.connected.values())), timeout=15)
        await asyncio.sleep(0.3)

    async def stats(self):
        result = {}
        for name, peer in self.peers.items():
            stats = await peer.getStats()
            result[name] = [
                {
                    k: v
                    for k, v in vars(item).items()
                    if k
                    in (
                        "type",
                        "packetsSent",
                        "packetsReceived",
                        "bytesSent",
                        "packetsLost",
                        "jitter",
                        "kind",
                    )
                }
                for item in stats.values()
                if item.type in ("inbound-rtp", "outbound-rtp")
            ]
        return result

    async def close(self):
        await asyncio.gather(*(pc.close() for pc in self.peers.values()))
        await asyncio.gather(*(receiver.close() for receiver in self.inputs.values()))

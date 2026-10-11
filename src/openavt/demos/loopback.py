"""Real mutual TLS 1.3 over a simple WAV/FSK loopback with known symbol timing."""

from __future__ import annotations

import argparse
import array
import json
import shutil
import ssl
import tempfile
from pathlib import Path

from openavt.pki import endpoints, issue_certificates
from openavt.protocol import (
    ACK,
    BAUD,
    DATA,
    HEADER,
    MAX_PAYLOAD,
    PREAMBLE,
    RATE,
    SAMPLES_PER_BIT,
    TONES,
    FrameError,
    demodulate,
    frame,
    modulate,
    read_wav,
    unframe,
    write_wav,
)
from openavt.tls import Endpoint


class AudioLink:
    def __init__(self, directory: Path, impairments: bool):
        self.directory = directory
        self.impairments = impairments
        self.corrupted = False
        self.lost_ack = False
        self.sequence = {"agent": 0, "desk": 0}
        self.expected = {"agent": 0, "desk": 0}
        self.events: list[dict] = []
        self.timeline = array.array("h")
        self.tls_bytes = 0
        self.retries = 0
        self.duplicates = 0
        self.phase = "handshake"

    def acoustic_frame(
        self, raw: bytes, sender: str, kind: str, corrupt: bool = False, drop: bool = False
    ) -> bytes:
        samples = modulate(raw)
        if corrupt:
            # Replace one complete payload bit with the opposite tone. This
            # damages the waveform, rather than bypassing the audio decoder.
            bit = (len(PREAMBLE) + HEADER.size) * 8
            start = bit * SAMPLES_PER_BIT
            old = (raw[bit // 8] >> (7 - bit % 8)) & 1
            samples[start : start + SAMPLES_PER_BIT] = array.array("h", TONES[1 - old])
        filename = f"{len(self.events) + 1:03d}-{sender}-{kind}.wav"
        path = self.directory / filename
        write_wav(path, samples)
        self.timeline.extend(samples)
        self.timeline.extend([0] * (RATE // 10))
        self.events.append(
            {
                "file": filename,
                "sender": sender,
                "kind": kind,
                "phase": self.phase,
                "wire_bytes": len(raw),
                "audio_seconds": len(samples) / RATE,
                "corrupted": corrupt,
                "dropped": drop,
            }
        )
        return b"" if drop else demodulate(read_wav(path))

    def transfer(self, source: Endpoint, destination: Endpoint) -> int:
        wire = source.outgoing.read()
        for offset in range(0, len(wire), MAX_PAYLOAD):
            payload = wire[offset : offset + MAX_PAYLOAD]
            sequence = self.sequence[source.name]
            raw = frame(sequence, DATA, payload)
            for attempt in range(4):
                corrupt = self.impairments and not self.corrupted
                if corrupt:
                    self.corrupted = True
                received = self.acoustic_frame(raw, source.name, "data", corrupt=corrupt)
                try:
                    number, kind, decoded = unframe(received)
                except FrameError:
                    self.retries += 1
                    continue
                if kind != DATA:
                    raise FrameError("expected DATA")
                expected = self.expected[source.name]
                if number == expected:
                    destination.incoming.write(decoded)
                    self.expected[source.name] += 1
                    self.tls_bytes += len(decoded)
                elif number == expected - 1:
                    self.duplicates += 1
                else:
                    raise FrameError("out-of-order frame")
                drop = self.impairments and not self.lost_ack
                if drop:
                    self.lost_ack = True
                acknowledged = self.acoustic_frame(frame(number, ACK), destination.name, "ack", drop=drop)
                try:
                    ack_number, ack_kind, _ = unframe(acknowledged)
                except FrameError:
                    self.retries += 1
                    continue
                if (ack_number, ack_kind) != (sequence, ACK):
                    raise FrameError("invalid acknowledgement")
                self.sequence[source.name] += 1
                break
            else:
                raise FrameError("retry budget exceeded")
        return len(wire)

    def finish(self, result: dict) -> dict:
        write_wav(self.directory / "call.wav", self.timeline)
        handshake = [event for event in self.events if event["phase"] == "handshake"]
        result.update(
            {
                "transport": "TLS bytes -> binary FSK -> PCM WAV -> binary FSK -> TLS bytes",
                "sample_rate": RATE,
                "raw_bits_per_second": BAUD,
                "tls_bytes_delivered": self.tls_bytes,
                "audio_seconds": round(len(self.timeline) / RATE, 3),
                "handshake_tone_seconds": round(sum(e["audio_seconds"] for e in handshake), 3),
                "retries": self.retries,
                "duplicates_suppressed": self.duplicates,
                "events": self.events,
            }
        )
        (self.directory / "trace.json").write_text(json.dumps(result, indent=2) + "\n")
        return result


def handshake(agent: Endpoint, desk: Endpoint, link: AudioLink) -> None:
    for _ in range(20):
        moved = 0
        for source, destination in ((agent, desk), (desk, agent)):
            if not source.ready:
                try:
                    source.tls.do_handshake()
                    source.ready = True
                except ssl.SSLWantReadError:
                    pass
            moved += link.transfer(source, destination)
        if agent.ready and desk.ready:
            return
        if not moved:
            raise RuntimeError("TLS handshake stalled")
    raise RuntimeError("TLS handshake did not finish")


def send_json(source: Endpoint, destination: Endpoint, link: AudioLink, message: dict) -> dict:
    data = json.dumps(message, separators=(",", ":")).encode() + b"\n"
    remaining = data
    while remaining:
        consumed = source.tls.write(remaining)
        remaining = remaining[consumed:]
        link.transfer(source, destination)
    received = bytearray()
    while b"\n" not in received:
        received.extend(destination.tls.read(16384))
    return json.loads(received)


def run(output: Path, scenario: str) -> dict:
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise ValueError(f"output directory must be empty: {output}")
    link = AudioLink(output, impairments=scenario == "loss")
    with tempfile.TemporaryDirectory(prefix="tls-audio-demo-") as temporary:
        certificates = Path(temporary)
        issue_certificates(certificates, rogue=scenario == "untrusted")
        shutil.copyfile(certificates / "root.pem", output / "demo-root.pem")
        agent, desk = endpoints(certificates)
        try:
            handshake(agent, desk, link)
        except ssl.SSLCertVerificationError as error:
            if scenario != "untrusted":
                raise
            return link.finish(
                {
                    "scenario": scenario,
                    "result": "untrusted agent rejected",
                    "tls_error": error.verify_message,
                }
            )

        # Deliberately small fixture: authenticated agent identity has a fixed
        # read-only policy. This is not customer consent or OAuth delegation.
        peer = desk.tls.getpeercert()
        identities = [value for kind, value in peer.get("subjectAltName", ()) if kind == "URI"]
        expected_identity = "urn:demo:agent:assistant"
        if expected_identity not in identities:
            raise RuntimeError("unexpected authenticated agent identity")
        link.phase = "request"
        request = {
            "id": "request-1",
            "action": "address.change" if scenario == "scope" else "order.read",
            "order": "demo-order-1234",
        }
        received = send_json(agent, desk, link, request)
        allowed = received["action"] == "order.read" and received["order"] == "demo-order-1234"
        response = {
            "id": received["id"],
            "result": "allowed" if allowed else "denied",
            "reason": "read-only demo policy",
            "status": "shipped" if allowed else None,
        }
        protected_response = send_json(desk, agent, link, response)
        if protected_response != response:
            raise RuntimeError("response mismatch")
        result = {
            "scenario": scenario,
            "result": protected_response["result"],
            "tls_version": agent.tls.version(),
            "cipher": agent.tls.cipher()[0],
            "authenticated_agent": expected_identity,
            "request": received,
            "response": protected_response,
        }
        return link.finish(result)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", choices=("valid", "loss", "untrusted", "scope"), default="valid")
    parser.add_argument("--output", type=Path)
    options = parser.parse_args(argv)
    output = options.output or Path("output") / options.scenario
    if options.output is None:
        suffix = 2
        while output.exists():
            output = Path("output") / f"{options.scenario}-{suffix}"
            suffix += 1
    result = run(output, options.scenario)
    for field in (
        "result",
        "tls_version",
        "authenticated_agent",
        "tls_bytes_delivered",
        "handshake_tone_seconds",
        "audio_seconds",
        "retries",
        "duplicates_suppressed",
    ):
        if field in result:
            print(f"{field}: {result[field]}")
    print(f"WAV audio and trace: {output.resolve()}")


if __name__ == "__main__":
    main()

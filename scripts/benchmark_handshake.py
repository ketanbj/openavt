"""Repeat fresh live audio calls and write public, transcript-free evidence."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import hashlib
import importlib.metadata
import json
import math
import platform
import ssl
import statistics
from datetime import datetime, timezone
from pathlib import Path

from openavt.demos.live import run


async def benchmark(output: Path, runs: int, profile: str) -> dict:
    output.mkdir(parents=True, exist_ok=False)
    measurements = []
    for index in range(runs):
        directory = output / f"call-{index + 1:03}"
        with (output / "trace.log").open("a") as log, contextlib.redirect_stdout(log):
            report = await run(directory, "valid", True, "PCMU", profile)
        if not report["verified"] or any(item["session_reused"] for item in report["tls"].values()):
            raise RuntimeError("call failed fresh mutual authentication or protected request verification")
        measurements.append(
            {
                "run": index + 1,
                "handshake_seconds": report["handshake_wall_seconds"],
                "protected_round_trip_seconds": report["request_round_trip_seconds"],
                "verified": report["verified"],
                "tls": report["tls"],
                "audio": report["audio"],
                "rtp_stats": report["rtp_stats"],
                "report_sha256": hashlib.sha256((directory / "report.json").read_bytes()).hexdigest(),
                "recording_sha256": hashlib.sha256((directory / "call-stereo.wav").read_bytes()).hexdigest(),
            }
        )
        print(f"Call {index + 1}/{runs}: {report['handshake_wall_seconds']:.3f}s", flush=True)
    timings = sorted(item["handshake_seconds"] for item in measurements)
    result = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "environment": {
            "os": platform.system(),
            "os_release": platform.release(),
            "arch": platform.machine(),
            "python": platform.python_version(),
            "openssl": ssl.OPENSSL_VERSION,
            "dependencies": {name: importlib.metadata.version(name) for name in ("aiortc", "av", "numpy")},
        },
        "profile": profile,
        "codec": "G.711 PCMU: 64,000 bits/s audio payload; excludes RTP/SRTP/IP headers",
        "modem_raw_bitrate_bps": 56000 if profile == "pcm" else 1000,
        "conditions": "two local audio-only WebRTC peers; fresh CA, contexts and full TLS 1.3 mTLS per run; P-256; no session reuse or data channel",
        "timing_boundary": "client TLS start through both authenticated endpoints and final audio ACK; excludes PKI/call setup and LLM/speech",
        "statistics": {
            "runs": runs,
            "min_seconds": min(timings),
            "median_seconds": statistics.median(timings),
            "p95_seconds": timings[math.ceil(0.95 * runs) - 1],
            "max_seconds": max(timings),
            "all_under_one_second": max(timings) < 1.0,
        },
        "measurements": measurements,
    }
    (output / "summary.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, default=20)
    parser.add_argument("--profile", choices=("voiceband", "pcm"), default="pcm")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--require-under-one-second", action="store_true")
    args = parser.parse_args()
    if args.runs < 1:
        parser.error("--runs must be positive")
    result = asyncio.run(benchmark(args.output, args.runs, args.profile))
    print(json.dumps(result["statistics"], indent=2))
    if args.require_under_one_second and not result["statistics"]["all_under_one_second"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

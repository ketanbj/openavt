#!/usr/bin/env python3
"""A real-time local WebRTC audio call with two OpenAI-powered agents."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import ssl
import sys
import tempfile
import time
import uuid
from functools import partial
from pathlib import Path

from dotenv import load_dotenv

from openavt.channel import AudioTLS
from openavt.demos.policy import decide
from openavt.pki import endpoints, issue_certificates
from openavt.transports.webrtc import AudioCall, stereo_recording


class Trace:
    def __init__(self, output: Path):
        self.output = output
        self.started = time.monotonic()
        self.events = []

    def log(self, role: str, event: str, **fields):
        entry = {"seconds": round(time.monotonic() - self.started, 3), "role": role, "event": event, **fields}
        self.events.append(entry)
        if event not in ("audio_frame_tx", "audio_frame_rx"):
            print(json.dumps(entry), flush=True)

    def save(self, report: dict):
        report["events"] = self.events
        (self.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")


async def run(output: Path, scenario: str, transport_only: bool, codec: str) -> dict:
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise ValueError("output directory must be empty")
    trace = Trace(output)
    call = AudioCall(output, trace.log, codec)
    report = {
        "mode": "transport_only" if transport_only else "openai_agents",
        "scenario": scenario,
        "codec": codec,
        "call_path": "two local WebRTC peers over live UDP/SRTP audio",
        "inner_tls_path": "FSK tones in decoded RTP audio; no WebRTC data channel",
        "llm_agents_executed": False,
        "verified": False,
    }
    tasks = []
    sessions = {}
    client = None
    agents = {}
    try:
        with tempfile.TemporaryDirectory(prefix="tls-live-cert-") as temporary:
            certificates = Path(temporary)
            issue_certificates(certificates, rogue=scenario == "untrusted")
            shutil.copyfile(certificates / "root.pem", output / "demo-root.pem")
            for endpoint in endpoints(certificates):
                name = endpoint.name
                session = AudioTLS(endpoint, call.outputs[name].send, partial(trace.log, name), scenario)
                sessions[name] = session
                call.inputs[name].on_frame = session.receive_frame
            await call.connect()
            agent_tls, desk_tls = sessions["agent"], sessions["desk"]
            tasks.append(asyncio.create_task(desk_tls.run()))

            if not transport_only:
                from openai import AsyncOpenAI

                from openavt.agents.openai import VoiceAgent

                client = AsyncOpenAI(timeout=45, max_retries=1)
                for name in ("agent", "desk"):
                    agents[name] = VoiceAgent(
                        name, client, call.outputs[name].send, call.inputs[name], partial(trace.log, name)
                    )
                await agents["desk"].greet()
                function_call, arguments = await agents["agent"].request(scenario)
                await agents["agent"].speak(arguments["announcement"])
                await asyncio.sleep(1.0)  # finish the receiver's speech turn before modem bursts
                request = {
                    "id": str(uuid.uuid4()),
                    "action": arguments["action"],
                    "order": arguments["order"],
                }
            else:
                request = {
                    "id": str(uuid.uuid4()),
                    "action": "address.change" if scenario == "scope" else "order.read",
                    "order": "demo-order-1234",
                }

            handshake_start = time.monotonic()
            tasks.append(asyncio.create_task(agent_tls.run(initiate=True)))
            try:
                await asyncio.gather(agent_tls.wait_ready(), desk_tls.wait_ready())
            except ssl.SSLError as error:
                if scenario != "untrusted" or not isinstance(desk_tls.error, ssl.SSLCertVerificationError):
                    raise
                report.update(
                    verified=True, result="untrusted agent rejected", rejection_type=type(error).__name__
                )
                return report
            report["handshake_wall_seconds"] = round(time.monotonic() - handshake_start, 3)
            trace.log(
                "call", "both_tls_endpoints_authenticated", handshake_seconds=report["handshake_wall_seconds"]
            )

            request_start = time.monotonic()
            await agent_tls.send_json(request)
            received_request = await desk_tls.receive_json()
            decision = decide(desk_tls.endpoint.tls.getpeercert(), received_request)
            if agents:
                reply_call, spoken_reply = await agents["desk"].prepare_reply(received_request, decision)
            await desk_tls.send_json(decision)
            protected_response = await agent_tls.receive_json()
            report["request_round_trip_seconds"] = round(time.monotonic() - request_start, 3)
            if protected_response["id"] != request["id"] or protected_response != decision:
                raise RuntimeError("protected response does not match the outstanding request")
            if agents:
                await asyncio.sleep(0.3)
                await agents["desk"].speak(spoken_reply)
                await agents["agent"].finish_request(function_call, protected_response)
                await agents["desk"].finish_reply(reply_call, decision)

            expected = "denied" if scenario == "scope" else "allowed"
            report.update(
                request=received_request,
                response=protected_response,
                result=protected_response["result"],
                request_workflow_seconds=round(time.monotonic() - request_start, 3),
                llm_agents_executed=bool(agents)
                and all(a.calls["llm"] >= 2 and a.calls["asr"] >= 1 for a in agents.values()),
                verified=protected_response["result"] == expected,
            )
            if scenario == "loss":
                report["verified"] = (
                    report["verified"] and agent_tls.retries >= 2 and desk_tls.duplicates >= 1
                )
            if not transport_only:
                report["verified"] = report["verified"] and report["llm_agents_executed"]
            return report
    finally:
        failure = sys.exception()
        if failure:
            report["failure"] = {
                "type": type(failure).__name__,
                "status_code": getattr(failure, "status_code", None),
                "code": getattr(failure, "code", None),
                "param": getattr(failure, "param", None),
            }
        report["call_wall_seconds"] = round(time.monotonic() - trace.started, 3)
        report["tls"] = {name: session.summary() for name, session in sessions.items()}
        report["audio"] = {name: receiver.summary() for name, receiver in call.inputs.items()}
        report["agents"] = {name: agent.summary() for name, agent in agents.items()}
        report["rtp_stats"] = await call.stats()
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await asyncio.gather(*(session.close() for session in sessions.values()))
        await call.close()
        stereo_recording(output)
        report["recording"] = "call-stereo.wav (caller left, service desk right)"
        if client:
            await client.close()
        trace.save(report)


def main(argv: list[str] | None = None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--transport-only",
        action="store_true",
        help="test live audio TLS without claiming an OpenAI-agent run",
    )
    parser.add_argument("--scenario", choices=("valid", "scope", "loss", "untrusted"), default="valid")
    parser.add_argument("--codec", choices=("PCMU", "opus"), default="PCMU")
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--env-file",
        type=Path,
        default=Path.cwd() / ".env",
        help="dotenv file to load; existing environment variables take precedence",
    )
    options = parser.parse_args(argv)
    load_dotenv(options.env_file)
    if not options.transport_only and not os.getenv("OPENAI_API_KEY"):
        parser.error(
            "OPENAI_API_KEY is missing. Configure it in .env or the environment. "
            "Use --transport-only only for the separate transport test."
        )
    output = options.output or Path("output") / ("webrtc" if options.transport_only else "agents")
    if options.output is None:
        base, suffix = output, 2
        while output.exists():
            output = base.with_name(f"{base.name}-{suffix}")
            suffix += 1
    try:
        result = asyncio.run(
            asyncio.wait_for(
                run(output, options.scenario, options.transport_only, options.codec), timeout=240
            )
        )
    except Exception as error:
        # Do not echo provider authentication error bodies or credentials.
        print(f"Run failed: {type(error).__name__}. Inspect {output / 'report.json'} for transport evidence.")
        raise SystemExit(1)
    print(json.dumps({k: v for k, v in result.items() if k not in ("events", "rtp_stats")}, indent=2))
    print(f"Evidence: {output.resolve() / 'report.json'}")
    if not result["verified"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

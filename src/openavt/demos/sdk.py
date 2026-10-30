"""Two independent agents use the same VoiceSession and Gateway over audio."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import tempfile
import threading
from pathlib import Path

from openavt.authority.ca import AgentAuthority
from openavt.authority.client import AuthorityClient
from openavt.authority.common import canonical, private_write
from openavt.authority.delegation import BusinessAuthority
from openavt.authority.service import AuthorityServer

CASES = (
    "valid",
    "scope",
    "replay",
    "other_customer",
    "expired",
    "revoked_grant",
    "wrong_key",
    "revoked_certificate",
)


def provision(
    directory: Path, enrollment: AuthorityClient, authority: AgentAuthority, business: BusinessAuthority
):
    alice = business.register_customer("alice", ["demo-order-1234"])
    bob = business.register_customer("bob", ["bob-order-5678"])
    account = enrollment.account()
    bundle = directory / "identity"
    enrolled = enrollment.enroll(account, "assistant", (authority.state / "root.pem").read_bytes(), bundle)
    authority.provision_service(bundle)
    other = directory / "other"
    enrollment.enroll(account, "other", (authority.state / "root.pem").read_bytes(), other)
    certificate = (bundle / "agent.pem").read_text()
    probes = []
    valid = None
    for case in CASES:
        grant = (
            valid
            if case == "replay"
            else enrollment.consent(
                bob if case == "other_customer" else alice,
                (other / "agent.pem").read_text() if case == "wrong_key" else certificate,
                "order.read",
                "bob-order-5678" if case == "other_customer" else "demo-order-1234",
                ttl=1 if case == "expired" else 300,
            )
        )
        if case == "valid":
            valid = grant
        if case == "revoked_grant":
            business.revoke(grant["grant_id"], alice["credential"])
        probes.append(
            {
                "case": case,
                "action": "address.change" if case == "scope" else "order.read",
                "resource": "demo-order-1234",
                "customer": "alice",
                "grant": grant["delegation"],
                "expires": grant["expires"],
            }
        )
    return {
        "bundle": str(bundle),
        "probes": probes,
        "authority_url": enrollment.url,
        "account_credential": account["credential"],
        "certificate_serial": enrolled["serial"],
    }


async def worker_message(worker, timeout: float = 180) -> dict:
    line = await asyncio.wait_for(worker.stdout.readline(), timeout)
    if not line or len(line) > 65536:
        raise RuntimeError("agent worker ended without a valid report")
    message = json.loads(line)
    if "error_type" in message:
        raise RuntimeError(
            "agent worker failed: " + message["error_type"] + " " + str(message.get("locations", []))
        )
    return message


async def run(
    output: Path,
    *,
    transport: str = "webrtc",
    agents: bool = False,
    protocol: str = "tls",
    profile: str = "pcm",
    loss: bool = False,
) -> dict:
    if protocol not in {"tls", "quic"} or profile not in {"pcm", "voiceband"}:
        raise ValueError("unsupported session protocol or profile")
    if profile == "voiceband" and transport != "webrtc":
        raise ValueError("the provider SDK demo supports the PCM profile")
    if loss and transport == "twilio-live":
        raise ValueError("audio fault injection is only supported on local calls")
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise ValueError("output directory must be empty")
    workers, relay, api = [], None, None
    thread = None
    with tempfile.TemporaryDirectory(prefix="openavt-sdk-") as temporary:
        directory = Path(temporary)
        authority = AgentAuthority.initialize(directory / "ava")
        business = BusinessAuthority.initialize(directory / "business", authority)
        api = AuthorityServer(("127.0.0.1", 0), authority, business)
        thread = threading.Thread(target=api.serve_forever, daemon=True)
        thread.start()
        enrollment = AuthorityClient(f"http://127.0.0.1:{api.server_port}")
        try:
            caller = provision(directory, enrollment, authority, business)
            common = {
                "agents": agents,
                "protocol": protocol,
                "profile": profile,
                "loss": loss,
                "bundle": caller["bundle"],
                "request_count": len(CASES),
                "handshake_timeout": 150
                if profile == "voiceband"
                else (60 if transport == "twilio-live" else 30 if loss else 15),
            }
            relay_url = None
            if transport in {"twilio-emulated", "twilio-live"}:
                from openavt.demos.twilio_bridge import ProviderBridge

                relay = ProviderBridge(live=transport == "twilio-live")
                relay_url = await relay.start()
                common["twilio_account_sid"] = relay.account_sid
            for role, configuration in (
                ("agent", {**common, **caller}),
                ("desk", {**common, "ava": str(authority.state), "business": str(business.state)}),
            ):
                path = directory / f"{role}.json"
                private_write(path, canonical(configuration))
                args = [
                    sys.executable,
                    "-I",
                    "-m",
                    "openavt.demos.sdk_worker",
                    "--role",
                    role,
                    "--config",
                    str(path),
                    "--transport",
                    "webrtc" if transport == "webrtc" else "twilio",
                ]
                if relay_url:
                    args += ["--relay", relay_url]
                worker = await asyncio.create_subprocess_exec(
                    *args,
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                workers.append(worker)
            if transport == "webrtc":
                offer = await worker_message(workers[0])
                assert set(offer) == {"sdp", "type"}
                workers[1].stdin.write(canonical(offer) + b"\n")
                await workers[1].stdin.drain()
                answer = await worker_message(workers[1])
                assert set(answer) == {"sdp", "type"}
                workers[0].stdin.write(canonical(answer) + b"\n")
                await workers[0].stdin.drain()
            else:
                ready = await asyncio.gather(*(worker_message(w) for w in workers))
                if ready != [{"ready": "agent"}, {"ready": "desk"}]:
                    raise RuntimeError("provider workers did not attach")
                await relay.connect()
            messages = await asyncio.gather(
                *(worker_message(w, timeout=600 if profile == "voiceband" else 180) for w in workers)
            )
            caller_report, business_report = (message["report"] for message in messages)
            codes = await asyncio.gather(*(w.wait() for w in workers))
            verified = (
                codes == [0, 0]
                and caller_report["pid"] != business_report["pid"]
                and all(r["verified"] for r in caller_report["results"])
                and business_report["gateway"] == {"requests": 8, "handler_executions": 1, "denials": 7}
            )
            report = {
                "verified": verified,
                "transport": transport,
                "protocol": protocol,
                "profile": profile,
                "audio_fault_injection": loss,
                "openai_agents": agents,
                "independent_processes": True,
                "protected_request_delivery": "audio only",
                "provider_network_verified": transport == "twilio-live" and verified,
                "caller": caller_report,
                "business": business_report,
                "provider": relay.summary() if relay else None,
                "scope": "Local demo identities and simulated customer consent; fixed read-only business handler",
            }
            (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
            if not verified:
                raise RuntimeError("SDK demonstration verification failed")
            return report
        finally:
            for worker in workers:
                if worker.returncode is None:
                    worker.terminate()
                    try:
                        await asyncio.wait_for(worker.wait(), 5)
                    except TimeoutError:
                        worker.kill()
                        await worker.wait()
            if relay:
                await relay.close()
            if api:
                await asyncio.to_thread(api.shutdown)
                api.server_close()
                thread.join(timeout=5)


def main(argv: list[str] | None = None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--transport", choices=("webrtc", "twilio-emulated", "twilio-live"), default="webrtc")
    parser.add_argument("--agents", action="store_true", help="run two independent OpenAI voice agents")
    parser.add_argument("--protocol", choices=("tls", "quic"), default="tls")
    parser.add_argument("--profile", choices=("pcm", "voiceband"), default="pcm")
    parser.add_argument(
        "--loss", action="store_true", help="inject dropped, damaged and duplicate audio bursts locally"
    )
    parser.add_argument("--env-file", type=Path, default=Path(".env"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    if args.agents or args.transport == "twilio-live":
        from dotenv import load_dotenv

        load_dotenv(args.env_file, override=False)
    if args.agents:
        import os

        if not os.getenv("OPENAI_API_KEY"):
            parser.error("Configure OPENAI_API_KEY locally, or omit --agents")
    if args.transport == "twilio-live":
        from openavt.transports.twilio import TwilioConfig

        try:
            TwilioConfig.from_env()
        except ValueError as error:
            parser.error(str(error))
    if args.output is None:
        Path("output").mkdir(exist_ok=True)
    output = args.output or Path(tempfile.mkdtemp(prefix="sdk-call-", dir="output"))
    report = asyncio.run(
        run(
            output,
            transport=args.transport,
            agents=args.agents,
            protocol=args.protocol,
            profile=args.profile,
            loss=args.loss,
        )
    )
    print(
        json.dumps(
            {
                "verified": report["verified"],
                "transport": report["transport"],
                "protocol": report["protocol"],
                "independent_processes": report["independent_processes"],
                "handshake_seconds": round(report["caller"]["sdk"]["handshake_wall_seconds"], 3),
                "handler_executions": report["business"]["gateway"]["handler_executions"],
                "provider_network_verified": report["provider_network_verified"],
                "report": str(output / "report.json"),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()

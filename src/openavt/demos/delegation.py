"""Self-service enrollment and customer delegation over a real audio TLS call."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import tempfile
import threading
import time
import uuid
from functools import partial
from pathlib import Path

from dotenv import load_dotenv

from openavt.authority.ca import AgentAuthority
from openavt.authority.client import AuthorityClient
from openavt.authority.delegation import BusinessAuthority
from openavt.authority.service import AuthorityServer
from openavt.channel import AudioTLS
from openavt.demos.live import Trace
from openavt.pki import endpoints
from openavt.transports.webrtc import AudioCall, stereo_recording

EXPECTED = {
    "valid": "verified_customer_delegation",
    "expired": "delegation_expired_or_not_yet_valid",
    "other_customer": "wrong_customer",
    "scope": "outside_delegated_scope",
    "replay": "delegation_already_used",
    "revoked_grant": "delegation_revoked_or_unknown",
    "wrong_key": "wrong_agent_binding",
    "revoked_certificate": "certificate_revoked_or_unknown",
}


async def run(output: Path, use_agents: bool = False) -> dict:
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise ValueError("output directory must be empty")
    trace = Trace(output)
    report = {
        "verified": False,
        "mode": "openai_agents" if use_agents else "transport_only",
        "profile": "pcm",
        "enrollment": "HTTP account/order/key proof; client retains private key; pinned root",
        "identity_assurance": "pseudonymous agent; operator-provisioned demo customers",
        "results": [],
        "llm_agents_executed": False,
    }
    tasks, sessions, voice_agents = [], {}, {}
    call, api, thread, client = None, None, None, None
    try:
        with tempfile.TemporaryDirectory(prefix="openavt-ava-demo-") as temp:
            directory = Path(temp)
            authority = AgentAuthority.initialize(directory / "ava")
            business = BusinessAuthority.initialize(directory / "business", authority)
            alice = business.register_customer("alice", ["demo-order-1234"])
            bob = business.register_customer("bob", ["bob-order-5678"])
            api = AuthorityServer(("127.0.0.1", 0), authority, business)
            thread = threading.Thread(target=api.serve_forever, daemon=True)
            thread.start()
            enrollment = AuthorityClient(f"http://127.0.0.1:{api.server_port}")
            account = enrollment.account()
            root = (authority.state / "root.pem").read_bytes()
            bundle = directory / "agent"
            enrolled = enrollment.enroll(account, "assistant", root, bundle)
            # Same principal, renewed leaf: old consent must not bind to it.
            renewed = directory / "renewed"
            enrollment.enroll(account, "assistant", root, renewed, bundle / "agent.key")
            other_agent = directory / "other-agent"
            enrollment.enroll(account, "other-agent", root, other_agent)
            authority.provision_service(bundle)
            report["certificate_renewal_verified"] = (bundle / "agent.pem").read_bytes() != (
                renewed / "agent.pem"
            ).read_bytes()
            shutil.copyfile(authority.state / "root.pem", output / "demo-root.pem")
            shutil.copyfile(business.state / "grant-public.pem", output / "business-grant-public.pem")
            call = AudioCall(output, trace.log, "PCMU", profile="pcm")
            for endpoint in endpoints(bundle):
                session = AudioTLS(
                    endpoint,
                    call.outputs[endpoint.name].send,
                    partial(trace.log, endpoint.name),
                    profile="pcm",
                )
                sessions[endpoint.name] = session
                call.inputs[endpoint.name].on_frame = session.receive_frame
            await call.connect()
            agent, desk = sessions["agent"], sessions["desk"]
            tasks.append(asyncio.create_task(desk.run()))
            action, resource = "order.read", "demo-order-1234"
            if use_agents:
                from openai import AsyncOpenAI

                from openavt.agents.openai import VoiceAgent

                client = AsyncOpenAI(timeout=45, max_retries=1)
                for name in ("agent", "desk"):
                    voice_agents[name] = VoiceAgent(
                        name, client, call.outputs[name].send, call.inputs[name], partial(trace.log, name)
                    )
                await voice_agents["desk"].greet()
                function_call, arguments = await voice_agents["agent"].request("valid")
                action, resource = arguments["action"], arguments["order"]
                await voice_agents["agent"].speak(arguments["announcement"])
                await asyncio.sleep(1.0)
            start = time.monotonic()
            tasks.append(asyncio.create_task(agent.run(initiate=True)))
            await asyncio.gather(agent.wait_ready(), desk.wait_ready())
            report["handshake_wall_seconds"] = round(time.monotonic() - start, 3)
            peer_der = desk.endpoint.tls.getpeercert(binary_form=True)
            original_cert = (bundle / "agent.pem").read_text()
            used_grant, allowed = None, None
            for scenario, expected_reason in EXPECTED.items():
                credentials = bob if scenario == "other_customer" else alice
                cert = (other_agent / "agent.pem").read_text() if scenario == "wrong_key" else original_cert
                target_resource = "bob-order-5678" if scenario == "other_customer" else resource
                grant = (
                    used_grant
                    if scenario == "replay"
                    else await asyncio.to_thread(
                        enrollment.consent,
                        credentials,
                        cert,
                        "order.read",
                        target_resource,
                        1 if scenario == "expired" else 300,
                    )
                )
                if scenario == "expired":
                    await asyncio.sleep(max(0, grant["expires"] - time.time() + 0.05))
                elif scenario == "revoked_grant":
                    await asyncio.to_thread(
                        enrollment.post, f"/v1/grants/{grant['grant_id']}/revoke", {}, alice["credential"]
                    )
                nonce = business.challenge(peer_der)
                await desk.send_json({"type": "authorization_challenge", "nonce": nonce})
                challenge = await agent.receive_json()
                if challenge != {"type": "authorization_challenge", "nonce": nonce}:
                    raise RuntimeError("authorization challenge did not arrive intact")
                if scenario == "revoked_certificate":
                    await asyncio.to_thread(
                        enrollment.post,
                        "/v1/certificates/revoke",
                        {"serial": enrolled["serial"]},
                        account["credential"],
                    )
                request = {
                    "id": str(uuid.uuid4()),
                    "customer": "alice",
                    "action": "address.change" if scenario == "scope" else action,
                    "order": resource,
                    "nonce": challenge["nonce"],
                    "delegation": grant["delegation"],
                }
                request_start = time.monotonic()
                await agent.send_json(request)
                received = await desk.receive_json()
                decision = business.decide(peer_der, received, nonce)
                await desk.send_json(decision)
                response = await agent.receive_json()
                expected_result = "allowed" if scenario == "valid" else "denied"
                verified = (
                    response == decision
                    and response["id"] == request["id"]
                    and response["result"] == expected_result
                    and response["reason"] == expected_reason
                )
                report["results"].append(
                    {
                        "scenario": scenario,
                        "result": response["result"],
                        "reason": response["reason"],
                        "verified": verified,
                        "protected_round_trip_seconds": round(time.monotonic() - request_start, 3),
                    }
                )
                trace.log("call", "delegation_verified", **report["results"][-1])
                if scenario == "valid":
                    used_grant, allowed = grant, decision
                    if voice_agents:
                        safe_request = {k: v for k, v in request.items() if k not in ("delegation", "nonce")}
                        reply_call, spoken_reply = await voice_agents["desk"].prepare_reply(
                            safe_request, decision
                        )
            if voice_agents:
                await asyncio.sleep(0.3)
                await voice_agents["desk"].speak(spoken_reply)
                await voice_agents["agent"].finish_request(function_call, allowed)
                await voice_agents["desk"].finish_reply(reply_call, allowed)
                report["llm_agents_executed"] = all(
                    a.calls["llm"] >= 2 and a.calls["asr"] >= 1 for a in voice_agents.values()
                )
            report["verified"] = (
                all(r["verified"] for r in report["results"])
                and report["certificate_renewal_verified"]
                and (not use_agents or report["llm_agents_executed"])
            )
            return report
    finally:
        report["tls"] = {name: session.summary() for name, session in sessions.items()}
        report["agents"] = {name: agent.summary() for name, agent in voice_agents.items()}
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await asyncio.gather(*(session.close() for session in sessions.values()))
        if call:
            report["rtp_stats"] = await call.stats()
            report["audio"] = {name: receiver.summary() for name, receiver in call.inputs.items()}
            await call.close()
            stereo_recording(output)
        if api:
            await asyncio.to_thread(api.shutdown)
            api.server_close()
        if thread:
            thread.join(timeout=5)
        if client:
            await client.close()
        trace.save(report)


def main(argv: list[str] | None = None):
    parser = argparse.ArgumentParser(prog="openavt delegation-demo", description=__doc__)
    parser.add_argument("--agents", action="store_true", help="include two actual OpenAI voice agents")
    parser.add_argument("--env-file", type=Path, default=Path.cwd() / ".env")
    parser.add_argument("--output", type=Path)
    options = parser.parse_args(argv)
    load_dotenv(options.env_file)
    if options.agents and not os.getenv("OPENAI_API_KEY"):
        parser.error("Configure OPENAI_API_KEY locally for --agents")
    output = options.output or Path("output/delegation")
    if options.output is None:
        base, suffix = output, 2
        while output.exists():
            output = base.with_name(f"{base.name}-{suffix}")
            suffix += 1
    try:
        report = asyncio.run(asyncio.wait_for(run(output, options.agents), 240))
    except Exception as error:
        parser.exit(1, f"Delegation demo failed: {type(error).__name__}; inspect {output / 'report.json'}\n")
    print(
        json.dumps({k: v for k, v in report.items() if k not in ("events", "agents", "rtp_stats")}, indent=2)
    )
    print(f"Evidence: {output.resolve() / 'report.json'}")
    if not report["verified"]:
        raise SystemExit(1)

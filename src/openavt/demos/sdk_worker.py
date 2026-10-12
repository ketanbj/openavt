"""One agent process using the public SDK. Stdio carries signaling and reports only."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
import traceback
from pathlib import Path

from openavt.authority.ca import AgentAuthority
from openavt.authority.client import AuthorityClient
from openavt.authority.delegation import BusinessAuthority
from openavt.authority.policy import AVAPolicy
from openavt.gateway import Gateway, Request
from openavt.identity import Identity
from openavt.session import VoiceSession
from openavt.transports.audio import SpeechInbox


def emit(message: dict) -> None:
    print(json.dumps(message), flush=True)


async def read_signal() -> dict:
    line = await asyncio.to_thread(sys.stdin.readline, 65537)
    if len(line) > 65536 or not line.endswith("\n"):
        raise ValueError("invalid worker signaling")
    return json.loads(line)


def no_arguments(request: Request) -> None:
    if request.arguments:
        raise ValueError("this operation accepts no additional arguments")


async def run(role: str, config: dict, transport: str, relay: str | None) -> dict:
    http, client = None, None
    inbox = SpeechInbox()
    events: list[str] = []
    adapter = None
    try:
        if config["agents"]:
            # Initialize SDK imports/HTTP state before a paced audio call starts.
            from openai import AsyncOpenAI

            from openavt.agents.openai import VoiceAgent

            client = AsyncOpenAI(timeout=45, max_retries=1)
        if transport == "webrtc":
            from openavt.transports.peer import WebRTCAdapter

            adapter = WebRTCAdapter()
            if role == "agent":
                emit(await adapter.offer())
                await adapter.accept(await read_signal())
            else:
                emit(await adapter.answer(await read_signal()))
        else:
            from aiohttp import ClientSession

            from openavt.transports.twilio import TwilioAdapter

            http = ClientSession()
            websocket = await http.ws_connect(relay + "/" + role, max_msg_size=32768)
            adapter = TwilioAdapter(websocket, account_sid=config["twilio_account_sid"])
            emit({"ready": role})

        def log(event, **_fields):
            if len(events) < 1000:
                events.append(event)

        session = VoiceSession(
            audio=adapter,
            identity=Identity.load(config["bundle"], name=role),
            trust=Path(config["bundle"]) / "root.pem",
            expected_peer="desk.demo" if role == "agent" else None,
            server=role == "desk",
            on_speech=inbox.feed,
            log=log,
            request_timeout=30,
            handshake_timeout=config["handshake_timeout"],
        )
        voice = VoiceAgent(role, client, adapter.send, inbox, log) if config["agents"] else None
        async with session:
            if role == "desk":
                business = BusinessAuthority(Path(config["business"]), AgentAuthority(Path(config["ava"])))
                gateway = Gateway(AVAPolicy(business), request_timeout=30)

                async def order_status(request: Request, _claims: dict) -> dict:
                    # A fixed read-only business tool. The gateway controls entry.
                    return {"order": request.resource, "status": "shipped"}

                for action in ("order.read", "address.change"):
                    gateway.register(action, validate=no_arguments, handler=order_status)

                async def speak_result(request: Request, response: dict):
                    if voice and response["result"] == "allowed":
                        safe_request = {"id": request.id, "action": request.action, "order": request.resource}
                        call, speech = await voice.prepare_reply(safe_request, response)
                        await voice.speak(speech)
                        await voice.finish_reply(call, response)
                        await voice.hear()

                if voice:
                    await asyncio.sleep(0.25)
                    await voice.greet()
                await gateway.serve(session, limit=config["request_count"], on_response=speak_result)
                # Let the client consume the final protected response after its audio ACK.
                await asyncio.sleep(0.25)
                report = {"gateway": gateway.summary()}
            else:
                call, requested = None, None
                if voice:
                    call, requested = await voice.request("valid")
                    await voice.speak(requested["announcement"])
                    await asyncio.sleep(1)
                results = []
                for probe in config["probes"]:
                    if probe["case"] == "expired":
                        await asyncio.sleep(max(0, probe["expires"] - time.time() + 0.1))
                    if probe["case"] == "revoked_certificate":
                        await asyncio.to_thread(
                            AuthorityClient(config["authority_url"]).post,
                            "/v1/certificates/revoke",
                            {"serial": config["certificate_serial"]},
                            config["account_credential"],
                        )
                    started = time.monotonic()
                    response = await session.request(
                        requested["action"] if requested and probe["case"] == "valid" else probe["action"],
                        resource=probe["resource"],
                        customer=probe["customer"],
                        grant=probe["grant"],
                    )
                    verified = response["result"] == ("allowed" if probe["case"] == "valid" else "denied")
                    results.append(
                        {
                            "case": probe["case"],
                            "result": response["result"],
                            "reason": response["reason"],
                            "verified": verified,
                            "round_trip_seconds": round(time.monotonic() - started, 6),
                        }
                    )
                    if probe["case"] == "valid" and voice:
                        await voice.finish_request(call, response)
                report = {"results": results}
            report.update(
                pid=os.getpid(),
                role=role,
                sdk=session.summary(),
                audio=adapter.summary(),
                event_types=sorted(set(events)),
                llm={"model": voice.model, "api_calls": voice.calls} if voice else None,
            )
            return report
    finally:
        if adapter:
            await adapter.close()
        if http:
            await http.close()
        if client:
            await client.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", choices=("agent", "desk"), required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--transport", choices=("webrtc", "twilio"), required=True)
    parser.add_argument("--relay")
    args = parser.parse_args()
    try:
        report = asyncio.run(run(args.role, json.loads(args.config.read_text()), args.transport, args.relay))
        emit({"report": report})
    except Exception as error:
        # Provider/LLM exceptions can contain credentials or request contents.
        emit(
            {
                "error_type": type(error).__name__,
                "locations": [
                    {"file": Path(frame.filename).name, "line": frame.lineno, "function": frame.name}
                    for frame in traceback.extract_tb(error.__traceback__)
                ],
            }
        )
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()

"""Provider fixture and configurable live ingress for independent SDK workers.

Emulation is explicitly not proof of Twilio/carrier interoperability. Both
modes relay the same provider envelopes; application TLS stays inside audio.
"""

from __future__ import annotations

import asyncio
import secrets

from aiohttp import WSMsgType, web

from openavt.transports.twilio import TwilioConfig, TwilioIngress, decode_mulaw


class ProviderBridge:
    def __init__(self, *, live: bool = False):
        self.live = live
        self.config = TwilioConfig.from_env() if live else None
        self.account_sid = self.config.account_sid if live else "AC" + "0" * 32
        self.workers = {}
        self.external = {}
        self.ready = {role: asyncio.Event() for role in ("agent", "desk")}
        self.locks = {role: asyncio.Lock() for role in self.ready}
        self.sequence = {role: 0 for role in self.ready}
        self.offset = {role: 0 for role in self.ready}
        self.streams = {role: "MZ" + secrets.token_hex(16) for role in self.ready}
        self.runners = []
        self.forwarded_audio_packets = self.playback_marks = 0
        self.call = None
        self.started = False
        self.audio_ready = asyncio.Event()
        self.provider_ready = asyncio.Event()
        self.provider_started: set[str] = set()

    async def start(self) -> str:
        app = web.Application(client_max_size=32768)
        app.router.add_get("/{role}", self.worker)
        runner = web.AppRunner(app, access_log=None)
        await runner.setup()
        self.runners.append(runner)
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        if self.live:
            import os

            ingress = TwilioIngress(self.config, self.provider)
            runner = web.AppRunner(ingress.application(), access_log=None)
            await runner.setup()
            self.runners.append(runner)
            listen_port = int(os.getenv("TWILIO_LISTEN_PORT", "8080"))
            await web.TCPSite(runner, "127.0.0.1", listen_port).start()
        return f"http://127.0.0.1:{port}"

    async def worker(self, request: web.Request) -> web.WebSocketResponse:
        role = request.match_info["role"]
        if role not in self.ready:
            raise web.HTTPNotFound()
        if role in self.workers:
            raise web.HTTPConflict()
        ws = web.WebSocketResponse(max_msg_size=32768, heartbeat=10)
        await ws.prepare(request)
        self.workers[role] = ws
        self.ready[role].set()
        try:
            async for event in ws:
                if event.type != WSMsgType.TEXT:
                    break
                message = event.json()
                kind = message.get("event")
                if not self.started or kind not in {"media", "mark"}:
                    raise ValueError("only provider audio and playback marks may cross this bridge")
                await asyncio.wait_for(self.audio_ready.wait(), 60)
                if self.live:
                    if role not in self.external:
                        raise ConnectionError("provider leg unavailable")
                    await self.external[role].send_json(message)
                elif kind == "media":
                    if set(message) != {"event", "streamSid", "media"} or set(message["media"]) != {
                        "payload"
                    }:
                        raise ValueError("unexpected provider side channel")
                    payload = message["media"]["payload"]
                    samples = decode_mulaw(payload)
                    peer = "desk" if role == "agent" else "agent"
                    await self.emit(
                        peer,
                        {
                            "event": "media",
                            "streamSid": self.streams[peer],
                            "media": {
                                "track": "inbound",
                                "chunk": str(self.offset[peer] // 160 + 1),
                                "timestamp": str(self.offset[peer] // 8),
                                "payload": payload,
                            },
                        },
                    )
                    self.offset[peer] += len(samples)
                    self.forwarded_audio_packets += 1
                else:
                    await self.emit(
                        role, {"event": "mark", "streamSid": self.streams[role], "mark": message["mark"]}
                    )
                    self.playback_marks += 1
        except (ConnectionError, ValueError, KeyError):
            await ws.close(code=1008, message=b"invalid provider envelope")
        finally:
            self.workers.pop(role, None)
            await ws.close()
        return ws

    async def emit(self, role: str, message: dict) -> None:
        async with self.locks[role]:
            self.sequence[role] += 1
            await self.workers[role].send_json({**message, "sequenceNumber": str(self.sequence[role])})

    async def connect(self) -> None:
        await asyncio.wait_for(asyncio.gather(*(e.wait() for e in self.ready.values())), 15)
        self.started = True
        if self.live:
            await asyncio.to_thread(self._place_owned_call)
        else:
            for role, ws in list(self.workers.items()):
                await ws.send_json({"event": "connected", "protocol": "Call", "version": "1.0.0"})
                await self.emit(
                    role,
                    {
                        "event": "start",
                        "streamSid": self.streams[role],
                        "start": {
                            "accountSid": self.account_sid,
                            "callSid": "CA" + secrets.token_hex(16),
                            "streamSid": self.streams[role],
                            "tracks": ["inbound"],
                            "mediaFormat": {"encoding": "audio/x-mulaw", "sampleRate": 8000, "channels": 1},
                        },
                    },
                )
            self.audio_ready.set()

    def _place_owned_call(self) -> None:
        from twilio.http.http_client import TwilioHttpClient
        from twilio.rest import Client

        try:
            client = Client(
                self.config.account_sid,
                self.config.auth_token,
                http_client=TwilioHttpClient(timeout=10),
            )
            caller = client.incoming_phone_numbers.list(phone_number=self.config.caller_number, limit=1)
            business = client.incoming_phone_numbers.list(phone_number=self.config.business_number, limit=1)
            if not caller or not business:
                raise ValueError("both configured numbers must be owned by this Twilio account")
            if business[0].voice_url != self.config.url("/voice/desk") or business[0].voice_method != "POST":
                raise ValueError("configure the business number's POST voice webhook to /voice/desk")
            self.call = client.calls.create(
                to=self.config.business_number,
                from_=self.config.caller_number,
                url=self.config.url("/voice/agent"),
                method="POST",
                record=False,
                timeout=20,
                time_limit=180,
            )
        except ValueError:
            raise
        except Exception:
            # Never automatically repeat an ambiguous call-creation request.
            raise RuntimeError(
                "Twilio call setup failed; check the provider console before retrying"
            ) from None

    async def provider(self, role: str, websocket) -> None:
        if role not in self.workers:
            await websocket.close(code=1013)
            return
        self.external[role] = websocket
        if len(self.external) == 2:
            self.provider_ready.set()
        try:
            async for event in websocket:
                if event.type != WSMsgType.TEXT:
                    break
                message = event.json()
                if message.get("event") == "start":
                    await asyncio.wait_for(self.provider_ready.wait(), 60)
                if message.get("event") == "media":
                    self.forwarded_audio_packets += 1
                elif message.get("event") == "mark":
                    self.playback_marks += 1
                await self.workers[role].send_json(message)
                if message.get("event") == "start":
                    self.provider_started.add(role)
                    if len(self.provider_started) == 2:
                        self.audio_ready.set()
        finally:
            self.external.pop(role, None)
            if role in self.workers:
                await self.workers[role].close()

    async def close(self) -> None:
        for ws in (*self.external.values(), *self.workers.values()):
            await ws.close()
        if self.call:
            try:
                await asyncio.to_thread(self.call.update, status="completed")
            except Exception:
                pass
        for runner in reversed(self.runners):
            await runner.cleanup()

    def summary(self) -> dict:
        return {
            "emulated": not self.live,
            "audio_packets_forwarded": self.forwarded_audio_packets,
            "playback_marks": self.playback_marks,
            "permitted_worker_events": ["media", "mark"],
        }

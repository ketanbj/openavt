"""A receiving gateway that authorizes requests before invoking business tools."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Protocol

from openavt.risk import RequestSignal, RiskOutcome
from openavt.session import ProtocolError, VoiceSession, identifier


@dataclass(frozen=True)
class Request:
    id: str
    action: str
    resource: str
    customer: str
    arguments: dict
    nonce: str = field(repr=False)
    grant: str = field(repr=False)

    @classmethod
    def parse(cls, message: dict) -> Request:
        if (
            set(message)
            != {"v", "type", "id", "action", "resource", "customer", "arguments", "nonce", "grant"}
            or type(message["v"]) is not int
            or message["v"] != 1
            or message["type"] != "request"
            or not isinstance(message["arguments"], dict)
            or not isinstance(message["grant"], str)
            or not 1 <= len(message["grant"]) <= 4096
        ):
            raise ProtocolError("invalid protected request")
        return cls(
            **{
                name: identifier(message[name], name)
                for name in ("id", "action", "resource", "customer", "nonce")
            },
            arguments=message["arguments"],
            grant=message["grant"],
        )


class AuthorizationPolicy(Protocol):
    async def challenge(self, peer_certificate: bytes) -> str: ...

    async def authorize(self, peer_certificate: bytes, request: Request) -> dict:
        """Return verified claims or raise PermissionError. Recheck current permission.

        Policies may also implement revalidate(peer, request, claims) to recheck
        authority immediately before the handler, after risk assessment.
        """


class Gateway:
    def __init__(self, policy: AuthorizationPolicy, *, request_timeout: float = 15):
        if policy is None or not 0 < request_timeout <= 150:
            raise ValueError("a policy and bounded request timeout are required")
        self.policy, self.request_timeout = policy, request_timeout
        self.handlers: dict[str, tuple[Callable, Callable]] = {}
        self.requests = self.executions = self.denials = 0

    def register(
        self,
        action: str,
        *,
        validate: Callable[[Request], None],
        handler: Callable[[Request, dict], Awaitable[dict]],
    ) -> None:
        identifier(action, "action")
        if action in self.handlers or len(self.handlers) >= 32:
            raise ValueError("duplicate action or handler capacity exceeded")
        if not callable(validate) or not callable(handler):
            raise ValueError("a schema validator and async handler are required")
        self.handlers[action] = (validate, handler)

    async def serve(
        self, session: VoiceSession, *, limit: int | None = None, on_response: Callable | None = None
    ) -> None:
        if not session.server:
            raise ValueError("the gateway requires a receiving session")
        while limit is None or self.requests < limit:
            challenge_request = await session.channel.receive_json()
            if (
                set(challenge_request) != {"v", "type", "id"}
                or type(challenge_request["v"]) is not int
                or challenge_request["v"] != 1
                or challenge_request["type"] != "challenge"
            ):
                raise ProtocolError("expected a challenge request")
            request_id = identifier(challenge_request["id"], "id")
            peer = session.peer_certificate
            async with asyncio.timeout(self.request_timeout):
                try:
                    nonce = identifier(await self.policy.challenge(peer), "nonce")
                except Exception as error:
                    denied = isinstance(error, PermissionError)
                    self.requests += 1
                    self.denials += int(denied)
                    await session.channel.send_json(
                        {
                            "v": 1,
                            "type": "response",
                            "id": request_id,
                            "result": "denied" if denied else "error",
                            "reason": "not_authorized" if denied else "authorization_unavailable",
                            "data": {},
                        }
                    )
                    continue
                await session.channel.send_json(
                    {"v": 1, "type": "challenge", "id": request_id, "nonce": nonce}
                )
                request = Request.parse(await session.channel.receive_json())
                if request.id != request_id or request.nonce != nonce:
                    raise ProtocolError("request does not match this challenge")
                self.requests += 1
                response = {
                    "v": 1,
                    "type": "response",
                    "id": request_id,
                    "result": "denied",
                    "reason": "not_authorized",
                    "data": {},
                }
                if request.action not in self.handlers:
                    response["reason"] = "unsupported_action"
                else:
                    validate, handler = self.handlers[request.action]
                    try:
                        validate(request)
                    except (ValueError, TypeError):
                        response["reason"] = "invalid_arguments"
                    else:
                        try:
                            claims = await self.policy.authorize(peer, request)
                            if not isinstance(claims, dict):
                                raise TypeError("a policy must return verified claims")
                        except PermissionError:
                            pass
                        except Exception:
                            response.update(result="error", reason="authorization_unavailable")
                        else:
                            assessment = None
                            if session.monitor:
                                assessment = await session.monitor.assess(
                                    session.risk_context,
                                    RequestSignal(
                                        request.id, request.action, request.resource, request.customer
                                    ),
                                )
                            if assessment and assessment.outcome != RiskOutcome.CONTINUE:
                                response["reason"] = "risk_" + (
                                    "unavailable"
                                    if assessment.reason == "unavailable"
                                    else assessment.outcome.value
                                )
                            else:
                                try:
                                    revalidate = getattr(self.policy, "revalidate", None)
                                    if revalidate:
                                        await revalidate(peer, request, claims)
                                except PermissionError:
                                    pass
                                except Exception:
                                    response.update(result="error", reason="authorization_unavailable")
                                else:
                                    await self._execute(handler, request, claims, response)
                if response["result"] == "denied":
                    self.denials += 1
                await session.channel.send_json(response)
            if on_response:
                await on_response(request, response)

    async def _execute(self, handler, request, claims, response):
        try:
            self.executions += 1
            data = await handler(request, claims)
            if not isinstance(data, dict):
                raise TypeError("a handler must return an object")
            response.update(result="allowed", reason="authorized", data=data)
        except Exception:
            response.update(result="error", reason="handler_failed")

    def summary(self) -> dict:
        return {"requests": self.requests, "handler_executions": self.executions, "denials": self.denials}

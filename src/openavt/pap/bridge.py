"""Business-side PAP authorization exchanged for a call-bound voice grant.

SessionBackend plugs into an existing PAP/OAuth server. It MUST validate DPoP
and resolve opaque tokens on its own; no client-supplied identity is trusted.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Protocol
from urllib.parse import urlsplit

from aiohttp import web
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from openavt.authority.ca import AgentAuthority
from openavt.authority.common import (
    b64,
    canonical,
    create_database,
    database,
    fingerprint,
    initialize_directory,
    key_pem,
    parse_json,
    private_write,
    unb64,
)
from openavt.identity import Identity

from .crypto import https_url
from .http import PAPError

if TYPE_CHECKING:
    from openavt.gateway import Request
    from openavt.session import GrantRequest

    from .client import PAPClient

TYPE = "openavt-pap-voice+jwt"
FIELDS = {"session_id", "request_id", "nonce", "action", "resource", "customer", "arguments", "certificate"}
SCHEMA = """
CREATE TABLE challenges (nonce TEXT PRIMARY KEY, peer TEXT NOT NULL, expires INTEGER NOT NULL, used INTEGER NOT NULL);
CREATE TABLE grants (id TEXT PRIMARY KEY, expires INTEGER NOT NULL, used INTEGER NOT NULL);
"""


@dataclass(frozen=True)
class VerifiedSession:
    client_id: str
    user_id: str
    session_id: str
    credential_id: str
    customer: str | None
    scopes: frozenset[str]
    expires_at: int
    signed_in: bool


class SessionBackend(Protocol):
    async def authenticate(self, *, method: str, url: str, authorization: str, dpop: str) -> VerifiedSession:
        """Verify opaque access token, current session, DPoP signature/key/ath/URL/time/nonce/replay."""

    async def current(self, credential_id: str) -> VerifiedSession | None:
        """Resolve current authority; expiry, sign-out, withdrawal and token invalidation apply."""

    async def supports_extension(self, client_id: str, namespace: str, version: str) -> bool:
        """Check verified HTTPS client metadata, never request-supplied extension claims."""


def binding(endpoint: str, body: dict, token: str) -> bytes:
    return canonical(
        {
            "type": "openavt-pap-key-binding-v1",
            "endpoint": endpoint,
            "access_token_hash": b64(hashlib.sha256(token.encode()).digest()),
            "request": body,
        }
    )


def extension(namespace: str, endpoint: str, audience: str) -> dict:
    # Namespace ownership is an operator prerequisite, not a library assertion.
    host, separator, name = namespace.partition("/")
    if not separator or not name or urlsplit("https://" + host).hostname != host or "." not in host:
        raise ValueError("configure an extension namespace under a domain you control")
    return {
        namespace: {
            "version": "1",
            "grant_endpoint": https_url(endpoint),
            "audience": audience,
            "profile": "pcm",
        }
    }


class VoiceAuthority:
    """Persistent grants and challenges; independent business signing key, not AVA's key."""

    def __init__(
        self,
        state: Path,
        *,
        agents: AgentAuthority,
        sessions: SessionBackend,
        audience: str,
        authorize_intent: Callable,
    ):
        self.state, self.agents, self.sessions, self.audience = state, agents, sessions, audience
        self.authorize_intent = authorize_intent
        self.db = state / "voice.sqlite3"
        self.public = serialization.load_pem_public_key((state / "voice-public.pem").read_bytes())
        if not isinstance(self.public, ed25519.Ed25519PublicKey):
            raise ValueError("invalid voice verification key")
        config = parse_json((state / "config.json").read_bytes())
        if config != {
            "audience": audience,
            "agent_root": fingerprint(agents.root.public_bytes(serialization.Encoding.DER)),
        }:
            raise ValueError("voice authority trust configuration mismatch")

    @classmethod
    def initialize(cls, state: Path, **kwargs):
        initialize_directory(state)
        key = ed25519.Ed25519PrivateKey.generate()
        private_write(state / "voice.key", key_pem(key))
        (state / "voice-public.pem").write_bytes(
            key.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
        (state / "config.json").write_bytes(
            canonical(
                {
                    "audience": kwargs["audience"],
                    "agent_root": fingerprint(kwargs["agents"].root.public_bytes(serialization.Encoding.DER)),
                }
            )
        )
        create_database(state / "voice.sqlite3", SCHEMA)
        return cls(state, **kwargs)

    async def challenge(self, peer_certificate: bytes) -> str:
        return await asyncio.to_thread(self._challenge, peer_certificate)

    def _challenge(self, peer):
        self.agents.require_active(peer)
        nonce = secrets.token_urlsafe(32)
        now = int(time.time())
        with database(self.db) as db:
            db.execute("DELETE FROM challenges WHERE expires<=?", (now,))
            if db.execute("SELECT COUNT(*) FROM challenges").fetchone()[0] >= 1000:
                raise RuntimeError("challenge capacity")
            db.execute("INSERT INTO challenges VALUES (?,?,?,0)", (nonce, fingerprint(peer), now + 30))
        return nonce

    async def issue(self, body: dict, session: VerifiedSession, *, endpoint: str, token: str) -> str:
        if set(body) != FIELDS | {"proof"} or not isinstance(body.get("arguments"), dict):
            raise PermissionError()
        for name in FIELDS - {"arguments"}:
            limit = 4096 if name == "certificate" else 256
            if not isinstance(body[name], str) or not 1 <= len(body[name]) <= limit:
                raise PermissionError()
        if not isinstance(body["proof"], str) or len(body["proof"]) > 1024:
            raise PermissionError()
        cert = x509.load_pem_x509_certificate(body["certificate"].encode())
        der = cert.public_bytes(serialization.Encoding.DER)
        self.agents.require_active(der)
        key = cert.public_key()
        if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
            raise PermissionError()
        key.verify(
            unb64(body["proof"]),
            binding(endpoint, {k: body[k] for k in FIELDS}, token),
            ec.ECDSA(hashes.SHA256()),
        )
        await self._permission(session, body)
        now = int(time.time())
        claims = {
            "aud": self.audience,
            "iat": now,
            "exp": min(now + 30, session.expires_at, int(cert.not_valid_after_utc.timestamp())),
            "jti": secrets.token_urlsafe(24),
            "cnf": {"x5t#S256": fingerprint(der)},
            "session": session.credential_id,
            "client_id": session.client_id,
            "user_id": session.user_id,
            "session_id": session.session_id,
            "request_id": body["request_id"],
            "nonce": body["nonce"],
            "action": body["action"],
            "resource": body["resource"],
            "customer": body["customer"],
            "arguments_hash": b64(hashlib.sha256(canonical(body["arguments"])).digest()),
        }
        if claims["exp"] <= now:
            raise PermissionError()
        return await asyncio.to_thread(self._issue, claims, der)

    def _issue(self, claims, der):
        with database(self.db) as db:
            row = db.execute("SELECT * FROM challenges WHERE nonce=?", (claims["nonce"],)).fetchone()
            if not row or row["used"] or row["expires"] <= time.time() or row["peer"] != fingerprint(der):
                raise PermissionError()
            db.execute("DELETE FROM grants WHERE expires<=?", (int(time.time()),))
            if db.execute("SELECT COUNT(*) FROM grants").fetchone()[0] >= 10000:
                raise RuntimeError("grant capacity")
            db.execute("INSERT INTO grants VALUES (?,?,0)", (claims["jti"], claims["exp"]))
        wire = b64(canonical({"alg": "EdDSA", "typ": TYPE})) + "." + b64(canonical(claims))
        key = serialization.load_pem_private_key((self.state / "voice.key").read_bytes(), None)
        return wire + "." + b64(key.sign(wire.encode()))

    async def _permission(self, session, request):
        if (
            not isinstance(session, VerifiedSession)
            or not session.signed_in
            or session.expires_at <= time.time()
            or session.session_id != request["session_id"]
            or session.customer != request["customer"]
        ):
            raise PermissionError()
        if not await self.authorize_intent(
            session, request["action"], request["resource"], request["arguments"]
        ):
            raise PermissionError()

    async def authorize(self, peer_certificate: bytes, request: Request) -> dict:
        return await self._verify(peer_certificate, request, consume=True)

    async def revalidate(self, peer_certificate: bytes, request: Request, claims: dict) -> None:
        """Recheck after a potentially slow risk assessment, without consuming twice."""
        await self._verify(peer_certificate, request, consume=False)

    async def _verify(self, peer_certificate: bytes, request: Request, *, consume: bool) -> dict:
        try:
            header, payload, signature = request.grant.split(".")
            if parse_json(unb64(header)) != {"alg": "EdDSA", "typ": TYPE}:
                raise PermissionError()
            self.public.verify(unb64(signature), (header + "." + payload).encode())
            c = parse_json(unb64(payload))
            expected = {
                "aud",
                "iat",
                "exp",
                "jti",
                "cnf",
                "session",
                "client_id",
                "user_id",
                "session_id",
                "request_id",
                "nonce",
                "action",
                "resource",
                "customer",
                "arguments_hash",
            }
            if (
                set(c) != expected
                or type(c["iat"]) is not int
                or type(c["exp"]) is not int
                or not c["iat"] <= time.time() < c["exp"]
                or not 0 < c["exp"] - c["iat"] <= 30
                or c["aud"] != self.audience
                or c["cnf"] != {"x5t#S256": fingerprint(peer_certificate)}
            ):
                raise PermissionError()
            self.agents.require_active(peer_certificate)
            for name in ("request_id", "nonce", "action", "resource", "customer"):
                actual = request.id if name == "request_id" else getattr(request, name)
                if c[name] != actual:
                    raise PermissionError()
            if c["arguments_hash"] != b64(hashlib.sha256(canonical(request.arguments)).digest()):
                raise PermissionError()
            current = await self.sessions.current(c["session"])
            if not current or (current.client_id, current.user_id, current.session_id) != (
                c["client_id"],
                c["user_id"],
                c["session_id"],
            ):
                raise PermissionError()
            await self._permission(current, {**c, "arguments": request.arguments})
            if consume:
                await asyncio.to_thread(self._consume, c)
            else:
                await asyncio.to_thread(self._consumed, c)
            return {
                "client_id": c["client_id"],
                "session_id": c["session_id"],
                "credential_id": c["session"],
                "sub": c["customer"],
                "scope": [c["action"]],
            }
        except (ValueError, KeyError, TypeError, InvalidSignature):
            raise PermissionError("voice authorization rejected") from None

    def _consumed(self, c):
        with database(self.db) as db:
            grant = db.execute("SELECT * FROM grants WHERE id=?", (c["jti"],)).fetchone()
            nonce = db.execute("SELECT * FROM challenges WHERE nonce=?", (c["nonce"],)).fetchone()
            if (
                not grant
                or not nonce
                or not grant["used"]
                or not nonce["used"]
                or grant["expires"] <= time.time()
                or nonce["expires"] <= time.time()
            ):
                raise PermissionError()

    def _consume(self, c):
        with database(self.db) as db:
            grant = db.execute("SELECT * FROM grants WHERE id=?", (c["jti"],)).fetchone()
            nonce = db.execute("SELECT * FROM challenges WHERE nonce=?", (c["nonce"],)).fetchone()
            if (
                not grant
                or grant["used"]
                or grant["expires"] <= time.time()
                or not nonce
                or nonce["used"]
                or nonce["expires"] <= time.time()
                or nonce["peer"] != c["cnf"]["x5t#S256"]
            ):
                raise PermissionError()
            db.execute("UPDATE grants SET used=1 WHERE id=?", (c["jti"],))
            db.execute("UPDATE challenges SET used=1 WHERE nonce=?", (c["nonce"],))


class VoiceBridge:
    def __init__(self, authority: VoiceAuthority, *, endpoint: str, namespace: str):
        self.authority, self.endpoint = authority, https_url(endpoint)
        extension(namespace, endpoint, authority.audience)
        self.namespace = namespace
        if urlsplit(endpoint).query:
            raise ValueError("grant endpoint cannot have a query")

    def application(self) -> web.Application:
        app = web.Application(client_max_size=16384)
        app.router.add_post(urlsplit(self.endpoint).path, self.issue)
        return app

    async def issue(self, request: web.Request) -> web.Response:
        if request.query_string:
            raise web.HTTPBadRequest()
        try:
            authorization = request.headers.get("Authorization", "")
            if not authorization.startswith("DPoP ") or len(authorization) > 16390:
                raise PermissionError()
            async with asyncio.timeout(10):
                session = await self.authority.sessions.authenticate(
                    method="POST",
                    url=self.endpoint,
                    authorization=authorization,
                    dpop=request.headers.get("DPoP", ""),
                )
                if not await self.authority.sessions.supports_extension(
                    session.client_id, self.namespace, "1"
                ):
                    return web.json_response(
                        {"error": "extension_required", "extension": self.namespace}, status=403
                    )
                body = parse_json(await request.read())
                grant = await self.authority.issue(
                    body, session, endpoint=self.endpoint, token=authorization[5:]
                )
            return web.json_response(
                {"grant": grant, "expires_in": 30}, headers={"Cache-Control": "no-store"}
            )
        except PAPError as error:
            code = error.code if re.fullmatch(r"[a-z_]{1,64}", error.code) else "invalid_token"
            headers = {"WWW-Authenticate": 'DPoP error="' + code + '"'}
            nonce = getattr(error, "nonce", None)
            if isinstance(nonce, str) and 1 <= len(nonce) <= 512 and all(33 <= ord(c) <= 126 for c in nonce):
                headers["DPoP-Nonce"] = nonce
            return web.json_response(
                {"error": code},
                status=error.status if error.status in {400, 401, 403, 429} else 401,
                headers=headers,
            )
        except (PermissionError, ValueError, KeyError, InvalidSignature):
            return web.json_response({"error": "voice_authorization_denied"}, status=403)
        except Exception:
            return web.json_response({"error": "authorization_unavailable"}, status=503)


class PAPVoiceGrant:
    """VoiceSession grant callback. Account/session credentials never enter audio."""

    def __init__(self, client: PAPClient, identity: Identity, *, namespace: str):
        self.client, self.identity = client, identity
        if not client.discovery:
            raise PAPError("discovery_required")
        entry = client.discovery.get("extensions", {}).get(namespace, {})
        if entry.get("version") != "1" or client.extensions.get(namespace, {}).get("version") != "1":
            raise PAPError("extension_required")
        self.endpoint = https_url(entry.get("grant_endpoint"))

    async def __call__(self, request: GrantRequest) -> str:
        session = self.client._current()
        body = {
            "session_id": session.session_id,
            "request_id": request.request_id,
            "nonce": request.nonce,
            "action": request.action,
            "resource": request.resource,
            "customer": request.customer,
            "arguments": request.arguments,
            "certificate": self.identity.certificate.read_text(),
        }
        key = serialization.load_pem_private_key(self.identity.private_key.read_bytes(), None)
        if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
            raise ValueError("voice binding profile requires P-256")
        body["proof"] = b64(
            key.sign(binding(self.endpoint, body, session.access_token), ec.ECDSA(hashes.SHA256()))
        )
        reply = await self.client.api("POST", self.endpoint, body=body)
        grant = reply.data.get("grant")
        if not isinstance(grant, str) or not 1 <= len(grant) <= 4096:
            raise PAPError("invalid_voice_grant")
        return grant

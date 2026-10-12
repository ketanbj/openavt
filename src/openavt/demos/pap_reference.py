"""Independent local PAP wire counterpart, NOT a production identity provider.

Uses PyJWT to verify client-generated JWTs (the client signs with cryptography).
State and simulated user approval exist only for tests/demo. No real credentials.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from dataclasses import replace
from datetime import datetime, timezone
from urllib.parse import urlencode, urlsplit

import jwt
from aiohttp import web

from openavt.pap.bridge import VerifiedSession, extension
from openavt.pap.http import PAPError


def encode(raw):
    import base64

    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def key_hash(jwk):
    selected = {name: jwk[name] for name in ("crv", "kty", "x", "y")}
    return encode(
        hashlib.sha256(json.dumps(selected, sort_keys=True, separators=(",", ":")).encode()).digest()
    )


class ReferenceCompany:
    def __init__(self, *, base: str, namespace="example.test/openavt-voice"):
        self.base, self.namespace = base, namespace
        self.clients = {}
        self.sessions = {}
        self.tokens = {}
        self.refresh_tokens = {}
        self.codes = {}
        self.devices = {}
        self.mediated = {}
        self.proof_ids = {}
        self.assertion_ids = {}
        self.nonce = secrets.token_urlsafe(24)
        self.used_nonce_challenges = 0
        self.operations = {}
        self.effects = 0
        self.grant_url = base + "/voice/grants"
        self.bridge = None
        self.account_resources = {"alice": {"order-1"}, "bob": {"order-2"}}

    def register(self, metadata: dict, jwks: dict):
        # Simulate operator registration; metadata is served separately over HTTPS.
        cid = metadata["client_id"]
        if urlsplit(metadata["jwks_uri"]).hostname != urlsplit(cid).hostname:
            raise ValueError()
        self.clients[cid] = (metadata, jwks)

    def application(self):
        app = web.Application(client_max_size=16384)
        app.router.add_get("/.well-known/poppy.json", self.discovery)
        app.router.add_get("/.well-known/oauth-authorization-server", self.metadata)
        app.router.add_get("/agent.json", self.agent_metadata)
        app.router.add_get("/jwks.json", self.jwks)
        app.router.add_post("/oauth/token", self.token)
        app.router.add_get("/oauth/authorize", self.authorize)
        app.router.add_post("/oauth/device", self.device)
        app.router.add_post("/oauth/revoke", self.revoke)
        app.router.add_post("/signin", self.signin)
        app.router.add_post("/signin/{id}", self.signin_code)
        app.router.add_post("/voice/grants", self.voice)
        app.router.add_get("/openapi.json", self.openapi)
        app.router.add_route("*", "/operations/{id}", self.operation)
        app.router.add_post("/operations/{id}/{verb}", self.operation)
        return app

    def discovered(self):
        return {
            "protocol_version": "0.1",
            "organization": {"name": "Local reference company", "domain": urlsplit(self.base).hostname},
            "auth": {
                "issuer": self.base,
                "direct": {"scopes": ["poppy:read", "poppy:write"]},
                "device": {"scopes": ["poppy:read", "poppy:write"]},
                "mediated": {
                    "endpoint": self.base + "/signin",
                    "scopes": ["poppy:read"],
                    "fields": [{"name": "demo_account", "label": "Demo account", "secret": True}],
                },
            },
            "apis": [
                {
                    "type": "openapi",
                    "url": self.base + "/openapi.json",
                    "description": "OpenAVT voice authorization",
                }
            ],
            "extensions": {
                "operations": {"version": "1", "endpoint": self.base + "/operations"},
                **extension(self.namespace, self.grant_url, "desk.demo"),
            },
        }

    async def discovery(self, request):
        return web.json_response(self.discovered(), headers={"Cache-Control": "max-age=60"})

    async def metadata(self, request):
        return web.json_response(
            {
                "issuer": self.base,
                "poppy_domains": [urlsplit(self.base).hostname],
                "token_endpoint": self.base + "/oauth/token",
                "revocation_endpoint": self.base + "/oauth/revoke",
                "authorization_endpoint": self.base + "/oauth/authorize",
                "device_authorization_endpoint": self.base + "/oauth/device",
            }
        )

    async def agent_metadata(self, request):
        return web.json_response(next(iter(self.clients.values()))[0])

    async def jwks(self, request):
        return web.json_response(next(iter(self.clients.values()))[1])

    async def openapi(self, request):
        return web.json_response(
            {
                "openapi": "3.1.0",
                "info": {"title": "OpenAVT PAP voice bridge", "version": "1.0.0"},
                "servers": [{"url": self.base}],
                "paths": {
                    "/voice/grants": {
                        "post": {
                            "summary": "Issue a call-bound authorization",
                            "security": [{"SessionDPoP": []}],
                            "responses": {
                                "200": {"description": "Voice grant"},
                                "403": {"description": "Not authorized"},
                            },
                        }
                    }
                },
                "components": {"securitySchemes": {"SessionDPoP": {"type": "http", "scheme": "DPoP"}}},
            }
        )

    def _error(self, error):
        headers = {}
        if error.code in {"use_dpop_nonce", "invalid_dpop_proof", "invalid_token"}:
            headers["WWW-Authenticate"] = 'DPoP error="' + error.code + '"'
        if error.code == "use_dpop_nonce":
            headers["DPoP-Nonce"] = self.nonce
        return web.json_response({"error": error.code}, status=error.status or 400, headers=headers)

    def _assertion(self, token, client_id, audience, *, user=False):
        try:
            metadata, jwks = self.clients[client_id]
            header = jwt.get_unverified_header(token)
            keys = [k for k in jwks["keys"] if not header.get("kid") or k.get("kid") == header["kid"]]
            if header.get("alg") != "ES256" or header.get("typ") != "JWT" or len(keys) != 1:
                raise ValueError()
            key = jwt.PyJWK.from_dict(keys[0]).key
            claims = jwt.decode(
                token,
                key,
                algorithms=["ES256"],
                audience=audience,
                issuer=client_id,
                options={"require": ["iss", "sub", "aud", "iat", "exp", "jti"]},
            )
            if (
                type(claims["iat"]) is not int
                or type(claims["exp"]) is not int
                or claims["exp"] - claims["iat"] > 60
                or claims["iat"] > time.time() + 5
                or not isinstance(claims["jti"], str)
                or len(claims["jti"]) < 22
                or not isinstance(claims["sub"], str)
                or claims["aud"] != audience
            ):
                raise ValueError()
            if not user and claims["sub"] != client_id:
                raise ValueError()
            replay = (client_id, claims["jti"])
            now = time.time()
            self.assertion_ids = {k: expiry for k, expiry in self.assertion_ids.items() if expiry > now}
            if replay in self.assertion_ids:
                raise ValueError()
            self.assertion_ids[replay] = claims["exp"]
            return claims
        except (ValueError, KeyError, jwt.PyJWTError):
            raise PAPError(
                "invalid_client" if not user else "invalid_grant", status=401 if not user else 400
            ) from None

    def _proof(self, value, method, url, token=None, thumbprint=None):
        try:
            header = jwt.get_unverified_header(value)
            jwk = header["jwk"]
            if (
                header.get("typ") != "dpop+jwt"
                or header.get("alg") != "ES256"
                or set(jwk) != {"kty", "crv", "x", "y"}
            ):
                raise ValueError()
            public = jwt.PyJWK.from_dict(jwk).key
            claims = jwt.decode(
                value,
                public,
                algorithms=["ES256"],
                options={"verify_aud": False, "require": ["jti", "iat", "htm", "htu"]},
            )
            kh = key_hash(jwk)
            if (
                type(claims["iat"]) is not int
                or abs(time.time() - claims["iat"]) > 60
                or not isinstance(claims["jti"], str)
                or len(claims["jti"]) < 22
                or claims["htm"] != method
                or claims["htu"] != url
                or thumbprint
                and kh != thumbprint
            ):
                raise ValueError()
            if token is not None and claims.get("ath") != encode(hashlib.sha256(token.encode()).digest()):
                raise ValueError()
            if token is None and "ath" in claims:
                raise ValueError()
            if claims.get("nonce") != self.nonce:
                self.used_nonce_challenges += 1
                error = PAPError("use_dpop_nonce", status=401 if token else 400)
                error.nonce = self.nonce
                raise error
            now = time.time()
            self.proof_ids = {k: t for k, t in self.proof_ids.items() if t > now}
            replay = (kh, claims["jti"])
            if replay in self.proof_ids:
                raise ValueError()
            self.proof_ids[replay] = now + 60
            return kh
        except PAPError:
            raise
        except (ValueError, KeyError, jwt.PyJWTError):
            raise PAPError("invalid_dpop_proof", status=401 if token else 400) from None

    def _client(self, form, endpoint):
        cid = form.get("client_id")
        if form.get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer":
            raise PAPError("invalid_client", status=401)
        self._assertion(form.get("client_assertion"), cid, endpoint)
        return cid

    def _issue_token(self, sid, kh, *, scope=None, resource=None, refresh=False):
        row = self.sessions[sid]
        scopes = frozenset(scope.split()) if scope is not None else row["scope"]
        if not scopes <= row["scope"]:
            raise PAPError("invalid_scope")
        token = secrets.token_urlsafe(32)
        verified = VerifiedSession(
            row["client"],
            row["user"],
            sid,
            hashlib.sha256(token.encode()).hexdigest(),
            row["customer"],
            scopes,
            int(time.time()) + 3600,
            bool(row["customer"]),
        )
        self.tokens[token] = {"verified": verified, "key": kh, "resource": resource, "active": True}
        response = {
            "access_token": token,
            "token_type": "DPoP",
            "scope": " ".join(sorted(scopes)),
            "session_id": sid,
            "signed_in": bool(row["customer"]),
            "expires_in": 3600,
        }
        if refresh:
            rt = secrets.token_urlsafe(32)
            self.refresh_tokens[rt] = {
                "client": row["client"],
                "user": row["user"],
                "customer": row["customer"],
                "scope": row["scope"],
                "expires": time.time() + 86400,
                "active": True,
            }
            response["refresh_token"] = rt
        return response

    async def token(self, request):
        try:
            form = await request.post()
            endpoint = self.base + "/oauth/token"
            cid = self._client(form, endpoint)
            kh = self._proof(request.headers.get("DPoP", ""), "POST", endpoint)
            grant = form.get("grant_type")
            sid = form.get("session_id")
            if grant == "urn:ietf:params:oauth:grant-type:jwt-bearer":
                assertion = self._assertion(form.get("assertion"), cid, endpoint, user=True)
                user = assertion["sub"]
                if sid:
                    row = self.sessions.get(sid)
                    if not row or row["client"] != cid or row["user"] != user or row["customer"]:
                        raise PAPError("invalid_session")
                else:
                    sid = "ses_" + secrets.token_urlsafe(24)
                    self.sessions[sid] = {"client": cid, "user": user, "customer": None, "scope": frozenset()}
                return web.json_response(
                    self._issue_token(sid, kh, resource=form.get("resource")),
                    headers={"Cache-Control": "no-store"},
                )
            row = self.sessions.get(sid) if sid else None
            if grant == "refresh_token":
                account = self.refresh_tokens.get(form.get("refresh_token"))
                if (
                    not account
                    or not account["active"]
                    or account["expires"] <= time.time()
                    or account["client"] != cid
                ):
                    raise PAPError("invalid_grant")
                if not sid:
                    sid = "ses_" + secrets.token_urlsafe(24)
                    row = {
                        "client": cid,
                        "user": account["user"],
                        "customer": account["customer"],
                        "scope": account["scope"],
                    }
                    self.sessions[sid] = row
                if not row or (row["client"], row["user"]) != (cid, account["user"]):
                    raise PAPError("invalid_session")
                if row["customer"] not in {None, account["customer"]}:
                    raise PAPError("account_mismatch")
                row.update(customer=account["customer"], scope=account["scope"])
                return web.json_response(
                    self._issue_token(sid, kh, scope=form.get("scope"), resource=form.get("resource"))
                )
            if not row or row["client"] != cid:
                raise PAPError("invalid_session")
            if grant == "authorization_code":
                code = self.codes.get(form.get("code"))
                if (
                    not code
                    or code["used"]
                    or code["expires"] < time.time()
                    or code["client"] != cid
                    or code["redirect"] != form.get("redirect_uri")
                    or code["challenge"]
                    != encode(hashlib.sha256(form.get("code_verifier", "").encode()).digest())
                ):
                    raise PAPError("invalid_grant")
                code["used"] = True
                scope = code["scope"]
                customer = code["customer"]
            elif grant == "urn:ietf:params:oauth:grant-type:device_code":
                device = self.devices.get(form.get("device_code"))
                if not device or device["client"] != cid or device["used"] or device["expires"] < time.time():
                    raise PAPError("expired_token")
                if not device["approved"]:
                    raise PAPError("authorization_pending")
                device["used"] = True
                scope = device["scope"]
                customer = device["customer"]
            else:
                raise PAPError("unsupported_grant_type")
            if row["customer"] not in {None, customer}:
                raise PAPError("account_mismatch")
            row.update(customer=customer, scope=scope)
            return web.json_response(
                self._issue_token(sid, kh, refresh=True), headers={"Cache-Control": "no-store"}
            )
        except PAPError as error:
            return self._error(error)

    def approve_direct(self, url, *, customer="alice", approve=True):
        from urllib.parse import parse_qs

        q = {k: v[0] for k, v in parse_qs(urlsplit(url).query).items()}
        metadata = self.clients[q["client_id"]][0]
        if (
            q["redirect_uri"] not in metadata["redirect_uris"]
            or q.get("code_challenge_method") != "S256"
            or q.get("response_type") != "code"
        ):
            raise ValueError()
        scopes = frozenset(q["scope"].split())
        if not scopes or not scopes <= {"poppy:read", "poppy:write"}:
            raise ValueError()
        result = {"state": q["state"], "iss": self.base}
        if approve:
            code = secrets.token_urlsafe(32)
            self.codes[code] = {
                "client": q["client_id"],
                "redirect": q["redirect_uri"],
                "challenge": q["code_challenge"],
                "scope": scopes,
                "customer": customer,
                "used": False,
                "expires": time.time() + 60,
            }
            result["code"] = code
        else:
            result["error"] = "access_denied"
        return q["redirect_uri"] + "?" + urlencode(result)

    async def authorize(self, request):
        # This reference has NO browser login endpoint or automatic approval.
        return web.json_response({"error": "demo_requires_explicit_approval_callback"}, status=501)

    async def device(self, request):
        try:
            form = await request.post()
            cid = self._client(form, self.base + "/oauth/device")
            scope = frozenset(form.get("scope", "").split())
            if not scope or not scope <= {"poppy:read", "poppy:write"}:
                raise PAPError("invalid_scope")
            code = secrets.token_urlsafe(32)
            user_code = secrets.token_urlsafe(6)
            self.devices[code] = {
                "client": cid,
                "scope": scope,
                "customer": "alice",
                "approved": False,
                "used": False,
                "expires": time.time() + 600,
                "user_code": user_code,
            }
            return web.json_response(
                {
                    "device_code": code,
                    "user_code": user_code,
                    "verification_uri": self.base + "/device",
                    "expires_in": 600,
                    "interval": 1,
                }
            )
        except PAPError as error:
            return self._error(error)

    def approve_device(self, user_code):
        for row in self.devices.values():
            if row["user_code"] == user_code:
                row["approved"] = True
                return
        raise ValueError()

    async def authenticate(self, *, method, url, authorization, dpop):
        if not authorization.startswith("DPoP "):
            raise PAPError("invalid_token", status=401)
        token = authorization[5:]
        row = self.tokens.get(token)
        current = await self.current(hashlib.sha256(token.encode()).hexdigest())
        if not row or not current:
            raise PAPError("invalid_token", status=401)
        if (
            row["resource"]
            and not url.startswith(row["resource"].rstrip("/") + "/")
            and url != row["resource"]
        ):
            raise PAPError("invalid_token", status=401)
        self._proof(dpop, method, url, token, row["key"])
        return current

    async def supports_extension(self, client_id, namespace, version):
        return self.clients[client_id][0].get("extensions", {}).get(namespace, {}).get("version") == version

    async def current(self, credential_id):
        row = next((r for r in self.tokens.values() if r["verified"].credential_id == credential_id), None)
        if not row or not row["active"] or row["verified"].expires_at <= time.time():
            return None
        verified = row["verified"]
        session = self.sessions[verified.session_id]
        if verified.signed_in and session["customer"] != verified.customer:
            return None
        return replace(verified, scopes=verified.scopes & session["scope"])

    async def signin(self, request):
        try:
            session = await self.authenticate(
                method="POST",
                url=self.base + "/signin",
                authorization=request.headers.get("Authorization", ""),
                dpop=request.headers.get("DPoP", ""),
            )
            body = await request.json()
            if body.get("scope") != "poppy:read":
                raise PAPError("invalid_scope")
            if body.get("credentials") == {"demo_account": "alice-code"}:
                sid = secrets.token_urlsafe(24)
                self.mediated[sid] = {
                    "session": session.session_id,
                    "client": session.client_id,
                    "expires": time.time() + 60,
                    "attempts": 0,
                }
                return web.json_response(
                    {
                        "status": "code_required",
                        "sign_in_id": sid,
                        "expires_at": datetime.fromtimestamp(time.time() + 60, timezone.utc).isoformat(),
                        "code": {"sent_to": "Demo interface"},
                    }
                )
            if body.get("credentials") != {"demo_account": "alice"}:
                return web.json_response({"status": "failed"})
            row = self.sessions[session.session_id]
            if row["customer"] not in {None, "alice"}:
                raise PAPError("account_mismatch")
            row.update(customer="alice", scope=frozenset({"poppy:read"}))
            token = request.headers["Authorization"][5:]
            return web.json_response(
                {
                    "status": "complete",
                    **self._issue_token(session.session_id, self.tokens[token]["key"], refresh=True),
                }
            )
        except PAPError as error:
            return self._error(error)

    async def signin_code(self, request):
        try:
            session = await self.authenticate(
                method="POST",
                url=self.base + request.path,
                authorization=request.headers.get("Authorization", ""),
                dpop=request.headers.get("DPoP", ""),
            )
            pending = self.mediated.get(request.match_info["id"])
            if (
                not pending
                or pending["expires"] <= time.time()
                or (pending["client"], pending["session"]) != (session.client_id, session.session_id)
            ):
                raise PAPError("invalid_sign_in_id")
            body = await request.json()
            if body != {"code": "123456"}:
                pending["attempts"] += 1
                if pending["attempts"] >= 3:
                    del self.mediated[request.match_info["id"]]
                    return web.json_response({"status": "failed"})
                return web.json_response(
                    {
                        "status": "code_required",
                        "sign_in_id": request.match_info["id"],
                        "expires_at": datetime.fromtimestamp(pending["expires"], timezone.utc).isoformat(),
                        "code": {"sent_to": "Demo interface"},
                    }
                )
            del self.mediated[request.match_info["id"]]
            self.sessions[session.session_id].update(customer="alice", scope=frozenset({"poppy:read"}))
            token = request.headers["Authorization"][5:]
            return web.json_response(
                {
                    "status": "complete",
                    **self._issue_token(session.session_id, self.tokens[token]["key"], refresh=True),
                }
            )
        except PAPError as error:
            return self._error(error)

    async def revoke(self, request):
        try:
            form = await request.post()
            cid = self._client(form, self.base + "/oauth/revoke")
            row = self.refresh_tokens.get(form.get("token"))
            if row and row["client"] == cid:
                row["active"] = False
                for session in self.sessions.values():
                    if (session["client"], session["user"], session["customer"]) == (
                        cid,
                        row["user"],
                        row["customer"],
                    ):
                        session.update(customer=None, scope=frozenset())
            return web.Response(status=200)
        except PAPError as error:
            return self._error(error)

    async def voice(self, request):
        if not self.bridge:
            raise web.HTTPServiceUnavailable()
        return await self.bridge.issue(request)

    async def authorize_intent(self, session, action, resource, arguments):
        needed = "poppy:write" if action == "order.exchange" else "poppy:read"
        return (
            action in {"order.read", "order.exchange"}
            and needed in session.scopes
            and resource in self.account_resources.get(session.customer, set())
            and (not arguments if action == "order.read" else arguments == {"replacement": "blue"})
        )

    def propose(self, session, terms):
        if not session.signed_in:
            raise PAPError("sign_in_required", status=403)
        if (
            self.clients[session.client_id][0].get("extensions", {}).get("operations", {}).get("version")
            != "1"
        ):
            raise PAPError("extension_required", status=403)
        operation_id = "op_" + secrets.token_urlsafe(24)
        operation = {
            "operation_id": operation_id,
            "revision": 1,
            "state": "proposed",
            "summary": "Exchange order-1 for blue, no charge.",
            "terms": terms,
            "expires_at": datetime.fromtimestamp(time.time() + 60, timezone.utc)
            .isoformat()
            .replace("+00:00", "Z"),
            "user_approval_required": True,
            "confirmation": None,
            "result": None,
        }
        self.operations[operation_id] = {
            "operation": operation,
            "owner": (session.client_id, session.user_id, session.customer),
            "expires": time.time() + 60,
        }
        return operation

    async def operation(self, request):
        try:
            path = request.path
            session = await self.authenticate(
                method=request.method,
                url=self.base + path,
                authorization=request.headers.get("Authorization", ""),
                dpop=request.headers.get("DPoP", ""),
            )
            row = self.operations.get(request.match_info["id"])
            if not row or row["owner"] != (session.client_id, session.user_id, session.customer):
                raise PAPError("operation_not_found", status=404)
            op = row["operation"]
            verb = request.match_info.get("verb")
            if verb == "confirm":
                body = await request.json()
                if "poppy:write" not in session.scopes:
                    raise PAPError("insufficient_scope", status=403)
                if op["state"] != "proposed":
                    return web.json_response(op)
                if body.get("revision") != op["revision"]:
                    return web.json_response({"error": "terms_changed", "operation": op}, status=409)
                if op["user_approval_required"] and body.get("approved_by") != "user":
                    raise PAPError("user_approval_required", status=403)
                if body.get("approved_by") not in {"user", "standing_permission"}:
                    raise PAPError("user_approval_required", status=403)
                if row["expires"] <= time.time():
                    op["state"] = "expired"
                    op["result"] = {"summary": "No action performed."}
                else:
                    self.effects += 1
                    op.update(
                        state="succeeded",
                        confirmation={
                            "revision": op["revision"],
                            "approved_by": body["approved_by"],
                            "confirmed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                        },
                        result={"summary": "Demo exchange completed."},
                    )
            elif verb == "cancel" and op["state"] == "proposed":
                op.update(state="cancelled", result={"summary": "No action performed."})
            elif verb not in {None, "cancel"}:
                raise PAPError("request_failed", status=404)
            return web.json_response(op)
        except PAPError as error:
            return self._error(error)

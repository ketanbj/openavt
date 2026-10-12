"""PAP draft 0.1 HTTPS sessions, sign-in and operations. Tokens stay opaque."""

from __future__ import annotations

import asyncio
import hashlib
import secrets
import time
from dataclasses import dataclass, field, replace
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

from openavt.authority.common import b64, create_database, database

from .crypto import SigningKey, https_url
from .http import HTTPS, PAPError

ASSERTION = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
JWT_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer"


def text(value, *, maximum=4096):
    if not isinstance(value, str) or not 1 <= len(value) <= maximum:
        raise PAPError("invalid_protocol_field")
    return value


def scopes(value: str) -> frozenset[str]:
    if (
        not isinstance(value, str)
        or len(value) > 4096
        or any(ord(c) < 32 or ord(c) > 126 or c in '\\"' for c in value)
    ):
        raise PAPError("invalid_scope")
    return frozenset(value.split(" ")) - {""}


class UserIDs:
    """One private store per user; random stable IDs per issuer, never PII-derived."""

    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not path.exists():
            try:
                create_database(path, "CREATE TABLE users (issuer TEXT PRIMARY KEY, id TEXT NOT NULL);")
            except FileExistsError:
                pass

    def get(self, issuer: str) -> str:
        https_url(issuer)
        with database(self.path) as db:
            row = db.execute("SELECT id FROM users WHERE issuer=?", (issuer,)).fetchone()
            if row:
                return row["id"]
            value = "usr_" + secrets.token_urlsafe(24)
            db.execute("INSERT INTO users VALUES (?,?)", (issuer, value))
            return value


@dataclass(frozen=True)
class Session:
    session_id: str
    access_token: str = field(repr=False)
    scope: frozenset[str]
    signed_in: bool
    expires_at: float
    resource: str | None = None


@dataclass(frozen=True)
class DirectSignIn:
    url: str
    state: str = field(repr=False)
    verifier: str = field(repr=False)
    redirect_uri: str
    session_id: str
    requested_scope: frozenset[str]
    expires_at: float


class PAPClient:
    def __init__(
        self,
        *,
        client_id: str,
        signing_key: SigningKey,
        dpop_key: SigningKey,
        user_ids: UserIDs,
        http: HTTPS | None = None,
        extensions: dict | None = None,
        redirect_uris: tuple[str, ...] = (),
    ):
        self.client_id = https_url(client_id)
        if signing_key.thumbprint == dpop_key.thumbprint:
            raise ValueError("client assertion and DPoP keys must be separate")
        self.signing_key, self.dpop_key, self.user_ids = signing_key, dpop_key, user_ids
        self.http = http or HTTPS()
        self.extensions = extensions or {}
        self.redirect_uris = redirect_uris
        for url in redirect_uris:
            if urlsplit(https_url(url)).hostname != urlsplit(client_id).hostname:
                raise ValueError("redirect URIs must share the client metadata host")
        self.discovery: dict | None = None
        self.oauth: dict | None = None
        self.session: Session | None = None
        self.account_token: str | None = None
        self.account_scope: frozenset[str] = frozenset()
        self.pending_direct: DirectSignIn | None = None
        self.mediated_id: tuple[str, frozenset[str], str, float] | None = None
        self.lock = asyncio.Lock()

    def metadata(self, jwks_uri: str, *, name: str) -> dict:
        if urlsplit(https_url(jwks_uri)).hostname != urlsplit(self.client_id).hostname:
            raise ValueError("JWKS must share the client metadata host")
        return {
            "client_id": self.client_id,
            "client_name": name,
            "jwks_uri": jwks_uri,
            "redirect_uris": list(self.redirect_uris),
            "token_endpoint_auth_method": "private_key_jwt",
            "extensions": self.extensions,
        }

    async def close(self):
        await self.http.close()

    async def discover(self, company: str):
        parsed = urlsplit(https_url(company))
        if parsed.path not in {"", "/"} or parsed.query:
            raise ValueError("company must be an HTTPS origin")
        discovery = await self.http.document(company.rstrip("/") + "/.well-known/poppy.json")
        version = text(discovery.get("protocol_version"))
        if not version.startswith("0.") or not version[2:].isdecimal():
            raise PAPError("unsupported_protocol_version")
        organization = discovery.get("organization", {})
        if not isinstance(organization, dict):
            raise PAPError("invalid_discovery")
        domain = organization.get("domain")
        if not isinstance(domain, str) or domain.lower().removeprefix(
            "www."
        ) != parsed.hostname.lower().removeprefix("www."):
            raise PAPError("organization_domain_mismatch")
        auth = discovery.get("auth", {})
        if not isinstance(auth, dict):
            raise PAPError("invalid_discovery")
        issuer = https_url(auth.get("issuer"))
        if urlsplit(issuer).query:
            raise PAPError("invalid_issuer")
        p = urlsplit(issuer)
        metadata_url = f"{p.scheme}://{p.netloc}/.well-known/oauth-authorization-server{p.path.rstrip('/')}"
        oauth = await self.http.document(metadata_url)
        if (
            oauth.get("issuer") != issuer
            or not isinstance(oauth.get("poppy_domains"), list)
            or domain not in oauth["poppy_domains"]
        ):
            raise PAPError("issuer_domain_mismatch")
        required = ["token_endpoint", "revocation_endpoint"]
        if "direct" in auth:
            required.append("authorization_endpoint")
        if "device" in auth:
            required.append("device_authorization_endpoint")
        for name in required:
            https_url(oauth.get(name))
        if self.oauth and self.oauth["issuer"] != issuer and (self.session or self.account_token):
            raise PAPError("use_a_separate_client_for_each_company")
        self.discovery, self.oauth = discovery, oauth
        return discovery

    def _form(self, endpoint: str, **values):
        return {
            "client_id": self.client_id,
            "client_assertion_type": ASSERTION,
            "client_assertion": self.signing_key.assertion(self.client_id, endpoint),
            **values,
        }

    def _accept(
        self,
        data: dict,
        *,
        session_id=None,
        requested=None,
        resource=None,
        signed_in=None,
        preserve_account_scope=False,
        require_account=False,
    ):
        sid = text(data.get("session_id"), maximum=256)
        if session_id and sid != session_id:
            raise PAPError("session_id_mismatch")
        if data.get("token_type") != "DPoP" or type(data.get("signed_in")) is not bool:
            raise PAPError("invalid_session_token_response")
        if signed_in is not None and data["signed_in"] != signed_in:
            raise PAPError("unexpected_sign_in_state")
        expiry = data.get("expires_in")
        if type(expiry) is not int or not 0 < expiry <= 2**53:
            raise PAPError("invalid_token_lifetime")
        granted = scopes(data.get("scope"))
        if not data["signed_in"] and granted or requested is not None and not granted <= requested:
            raise PAPError("unexpected_scope")
        result = Session(
            sid, text(data.get("access_token")), granted, data["signed_in"], time.time() + expiry, resource
        )
        refresh = data.get("refresh_token")
        if require_account and refresh is None:
            raise PAPError("account_token_missing")
        if refresh is not None:
            text(refresh)
        self.session = result
        if refresh:
            self.account_token = refresh
            if not preserve_account_scope:
                self.account_scope = granted
        return result

    async def start_session(self, *, renew=False, resource=None):
        if not self.oauth:
            raise PAPError("discovery_required")
        async with self.lock:
            if renew and (not self.session or self.session.signed_in):
                raise PAPError("signed_in_sessions_require_account_token")
            endpoint = self.oauth["token_endpoint"]
            sid = self.session.session_id if renew else None

            def form():
                values = {
                    "grant_type": JWT_GRANT,
                    "assertion": self.signing_key.assertion(
                        self.client_id, endpoint, subject=self.user_ids.get(self.oauth["issuer"])
                    ),
                }
                if sid:
                    values["session_id"] = sid
                if resource:
                    values["resource"] = https_url(resource)
                return self._form(endpoint, **values)

            reply = await self.http.request("POST", endpoint, key=self.dpop_key, form_factory=form)
            if reply.data.get("signed_in") is not False:
                raise PAPError("new_session_must_be_signed_out")
            return self._accept(reply.data, session_id=sid, resource=resource)

    def _sign_in_scopes(self, kind, scope):
        wanted = scopes(scope)
        if not self.discovery:
            raise PAPError("discovery_required")
        offered = self.discovery["auth"].get(kind)
        if not wanted or not offered or not wanted <= frozenset(offered.get("scopes", [])):
            raise PAPError("invalid_scope")
        return wanted

    def _current(self):
        if not self.session or self.session.expires_at <= time.time():
            raise PAPError("active_session_required")
        return self.session

    def begin_direct(self, scope: str, redirect_uri: str) -> DirectSignIn:
        session = self._current()
        wanted = self._sign_in_scopes("direct", scope)
        if redirect_uri not in self.redirect_uris:
            raise PAPError("unregistered_redirect_uri")
        verifier = secrets.token_urlsafe(48)
        state = secrets.token_urlsafe(24)
        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "state": state,
            "code_challenge": b64(hashlib.sha256(verifier.encode()).digest()),
            "code_challenge_method": "S256",
        }
        endpoint = self.oauth["authorization_endpoint"]
        url = endpoint + ("&" if urlsplit(endpoint).query else "?") + urlencode(params)
        flow = DirectSignIn(url, state, verifier, redirect_uri, session.session_id, wanted, time.time() + 600)
        self.pending_direct = flow
        return flow

    async def finish_direct(self, callback: str):
        async with self.lock:
            flow = self.pending_direct
            if (
                not flow
                or flow.expires_at < time.time()
                or not self.session
                or self.session.session_id != flow.session_id
            ):
                raise PAPError("invalid_sign_in_state")
            uri = urlsplit(https_url(callback))
            redirect = urlsplit(flow.redirect_uri)
            params = parse_qs(uri.query, keep_blank_values=True)
            registered_query = parse_qs(redirect.query, keep_blank_values=True)
            if (
                (uri.scheme, uri.netloc, uri.path) != (redirect.scheme, redirect.netloc, redirect.path)
                or any(params.get(k) != v for k, v in registered_query.items())
                or any(len(v) != 1 for v in params.values())
                or params.get("state") != [flow.state]
                or params.get("iss") != [self.oauth["issuer"]]
            ):
                raise PAPError("sign_in_response_mismatch")
            self.pending_direct = None
            if "error" in params:
                raise PAPError("access_denied")
            code = text(params.get("code", [None])[0])
            endpoint = self.oauth["token_endpoint"]
            reply = await self.http.request(
                "POST",
                endpoint,
                key=self.dpop_key,
                form_factory=lambda: self._form(
                    endpoint,
                    grant_type="authorization_code",
                    code=code,
                    redirect_uri=flow.redirect_uri,
                    code_verifier=flow.verifier,
                    session_id=flow.session_id,
                ),
            )
            return self._accept(
                reply.data,
                session_id=flow.session_id,
                requested=flow.requested_scope,
                signed_in=True,
                require_account=True,
            )

    async def device_sign_in(self, scope: str, *, present, timeout: float = 600):
        wanted = self._sign_in_scopes("device", scope)
        session = self._current()
        endpoint = self.oauth["device_authorization_endpoint"]
        # Device authorization authenticates the client; no Session Token is sent.
        reply = await self.http.request(
            "POST", endpoint, key=self.dpop_key, form_factory=lambda: self._form(endpoint, scope=scope)
        )
        data = reply.data
        interval = data.get("interval", 5)
        lifetime = data.get("expires_in")
        if (
            type(interval) is not int
            or interval <= 0
            or type(lifetime) is not int
            or lifetime <= 0
            or not 0 < timeout <= 3600
        ):
            raise PAPError("invalid_device_response")
        await present(
            {
                "verification_uri": https_url(data.get("verification_uri")),
                "verification_uri_complete": https_url(data["verification_uri_complete"])
                if data.get("verification_uri_complete")
                else None,
                "user_code": text(data.get("user_code")),
                "expires_in": lifetime,
            }
        )
        code = text(data.get("device_code"))
        endpoint = self.oauth["token_endpoint"]
        deadline = time.monotonic() + min(timeout, lifetime)
        while time.monotonic() + interval < deadline:
            await asyncio.sleep(interval)
            try:
                reply = await self.http.request(
                    "POST",
                    endpoint,
                    key=self.dpop_key,
                    form_factory=lambda: self._form(
                        endpoint,
                        grant_type="urn:ietf:params:oauth:grant-type:device_code",
                        device_code=code,
                        session_id=session.session_id,
                    ),
                )
            except PAPError as error:
                if error.code == "authorization_pending":
                    continue
                if error.code == "slow_down":
                    interval += 5
                    continue
                if error.status == 429:
                    interval = max(interval, error.retry_after)
                    continue
                raise
            return self._accept(
                reply.data,
                session_id=session.session_id,
                requested=wanted,
                signed_in=True,
                require_account=True,
            )
        raise PAPError("expired_token")

    async def mediated_sign_in(self, scope: str, credentials: dict):
        wanted = self._sign_in_scopes("mediated", scope)
        fields = self.discovery["auth"]["mediated"].get("fields", [])
        if set(credentials) != {f["name"] for f in fields} or any(
            not isinstance(v, str) for v in credentials.values()
        ):
            raise PAPError("invalid_credentials_fields")
        endpoint = https_url(self.discovery["auth"]["mediated"]["endpoint"])
        reply = await self.api("POST", endpoint, body={"scope": scope, "credentials": credentials})
        return self._mediated_response(reply.data, wanted, self._current().session_id)

    def _mediated_response(self, data, wanted, session_id, expected_id=None):
        status = data.get("status")
        if status == "complete":
            result = self._accept(
                data, session_id=session_id, requested=wanted, signed_in=True, require_account=True
            )
            self.mediated_id = None
            return result
        if status in {"failed", "expired"}:
            self.mediated_id = None
            return data
        if status != "code_required":
            raise PAPError("invalid_mediated_response")
        sign_in_id = text(data.get("sign_in_id"), maximum=256)
        if expected_id and sign_in_id != expected_id:
            raise PAPError("invalid_sign_in_state")
        try:
            expiry = datetime.fromisoformat(text(data.get("expires_at")))
            if not expiry.tzinfo:
                raise ValueError()
            expires_at = expiry.timestamp()
        except ValueError:
            raise PAPError("invalid_mediated_response") from None
        self.mediated_id = (sign_in_id, wanted, session_id, expires_at)
        return data

    async def finish_mediated(self, code: str):
        if not self.mediated_id:
            raise PAPError("sign_in_not_started")
        sid, wanted, session_id, expires = self.mediated_id
        if expires <= time.time():
            self.mediated_id = None
            raise PAPError("sign_in_expired")
        if self._current().session_id != session_id:
            raise PAPError("invalid_sign_in_state")
        from urllib.parse import quote

        endpoint = self.discovery["auth"]["mediated"]["endpoint"].rstrip("/") + "/" + quote(sid, safe="")
        reply = await self.api("POST", endpoint, body={"code": text(code)})
        return self._mediated_response(reply.data, wanted, session_id, expected_id=sid)

    async def refresh(self, *, scope: str | None = None, resource: str | None = None, new_session=False):
        if not self.account_token:
            raise PAPError("account_token_required")
        wanted = scopes(scope) if scope is not None else self.account_scope
        if not wanted <= self.account_scope:
            raise PAPError("insufficient_scope")
        async with self.lock:
            endpoint = self.oauth["token_endpoint"]
            if not new_session and not self.session:
                raise PAPError("session_required")
            sid = None if new_session else self.session.session_id
            values = {"grant_type": "refresh_token", "refresh_token": self.account_token}
            if sid:
                values["session_id"] = sid
            if scope is not None:
                values["scope"] = scope
            if resource:
                values["resource"] = https_url(resource)
            try:
                reply = await self.http.request(
                    "POST", endpoint, key=self.dpop_key, form_factory=lambda: self._form(endpoint, **values)
                )
            except PAPError as error:
                if error.code == "invalid_grant":
                    self._forget_account()
                raise
            return self._accept(
                reply.data,
                session_id=sid,
                requested=wanted,
                resource=resource,
                signed_in=True,
                preserve_account_scope=True,
            )

    async def sign_out(self):
        if not self.account_token:
            return
        endpoint = self.oauth["revocation_endpoint"]
        await self.http.request(
            "POST",
            endpoint,
            key=self.dpop_key,
            form_factory=lambda: self._form(
                endpoint, token=self.account_token, token_type_hint="refresh_token"
            ),
        )
        self._forget_account()

    def _forget_account(self):
        self.account_token = None
        self.account_scope = frozenset()
        self.pending_direct = None
        self.mediated_id = None
        # Existing signed-in access tokens must no longer be used by this client.
        if self.session:
            self.session = replace(
                self.session, access_token="", scope=frozenset(), signed_in=False, expires_at=0
            )

    async def api(self, method: str, url: str, *, body=None):
        if not self.discovery:
            raise PAPError("discovery_required")
        url = https_url(url)
        candidate = urlsplit(url)
        # Only services named by verified discovery may receive Session Tokens.
        allowed = [entry.get("endpoint") for entry in self.discovery.get("agent", {}).get("protocols", [])]
        allowed.extend(
            entry.get("url") for entry in self.discovery.get("apis", []) if entry.get("type") == "openapi"
        )
        for entry in self.discovery.get("extensions", {}).values():
            if isinstance(entry, dict):
                allowed.extend(entry.get(name) for name in ("endpoint", "grant_endpoint") if entry.get(name))
        mediated = self.discovery["auth"].get("mediated", {})
        if mediated.get("endpoint"):
            allowed.append(mediated["endpoint"])
        matched = False
        for base in allowed:
            if not base:
                continue
            base = urlsplit(https_url(base))
            if (candidate.scheme, candidate.netloc) == (base.scheme, base.netloc):
                # OpenAPI schemas can describe several API paths on this origin.
                matched = True
                break
        if not matched:
            raise PAPError("undiscovered_resource")
        session = self._current()
        return await self.http.request(method, url, key=self.dpop_key, token=session.access_token, body=body)

    async def operation(self, operation_id: str, *, revision=None, approved_by=None, cancel=False):
        import re

        if not re.fullmatch(r"[A-Za-z0-9_-]{1,256}", operation_id):
            raise PAPError("invalid_operation_id")
        if not self.discovery:
            raise PAPError("discovery_required")
        entry = self.discovery.get("extensions", {}).get("operations", {})
        if entry.get("version") != "1" or self.extensions.get("operations", {}).get("version") != "1":
            raise PAPError("extension_required")
        endpoint = https_url(entry.get("endpoint")).rstrip("/") + "/" + operation_id
        body = None
        method = "GET"
        if revision is not None:
            if (
                type(revision) is not int
                or revision < 1
                or approved_by not in {"user", "standing_permission"}
            ):
                raise PAPError("invalid_confirmation")
            method = "POST"
            endpoint += "/confirm"
            body = {"revision": revision, "approved_by": approved_by}
        elif cancel:
            method = "POST"
            endpoint += "/cancel"
        reply = await self.api(method, endpoint, body=body)
        return reply.data

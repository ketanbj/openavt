"""Bounded HTTPS transport: discovery redirects only, no credential forwarding."""

from __future__ import annotations

import re
import ssl
import time
from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime
from urllib.parse import urljoin

import aiohttp
from yarl import URL

from openavt.authority.common import parse_json

from .crypto import SigningKey, https_url


class PAPError(Exception):
    def __init__(self, code: str, *, status: int = 0, retry_after: float = 0):
        # Never reflect response text, tokens, credential bodies or provider errors.
        super().__init__(code)
        self.code, self.status, self.retry_after = code, status, retry_after


@dataclass
class Reply:
    status: int
    data: dict = field(repr=False)
    headers: dict


class HTTPS:
    def __init__(self, *, ssl_context: ssl.SSLContext | None = None, timeout: float = 15):
        if ssl_context is not None and (
            not isinstance(ssl_context, ssl.SSLContext)
            or ssl_context.verify_mode != ssl.CERT_REQUIRED
            or not ssl_context.check_hostname
        ):
            raise ValueError("HTTPS must verify the certificate and hostname")
        if not 0 < timeout <= 60:
            raise ValueError("invalid HTTPS timeout")
        self.ssl = ssl_context
        self.timeout = timeout
        self.http: aiohttp.ClientSession | None = None
        self.nonces: dict[str, str] = {}
        self.blocked: dict[str, float] = {}
        self.cache: dict[str, tuple[float, dict]] = {}

    async def close(self):
        if self.http:
            await self.http.close()
            self.http = None

    async def _send(self, method, url, *, headers=None, form=None, body=None) -> Reply:
        https_url(url)
        if self.http is None:
            self.http = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                trust_env=False,
                cookie_jar=aiohttp.DummyCookieJar(),
            )
        try:
            async with self.http.request(
                method, url, headers=headers, data=form, json=body, allow_redirects=False, ssl=self.ssl
            ) as response:
                raw = bytearray()
                async for chunk in response.content.iter_chunked(8192):
                    raw.extend(chunk)
                    if len(raw) > 131072:
                        raise PAPError("response_too_large")
                selected = {
                    name: response.headers[name]
                    for name in ("Location", "DPoP-Nonce", "WWW-Authenticate", "Retry-After", "Cache-Control")
                    if name in response.headers
                }
                data = (
                    parse_json(bytes(raw)) if raw and response.status not in {301, 302, 303, 307, 308} else {}
                )
                return Reply(response.status, data, selected)
        except PAPError:
            raise
        except (aiohttp.ClientError, TimeoutError, ValueError):
            raise PAPError("transport_or_response_invalid") from None

    async def document(self, url: str) -> dict:
        original = https_url(url)
        cached = self.cache.get(original)
        if cached and cached[0] > time.monotonic():
            return cached[1]
        for _ in range(6):
            response = await self._send("GET", url)
            if response.status in {301, 302, 303, 307, 308}:
                url = https_url(urljoin(url, response.headers.get("Location", "")))
                continue
            if response.status != 200:
                raise PAPError("discovery_failed", status=response.status)
            control = response.headers.get("Cache-Control", "")
            age = re.search(r"(?:^|,)\s*max-age=(\d+)", control)
            if age and "no-store" not in control and "no-cache" not in control:
                if len(self.cache) >= 256 and original not in self.cache:
                    self.cache.pop(next(iter(self.cache)))
                self.cache[original] = (time.monotonic() + min(int(age[1]), 86400), response.data)
            return response.data
        raise PAPError("too_many_discovery_redirects")

    async def request(
        self,
        method: str,
        url: str,
        *,
        key: SigningKey,
        token: str | None = None,
        form_factory=None,
        body=None,
    ) -> Reply:
        url = str(URL(https_url(url)))
        for attempt in range(2):
            remaining = self.blocked.get(url, 0) - time.monotonic()
            if remaining > 0:
                raise PAPError("rate_limited", status=429, retry_after=remaining)
            headers = {"DPoP": key.dpop(method, url, token=token, nonce=self.nonces.get(url))}
            if token:
                headers["Authorization"] = "DPoP " + token
            response = await self._send(
                method, url, headers=headers, form=form_factory() if form_factory else None, body=body
            )
            nonce = response.headers.get("DPoP-Nonce")
            if nonce:
                if not 1 <= len(nonce) <= 512 or any(ord(c) < 33 or ord(c) > 126 for c in nonce):
                    raise PAPError("invalid_dpop_nonce")
                if len(self.nonces) >= 256 and url not in self.nonces:
                    self.nonces.pop(next(iter(self.nonces)))
                self.nonces[url] = nonce
            challenge = response.data.get(
                "error"
            ) == "use_dpop_nonce" or 'error="use_dpop_nonce"' in response.headers.get("WWW-Authenticate", "")
            if response.status in {400, 401} and challenge and nonce and attempt == 0:
                continue
            if response.status == 429:
                retry = response.headers.get("Retry-After", "1")
                try:
                    seconds = (
                        int(retry)
                        if retry.isdecimal()
                        else max(0, parsedate_to_datetime(retry).timestamp() - time.time())
                    )
                except (ValueError, TypeError):
                    raise PAPError("invalid_retry_after") from None
                self.blocked = {k: v for k, v in self.blocked.items() if v > time.monotonic()}
                if len(self.blocked) >= 256 and url not in self.blocked:
                    raise PAPError("rate_limit_capacity", status=429, retry_after=seconds)
                self.blocked[url] = time.monotonic() + seconds
                raise PAPError("rate_limited", status=429, retry_after=seconds)
            if not 200 <= response.status < 300:
                code = response.data.get("error", "request_failed")
                if not isinstance(code, str) or not re.fullmatch(r"[a-z_]{1,64}", code):
                    code = "request_failed"
                raise PAPError(code, status=response.status)
            return response
        raise PAPError("dpop_nonce_rejected")

"""Bounded local enrollment/consent JSON service; TLS required off loopback."""

from __future__ import annotations

import ipaddress
import socket
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from openavt.authority.ca import AgentAuthority
from openavt.authority.common import AuthorityError, canonical, fingerprint, parse_json
from openavt.authority.delegation import BusinessAuthority

MAX_BODY = 16384


def loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class AuthorityServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 8

    def __init__(
        self,
        address,
        agents: AgentAuthority,
        business: BusinessAuthority | None = None,
        tls: ssl.SSLContext | None = None,
    ):
        if not loopback(address[0]) and tls is None:
            raise AuthorityError("tls_required_off_loopback")
        if business is not None and business.agents.issuer != agents.issuer:
            raise AuthorityError("wrong_agent_trust_root")
        self.agents, self.business = agents, business
        self.workers = threading.BoundedSemaphore(8)
        if ":" in address[0]:
            self.address_family = socket.AF_INET6
        super().__init__(address, Handler)
        if tls is not None:
            self.socket = tls.wrap_socket(self.socket, server_side=True, do_handshake_on_connect=False)

    def process_request(self, request, client_address):
        if not self.workers.acquire(blocking=False):
            # No request/body parsing and no additional worker for overload.
            try:
                request.settimeout(0.1)
                if not isinstance(request, ssl.SSLSocket):
                    request.sendall(b"HTTP/1.0 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n")
            except OSError:
                pass
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.workers.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            request.settimeout(5)
            if isinstance(request, ssl.SSLSocket):
                request.do_handshake()
            super().process_request_thread(request, client_address)
        except (OSError, ssl.SSLError):
            self.shutdown_request(request)
        finally:
            self.workers.release()


class Handler(BaseHTTPRequestHandler):
    server: AuthorityServer

    def log_message(self, *_):
        pass  # No credentials, proofs or grants in HTTP access logs.

    def _response(self, code: int, value: dict):
        raw = canonical(value)
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(raw)

    def _credential(self) -> str:
        values = self.headers.get_all("Authorization", [])
        if len(values) != 1 or not values[0].startswith("Bearer "):
            raise AuthorityError("credential_required", 401)
        return values[0][7:]

    def _body(self) -> dict:
        lengths = self.headers.get_all("Content-Length", [])
        if (
            len(lengths) != 1
            or not lengths[0].isascii()
            or not lengths[0].isdigit()
            or self.headers.get("Transfer-Encoding")
        ):
            raise AuthorityError("content_length_required", 411)
        length = int(lengths[0])
        if not 0 < length <= MAX_BODY:
            raise AuthorityError("body_too_large", 413)
        if self.headers.get("Content-Type") != "application/json":
            raise AuthorityError("json_content_type_required", 415)
        raw = self.rfile.read(length)
        if len(raw) != length:
            raise AuthorityError("incomplete_body")
        return parse_json(raw)

    def do_GET(self):
        if self.path != "/v1/directory":
            self._response(404, {"error": "unknown_endpoint"})
            return
        from cryptography.hazmat.primitives import serialization

        self._response(
            200,
            {
                "protocol": "openavt-ava-v1 (not ACME)",
                "issuer": self.server.agents.issuer,
                "root_sha256": fingerprint(self.server.agents.root.public_bytes(serialization.Encoding.DER)),
                "assurance": "pseudonymous-key-control",
                "certificate_lifetime_seconds": 86400,
                "business_audience": self.server.business.audience if self.server.business else None,
            },
        )

    def do_POST(self):
        try:
            body = self._body()
            agents, business = self.server.agents, self.server.business
            if self.path == "/v1/accounts" and not body:
                result = agents.register()
            elif self.path == "/v1/orders" and set(body) == {"agent", "csr"}:
                result = agents.order(self._credential(), body["agent"], body["csr"])
            elif (
                self.path.startswith("/v1/orders/")
                and self.path.endswith("/finalize")
                and set(body) == {"proof"}
            ):
                result = agents.finalize(self._credential(), self.path.split("/")[3], body["proof"])
            elif self.path == "/v1/certificates/revoke" and set(body) == {"serial"}:
                if (
                    not isinstance(body["serial"], str)
                    or not body["serial"].isdigit()
                    or len(body["serial"]) > 64
                ):
                    raise AuthorityError("invalid_serial")
                agents.revoke(self._credential(), body["serial"])
                result = {"revoked": True}
            elif (
                self.path == "/v1/grants"
                and business
                and set(body) == {"certificate", "action", "resource", "ttl"}
            ):
                result = business.issue(
                    self._credential(), body["certificate"], body["action"], body["resource"], body["ttl"]
                )
            elif (
                self.path.startswith("/v1/grants/")
                and self.path.endswith("/revoke")
                and business
                and not body
            ):
                business.revoke(self.path.split("/")[3], self._credential())
                result = {"revoked": True}
            else:
                raise AuthorityError("unknown_endpoint_or_fields", 400)
            self._response(200, result)
        except AuthorityError as error:
            self._response(error.status, {"error": error.code})
        except (ValueError, TypeError, KeyError):
            self._response(400, {"error": "invalid_request"})
        except (OSError, TimeoutError):
            self.close_connection = True
        except Exception:
            self._response(503, {"error": "authority_unavailable"})

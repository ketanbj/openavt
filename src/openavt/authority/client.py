"""Enrollment keeps private keys local and requires an explicitly pinned root."""

from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from openavt.authority.ca import validate_agent_certificate
from openavt.authority.common import (
    AuthorityError,
    b64,
    canonical,
    digest,
    initialize_directory,
    key_pem,
    label,
    parse_json,
    private_write,
    unb64,
)
from openavt.authority.service import loopback


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_):
        raise AuthorityError("redirect_refused")


class AuthorityClient:
    def __init__(self, url: str):
        parsed = urllib.parse.urlsplit(url)
        if (
            parsed.scheme not in ("http", "https")
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.path not in ("", "/")
        ):
            raise AuthorityError("invalid_authority_url")
        if parsed.scheme == "http" and not loopback(parsed.hostname):
            raise AuthorityError("https_required_off_loopback")
        self.url = url.rstrip("/")
        # System HTTPS trust validation remains enabled; never forward auth on a redirect.
        self.opener = urllib.request.build_opener(NoRedirect(), urllib.request.ProxyHandler({}))

    def post(self, path: str, body: dict, credential: str | None = None) -> dict:
        if not path.startswith("/v1/") or "?" in path or "#" in path:
            raise AuthorityError("invalid_api_path")
        headers = {"Content-Type": "application/json"}
        if credential:
            headers["Authorization"] = "Bearer " + credential
        request = urllib.request.Request(
            self.url + path, data=canonical(body), headers=headers, method="POST"
        )
        try:
            with self.opener.open(request, timeout=5) as response:
                raw = response.read(16385)
                if len(raw) > 16384:
                    raise AuthorityError("response_too_large")
                return parse_json(raw)
        except urllib.error.HTTPError as error:
            # Error bodies may reflect credentials; expose only the HTTP status.
            status = error.code
            error.close()
            raise AuthorityError(f"authority_http_{status}", status) from None

    def account(self) -> dict:
        return self.post("/v1/accounts", {})

    def enroll(
        self, credentials: dict, agent: str, root_pem: bytes, output: Path, key_path: Path | None = None
    ) -> dict:
        label(agent)
        if output.exists():
            raise AuthorityError("output_already_exists")
        root = x509.load_pem_x509_certificate(root_pem)
        key = (
            serialization.load_pem_private_key(key_path.read_bytes(), password=None)
            if key_path
            else ec.generate_private_key(ec.SECP256R1())
        )
        if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
            raise AuthorityError("invalid_agent_key")
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, agent)]))
            .sign(key, hashes.SHA256())
            .public_bytes(serialization.Encoding.PEM)
            .decode()
        )
        order = self.post("/v1/orders", {"agent": agent, "csr": csr}, credentials["credential"])
        proof_message = unb64(order["proof_message"])
        challenge = parse_json(proof_message)
        if (
            challenge["issuer"] != "urn:openavt:ava:" + root.fingerprint(hashes.SHA256()).hex()
            or challenge["account"] != credentials["account"]
            or challenge["agent"] != agent
            or challenge.get("csr_sha256") != digest(csr.encode())
            or challenge.get("order") != order["order"]
            or challenge.get("expires") != order["expires"]
        ):
            raise AuthorityError("unexpected_authority_challenge")
        proof = b64(key.sign(proof_message, ec.ECDSA(hashes.SHA256())))
        result = self.post(
            f"/v1/orders/{order['order']}/finalize", {"proof": proof}, credentials["credential"]
        )
        cert = x509.load_pem_x509_certificate(result["certificate"].encode())
        identity = validate_agent_certificate(cert, root)
        if (
            identity != f"urn:openavt:agent:{credentials['account']}:{agent}"
            or cert.public_key().public_numbers() != key.public_key().public_numbers()
        ):
            raise AuthorityError("unexpected_issued_certificate")
        initialize_directory(output)
        private_write(output / "agent.key", key_pem(key))
        (output / "agent.pem").write_text(result["certificate"])
        (output / "root.pem").write_bytes(root_pem)
        (output / "certificate.json").write_bytes(
            canonical({k: v for k, v in result.items() if k != "certificate"})
        )
        return {k: v for k, v in result.items() if k != "certificate"}

    def consent(
        self, credentials: dict, certificate: str, action: str, resource: str, ttl: int = 300
    ) -> dict:
        return self.post(
            "/v1/grants",
            {"certificate": certificate, "action": action, "resource": resource, "ttl": ttl},
            credentials["credential"],
        )


def save_credentials(path: Path, credentials: dict) -> None:
    private_write(path, canonical(credentials))

"""ES256 client assertions and RFC 9449 DPoP using separate keys."""

from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from openavt.authority.common import b64, canonical


def https_url(value: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 4096:
        raise ValueError("invalid HTTPS URL")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
    ):
        raise ValueError("an HTTPS URL without credentials or fragment is required")
    _ = parsed.port
    if any(ord(c) < 33 for c in value):
        raise ValueError("invalid HTTPS URL")
    return value


def htu(url: str) -> str:
    parsed = urlsplit(https_url(url))
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))


@dataclass
class SigningKey:
    private: ec.EllipticCurvePrivateKey = field(repr=False)
    kid: str | None = None

    def __post_init__(self):
        if not isinstance(self.private, ec.EllipticCurvePrivateKey) or not isinstance(
            self.private.curve, ec.SECP256R1
        ):
            raise ValueError("the PAP signing profile requires P-256")

    @classmethod
    def generate(cls, *, kid: str | None = None):
        return cls(ec.generate_private_key(ec.SECP256R1()), kid)

    @classmethod
    def load(cls, path, *, kid: str | None = None):
        return cls(serialization.load_pem_private_key(path.read_bytes(), None), kid)

    @property
    def jwk(self) -> dict:
        n = self.private.public_key().public_numbers()
        return {
            "kty": "EC",
            "crv": "P-256",
            "x": b64(n.x.to_bytes(32, "big")),
            "y": b64(n.y.to_bytes(32, "big")),
        }

    @property
    def jwks(self) -> dict:
        key = {**self.jwk, "alg": "ES256", "use": "sig"}
        if self.kid:
            key["kid"] = self.kid
        return {"keys": [key]}

    @property
    def thumbprint(self) -> str:
        return b64(hashlib.sha256(canonical(self.jwk)).digest())

    def jwt(self, claims: dict, *, proof: bool = False) -> str:
        header = {"alg": "ES256", "typ": "dpop+jwt" if proof else "JWT"}
        if proof:
            header["jwk"] = self.jwk
        elif self.kid:
            header["kid"] = self.kid
        wire = b64(canonical(header)) + "." + b64(canonical(claims))
        r, s = decode_dss_signature(self.private.sign(wire.encode(), ec.ECDSA(hashes.SHA256())))
        return wire + "." + b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))

    def assertion(self, client_id: str, audience: str, *, subject: str | None = None) -> str:
        now = int(time.time())
        return self.jwt(
            {
                "iss": client_id,
                "sub": subject or client_id,
                "aud": audience,
                "iat": now,
                "exp": now + 60,
                "jti": secrets.token_urlsafe(24),
            }
        )

    def dpop(self, method: str, url: str, *, token: str | None = None, nonce: str | None = None) -> str:
        claims = {
            "jti": secrets.token_urlsafe(24),
            "htm": method.upper(),
            "htu": htu(url),
            "iat": int(time.time()),
        }
        if token is not None:
            claims["ath"] = b64(hashlib.sha256(token.encode()).digest())
        if nonce:
            claims["nonce"] = nonce
        return self.jwt(claims, proof=True)

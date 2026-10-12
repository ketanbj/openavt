"""Local credentials with explicit peer trust; no implicit demo root."""

from __future__ import annotations

import ssl
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Identity:
    certificate: Path
    private_key: Path

    @classmethod
    def load(cls, directory: str | Path, *, name: str = "agent") -> Identity:
        if name not in {"agent", "desk"}:
            raise ValueError("identity name must be agent or desk")
        directory = Path(directory)
        identity = cls(directory / f"{name}.pem", directory / f"{name}.key")
        if not identity.certificate.is_file() or not identity.private_key.is_file():
            raise FileNotFoundError("identity certificate or private key is missing")
        return identity

    def context(self, trust: str | Path, *, server: bool = False) -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server else ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(str(trust))
        context.load_cert_chain(str(self.certificate), str(self.private_key))
        context.set_ecdh_curve("prime256v1")
        if server:
            context.num_tickets = 0
        return context

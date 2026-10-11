"""ACME-inspired account/order/key-proof enrollment, not an ACME server."""

from __future__ import annotations

import secrets
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from openavt.authority.common import (
    AuthorityError,
    b64,
    canonical,
    create_database,
    database,
    digest,
    fingerprint,
    initialize_directory,
    key_pem,
    label,
    private_write,
    unb64,
)

SCHEMA = """
CREATE TABLE accounts (id TEXT PRIMARY KEY, credential_hash TEXT NOT NULL);
CREATE TABLE orders (id TEXT PRIMARY KEY, account TEXT NOT NULL, agent TEXT NOT NULL,
 csr TEXT NOT NULL, nonce TEXT NOT NULL, created INTEGER NOT NULL, expires INTEGER NOT NULL,
 status TEXT NOT NULL, certificate TEXT);
CREATE TABLE certificates (serial TEXT PRIMARY KEY, account TEXT NOT NULL,
 agent TEXT NOT NULL, certificate TEXT NOT NULL, expires INTEGER NOT NULL, revoked INTEGER NOT NULL);
"""


def validate_agent_certificate(cert: x509.Certificate, root: x509.Certificate, now: int | None = None) -> str:
    now = int(time.time()) if now is None else now
    try:
        cert.verify_directly_issued_by(root)
        if not cert.not_valid_before_utc.timestamp() <= now < cert.not_valid_after_utc.timestamp():
            raise AuthorityError("certificate_expired", 403)
        if cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise AuthorityError("agent_certificate_is_ca", 403)
        if (
            ExtendedKeyUsageOID.CLIENT_AUTH
            not in cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        ):
            raise AuthorityError("wrong_certificate_purpose", 403)
        identities = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.UniformResourceIdentifier)
        if len(identities) != 1 or not identities[0].startswith("urn:openavt:agent:"):
            raise AuthorityError("invalid_agent_identity", 403)
        return identities[0]
    except (ValueError, TypeError, x509.ExtensionNotFound, InvalidSignature) as error:
        if isinstance(error, AuthorityError):
            raise
        raise AuthorityError("untrusted_agent_certificate", 403) from error


class AgentAuthority:
    def __init__(self, state: Path):
        self.state = state
        self.db = state / "authority.sqlite3"
        self.root = x509.load_pem_x509_certificate((state / "root.pem").read_bytes())
        self.issuer = "urn:openavt:ava:" + self.root.fingerprint(hashes.SHA256()).hex()

    @classmethod
    def initialize(cls, state: Path):
        initialize_directory(state)
        key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.now(timezone.utc)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "OpenAVT local Agent Voice Authority")])
        root = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True
            )
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256())
        )
        private_write(state / "root.key", key_pem(key))
        (state / "root.pem").write_bytes(root.public_bytes(serialization.Encoding.PEM))
        create_database(state / "authority.sqlite3", SCHEMA)
        return cls(state)

    def _sign(self, public_key, subject: str, san, purpose):
        key = serialization.load_pem_private_key((self.state / "root.key").read_bytes(), password=None)
        now = datetime.now(timezone.utc)
        if not self.root.not_valid_before_utc <= now < self.root.not_valid_after_utc:
            raise AuthorityError("authority_expired", 503)
        return (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
            .issuer_name(self.root.subject)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(seconds=30))
            .not_valid_after(min(now + timedelta(hours=24), self.root.not_valid_after_utc))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True
            )
            .add_extension(x509.ExtendedKeyUsage([purpose]), critical=False)
            .add_extension(x509.SubjectAlternativeName([san]), critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False
            )
            .sign(key, hashes.SHA256())
        )

    def provision_service(self, directory: Path, hostname: str = "desk.demo") -> None:
        """Local operator operation, deliberately absent from the enrollment API."""
        key = ec.generate_private_key(ec.SECP256R1())
        cert = self._sign(key.public_key(), hostname, x509.DNSName(hostname), ExtendedKeyUsageOID.SERVER_AUTH)
        private_write(directory / "desk.key", key_pem(key))
        (directory / "desk.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    def register(self) -> dict:
        account, credential = secrets.token_hex(16), secrets.token_urlsafe(32)
        with database(self.db) as db:
            if db.execute("SELECT COUNT(*) FROM accounts").fetchone()[0] >= 1000:
                raise AuthorityError("account_capacity", 429)
            db.execute("INSERT INTO accounts VALUES (?, ?)", (account, digest(credential.encode())))
        return {"account": account, "credential": credential, "assurance": "pseudonymous-key-control"}

    def _account(self, db, credential: str):
        if not isinstance(credential, str) or not 20 <= len(credential) <= 128:
            raise AuthorityError("invalid_account_credential", 401)
        row = db.execute(
            "SELECT id FROM accounts WHERE credential_hash = ?", (digest(credential.encode()),)
        ).fetchone()
        if row is None:
            raise AuthorityError("invalid_account_credential", 401)
        return row["id"]

    def order(self, credential: str, agent: str, csr_pem: str) -> dict:
        label(agent)
        if not isinstance(csr_pem, str) or len(csr_pem) > 4096:
            raise AuthorityError("invalid_csr")
        try:
            csr = x509.load_pem_x509_csr(csr_pem.encode())
            if (
                not csr.is_signature_valid
                or not isinstance(csr.public_key(), ec.EllipticCurvePublicKey)
                or not isinstance(csr.public_key().curve, ec.SECP256R1)
            ):
                raise AuthorityError("invalid_csr_key")
        except ValueError as error:
            raise AuthorityError("invalid_csr") from error
        # Requested names/extensions are never copied into the issued cert.
        now = int(time.time())
        with database(self.db) as db:
            account = self._account(db, credential)
            db.execute("DELETE FROM orders WHERE expires <= ?", (now,))
            db.execute("DELETE FROM certificates WHERE expires <= ?", (now,))
            if (
                db.execute("SELECT COUNT(*) FROM orders").fetchone()[0] >= 10000
                or db.execute("SELECT COUNT(*) FROM certificates").fetchone()[0] >= 10000
            ):
                raise AuthorityError("enrollment_capacity", 429)
            recent = db.execute(
                "SELECT COUNT(*) FROM orders WHERE account=? AND created > ?", (account, now - 60)
            ).fetchone()[0]
            if recent >= 10:
                raise AuthorityError("enrollment_rate_limit", 429)
            order_id, nonce = secrets.token_hex(16), secrets.token_urlsafe(32)
            db.execute(
                "INSERT INTO orders VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', NULL)",
                (order_id, account, agent, csr_pem, nonce, now, now + 120),
            )
            row = db.execute("SELECT * FROM orders WHERE id=?", (order_id,)).fetchone()
            return self._challenge(row)

    def _challenge(self, row) -> dict:
        message = {
            "issuer": self.issuer,
            "account": row["account"],
            "agent": row["agent"],
            "order": row["id"],
            "nonce": row["nonce"],
            "csr_sha256": digest(row["csr"].encode()),
            "expires": row["expires"],
        }
        return {"order": row["id"], "proof_message": b64(canonical(message)), "expires": row["expires"]}

    def finalize(self, credential: str, order_id: str, proof: str) -> dict:
        if not isinstance(proof, str) or len(proof) > 256:
            raise AuthorityError("invalid_proof")
        with database(self.db) as db:
            account = self._account(db, credential)
            row = db.execute("SELECT * FROM orders WHERE id=? AND account=?", (order_id, account)).fetchone()
            if row is None:
                raise AuthorityError("unknown_order", 404)
            if row["status"] != "pending" or row["expires"] <= int(time.time()):
                raise AuthorityError("order_expired_or_used", 409)
            csr = x509.load_pem_x509_csr(row["csr"].encode())
            try:
                csr.public_key().verify(
                    unb64(proof), unb64(self._challenge(row)["proof_message"]), ec.ECDSA(hashes.SHA256())
                )
            except InvalidSignature as error:
                raise AuthorityError("invalid_key_proof", 403) from error
            identity = f"urn:openavt:agent:{account}:{row['agent']}"
            db.execute("DELETE FROM certificates WHERE expires <= ?", (int(time.time()),))
            if db.execute("SELECT COUNT(*) FROM certificates").fetchone()[0] >= 10000:
                raise AuthorityError("enrollment_capacity", 429)
            cert = self._sign(
                csr.public_key(),
                row["agent"],
                x509.UniformResourceIdentifier(identity),
                ExtendedKeyUsageOID.CLIENT_AUTH,
            )
            pem = cert.public_bytes(serialization.Encoding.PEM).decode()
            db.execute(
                "INSERT INTO certificates VALUES (?, ?, ?, ?, ?, 0)",
                (str(cert.serial_number), account, identity, pem, int(cert.not_valid_after_utc.timestamp())),
            )
            db.execute("UPDATE orders SET status='valid', certificate=? WHERE id=?", (pem, order_id))
            return {
                "certificate": pem,
                "agent": identity,
                "serial": str(cert.serial_number),
                "expires": int(cert.not_valid_after_utc.timestamp()),
                "assurance": "pseudonymous-key-control",
            }

    def revoke(self, credential: str, serial: str) -> None:
        with database(self.db) as db:
            account = self._account(db, credential)
            result = db.execute(
                "UPDATE certificates SET revoked=1 WHERE serial=? AND account=?", (serial, account)
            )
            if result.rowcount != 1:
                raise AuthorityError("unknown_certificate", 404)

    def require_active(self, der: bytes) -> str:
        try:
            cert = x509.load_der_x509_certificate(der)
        except ValueError as error:
            raise AuthorityError("invalid_certificate", 403) from error
        identity = validate_agent_certificate(cert, self.root)
        with database(self.db) as db:
            row = db.execute(
                "SELECT revoked, certificate FROM certificates WHERE serial=?", (str(cert.serial_number),)
            ).fetchone()
            if (
                row is None
                or row["revoked"]
                or fingerprint(
                    x509.load_pem_x509_certificate(row["certificate"].encode()).public_bytes(
                        serialization.Encoding.DER
                    )
                )
                != fingerprint(der)
            ):
                raise AuthorityError("certificate_revoked_or_unknown", 403)
        return identity

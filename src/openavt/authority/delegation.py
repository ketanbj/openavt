"""Business-issued, single-use customer consent bound to a TLS certificate."""

from __future__ import annotations

import secrets
import time
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from openavt.authority.ca import AgentAuthority
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
    parse_json,
    private_write,
    unb64,
)

SCHEMA = """
CREATE TABLE customers (id TEXT PRIMARY KEY, credential_hash TEXT NOT NULL, resources TEXT NOT NULL);
CREATE TABLE grants (id TEXT PRIMARY KEY, customer TEXT NOT NULL, expires INTEGER NOT NULL, revoked INTEGER NOT NULL, used INTEGER NOT NULL);
CREATE TABLE challenges (nonce TEXT PRIMARY KEY, peer TEXT NOT NULL, expires INTEGER NOT NULL, used INTEGER NOT NULL);
"""
TYPE = "openavt-delegation+jwt"
CLAIMS = {"iss", "sub", "aud", "agent", "scope", "resource", "iat", "nbf", "exp", "jti", "cnf"}


class BusinessAuthority:
    """Demo account provisioning is an operator action, never AVA enrollment."""

    def __init__(self, state: Path, agents: AgentAuthority):
        self.state, self.agents = state, agents
        self.db = state / "delegation.sqlite3"
        self.config = parse_json((state / "config.json").read_bytes())
        self.public_key = serialization.load_pem_public_key((state / "grant-public.pem").read_bytes())
        if not isinstance(self.public_key, ed25519.Ed25519PublicKey):
            raise AuthorityError("invalid_business_verification_key")
        self.issuer = self.config["issuer"]
        self.audience = self.config["audience"]
        if self.config["agent_root"] != fingerprint(agents.root.public_bytes(serialization.Encoding.DER)):
            raise AuthorityError("wrong_agent_trust_root")

    @classmethod
    def initialize(cls, state: Path, agents: AgentAuthority, audience: str = "desk.demo"):
        if not isinstance(audience, str) or not 1 <= len(audience) <= 128:
            raise AuthorityError("invalid_audience")
        initialize_directory(state)
        key = ed25519.Ed25519PrivateKey.generate()
        public = key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        private_write(state / "grant.key", key_pem(key))
        (state / "grant-public.pem").write_bytes(public)
        config = {
            "issuer": "urn:openavt:business:" + digest(public),
            "audience": audience,
            "agent_root": fingerprint(agents.root.public_bytes(serialization.Encoding.DER)),
        }
        (state / "config.json").write_bytes(canonical(config))
        create_database(state / "delegation.sqlite3", SCHEMA)
        return cls(state, agents)

    def register_customer(self, customer: str, resources: list[str]) -> dict:
        label(customer)
        if not isinstance(resources, list) or not 1 <= len(resources) <= 20:
            raise AuthorityError("invalid_resources")
        for resource in resources:
            label(resource)
        credential = secrets.token_urlsafe(32)
        with database(self.db) as db:
            if db.execute("SELECT id FROM customers WHERE id=?", (customer,)).fetchone():
                raise AuthorityError("customer_exists", 409)
            if db.execute("SELECT COUNT(*) FROM customers").fetchone()[0] >= 1000:
                raise AuthorityError("customer_capacity", 429)
            db.execute(
                "INSERT INTO customers VALUES (?, ?, ?)",
                (customer, digest(credential.encode()), canonical({"owned": resources}).decode()),
            )
        return {
            "customer": customer,
            "credential": credential,
            "assurance": "operator-provisioned-demo-account",
        }

    def issue(self, credential: str, certificate: str, action: str, resource: str, ttl: int = 300) -> dict:
        if type(ttl) is not int or not 1 <= ttl <= 300:
            raise AuthorityError("invalid_grant_lifetime")
        if not isinstance(credential, str) or not 20 <= len(credential) <= 128:
            raise AuthorityError("invalid_customer_credential", 401)
        if not isinstance(certificate, str) or len(certificate) > 4096:
            raise AuthorityError("invalid_certificate")
        try:
            cert = x509.load_pem_x509_certificate(certificate.encode())
        except ValueError as error:
            raise AuthorityError("invalid_certificate") from error
        der = cert.public_bytes(serialization.Encoding.DER)
        identity = self.agents.require_active(der)
        now = int(time.time())
        with database(self.db) as db:
            customer = db.execute(
                "SELECT * FROM customers WHERE credential_hash=?", (digest(credential.encode()),)
            ).fetchone()
            if customer is None:
                raise AuthorityError("invalid_customer_credential", 401)
            if action != "order.read" or resource not in parse_json(customer["resources"].encode())["owned"]:
                raise AuthorityError("consent_outside_account_policy", 403)
            db.execute("DELETE FROM grants WHERE expires <= ?", (now,))
            if db.execute("SELECT COUNT(*) FROM grants").fetchone()[0] >= 10000:
                raise AuthorityError("grant_capacity", 429)
            claims = {
                "iss": self.issuer,
                "sub": customer["id"],
                "aud": self.audience,
                "agent": identity,
                "scope": [action],
                "resource": resource,
                "iat": now,
                "nbf": now,
                "exp": min(now + ttl, int(cert.not_valid_after_utc.timestamp())),
                "jti": secrets.token_hex(16),
                "cnf": {"x5t#S256": fingerprint(der)},
            }
            header = b64(canonical({"alg": "EdDSA", "typ": TYPE}))
            payload = b64(canonical(claims))
            signing = f"{header}.{payload}".encode("ascii")
            key = serialization.load_pem_private_key((self.state / "grant.key").read_bytes(), password=None)
            token = signing.decode() + "." + b64(key.sign(signing))
            db.execute(
                "INSERT INTO grants VALUES (?, ?, ?, 0, 0)", (claims["jti"], customer["id"], claims["exp"])
            )
        return {
            "delegation": token,
            "grant_id": claims["jti"],
            "expires": claims["exp"],
            "customer": claims["sub"],
            "action": action,
            "resource": resource,
        }

    def revoke(self, grant_id: str, credential: str | None = None) -> None:
        """Operator operation, or credential-authenticated customer revocation."""
        with database(self.db) as db:
            if credential is None:
                result = db.execute("UPDATE grants SET revoked=1 WHERE id=?", (grant_id,))
            else:
                if not isinstance(credential, str) or not 20 <= len(credential) <= 128:
                    raise AuthorityError("invalid_customer_credential", 401)
                customer = db.execute(
                    "SELECT id FROM customers WHERE credential_hash=?", (digest(credential.encode()),)
                ).fetchone()
                if customer is None:
                    raise AuthorityError("invalid_customer_credential", 401)
                result = db.execute(
                    "UPDATE grants SET revoked=1 WHERE id=? AND customer=?", (grant_id, customer["id"])
                )
            if result.rowcount != 1:
                raise AuthorityError("unknown_grant", 404)

    def challenge(self, peer_der: bytes) -> str:
        self.agents.require_active(peer_der)
        now, nonce = int(time.time()), secrets.token_urlsafe(32)
        with database(self.db) as db:
            db.execute("DELETE FROM challenges WHERE expires <= ?", (now,))
            if db.execute("SELECT COUNT(*) FROM challenges").fetchone()[0] >= 1000:
                raise AuthorityError("challenge_capacity", 429)
            db.execute("INSERT INTO challenges VALUES (?, ?, ?, 0)", (nonce, fingerprint(peer_der), now + 30))
        return nonce

    def verify(self, token: str, peer_der: bytes, request: dict, nonce: str) -> dict:
        # Verification uses only the pinned public grant key. No token-selected
        # alg/key/issuer, network discovery, or CA root as an authorization key.
        if not isinstance(token, str) or len(token) > 4096:
            raise AuthorityError("invalid_delegation", 403)
        try:
            header, payload, signature = token.split(".")
            metadata = parse_json(unb64(header))
            if metadata != {"alg": "EdDSA", "typ": TYPE}:
                raise AuthorityError("wrong_token_type_or_algorithm", 403)
            self.public_key.verify(unb64(signature), f"{header}.{payload}".encode("ascii"))
            claims = parse_json(unb64(payload))
        except (ValueError, InvalidSignature) as error:
            if isinstance(error, AuthorityError):
                raise
            raise AuthorityError("invalid_delegation_signature", 403) from error
        if set(claims) != CLAIMS:
            raise AuthorityError("invalid_delegation_claims", 403)
        for name in ("iss", "sub", "aud", "agent", "resource", "jti"):
            if not isinstance(claims[name], str) or not 1 <= len(claims[name]) <= 256:
                raise AuthorityError("invalid_delegation_claims", 403)
        if any(type(claims[name]) is not int for name in ("iat", "nbf", "exp")):
            raise AuthorityError("invalid_delegation_time", 403)
        now = int(time.time())
        if (
            not claims["iat"] <= claims["nbf"] <= now < claims["exp"]
            or not 0 < claims["exp"] - claims["iat"] <= 300
        ):
            raise AuthorityError("delegation_expired_or_not_yet_valid", 403)
        if claims["iss"] != self.issuer or claims["aud"] != self.audience:
            raise AuthorityError("wrong_issuer_or_audience", 403)
        identity = self.agents.require_active(peer_der)
        if claims["agent"] != identity or claims["cnf"] != {"x5t#S256": fingerprint(peer_der)}:
            raise AuthorityError("wrong_agent_binding", 403)
        if request.get("customer") != claims["sub"]:
            raise AuthorityError("wrong_customer", 403)
        if (
            claims["scope"] != ["order.read"]
            or request.get("action") not in claims["scope"]
            or request.get("order") != claims["resource"]
        ):
            raise AuthorityError("outside_delegated_scope", 403)
        with database(self.db) as db:
            challenge = db.execute("SELECT * FROM challenges WHERE nonce=?", (nonce,)).fetchone()
            if (
                challenge is None
                or challenge["peer"] != fingerprint(peer_der)
                or challenge["expires"] <= now
                or challenge["used"]
            ):
                raise AuthorityError("challenge_expired_or_used", 403)
            grant = db.execute("SELECT * FROM grants WHERE id=?", (claims["jti"],)).fetchone()
            if grant is None or grant["revoked"]:
                raise AuthorityError("delegation_revoked_or_unknown", 403)
            if grant["used"]:
                raise AuthorityError("delegation_already_used", 403)
            customer = db.execute("SELECT resources FROM customers WHERE id=?", (claims["sub"],)).fetchone()
            if (
                customer is None
                or claims["resource"] not in parse_json(customer["resources"].encode())["owned"]
            ):
                raise AuthorityError("account_resource_not_owned", 403)
            db.execute("UPDATE challenges SET used=1 WHERE nonce=?", (nonce,))
            db.execute("UPDATE grants SET used=1 WHERE id=?", (claims["jti"],))
        return claims

    def decide(self, peer_der: bytes, request: dict, nonce: str) -> dict:
        request_id = request.get("id", "") if isinstance(request, dict) else ""
        try:
            if not isinstance(request, dict) or set(request) != {
                "id",
                "customer",
                "action",
                "order",
                "nonce",
                "delegation",
            }:
                raise AuthorityError("invalid_request", 403)
            if any(
                not isinstance(request[name], str) or not 1 <= len(request[name]) <= 128
                for name in ("id", "customer", "action", "order", "nonce")
            ):
                raise AuthorityError("invalid_request", 403)
            if request["nonce"] != nonce:
                raise AuthorityError("wrong_challenge", 403)
            self.verify(request["delegation"], peer_der, request, nonce)
            return {
                "id": request_id,
                "result": "allowed",
                "reason": "verified_customer_delegation",
                "status": "shipped",
            }
        except AuthorityError as error:
            return {"id": request_id, "result": "denied", "reason": error.code}

"""Enrollment, consent trust boundaries, revocation and atomic replay defense."""

import asyncio
import http.client
import json
import stat
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from openavt.authority.ca import AgentAuthority
from openavt.authority.client import AuthorityClient, save_credentials
from openavt.authority.common import AuthorityError, b64, canonical, database, parse_json, unb64
from openavt.authority.delegation import BusinessAuthority
from openavt.authority.service import AuthorityServer
from openavt.demos.delegation import EXPECTED, run


@pytest.fixture
def authorities(tmp_path):
    ava = AgentAuthority.initialize(tmp_path / "ava")
    business = BusinessAuthority.initialize(tmp_path / "business", ava)
    alice = business.register_customer("alice", ["demo-order-1234"])
    bob = business.register_customer("bob", ["bob-order-5678"])
    return ava, business, alice, bob


def csr(key=None, malicious_names=False):
    key = key or ec.generate_private_key(ec.SECP256R1())
    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Meta Muse")])
    )
    if malicious_names:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName("meta.com")]), False
        ).add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
    return key, builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()


def enroll(ava, account=None, key=None, name="assistant"):
    account = account or ava.register()
    key, pem = csr(key)
    order = ava.order(account["credential"], name, pem)
    proof = b64(key.sign(unb64(order["proof_message"]), ec.ECDSA(hashes.SHA256())))
    cert = ava.finalize(account["credential"], order["order"], proof)
    der = x509.load_pem_x509_certificate(cert["certificate"].encode()).public_bytes(
        serialization.Encoding.DER
    )
    return account, key, cert, der


@pytest.fixture
def agent(authorities):
    return enroll(authorities[0])


@pytest.fixture
def service(authorities):
    ava, business, *_ = authorities
    server = AuthorityServer(("127.0.0.1", 0), ava, business)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, AuthorityClient(f"http://127.0.0.1:{server.server_port}")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def request(token, customer="alice", action="order.read", order="demo-order-1234", nonce="challenge"):
    return {
        "id": "request-1",
        "customer": customer,
        "action": action,
        "order": order,
        "nonce": nonce,
        "delegation": token,
    }


def test_enrollment_ignores_requested_names_and_ca_extensions(authorities):
    ava = authorities[0]
    account = ava.register()
    key, pem = csr(malicious_names=True)
    challenge = ava.order(account["credential"], "assistant", pem)
    cert = ava.finalize(
        account["credential"],
        challenge["order"],
        b64(key.sign(unb64(challenge["proof_message"]), ec.ECDSA(hashes.SHA256()))),
    )
    parsed = x509.load_pem_x509_certificate(cert["certificate"].encode())
    assert parsed.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "assistant"
    assert not parsed.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    assert parsed.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value == x509.ExtendedKeyUsage(
        [ExtendedKeyUsageOID.CLIENT_AUTH]
    )
    assert (
        parsed.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(
            x509.DNSName
        )
        == []
    )
    assert cert["assurance"] == "pseudonymous-key-control"
    assert (ava.state / "root.key").stat().st_mode & 0o777 == 0o600
    assert (ava.state / "authority.sqlite3").stat().st_mode & 0o777 == 0o600
    assert stat.S_IMODE(ava.state.stat().st_mode) == 0o700


def test_enrollment_rejects_wrong_key_account_expiry_and_replay(authorities):
    ava = authorities[0]
    account, stranger = ava.register(), ava.register()
    key, pem = csr()
    order = ava.order(account["credential"], "assistant", pem)
    wrong_key, _ = csr()
    wrong = b64(wrong_key.sign(unb64(order["proof_message"]), ec.ECDSA(hashes.SHA256())))
    with pytest.raises(AuthorityError, match="invalid_key_proof"):
        ava.finalize(account["credential"], order["order"], wrong)
    proof = b64(key.sign(unb64(order["proof_message"]), ec.ECDSA(hashes.SHA256())))
    with pytest.raises(AuthorityError, match="unknown_order"):
        ava.finalize(stranger["credential"], order["order"], proof)
    ava.finalize(account["credential"], order["order"], proof)
    with pytest.raises(AuthorityError, match="expired_or_used"):
        ava.finalize(account["credential"], order["order"], proof)
    another = ava.order(account["credential"], "assistant", pem)
    with database(ava.db) as db:
        db.execute("UPDATE orders SET expires=0 WHERE id=?", (another["order"],))
    with pytest.raises(AuthorityError, match="expired_or_used"):
        ava.finalize(account["credential"], another["order"], proof)


def test_proof_is_bound_to_order_and_enrollment_is_rate_limited(authorities):
    ava = authorities[0]
    account = ava.register()
    key, pem = csr()
    first = ava.order(account["credential"], "assistant", pem)
    second = ava.order(account["credential"], "assistant", pem)
    proof = b64(key.sign(unb64(first["proof_message"]), ec.ECDSA(hashes.SHA256())))
    with pytest.raises(AuthorityError, match="invalid_key_proof"):
        ava.finalize(account["credential"], second["order"], proof)
    for _ in range(8):
        ava.order(account["credential"], "assistant", pem)
    with pytest.raises(AuthorityError, match="rate_limit"):
        ava.order(account["credential"], "assistant", pem)


def test_http_client_enrolls_and_renews_with_explicit_trust(service, authorities, tmp_path):
    _, client = service
    ava = authorities[0]
    account = client.account()
    root = (ava.state / "root.pem").read_bytes()
    result = client.enroll(account, "assistant", root, tmp_path / "first")
    second = client.enroll(account, "assistant", root, tmp_path / "second", tmp_path / "first/agent.key")
    assert result["agent"] == second["agent"] and result["serial"] != second["serial"]
    assert (tmp_path / "first/agent.key").read_bytes() == (tmp_path / "second/agent.key").read_bytes()
    assert stat.S_IMODE((tmp_path / "first/agent.key").stat().st_mode) == 0o600
    wrong_root = AgentAuthority.initialize(tmp_path / "wrong-ava")
    with pytest.raises(AuthorityError, match="unexpected_authority_challenge"):
        client.enroll(account, "assistant", (wrong_root.state / "root.pem").read_bytes(), tmp_path / "wrong")
    assert not (tmp_path / "wrong").exists()


def test_http_requires_auth_and_bounds_body_and_workers(service):
    server, client = service
    with pytest.raises(AuthorityError) as error:
        client.post("/v1/orders", {"agent": "assistant", "csr": "invalid"})
    assert error.value.status == 401
    connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
    connection.request(
        "POST", "/v1/accounts", body=b"x" * 16385, headers={"Content-Type": "application/json"}
    )
    assert connection.getresponse().status == 413
    connection.close()
    for _ in range(8):
        assert server.workers.acquire(timeout=1)
    try:
        with pytest.raises(AuthorityError) as error:
            client.account()
        assert error.value.status == 503
    finally:
        for _ in range(8):
            server.workers.release()
    assert client.account()["assurance"] == "pseudonymous-key-control"


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com",
        "http://127.0.0.1@evil.example",
        "https://example.com?target=evil",
        "file:///tmp/key",
    ],
)
def test_client_refuses_insecure_or_ambiguous_urls(url):
    with pytest.raises(AuthorityError):
        AuthorityClient(url)


def test_off_loopback_service_requires_tls(authorities):
    with pytest.raises(AuthorityError, match="tls_required"):
        AuthorityServer(("0.0.0.0", 0), authorities[0])


def test_client_does_not_follow_redirects(service, monkeypatch):
    _, client = service
    from openavt.authority.client import NoRedirect

    with pytest.raises(AuthorityError, match="redirect_refused"):
        NoRedirect().redirect_request(None, None, 302, "redirect", {}, "http://evil.example")


@pytest.mark.parametrize("attack", ["agent_credential", "unknown_customer", "other_resource", "mutation"])
def test_ca_enrollment_is_not_customer_consent(authorities, agent, attack):
    _, business, alice, _ = authorities
    account, _, cert, _ = agent
    credential = (
        account["credential"]
        if attack == "agent_credential"
        else "unknown"
        if attack == "unknown_customer"
        else alice["credential"]
    )
    action = "address.change" if attack == "mutation" else "order.read"
    resource = "bob-order-5678" if attack == "other_resource" else "demo-order-1234"
    with pytest.raises(AuthorityError):
        business.issue(credential, cert["certificate"], action, resource)


def test_verified_grant_and_challenge_are_single_use_and_persistent(authorities, agent):
    ava, business, alice, _ = authorities
    _, _, cert, der = agent
    grant = business.issue(alice["credential"], cert["certificate"], "order.read", "demo-order-1234")
    nonce = business.challenge(der)
    assert business.decide(der, request(grant["delegation"], nonce=nonce), nonce)["result"] == "allowed"
    restarted = BusinessAuthority(business.state, AgentAuthority(ava.state))
    nonce2 = restarted.challenge(der)
    assert (
        restarted.decide(der, request(grant["delegation"], nonce=nonce2), nonce2)["reason"]
        == "delegation_already_used"
    )
    fresh = restarted.issue(alice["credential"], cert["certificate"], "order.read", "demo-order-1234")
    assert (
        restarted.decide(der, request(fresh["delegation"], nonce=nonce), nonce)["reason"]
        == "challenge_expired_or_used"
    )


def resign(business, token, change_claim=None, change_header=None):
    header, payload, _ = token.split(".")
    metadata, claims = parse_json(unb64(header)), parse_json(unb64(payload))
    if change_claim:
        claims.update(change_claim)
    if change_header:
        metadata.update(change_header)
    signing = f"{b64(canonical(metadata))}.{b64(canonical(claims))}".encode()
    key = serialization.load_pem_private_key((business.state / "grant.key").read_bytes(), None)
    return signing.decode() + "." + b64(key.sign(signing))


@pytest.mark.parametrize(
    "changes,reason",
    [
        ({"aud": "other-business"}, "wrong_issuer_or_audience"),
        ({"iss": "attacker"}, "wrong_issuer_or_audience"),
        ({"sub": "bob"}, "wrong_customer"),
        ({"scope": ["address.change"]}, "outside_delegated_scope"),
        ({"resource": "bob-order-5678"}, "outside_delegated_scope"),
        ({"exp": 0}, "delegation_expired_or_not_yet_valid"),
        ({"nbf": 9999999999}, "delegation_expired_or_not_yet_valid"),
        ({"exp": True}, "invalid_delegation_time"),
        ({"cnf": {}}, "wrong_agent_binding"),
        ({"extra": "unexpected"}, "invalid_delegation_claims"),
    ],
)
def test_strict_grant_claims(authorities, agent, changes, reason):
    _, business, alice, _ = authorities
    _, _, cert, der = agent
    grant = business.issue(alice["credential"], cert["certificate"], "order.read", "demo-order-1234")
    token = resign(business, grant["delegation"], change_claim=changes)
    nonce = business.challenge(der)
    assert business.decide(der, request(token, nonce=nonce), nonce)["reason"] == reason


@pytest.mark.parametrize(
    "changes", [{"alg": "none"}, {"alg": "HS256"}, {"typ": "JWT"}, {"jku": "https://evil.example"}]
)
def test_algorithm_type_and_key_source_are_pinned(authorities, agent, changes):
    _, business, alice, _ = authorities
    _, _, cert, der = agent
    grant = business.issue(alice["credential"], cert["certificate"], "order.read", "demo-order-1234")
    nonce = business.challenge(der)
    token = resign(business, grant["delegation"], change_header=changes)
    assert (
        business.decide(der, request(token, nonce=nonce), nonce)["reason"] == "wrong_token_type_or_algorithm"
    )


def test_tampered_grant_and_other_business_key_fail(authorities, agent, tmp_path):
    ava, business, alice, _ = authorities
    _, _, cert, der = agent
    grant = business.issue(alice["credential"], cert["certificate"], "order.read", "demo-order-1234")
    header, payload, signature = grant["delegation"].split(".")
    damaged = bytes([unb64(signature)[0] ^ 1]) + unb64(signature)[1:]
    nonce = business.challenge(der)
    assert (
        business.decide(der, request(f"{header}.{payload}.{b64(damaged)}", nonce=nonce), nonce)["reason"]
        == "invalid_delegation_signature"
    )
    other = BusinessAuthority.initialize(tmp_path / "other-business", ava)
    token = resign(other, grant["delegation"])
    assert (
        business.decide(der, request(token, nonce=nonce), nonce)["reason"] == "invalid_delegation_signature"
    )


def test_renewed_certificate_and_other_agent_cannot_use_old_grant(authorities, agent):
    ava, business, alice, _ = authorities
    account, key, cert, der = agent
    grant = business.issue(alice["credential"], cert["certificate"], "order.read", "demo-order-1234")
    for other_der in (enroll(ava, account, key)[3], enroll(ava, name="another-agent")[3]):
        nonce = business.challenge(other_der)
        assert (
            business.decide(other_der, request(grant["delegation"], nonce=nonce), nonce)["reason"]
            == "wrong_agent_binding"
        )
    nonce = business.challenge(der)
    assert business.decide(der, request(grant["delegation"], nonce=nonce), nonce)["result"] == "allowed"


def test_revocation_ownership_and_live_certificate_checks(authorities, agent):
    ava, business, alice, bob = authorities
    account, _, cert, der = agent
    grant = business.issue(alice["credential"], cert["certificate"], "order.read", "demo-order-1234")
    with pytest.raises(AuthorityError, match="unknown_grant"):
        business.revoke(grant["grant_id"], bob["credential"])
    business.revoke(grant["grant_id"], alice["credential"])
    nonce = business.challenge(der)
    assert (
        business.decide(der, request(grant["delegation"], nonce=nonce), nonce)["reason"]
        == "delegation_revoked_or_unknown"
    )
    fresh = business.issue(alice["credential"], cert["certificate"], "order.read", "demo-order-1234")
    stranger = ava.register()
    with pytest.raises(AuthorityError, match="unknown_certificate"):
        ava.revoke(stranger["credential"], cert["serial"])
    nonce = business.challenge(der)
    ava.revoke(account["credential"], cert["serial"])
    assert (
        business.decide(der, request(fresh["delegation"], nonce=nonce), nonce)["reason"]
        == "certificate_revoked_or_unknown"
    )
    with pytest.raises(AuthorityError, match="certificate_revoked"):
        business.challenge(der)


def test_concurrent_grant_use_has_only_one_winner(authorities, agent):
    _, business, alice, _ = authorities
    _, _, cert, der = agent
    grant = business.issue(alice["credential"], cert["certificate"], "order.read", "demo-order-1234")
    nonces = [business.challenge(der), business.challenge(der)]
    with ThreadPoolExecutor(2) as pool:
        outcomes = list(
            pool.map(
                lambda nonce: business.decide(der, request(grant["delegation"], nonce=nonce), nonce), nonces
            )
        )
    assert sorted(r["result"] for r in outcomes) == ["allowed", "denied"]


def test_demo_enrolls_over_http_and_verifies_all_cases_over_live_audio(tmp_path):
    report = asyncio.run(run(tmp_path))
    assert report["verified"] and not report["llm_agents_executed"]
    assert report["certificate_renewal_verified"]
    assert {r["scenario"]: r["reason"] for r in report["results"]} == EXPECTED
    assert all(not s["session_reused"] and s["retries"] == 0 for s in report["tls"].values())
    assert all(s["modem_bad_frames"] == 0 for s in report["audio"].values())
    assert all(
        e["message"]["delegation"] == "[redacted]"
        for e in report["events"]
        if e["event"].startswith("protected_message_") and "delegation" in e["message"]
    )


def test_json_duplicates_and_noncanonical_base64_are_rejected():
    with pytest.raises(AuthorityError):
        parse_json(b'{"aud":"desk.demo","aud":"attacker"}')
    with pytest.raises(AuthorityError):
        unb64("YQ=")


def test_verifier_needs_no_ca_or_business_signing_private_key(authorities, agent):
    ava, business, alice, _ = authorities
    _, _, cert, der = agent
    grant = business.issue(alice["credential"], cert["certificate"], "order.read", "demo-order-1234")
    (ava.state / "root.key").unlink()
    (business.state / "grant.key").unlink()
    verifier = BusinessAuthority(business.state, AgentAuthority(ava.state))
    nonce = verifier.challenge(der)
    assert verifier.decide(der, request(grant["delegation"], nonce=nonce), nonce)["result"] == "allowed"


def test_challenge_expiry_and_invalid_request_do_not_consume_consent(authorities, agent):
    _, business, alice, _ = authorities
    _, _, cert, der = agent
    grant = business.issue(alice["credential"], cert["certificate"], "order.read", "demo-order-1234")
    nonce = business.challenge(der)
    invalid = request(grant["delegation"], nonce=nonce)
    invalid["override"] = "allow"
    assert business.decide(der, invalid, nonce)["reason"] == "invalid_request"
    with database(business.db) as db:
        db.execute("UPDATE challenges SET expires=0 WHERE nonce=?", (nonce,))
    assert (
        business.decide(der, request(grant["delegation"], nonce=nonce), nonce)["reason"]
        == "challenge_expired_or_used"
    )
    fresh = business.challenge(der)
    assert business.decide(der, request(grant["delegation"], nonce=fresh), fresh)["result"] == "allowed"


def test_http_consent_requires_business_customer_credentials(service, authorities, agent):
    _, client = service
    _, _, alice, _ = authorities
    account, _, cert, _ = agent
    with pytest.raises(AuthorityError) as error:
        client.consent(account, cert["certificate"], "order.read", "demo-order-1234")
    assert error.value.status == 401
    grant = client.consent(alice, cert["certificate"], "order.read", "demo-order-1234")
    assert grant["customer"] == "alice"


def test_untrusted_agent_certificate_cannot_get_consent(authorities, tmp_path):
    _, business, alice, _ = authorities
    rogue = AgentAuthority.initialize(tmp_path / "rogue")
    _, _, cert, _ = enroll(rogue)
    with pytest.raises(AuthorityError, match="untrusted_agent_certificate"):
        business.issue(alice["credential"], cert["certificate"], "order.read", "demo-order-1234")


def test_installed_cli_enrollment_consent_and_revocation(service, authorities, tmp_path):
    _, client = service
    ava, _, alice, _ = authorities
    account_path, customer_path = tmp_path / "agent.credentials.json", tmp_path / "alice.credentials.json"
    save_credentials(customer_path, alice)

    def command(*args):
        result = subprocess.run(
            [sys.executable, "-I", "-m", "openavt", "ava", *map(str, args)],
            cwd=tmp_path,
            capture_output=True,
            text=True,
            check=True,
        )
        assert alice["credential"] not in result.stdout + result.stderr
        if account_path.exists():
            assert parse_json(account_path.read_bytes())["credential"] not in result.stdout + result.stderr
        return json.loads(result.stdout)

    command("account", "--url", client.url, "--credentials", account_path)
    bundle = tmp_path / "bundle"
    cert = command(
        "enroll",
        "--url",
        client.url,
        "--credentials",
        account_path,
        "--agent",
        "assistant",
        "--root",
        ava.state / "root.pem",
        "--output",
        bundle,
    )
    grant_path = tmp_path / "consent.grant.json"
    grant = command(
        "consent",
        "--url",
        client.url,
        "--credentials",
        customer_path,
        "--agent-cert",
        bundle / "agent.pem",
        "--action",
        "order.read",
        "--resource",
        "demo-order-1234",
        "--output",
        grant_path,
    )
    assert "delegation" not in grant and stat.S_IMODE(grant_path.stat().st_mode) == 0o600
    assert command(
        "withdraw-consent",
        "--url",
        client.url,
        "--credentials",
        customer_path,
        "--grant-id",
        grant["grant_id"],
    )["revoked"]
    assert command("revoke", "--url", client.url, "--credentials", account_path, "--serial", cert["serial"])[
        "revoked"
    ]

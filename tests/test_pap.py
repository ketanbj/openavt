"""PAP wire profile verified against a separate PyJWT/aiohttp HTTPS counterpart."""

import asyncio
import hashlib
import json
import ssl
from dataclasses import replace
from datetime import datetime
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

import jwt
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from openavt.demos.pap import NAMESPACE, enroll, local_company, run
from openavt.gateway import Request
from openavt.pap import PAPVoiceGrant, UserIDs
from openavt.pap.crypto import SigningKey
from openavt.pap.http import HTTPS, PAPError, Reply
from openavt.session import GrantRequest


async def sign_in(company, client, scope="poppy:read poppy:write", customer="alice"):
    await client.start_session()
    flow = client.begin_direct(scope, client.redirect_uris[0])
    return await client.finish_direct(company.approve_direct(flow.url, customer=customer))


async def protected(company, client, voice, identity, **changes):
    peer = x509.load_pem_x509_certificate(identity.certificate.read_bytes()).public_bytes(
        serialization.Encoding.DER
    )
    challenge = await voice.challenge(peer)
    intent = GrantRequest("request-1", challenge, "order.read", "order-1", "alice", {})
    intent = replace(intent, **changes)
    grant = await PAPVoiceGrant(client, identity, namespace=NAMESPACE)(intent)
    request = Request(
        intent.request_id,
        intent.action,
        intent.resource,
        intent.customer,
        intent.arguments,
        intent.nonce,
        grant,
    )
    return peer, request


def test_real_https_discovery_sessions_pkce_refresh_logout(tmp_path):
    async def scenario():
        async with local_company(tmp_path) as (company, client, voice, identity):
            metadata = await client.http.document(client.client_id)
            assert metadata == client.metadata(company.base + "/jwks.json", name="Local personal agent")
            jwks = await client.http.document(metadata["jwks_uri"])
            assert jwks == client.signing_key.jwks
            signed_out = await client.start_session()
            assert not signed_out.signed_in and not signed_out.scope
            assert signed_out.access_token not in repr(signed_out)
            renewed = await client.start_session(renew=True)
            assert renewed.session_id == signed_out.session_id
            flow = client.begin_direct("poppy:read poppy:write", client.redirect_uris[0])
            params = parse_qs(urlsplit(flow.url).query)
            assert params["code_challenge_method"] == ["S256"]
            assert params["code_challenge"] == [
                jwt.utils.base64url_encode(hashlib.sha256(flow.verifier.encode()).digest()).decode()
            ]
            assert flow.verifier not in flow.url
            callback = company.approve_direct(flow.url)
            parsed = urlsplit(callback)
            query = parse_qs(parsed.query)
            for changed in ({"iss": "https://evil.example"}, {"state": "wrong"}):
                invalid = {k: v[0] for k, v in query.items()} | changed
                with pytest.raises(PAPError, match="sign_in_response_mismatch"):
                    await client.finish_direct(urlunsplit(parsed._replace(query=urlencode(invalid))))
                assert client.session == renewed
            signed_in = await client.finish_direct(callback)
            assert signed_in.session_id == signed_out.session_id and signed_in.signed_in
            assert signed_in.scope == {"poppy:read", "poppy:write"}
            assert client.account_token
            # An expired Session Token can be replaced using the Account Token.
            client.session = replace(client.session, expires_at=0)
            narrow = await client.refresh(scope="poppy:read", resource=company.base + "/voice")
            assert narrow.scope == {"poppy:read"}
            with pytest.raises(PAPError, match="invalid_token"):
                await client.api("GET", company.base + "/operations/missing")
            await client.refresh()  # Restore account-authorized scope, not an escalation.
            with pytest.raises(PAPError, match="insufficient_scope"):
                await client.refresh(scope="poppy:read admin")
            peer, request = await protected(company, client, voice, identity)
            await client.sign_out()
            with pytest.raises(PermissionError):
                await voice.authorize(peer, request)
            assert client.account_token is None and not client.session.signed_in
            after = await client.start_session(renew=True)
            assert after.session_id == signed_out.session_id and not after.signed_in
            assert company.used_nonce_challenges >= 2

    asyncio.run(scenario())


def test_real_https_dpop_checks_signature_key_hash_method_url_and_replay(tmp_path):
    async def scenario():
        async with local_company(tmp_path) as (company, client, _, _):
            await sign_in(company, client)
            endpoint = company.base + "/operations/missing"
            token = client.session.access_token
            for key, method, url, credential in [
                (SigningKey.generate(), "GET", endpoint, token),
                (client.dpop_key, "POST", endpoint, token),
                (client.dpop_key, "GET", company.base + "/other", token),
                (client.dpop_key, "GET", endpoint, "wrong-access-token"),
            ]:
                reply = await client.http._send(
                    "GET",
                    endpoint,
                    headers={
                        "Authorization": "DPoP " + token,
                        "DPoP": key.dpop(method, url, token=credential, nonce=company.nonce),
                    },
                )
                assert reply.status == 401 and reply.data["error"] == "invalid_dpop_proof"
            proof = client.dpop_key.dpop("GET", endpoint, token=token, nonce=company.nonce)
            headers = {"Authorization": "DPoP " + token, "DPoP": proof}
            assert (await client.http._send("GET", endpoint, headers=headers)).status == 404
            assert (await client.http._send("GET", endpoint, headers=headers)).data[
                "error"
            ] == "invalid_dpop_proof"
            with pytest.raises(PAPError, match="undiscovered_resource"):
                await client.api("GET", "https://unadvertised.example/orders")

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "changes",
    [
        {"id": "other"},
        {"action": "order.exchange"},
        {"resource": "order-2"},
        {"customer": "bob"},
        {"nonce": "wrong"},
        {"arguments": {"payment": 100}},
    ],
)
def test_voice_grant_binds_exact_request(tmp_path, changes):
    async def scenario():
        async with local_company(tmp_path) as (company, client, voice, identity):
            await sign_in(company, client)
            peer, request = await protected(company, client, voice, identity)
            with pytest.raises(PermissionError):
                await voice.authorize(peer, replace(request, **changes))
            assert (await voice.authorize(peer, request))["sub"] == "alice"
            with pytest.raises(PermissionError):
                await voice.authorize(peer, request)

    asyncio.run(scenario())


def test_scope_ownership_key_and_concurrent_replay(tmp_path):
    async def scenario():
        async with local_company(tmp_path) as (company, client, voice, identity):
            await sign_in(company, client, scope="poppy:read")
            for changes in (
                {"action": "order.exchange", "arguments": {"replacement": "blue"}},
                {"resource": "order-2"},
                {"customer": "bob"},
            ):
                with pytest.raises(PAPError, match="voice_authorization_denied"):
                    await protected(company, client, voice, identity, **changes)
            peer, request = await protected(company, client, voice, identity)
            other = enroll(voice.agents, tmp_path / "other", name="other")
            other_peer = x509.load_pem_x509_certificate(other.certificate.read_bytes()).public_bytes(
                serialization.Encoding.DER
            )
            with pytest.raises(PermissionError):
                await voice.authorize(other_peer, request)
            results = await asyncio.gather(
                *(voice.authorize(peer, request) for _ in range(8)), return_exceptions=True
            )
            assert sum(isinstance(r, dict) for r in results) == 1
            assert sum(isinstance(r, PermissionError) for r in results) == 7
            peer, request = await protected(company, client, voice, identity)
            company.sessions[client.session.session_id]["scope"] = frozenset()
            with pytest.raises(PermissionError):
                await voice.authorize(peer, request)

    asyncio.run(scenario())


def test_operations_revision_approval_ownership_and_once(tmp_path):
    async def scenario():
        async with local_company(tmp_path) as (company, client, _, _):
            await sign_in(company, client)
            verified = await company.current(hashlib.sha256(client.session.access_token.encode()).hexdigest())
            op = company.propose(verified, {"amount": 0})
            datetime.fromisoformat(op["expires_at"].replace("Z", "+00:00"))
            oid = op["operation_id"]
            for revision, approved_by, code in [
                (2, "user", "terms_changed"),
                (1, "standing_permission", "user_approval_required"),
            ]:
                with pytest.raises(PAPError, match=code):
                    await client.operation(oid, revision=revision, approved_by=approved_by)
            assert company.effects == 0
            result = await client.operation(oid, revision=1, approved_by="user")
            assert result["state"] == "succeeded" and company.effects == 1
            # Recovery after lost confirmation response uses the SAME operation ID.
            assert await client.operation(oid) == result
            assert await client.operation(oid, revision=1, approved_by="user") == result
            assert company.effects == 1
            await client.sign_out()
            await sign_in(company, client, customer="bob")
            with pytest.raises(PAPError, match="operation_not_found"):
                await client.operation(oid)

    asyncio.run(scenario())


def test_device_and_mediated_signin_are_standard_https(tmp_path):
    async def scenario():
        async with local_company(tmp_path) as (company, client, _, _):
            await client.start_session()
            presented = []

            async def present(data):
                presented.append(data)
                assert "device_code" not in data
                company.approve_device(data["user_code"])

            session = await client.device_sign_in("poppy:read", present=present, timeout=4)
            assert session.signed_in and session.scope == {"poppy:read"} and len(presented) == 1
            await client.sign_out()
            await client.start_session(renew=True)
            with pytest.raises(PAPError, match="invalid_credentials_fields"):
                await client.mediated_sign_in("poppy:read", {"password": "must-not-send"})
            session = await client.mediated_sign_in("poppy:read", {"demo_account": "alice"})
            assert session.signed_in and session.scope == {"poppy:read"}

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "change,code",
    [
        ({"token_type": "Bearer"}, "invalid_session_token_response"),
        ({"expires_in": True}, "invalid_token_lifetime"),
        ({"expires_in": 0}, "invalid_token_lifetime"),
        ({"scope": "poppy:write"}, "unexpected_scope"),
        ({"session_id": "other"}, "session_id_mismatch"),
        ({"signed_in": False, "scope": "poppy:read"}, "unexpected_scope"),
    ],
)
def test_invalid_token_response_never_replaces_latest_session(tmp_path, change, code):
    async def scenario():
        async with local_company(tmp_path) as (company, client, _, _):
            original = await sign_in(company, client, scope="poppy:read")
            response = {
                "session_id": original.session_id,
                "token_type": "DPoP",
                "signed_in": True,
                "scope": "poppy:read",
                "expires_in": 60,
                "access_token": "opaque",
            } | change
            with pytest.raises(PAPError, match=code):
                client._accept(response, session_id=original.session_id, requested=frozenset({"poppy:read"}))
            assert client.session == original

    asyncio.run(scenario())


def test_discovery_domain_issuer_binding_and_minor_compatibility(tmp_path):
    async def scenario():
        async with local_company(tmp_path) as (company, client, _, _):
            original = company.discovered()

            async def document(url):
                if "poppy.json" in url:
                    return discovery
                return {**client.oauth, "poppy_domains": domains}

            client.http.document = document
            discovery = {**original, "protocol_version": "0.99", "future_field": True}
            domains = ["127.0.0.1"]
            await client.discover(company.base)
            discovery = {**original, "organization": {"domain": "evil.example"}}
            with pytest.raises(PAPError, match="organization_domain_mismatch"):
                await client.discover(company.base)
            discovery = original
            domains = ["elsewhere.example"]
            with pytest.raises(PAPError, match="issuer_domain_mismatch"):
                await client.discover(company.base)
            discovery = {**original, "protocol_version": "1.0"}
            with pytest.raises(PAPError, match="unsupported_protocol_version"):
                await client.discover(company.base)

    asyncio.run(scenario())


def test_transport_never_forwards_auth_on_redirect_and_respects_retry_after():
    async def scenario():
        http = HTTPS()
        calls = []

        async def send(method, url, **kwargs):
            calls.append((url, kwargs))
            return reply

        http._send = send
        reply = Reply(302, {}, {"Location": "https://elsewhere.example"})
        with pytest.raises(PAPError):
            await http.request(
                "POST", "https://company.example/action", key=SigningKey.generate(), token="secret"
            )
        assert len(calls) == 1
        reply = Reply(429, {"error": "rate_limited"}, {"Retry-After": "30"})
        with pytest.raises(PAPError) as error:
            await http.request("POST", "https://company.example/action", key=SigningKey.generate())
        assert error.value.retry_after == 30
        with pytest.raises(PAPError):
            await http.request("POST", "https://company.example/action", key=SigningKey.generate())
        assert len(calls) == 2
        reply = Reply(302, {}, {"Location": "http://insecure.example"})
        with pytest.raises(ValueError):
            await http.document("https://company.example/discovery")

    asyncio.run(scenario())
    context = ssl._create_unverified_context()
    with pytest.raises(ValueError):
        HTTPS(ssl_context=context)


def test_random_user_ids_persist_per_issuer_and_are_private(tmp_path):
    file = tmp_path / "user.sqlite3"
    ids = UserIDs(file)
    first = ids.get("https://company.example")
    assert first == UserIDs(file).get("https://company.example")
    assert first != ids.get("https://other.example")
    assert file.stat().st_mode & 0o777 == 0o600


def test_real_https_to_audio_demo(tmp_path):
    report = asyncio.run(run(tmp_path / "report"))
    assert report["verified"]
    assert report["gateway"] == {"requests": 4, "handler_executions": 2, "denials": 2}
    assert report["https_confirmation_effects"] == 1
    assert report["authenticated_risk_block"] and report["signed_out_grant_denied"]
    assert not report["webrtc_data_channel"]
    public = json.dumps(report)
    assert "access_token" not in public and "refresh_token" not in public


def test_mediated_code_bound_to_session_and_keeps_credentials_https(tmp_path):
    async def scenario():
        async with local_company(tmp_path) as (company, client, _, _):
            await client.start_session()
            response = await client.mediated_sign_in("poppy:read", {"demo_account": "alice-code"})
            assert response["status"] == "code_required"
            assert (await client.finish_mediated("wrong"))["status"] == "code_required"
            signed_in = await client.finish_mediated("123456")
            assert signed_in.signed_in and client.account_token and client.mediated_id is None

    asyncio.run(scenario())


def test_voice_extension_negotiation_key_proof_and_grant_expiry(tmp_path):
    async def scenario():
        async with local_company(tmp_path) as (company, client, voice, identity):
            await sign_in(company, client)
            company.clients[client.client_id][0]["extensions"][NAMESPACE]["version"] = "2"
            with pytest.raises(PAPError, match="extension_required"):
                await protected(company, client, voice, identity)
            company.clients[client.client_id][0]["extensions"][NAMESPACE]["version"] = "1"
            real_api = client.api

            async def tampered(method, url, *, body=None):
                body = {**body, "arguments": {"injected": True}}
                return await real_api(method, url, body=body)

            client.api = tampered
            with pytest.raises(PAPError, match="voice_authorization_denied"):
                await protected(company, client, voice, identity)
            client.api = real_api
            peer, request = await protected(company, client, voice, identity)
            from openavt.authority.common import database

            with database(voice.db) as db:
                db.execute("UPDATE grants SET expires=0")
            with pytest.raises(PermissionError):
                await voice.authorize(peer, request)

    asyncio.run(scenario())


def test_device_waits_for_explicit_approval_and_timeout_stays_signed_out(tmp_path):
    async def scenario():
        async with local_company(tmp_path) as (company, client, _, _):
            await client.start_session()

            async def present(data):
                pass

            with pytest.raises(PAPError, match="expired_token"):
                await client.device_sign_in("poppy:read", present=present, timeout=1.5)
            assert not client.session.signed_in and client.account_token is None

    asyncio.run(scenario())


def test_permission_withdrawn_during_risk_check_never_executes(tmp_path):
    from types import SimpleNamespace

    from openavt.gateway import Gateway
    from openavt.risk import CallbackFraudAdapter, CallContext, RiskAssessment, RiskMonitor, RiskOutcome

    async def scenario():
        async with local_company(tmp_path) as (company, client, voice, identity):
            await sign_in(company, client)
            peer, request = await protected(company, client, voice, identity)

            async def challenge(peer):
                return request.nonce

            voice.challenge = challenge

            async def assess(context, signal):
                await client.sign_out()
                return RiskAssessment(RiskOutcome.CONTINUE)

            monitor = RiskMonitor(CallbackFraudAdapter(assess=assess))
            messages = iter(
                [
                    {"v": 1, "type": "challenge", "id": request.id},
                    {
                        "v": 1,
                        "type": "request",
                        "id": request.id,
                        "action": request.action,
                        "resource": request.resource,
                        "customer": request.customer,
                        "arguments": request.arguments,
                        "nonce": request.nonce,
                        "grant": request.grant,
                    },
                ]
            )
            sent = []
            executed = []

            async def receive():
                return next(messages)

            async def send(message):
                sent.append(message)

            async def handler(request, claims):
                executed.append(request)
                return {}

            gateway = Gateway(voice)
            gateway.register("order.read", validate=lambda r: None, handler=handler)
            session = SimpleNamespace(
                server=True,
                peer_certificate=peer,
                monitor=monitor,
                risk_context=CallContext("call", True),
                channel=SimpleNamespace(receive_json=receive, send_json=send),
            )
            await gateway.serve(session, limit=1)
            assert not executed and sent[-1]["result"] == "denied"
            await monitor.close()

    asyncio.run(scenario())


def test_revoked_account_token_clears_local_authority(tmp_path):
    async def scenario():
        async with local_company(tmp_path) as (company, client, _, _):
            original = await sign_in(company, client)
            company.refresh_tokens[client.account_token]["active"] = False
            company.sessions[original.session_id].update(customer=None, scope=frozenset())
            with pytest.raises(PAPError, match="invalid_grant"):
                await client.refresh()
            assert client.account_token is None and not client.session.signed_in
            assert (await client.start_session(renew=True)).session_id == original.session_id

    asyncio.run(scenario())

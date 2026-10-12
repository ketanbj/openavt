"""Local verified HTTPS PAP reference service connected to a real WebRTC audio call."""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import socket
import ssl
import tempfile
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from aiohttp import web
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from openavt.authority.ca import AgentAuthority
from openavt.authority.common import b64, key_pem, private_write, unb64
from openavt.demos.pap_reference import ReferenceCompany
from openavt.identity import Identity
from openavt.pap import PAPClient, PAPVoiceGrant, UserIDs, VoiceAuthority, VoiceBridge
from openavt.pap.crypto import SigningKey
from openavt.pap.http import HTTPS
from openavt.risk import CallbackFraudAdapter, CallContext, RiskAssessment, RiskMonitor, RiskOutcome

NAMESPACE = "example.test/openavt-voice"


def enroll(authority, directory, name="assistant"):
    """Local AVA operator enrollment; no real identity-verification claim."""
    directory.mkdir(mode=0o700)
    account = authority.register()
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
        .sign(key, hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM)
        .decode()
    )
    order = authority.order(account["credential"], name, csr)
    result = authority.finalize(
        account["credential"],
        order["order"],
        b64(key.sign(unb64(order["proof_message"]), ec.ECDSA(hashes.SHA256()))),
    )
    private_write(directory / "agent.key", key_pem(key))
    (directory / "agent.pem").write_text(result["certificate"])
    (directory / "root.pem").write_bytes((authority.state / "root.pem").read_bytes())
    authority.provision_service(directory)
    return Identity.load(directory)


def https_contexts(directory):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Local PAP demo")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    private_write(directory / "https.key", key_pem(key))
    (directory / "https.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.minimum_version = ssl.TLSVersion.TLSv1_3
    server.load_cert_chain(directory / "https.pem", directory / "https.key")
    client = ssl.create_default_context(cafile=str(directory / "https.pem"))
    return server, client


@asynccontextmanager
async def local_company(directory, *, namespace=NAMESPACE):
    """Ephemeral real HTTPS service, private identity state and independent JWT verifier."""
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    authority = AgentAuthority.initialize(directory / "ava")
    identity = enroll(authority, directory / "identity")
    server_ssl, client_ssl = https_contexts(directory)
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.setblocking(False)
    base = f"https://127.0.0.1:{sock.getsockname()[1]}"
    company = ReferenceCompany(base=base, namespace=namespace)
    client = PAPClient(
        client_id=base + "/agent.json",
        signing_key=SigningKey.generate(kid="assertion-1"),
        dpop_key=SigningKey.generate(),
        user_ids=UserIDs(directory / "user.sqlite3"),
        http=HTTPS(ssl_context=client_ssl),
        redirect_uris=(base + "/callback",),
        extensions={namespace: {"version": "1"}, "operations": {"version": "1"}},
    )
    company.register(
        client.metadata(base + "/jwks.json", name="Local personal agent"), client.signing_key.jwks
    )
    voice = VoiceAuthority.initialize(
        directory / "voice",
        agents=authority,
        sessions=company,
        audience="desk.demo",
        authorize_intent=company.authorize_intent,
    )
    company.bridge = VoiceBridge(voice, endpoint=company.grant_url, namespace=namespace)
    runner = web.AppRunner(company.application())
    await runner.setup()
    try:
        await web.SockSite(runner, sock, ssl_context=server_ssl).start()
        await client.discover(base)
        yield company, client, voice, identity
    finally:
        await client.close()
        await runner.cleanup()
        sock.close()


async def run(output: Path, *, namespace=NAMESPACE):
    from openavt import Gateway, VoiceSession
    from openavt.transports.peer import WebRTCAdapter

    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise ValueError("output directory must be empty")
    with tempfile.TemporaryDirectory(prefix="openavt-pap-") as temporary:
        async with local_company(Path(temporary), namespace=namespace) as (company, client, voice, identity):
            await client.start_session()
            flow = client.begin_direct("poppy:read poppy:write", client.redirect_uris[0])
            # Explicit simulated user sign-in/consent, never model-controlled approval.
            await client.finish_direct(company.approve_direct(flow.url))
            a, b = WebRTCAdapter(), WebRTCAdapter()
            risk = {"block": False, "observed": 0}

            async def observe(context, pcm):
                risk["observed"] += 1

            async def assess(context, request):
                return RiskAssessment(RiskOutcome.BLOCK if risk["block"] else RiskOutcome.CONTINUE)

            monitor = RiskMonitor(CallbackFraudAdapter(observe=observe, assess=assess))
            caller = VoiceSession(
                audio=a,
                identity=identity,
                trust=identity.certificate.parent / "root.pem",
                expected_peer="desk.demo",
            )
            desk = VoiceSession(
                audio=b,
                identity=Identity.load(identity.certificate.parent, name="desk"),
                trust=identity.certificate.parent / "root.pem",
                server=True,
                monitor=monitor,
            )
            gateway = Gateway(voice)

            def validate_read(request):
                if request.arguments:
                    raise ValueError()

            async def read(request, claims):
                return {"status": "shipped"}

            def validate_exchange(request):
                if request.arguments != {"replacement": "blue"}:
                    raise ValueError()

            async def propose(request, claims):
                session = await company.current(claims["credential_id"])
                return company.propose(
                    session, {"order_id": request.resource, "replacement": "blue", "charge": 0}
                )

            gateway.register("order.read", validate=validate_read, handler=read)
            gateway.register("order.exchange", validate=validate_exchange, handler=propose)
            serving = None
            try:
                await a.accept(await b.answer(await a.offer()))
                await asyncio.gather(caller.__aenter__(), desk.__aenter__())
                serving = asyncio.create_task(gateway.serve(desk, limit=4))
                grant = PAPVoiceGrant(client, identity, namespace=namespace)
                options = {"resource": "order-1", "customer": "alice", "grant": grant}
                read_result = await caller.request("order.read", **options)
                proposal = await caller.request(
                    "order.exchange", **options, arguments={"replacement": "blue"}
                )
                op = proposal["data"]
                no_effect_before_approval = company.effects == 0
                confirmed = await client.operation(
                    op["operation_id"], revision=op["revision"], approved_by="user"
                )
                repeated = await client.operation(
                    op["operation_id"], revision=op["revision"], approved_by="user"
                )
                recovered = await client.operation(op["operation_id"])
                risk["block"] = True
                blocked = await caller.request("order.read", **options)
                risk["block"] = False

                async def revoked(request):
                    issued = await grant(request)
                    await client.sign_out()
                    return issued

                revoked_result = await caller.request("order.read", **{**options, "grant": revoked})
                await serving
                audio_summary = caller.summary()
                context_verified = desk.risk_context.authenticated
            finally:
                if serving and not serving.done():
                    serving.cancel()
                    await asyncio.gather(serving, return_exceptions=True)
                await asyncio.gather(caller.close(), desk.close())

            async def legacy(context, request):
                assert not context.authenticated
                return RiskAssessment(RiskOutcome.REVIEW)

            unsupported = RiskMonitor(CallbackFraudAdapter(assess=legacy))
            legacy_result = await unsupported.assess(CallContext("unsupported-demo"))
            await unsupported.close()
            verified = (
                read_result["result"] == "allowed"
                and proposal["result"] == "allowed"
                and no_effect_before_approval
                and confirmed == repeated == recovered
                and confirmed["state"] == "succeeded"
                and company.effects == 1
                and blocked["reason"] == "risk_block"
                and revoked_result["result"] == "denied"
                and gateway.executions == 2
                and context_verified
                and risk["observed"] > 0
            )
            report = {
                "verified": verified,
                "pap_draft": "0.1 (2026-10-09)",
                "operations_version": "1",
                "extension_namespace": namespace,
                "reference_only": True,
                "external_provider_interoperability_verified": False,
                "simulated_user_approval": True,
                "https_certificate_verified": True,
                "transport": "WebRTC audio, PCM/G.711",
                "tls_handshake_seconds": audio_summary["handshake_seconds"],
                "webrtc_data_channel": False,
                "protected_request_delivery": "audio only; session and account tokens stay on HTTPS",
                "read_allowed": read_result["result"] == "allowed",
                "write_proposed_without_execution": no_effect_before_approval,
                "https_confirmation_effects": company.effects,
                "same_operation_retry_and_recovery": confirmed == repeated == recovered,
                "authenticated_risk_block": blocked["reason"] == "risk_block",
                "signed_out_grant_denied": revoked_result["result"] == "denied",
                "unsupported_caller_risk": legacy_result.outcome.value,
                "risk_audio_chunks": risk["observed"],
                "gateway": gateway.summary(),
                "dpop_nonce_challenges": company.used_nonce_challenges,
                "elapsed_epoch": int(time.time()),
            }
            (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
            if not verified:
                raise RuntimeError("PAP bridge demonstration verification failed")
            return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("output/pap-demo"))
    parser.add_argument("--namespace", default=NAMESPACE)
    args = parser.parse_args(argv)
    report = asyncio.run(run(args.output, namespace=args.namespace))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()

"""Matched TLS/QUIC authority trials over real local PCMU WebRTC audio.

This is an executable transport ablation, not an independent OAuth implementation
or a test of public CA deployment. All effects are an in-memory experiment ledger.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import platform
import subprocess
import tempfile
import time
import uuid
from contextlib import AsyncExitStack
from dataclasses import asdict, replace
from datetime import datetime, timezone
from importlib.metadata import version
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from openavt import Gateway, Identity, VoiceSession
from openavt.authority.common import b64, key_pem, private_write, unb64
from openavt.demos.pap import NAMESPACE, local_company
from openavt.pap import PAPVoiceGrant
from openavt.risk import CallbackFraudAdapter, RiskAssessment, RiskMonitor, RiskOutcome
from openavt.session import GrantRequest, ProtocolError
from openavt.transports.impaired import ImpairedAudio
from openavt.transports.peer import WebRTCAdapter


class WithoutRevalidation:
    """Intentional negative control: omit the check after the risk callback."""

    def __init__(self, authority):
        self.challenge, self.authorize = authority.challenge, authority.authorize


def enroll_rotated(authority, directory):
    """Use public account/order/finalize/revoke APIs; keep account credentials private."""
    directory.mkdir(mode=0o700)
    account = authority.register()
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "rotated")]))
        .sign(key, hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM)
        .decode()
    )
    order = authority.order(account["credential"], "rotated", csr)
    issued = authority.finalize(
        account["credential"],
        order["order"],
        b64(key.sign(unb64(order["proof_message"]), ec.ECDSA(hashes.SHA256()))),
    )
    private_write(directory / "agent.key", key_pem(key))
    (directory / "agent.pem").write_text(issued["certificate"])
    (directory / "root.pem").write_bytes((authority.state / "root.pem").read_bytes())
    authority.provision_service(directory)
    return Identity.load(directory), account["credential"], issued["serial"]


class Call:
    def __init__(self, identity, authority, company, ledger, *, protocol, loss):
        self.identity, self.authority, self.company, self.ledger = identity, authority, company, ledger
        self.hook = self.before_effect = None
        self.serving = None
        self.a, self.b = WebRTCAdapter(), WebRTCAdapter()
        outgoing, incoming = (ImpairedAudio(self.a), ImpairedAudio(self.b)) if loss else (self.a, self.b)
        root = identity.certificate.parent / "root.pem"

        async def assess(context, request):
            if self.hook:
                hook, self.hook = self.hook, None
                await hook()
            return RiskAssessment(RiskOutcome.CONTINUE)

        self.caller = VoiceSession(
            audio=outgoing,
            identity=identity,
            trust=root,
            expected_peer="desk.demo",
            protocol=protocol,
            handshake_timeout=30,
            request_timeout=30,
        )
        self.desk = VoiceSession(
            audio=incoming,
            identity=Identity.load(identity.certificate.parent, name="desk"),
            trust=root,
            server=True,
            protocol=protocol,
            handshake_timeout=30,
            monitor=RiskMonitor(CallbackFraudAdapter(assess=assess), timeout=10),
        )
        self.gateway = Gateway(authority, request_timeout=30)

        def validate(request):
            # Both blue and green are syntactically valid; authority permits blue.
            if request.action == "order.read" and request.arguments:
                raise ValueError()
            if request.action == "order.exchange" and request.arguments not in (
                {"replacement": "blue"},
                {"replacement": "green"},
            ):
                raise ValueError()

        async def effect(request, claims):
            if self.before_effect:
                hook, self.before_effect = self.before_effect, None
                await hook()
            current = await company.current(claims["credential_id"])
            active = bool(
                current
                and await company.authorize_intent(
                    current, request.action, request.resource, request.arguments
                )
            )
            ledger.append({"action": request.action, "authority_active_at_effect": active})
            return {"experiment_ledger_sequence": len(ledger)}

        for action in ("order.read", "order.exchange"):
            self.gateway.register(action, validate=validate, handler=effect)

    async def __aenter__(self):
        try:
            await self.a.accept(await self.b.answer(await self.a.offer()))
            await asyncio.gather(self.caller.__aenter__(), self.desk.__aenter__())
            return self
        except BaseException:
            await self.__aexit__()
            raise

    async def __aexit__(self, *_args):
        if self.serving and not self.serving.done():
            self.serving.cancel()
            await asyncio.gather(self.serving, return_exceptions=True)
        await asyncio.gather(self.caller.close(), self.desk.close())

    async def begin(self, *, request_id=None, action="order.read", arguments=None):
        if self.serving and not self.serving.done():
            raise RuntimeError("finish the outstanding request first")
        self.serving = asyncio.create_task(self.gateway.serve(self.desk, limit=self.gateway.requests + 1))
        request_id = request_id or uuid.uuid4().hex
        await self.caller.channel.send_json({"v": 1, "type": "challenge", "id": request_id})
        challenge = await asyncio.wait_for(self.caller.channel.receive_json(), 30)
        if challenge.get("type") != "challenge" or challenge.get("id") != request_id:
            raise RuntimeError("expected a fresh authorization challenge")
        return GrantRequest(request_id, challenge["nonce"], action, "order-1", "alice", arguments or {})

    async def finish(self, intent, grant, **changes):
        message = {"v": 1, "type": "request", **asdict(intent), "grant": grant}
        message["id"] = message.pop("request_id")
        message.update(changes)
        await self.caller.channel.send_json(message)
        receiving = asyncio.create_task(self.caller.channel.receive_json())
        try:
            done, _ = await asyncio.wait(
                (receiving, self.serving), timeout=30, return_when=asyncio.FIRST_COMPLETED
            )
            if not done:
                raise TimeoutError("trial timed out; this is not an authorization denial")
            if self.serving.done():
                try:
                    self.serving.result()
                except ProtocolError:
                    return {"result": "protocol_rejected"}
            response = await asyncio.wait_for(receiving, 30)
            await self.serving
            return {"result": response["result"], "reason": response["reason"]}
        finally:
            if not receiving.done():
                receiving.cancel()
            await asyncio.gather(receiving, return_exceptions=True)

    def summary(self):
        return {
            "client": self.caller.summary(),
            "server": self.desk.summary(),
            "client_audio": self.caller.audio.summary(),
            "server_audio": self.desk.audio.summary(),
        }


async def sign_in(company, client):
    # Explicit local simulated user approval; no external account or user involved.
    await client.start_session()
    flow = client.begin_direct("poppy:read poppy:write", client.redirect_uris[0])
    await client.finish_direct(company.approve_direct(flow.url))


async def trial(directory, *, protocol, loss, repetition):
    ledger, rows, summaries = [], [], []
    started = time.monotonic()
    async with local_company(directory) as (company, client, authority, identity):
        await sign_in(company, client)
        grant = PAPVoiceGrant(client, identity, namespace=NAMESPACE)
        rotation_started = time.monotonic()
        rotated, enrollment_credential, rotated_serial = enroll_rotated(
            authority.agents, directory / "rotated"
        )
        enrollment_seconds = time.monotonic() - rotation_started

        def record(name, response, before, expected, expected_effects=0, expected_inactive=0):
            effects = ledger[before:]
            inactive = sum(not entry["authority_active_at_effect"] for entry in effects)
            row = {
                "case": name,
                **response,
                "effects": len(effects),
                "inactive_effects": inactive,
                "expected_result": expected,
                "expected_effects": expected_effects,
                "expected_inactive_effects": expected_inactive,
            }
            row["matched_expectation"] = (
                response["result"] == expected
                and len(effects) == expected_effects
                and inactive == expected_inactive
            )
            rows.append(row)
            if not row["matched_expectation"]:
                raise AssertionError(json.dumps(row))

        async with AsyncExitStack() as stack:

            async def open_call(who=identity):
                call = await stack.enter_async_context(
                    Call(who, authority, company, ledger, protocol=protocol, loss=loss)
                )
                summaries.append(call)
                return call

            a, b = await open_call(), await open_call()

            async def request(
                call,
                name,
                *,
                action="order.read",
                arguments=None,
                expected="allowed",
                expected_effects=1,
                signed_changes=None,
                wire_changes=None,
                expected_inactive=0,
                issuer=grant,
            ):
                before = len(ledger)
                intent = await call.begin(action=action, arguments=arguments)
                credential = await issuer(replace(intent, **(signed_changes or {})))
                response = await call.finish(intent, credential, **(wire_changes or {}))
                record(name, response, before, expected, expected_effects, expected_inactive)
                return intent, credential

            _, used = await request(a, "valid_call_a")
            await request(b, "valid_second_call_same_key")
            before = len(ledger)
            first, second = await asyncio.gather(a.begin(), b.begin())
            first_grant, second_grant = await asyncio.gather(grant(first), grant(second))
            concurrent = await asyncio.gather(a.finish(first, first_grant), b.finish(second, second_grant))
            record(
                "concurrent_legitimate_requests",
                {"result": "allowed" if all(r["result"] == "allowed" for r in concurrent) else "error"},
                before,
                "allowed",
                2,
            )
            for name, changes in (
                ("arguments_substitution", {"arguments": {"replacement": "green"}}),
                ("action_substitution", {"action": "order.exchange", "arguments": {"replacement": "blue"}}),
                ("resource_substitution", {"resource": "order-2"}),
                ("customer_substitution", {"customer": "bob"}),
            ):
                await request(
                    a,
                    name,
                    action="order.exchange" if name.startswith("arguments") else "order.read",
                    arguments={"replacement": "blue"} if name.startswith("arguments") else None,
                    wire_changes=changes,
                    expected="denied",
                    expected_effects=0,
                )
            await request(
                a,
                "request_id_substitution",
                signed_changes={"request_id": "other-request"},
                expected="denied",
                expected_effects=0,
            )

            before = len(ledger)
            intent = await a.begin()
            record("consumed_grant_replay", await a.finish(intent, used), before, "denied")

            before = len(ledger)
            pending = await a.begin()
            pending_grant = await grant(pending)
            other = await b.begin(request_id=pending.request_id)
            record("same_key_cross_call_grant", await b.finish(other, pending_grant), before, "denied")
            before = len(ledger)
            other = await b.begin(request_id=pending.request_id)
            record(
                "same_key_exact_transplant",
                await b.finish(pending, pending_grant),
                before,
                "protocol_rejected",
            )
            assert other.nonce != pending.nonce
            before = len(ledger)
            record(
                "original_call_after_transplant", await a.finish(pending, pending_grant), before, "allowed", 1
            )
            await b.__aexit__()

            pending = await a.begin()
            pending_grant = await grant(pending)
            await a.__aexit__()
            c = await open_call()
            before = len(ledger)
            await c.begin(request_id=pending.request_id)
            record(
                "reconnect_old_transaction",
                await c.finish(pending, pending_grant),
                before,
                "protocol_rejected",
            )
            # A protocol violation ends this connection; recovery uses a new call.
            await c.__aexit__()
            c = await open_call()
            await request(c, "reconnect_fresh_authorization")

            pending = await c.begin()
            pending_grant = await grant(pending)
            d = await open_call(rotated)
            before = len(ledger)
            other = await d.begin()
            record("rotated_key_old_grant", await d.finish(other, pending_grant), before, "denied")
            before = len(ledger)
            record("old_key_still_active", await c.finish(pending, pending_grant), before, "allowed", 1)
            rotated_grant = PAPVoiceGrant(client, rotated, namespace=NAMESPACE)
            await request(d, "rotated_key_fresh_authorization", issuer=rotated_grant)

            d.hook = client.sign_out
            await request(
                d, "signout_during_risk", issuer=rotated_grant, expected="denied", expected_effects=0
            )

            await sign_in(company, client)
            original_current = company.current

            async def unavailable(_credential):
                raise ConnectionError("experiment: authority unavailable")

            async def outage():
                company.current = unavailable

            d.hook = outage
            try:
                await request(
                    d,
                    "authority_outage_during_risk",
                    issuer=rotated_grant,
                    expected="error",
                    expected_effects=0,
                )
            finally:
                company.current = original_current

            # Negative control verifies the scheduled revocation actually matters.
            d.gateway.policy = WithoutRevalidation(authority)
            d.hook = client.sign_out
            await request(
                d, "ablation_omit_revalidation", issuer=rotated_grant, expected_effects=1, expected_inactive=1
            )
            d.gateway.policy = authority

            await sign_in(company, client)
            # An async backend can yield after the final check and before its effect.
            # This deliberately schedules revocation in that real remaining window.
            d.before_effect = client.sign_out
            await request(
                d,
                "revocation_after_final_check",
                issuer=rotated_grant,
                expected_effects=1,
                expected_inactive=1,
            )

            await sign_in(company, client)

            async def revoke_certificate():
                authority.agents.revoke(enrollment_credential, rotated_serial)

            d.hook = revoke_certificate
            # CA rejection must prevent a handler effect in the established call.
            await request(
                d,
                "certificate_revocation_during_risk",
                issuer=rotated_grant,
                expected="denied",
                expected_effects=0,
            )

            call_summaries = [call.summary() for call in summaries]

        return {
            "protocol": protocol,
            "loss": loss,
            "repetition": repetition,
            "elapsed_seconds": time.monotonic() - started,
            "local_reenrollment_seconds": enrollment_seconds,
            "cases": rows,
            "calls": call_summaries,
            "ledger": ledger,
            "all_expectations_matched": all(row["matched_expectation"] for row in rows),
        }


async def run(output, repetitions, protocols, impairments):
    output.mkdir(parents=True, exist_ok=False)
    report = {
        "schema": 1,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
        "tracked_worktree_dirty": bool(subprocess.check_output(["git", "diff", "HEAD"], text=True)),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "dependencies": {name: version(name) for name in ("aioquic", "aiortc", "cryptography", "aiohttp")},
        "transport": "local real WebRTC PCMU audio; no data channel",
        "baseline": "TLS 1.3 + existing audio ARQ + identical PAP/DPoP/voice grants and Gateway",
        "candidate": "QUIC v1 + identical PAP/DPoP/voice grants and Gateway",
        "effects": "in-memory synthetic handler ledger, not real business transactions",
        "trials": [],
    }
    for repetition in range(repetitions):
        for loss in impairments:
            # Alternate order to reduce a systematic warmup/order advantage.
            for protocol in protocols if repetition % 2 == 0 else list(reversed(protocols)):
                print(f"starting repetition={repetition} loss={loss} protocol={protocol}", flush=True)
                with tempfile.TemporaryDirectory(prefix="openavt-authority-trial-") as temporary:
                    result = await trial(Path(temporary), protocol=protocol, loss=loss, repetition=repetition)
                report["trials"].append(result)
                (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
                print(
                    f"finished {len(result['cases'])} cases in {result['elapsed_seconds']:.2f}s", flush=True
                )
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--protocol", choices=("tls", "quic"), action="append")
    parser.add_argument("--clean-only", action="store_true")
    args = parser.parse_args()
    if args.repetitions < 1:
        parser.error("repetitions must be positive")
    asyncio.run(
        run(
            args.output,
            args.repetitions,
            args.protocol or ["tls", "quic"],
            [False] if args.clean_only else [False, True],
        )
    )


if __name__ == "__main__":
    main()

"""Local AVA operator, enrollment, renewal and customer-consent commands."""

from __future__ import annotations

import argparse
import json
import ssl
from pathlib import Path

from openavt.authority.ca import AgentAuthority
from openavt.authority.client import AuthorityClient, save_credentials
from openavt.authority.common import AuthorityError, canonical, parse_json, private_write
from openavt.authority.delegation import BusinessAuthority
from openavt.authority.service import AuthorityServer


def main(argv: list[str] | None = None):
    parser = argparse.ArgumentParser(prog="openavt ava", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("init", "serve", "business-init", "customer", "revoke-grant"):
        command = sub.add_parser(name)
        command.add_argument("--state", type=Path, required=True)
        if name in ("business-init", "customer", "revoke-grant"):
            command.add_argument("--ava-state", type=Path, required=True)
        if name == "serve":
            command.add_argument("--business-state", type=Path)
            command.add_argument("--host", default="127.0.0.1")
            command.add_argument("--port", type=int, default=8400)
            command.add_argument("--https-cert", type=Path)
            command.add_argument("--https-key", type=Path)
        if name == "business-init":
            command.add_argument("--audience", default="desk.demo")
        if name == "customer":
            command.add_argument("--customer", required=True)
            command.add_argument("--resource", action="append", required=True)
            command.add_argument("--credentials", type=Path, required=True)
        if name == "revoke-grant":
            command.add_argument("--grant-id", required=True)
    for name in ("account", "enroll", "renew", "revoke", "consent", "withdraw-consent"):
        command = sub.add_parser(name)
        command.add_argument("--url", required=True)
        command.add_argument("--credentials", type=Path, required=True)
        if name in ("enroll", "renew"):
            command.add_argument("--agent", required=True)
            command.add_argument(
                "--root", type=Path, required=True, help="explicitly trusted AVA root, supplied out of band"
            )
            command.add_argument("--output", type=Path, required=True)
            command.add_argument("--key", type=Path, required=name == "renew")
        if name == "revoke":
            command.add_argument("--serial", required=True)
        if name == "consent":
            command.add_argument("--agent-cert", type=Path, required=True)
            command.add_argument("--action", choices=("order.read",), required=True)
            command.add_argument("--resource", required=True)
            command.add_argument("--ttl", type=int, default=300)
            command.add_argument("--output", type=Path, required=True)
        if name == "withdraw-consent":
            command.add_argument("--grant-id", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            authority = AgentAuthority.initialize(args.state)
            result = {"issuer": authority.issuer, "trust_root": str(args.state / "root.pem")}
        elif args.command == "business-init":
            business = BusinessAuthority.initialize(args.state, AgentAuthority(args.ava_state), args.audience)
            result = {"issuer": business.issuer, "audience": business.audience}
        elif args.command == "customer":
            if args.credentials.exists():
                raise AuthorityError("credentials_file_already_exists")
            result = BusinessAuthority(args.state, AgentAuthority(args.ava_state)).register_customer(
                args.customer, args.resource
            )
            save_credentials(args.credentials, result)
            result = {
                "customer": result["customer"],
                "credentials_file": str(args.credentials),
                "assurance": result["assurance"],
            }
        elif args.command == "revoke-grant":
            BusinessAuthority(args.state, AgentAuthority(args.ava_state)).revoke(args.grant_id)
            result = {"revoked": True}
        elif args.command == "serve":
            agents = AgentAuthority(args.state)
            business = BusinessAuthority(args.business_state, agents) if args.business_state else None
            tls = None
            if bool(args.https_cert) != bool(args.https_key):
                parser.error("--https-cert and --https-key must be provided together")
            if args.https_cert:
                tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                tls.minimum_version = ssl.TLSVersion.TLSv1_2
                tls.load_cert_chain(args.https_cert, args.https_key)
            with AuthorityServer((args.host, args.port), agents, business, tls) as server:
                print(
                    json.dumps(
                        {
                            "listening": list(server.server_address),
                            "tls": tls is not None,
                            "assurance": "pseudonymous-key-control",
                        }
                    ),
                    flush=True,
                )
                try:
                    server.serve_forever()
                except KeyboardInterrupt:
                    pass
            return
        else:
            client = AuthorityClient(args.url)
            if args.command == "account":
                if args.credentials.exists():
                    raise AuthorityError("credentials_file_already_exists")
                result = client.account()
                save_credentials(args.credentials, result)
                result = {
                    "account": result["account"],
                    "credentials_file": str(args.credentials),
                    "assurance": result["assurance"],
                }
            else:
                credentials = parse_json(args.credentials.read_bytes())
                if args.command in ("enroll", "renew"):
                    result = client.enroll(
                        credentials, args.agent, args.root.read_bytes(), args.output, args.key
                    )
                elif args.command == "revoke":
                    result = client.post(
                        "/v1/certificates/revoke", {"serial": args.serial}, credentials["credential"]
                    )
                elif args.command == "withdraw-consent":
                    result = client.post(f"/v1/grants/{args.grant_id}/revoke", {}, credentials["credential"])
                else:
                    if args.output.exists():
                        raise AuthorityError("output_already_exists")
                    grant = client.consent(
                        credentials, args.agent_cert.read_text(), args.action, args.resource, args.ttl
                    )
                    private_write(args.output, canonical(grant))
                    result = {k: v for k, v in grant.items() if k != "delegation"}
                    result["grant_file"] = str(args.output)
        print(json.dumps(result, indent=2))
    except (AuthorityError, OSError, ValueError, KeyError) as error:
        # Never echo credential contents, malformed provider bodies or key files.
        parser.exit(
            1,
            f"AVA command failed: {error.code if isinstance(error, AuthorityError) else type(error).__name__}\n",
        )

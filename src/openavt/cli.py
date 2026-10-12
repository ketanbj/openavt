"""Installed command-line entry point with lazy optional integrations."""

from __future__ import annotations

import argparse
import sys

from openavt import __version__


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="openavt", description="OpenAVT: TLS over voice, built for agents.")
    parser.add_argument("--version", action="version", version=f"openavt {__version__}")
    parser.add_argument(
        "command",
        choices=("loopback", "live", "ava", "delegation-demo", "sdk-demo", "pap-demo"),
        nargs="?",
        help="WAV proof, live call, authority, delegated access, or independent SDK agents",
    )
    arguments = list(sys.argv[1:] if argv is None else argv)
    # Parse only the leading command; each demo owns its options and help.
    options = parser.parse_args(arguments[:1])
    if options.command is None:
        parser.print_help()
        return
    if options.command == "loopback":
        from openavt.demos.loopback import main as run
    elif options.command == "ava":
        try:
            from openavt.authority.cli import main as run
        except ModuleNotFoundError as error:
            if error.name and error.name.split(".")[0] == "cryptography":
                parser.error("Install the optional dependencies: pip install 'openavt[authority]'")
            raise
    else:
        try:
            if options.command == "pap-demo":
                from openavt.demos.pap import main as run
            elif options.command == "sdk-demo":
                from openavt.demos.sdk import main as run
            elif options.command == "delegation-demo":
                from openavt.demos.delegation import main as run
            else:
                from openavt.demos.live import main as run

            needs_agents = (options.command == "live" and "--transport-only" not in arguments) or (
                options.command in {"delegation-demo", "sdk-demo"} and "--agents" in arguments
            )
            if needs_agents and not any(a in arguments for a in ("-h", "--help")):
                from openavt.agents.openai import VoiceAgent  # noqa: F401
            if options.command == "sdk-demo" and not any(a in arguments for a in ("-h", "--help")):
                from openavt.session import VoiceSession  # noqa: F401

                if any(a.startswith("twilio-") for a in arguments):
                    from openavt.transports.twilio import TwilioAdapter  # noqa: F401
                else:
                    from openavt.transports.peer import WebRTCAdapter  # noqa: F401
        except ModuleNotFoundError as error:
            dependencies = {
                "numpy",
                "scipy",
                "aiortc",
                "av",
                "dotenv",
                "openai",
                "cryptography",
                "twilio",
                "aiohttp",
                "jwt",
            }
            if error.name and error.name.split(".")[0] in dependencies:
                extra = "webrtc" if "--transport-only" in arguments else "agents"
                if options.command == "delegation-demo":
                    extra = "agents,authority" if "--agents" in arguments else "webrtc,authority"
                if options.command == "pap-demo":
                    extra = "pap,webrtc"
                if options.command == "sdk-demo":
                    transport_extra = (
                        "twilio" if any(a.startswith("twilio-") for a in arguments) else "webrtc"
                    )
                    extra = "agents,authority" if "--agents" in arguments else transport_extra + ",authority"
                    if transport_extra == "twilio" and "--agents" in arguments:
                        extra += ",twilio"
                parser.error(f"Install the optional dependencies: pip install 'openavt[{extra}]'")
            raise
    run(arguments[1:])

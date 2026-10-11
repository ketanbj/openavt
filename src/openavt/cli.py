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
        choices=("loopback", "live", "ava", "delegation-demo"),
        nargs="?",
        help="WAV proof, live call, Agent Voice Authority, or delegated-access demo",
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
            if options.command == "delegation-demo":
                from openavt.demos.delegation import main as run
            else:
                from openavt.demos.live import main as run

            needs_agents = (options.command == "live" and "--transport-only" not in arguments) or (
                options.command == "delegation-demo" and "--agents" in arguments
            )
            if needs_agents and not any(a in arguments for a in ("-h", "--help")):
                from openavt.agents.openai import VoiceAgent  # noqa: F401
        except ModuleNotFoundError as error:
            dependencies = {"numpy", "scipy", "aiortc", "av", "dotenv", "openai", "cryptography"}
            if error.name and error.name.split(".")[0] in dependencies:
                extra = "webrtc" if "--transport-only" in arguments else "agents"
                if options.command == "delegation-demo":
                    extra = "agents,authority" if "--agents" in arguments else "webrtc,authority"
                parser.error(f"Install the optional dependencies: pip install 'openavt[{extra}]'")
            raise
    run(arguments[1:])

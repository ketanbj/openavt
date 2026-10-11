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
        choices=("loopback", "live"),
        nargs="?",
        help="WAV loopback proof or live WebRTC audio call",
    )
    arguments = list(sys.argv[1:] if argv is None else argv)
    # Parse only the leading command; each demo owns its options and help.
    options = parser.parse_args(arguments[:1])
    if options.command is None:
        parser.print_help()
        return
    if options.command == "loopback":
        from openavt.demos.loopback import main as run
    else:
        try:
            from openavt.demos.live import main as run

            if "--transport-only" not in arguments and not any(a in arguments for a in ("-h", "--help")):
                from openavt.agents.openai import VoiceAgent  # noqa: F401
        except ModuleNotFoundError as error:
            dependencies = {"numpy", "scipy", "aiortc", "av", "dotenv", "openai"}
            if error.name and error.name.split(".")[0] in dependencies:
                extra = "webrtc" if "--transport-only" in arguments else "agents"
                parser.error(f"Install the optional dependencies: pip install 'openavt[{extra}]'")
            raise
    run(arguments[1:])

"""OpenAVT: TLS over voice, built for agents.

Open Agent Voice TLS transports real TLS records through actual call audio.

Optional integrations are imported explicitly so core imports need no third-party
packages. The 0.x API is experimental.
"""

try:
    from ._version import __version__
except ImportError:
    # A source checkout before its first build has no generated version file.
    __version__ = "0.1.0.dev0"


def __getattr__(name):
    # Keep importing the package usable without audio/authority dependencies.
    if name == "Identity":
        from .identity import Identity

        return Identity
    if name == "VoiceSession":
        from .session import VoiceSession

        return VoiceSession
    if name == "Gateway":
        from .gateway import Gateway

        return Gateway
    raise AttributeError(name)

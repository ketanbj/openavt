"""OpenAVT: TLS over voice, built for agents.

Open Agent Voice TLS transports real TLS records as audible FSK tones.

Optional integrations are imported explicitly so core imports need no third-party
packages. The 0.x API is experimental.
"""

try:
    from ._version import __version__
except ImportError:
    # A source checkout before its first build has no generated version file.
    __version__ = "0.1.0.dev0"

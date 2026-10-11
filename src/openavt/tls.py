"""OpenSSL MemoryBIO TLS endpoints, independent of the audio transport."""

from __future__ import annotations

import ssl


class Endpoint:
    def __init__(
        self, name: str, context: ssl.SSLContext, server: bool = False, server_hostname: str | None = None
    ):
        self.name = name
        self.incoming = ssl.MemoryBIO()
        self.outgoing = ssl.MemoryBIO()
        self.tls = context.wrap_bio(
            self.incoming,
            self.outgoing,
            server_side=server,
            server_hostname=None if server else server_hostname,
        )
        self.ready = False

"""Bounded, unreliable QUIC datagrams over the existing CRC audio frames.

Fragmentation supplies QUIC's minimum 1200-byte path MTU even on the 256-byte
FSK modem. Missing fragments discard a datagram; QUIC alone recovers loss.
"""

from __future__ import annotations

import struct
import time
from collections import OrderedDict

from openavt import protocol

MTU = 1200
FRAGMENT = struct.Struct("!BBH")  # index, fragment count, complete datagram length


class AudioDatagrams:
    def __init__(self, max_payload: int, *, lifetime: float = 30):
        if not FRAGMENT.size < max_payload <= 4096 or (max_payload - FRAGMENT.size) * 255 < MTU:
            raise ValueError("invalid audio datagram payload size")
        self.capacity = max_payload - FRAGMENT.size
        self.lifetime = lifetime
        self.next_tx = 0
        self.pending: OrderedDict = OrderedDict()
        self.discarded = 0

    def frame(self, data: bytes) -> list[bytes]:
        if not 0 < len(data) <= MTU:
            raise ValueError("invalid QUIC datagram size")
        count = (len(data) + self.capacity - 1) // self.capacity
        sequence = self.next_tx
        self.next_tx = (sequence + 1) & 0xFFFFFFFF
        return [
            protocol.frame(
                sequence,
                protocol.QUIC,
                FRAGMENT.pack(index, count, len(data)) + data[start : start + self.capacity],
            )
            for index, start in enumerate(range(0, len(data), self.capacity))
        ]

    def receive(self, sequence: int, kind: int, payload: bytes) -> bytes | None:
        now = time.monotonic()
        for key, (created, *_rest) in list(self.pending.items()):
            if now - created > self.lifetime:
                del self.pending[key]
                self.discarded += 1
        if kind != protocol.QUIC or len(payload) <= FRAGMENT.size:
            return None
        index, count, length = FRAGMENT.unpack_from(payload)
        body = payload[FRAGMENT.size :]
        expected_count = (length + self.capacity - 1) // self.capacity
        if (
            not 0 < length <= MTU
            or count != expected_count
            or index >= count
            or len(body) != min(self.capacity, length - index * self.capacity)
        ):
            self.discarded += 1
            return None
        if sequence not in self.pending:
            if len(self.pending) == 16:
                self.pending.popitem(last=False)
                self.discarded += 1
            self.pending[sequence] = (now, count, length, {})
        _, old_count, old_length, parts = self.pending[sequence]
        if count != old_count or length != old_length or (index in parts and parts[index] != body):
            del self.pending[sequence]
            self.discarded += 1
            return None
        parts[index] = body
        if len(parts) == count:
            del self.pending[sequence]
            return b"".join(parts[i] for i in range(count))
        return None

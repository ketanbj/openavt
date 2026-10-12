"""Adapt the local AVA business grants to the framework-neutral gateway."""

from __future__ import annotations

import asyncio

from openavt.authority.common import AuthorityError
from openavt.authority.delegation import BusinessAuthority
from openavt.gateway import Request


class AVAPolicy:
    def __init__(self, business: BusinessAuthority):
        self.business = business

    async def challenge(self, peer_certificate: bytes) -> str:
        try:
            return await asyncio.to_thread(self.business.challenge, peer_certificate)
        except AuthorityError as error:
            raise PermissionError("agent certificate is inactive") from error

    async def authorize(self, peer_certificate: bytes, request: Request) -> dict:
        # Existing grants authorize a fixed order.read operation with no parameters.
        if request.arguments:
            raise PermissionError("parameters are outside the delegated scope")
        legacy = {
            "id": request.id,
            "action": request.action,
            "order": request.resource,
            "customer": request.customer,
            "nonce": request.nonce,
            "delegation": request.grant,
        }
        try:
            return await asyncio.to_thread(
                self.business.verify, request.grant, peer_certificate, legacy, request.nonce
            )
        except AuthorityError as error:
            raise PermissionError("customer grant rejected") from error

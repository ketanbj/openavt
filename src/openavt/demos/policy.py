"""A fixed read-only fixture grant, enforced outside the LLM."""


def decide(peer: dict, request: dict) -> dict:
    identities = [value for kind, value in peer.get("subjectAltName", ()) if kind == "URI"]
    if "urn:demo:agent:assistant" not in identities:
        raise PermissionError("authenticated identity does not match the demo grant")
    if set(request) != {"id", "action", "order"} or not all(isinstance(v, str) for v in request.values()):
        raise ValueError("invalid request schema")
    allowed = request["action"] == "order.read" and request["order"] == "demo-order-1234"
    return {
        "id": request["id"],
        "result": "allowed" if allowed else "denied",
        "reason": "read-only demo grant",
        "status": "shipped" if allowed else None,
    }

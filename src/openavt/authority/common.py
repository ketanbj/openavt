"""Strict encoding, protected state, and bounded prototype errors."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import sqlite3
from contextlib import contextmanager
from pathlib import Path

from cryptography.hazmat.primitives import serialization


class AuthorityError(ValueError):
    def __init__(self, code: str, status: int = 400):
        super().__init__(code)
        self.code, self.status = code, status


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def unb64(value: str) -> bytes:
    if not isinstance(value, str) or not value or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise AuthorityError("invalid_encoding")
    try:
        raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except ValueError as error:
        raise AuthorityError("invalid_encoding") from error
    if b64(raw) != value:
        raise AuthorityError("noncanonical_encoding")
    return raw


def canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def parse_json(raw: bytes) -> dict:
    def invalid_constant(_):
        raise AuthorityError("invalid_json_number")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise AuthorityError("duplicate_json_key")
            result[key] = value
        return result

    try:
        result = json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid_constant)
    except (ValueError, UnicodeError) as error:
        raise AuthorityError("invalid_json") from error
    if not isinstance(result, dict):
        raise AuthorityError("invalid_json_object")
    return result


def label(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", value):
        raise AuthorityError("invalid_identifier")
    return value


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def fingerprint(der: bytes) -> str:
    return b64(hashlib.sha256(der).digest())


def private_write(path: Path, raw: bytes) -> None:
    # Exclusive creation prevents accidental replacement of keys or credentials.
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as output:
        output.write(raw)


def key_pem(key) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


@contextmanager
def database(path: Path):
    connection = sqlite3.connect(path, timeout=5)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("BEGIN IMMEDIATE")
        yield connection
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize_directory(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=False)


def create_database(path: Path, schema: str) -> None:
    private_write(path, b"")
    with sqlite3.connect(path) as connection:
        connection.executescript(schema)

"""Encrypt cloud login material before it leaves the ephemeral runner."""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken


class CloudAuthError(RuntimeError):
    pass


def _cipher() -> Fernet:
    try:
        return Fernet(os.environ["DOUYIN_STATE_KEY"].encode("ascii"))
    except (KeyError, ValueError, UnicodeError):
        raise CloudAuthError("Missing or invalid DOUYIN_STATE_KEY") from None


def encrypt_bytes(data: bytes, purpose: str) -> bytes:
    envelope = json.dumps({"version": 1, "purpose": purpose,
                           "data": base64.b64encode(data).decode("ascii")})
    return _cipher().encrypt(envelope.encode("utf-8"))


def decrypt_bytes(data: bytes, purpose: str) -> bytes:
    try:
        envelope = json.loads(_cipher().decrypt(data))
        if envelope.get("version") != 1 or envelope.get("purpose") != purpose:
            raise ValueError("Unexpected encrypted payload")
        return base64.b64decode(envelope["data"], validate=True)
    except (InvalidToken, ValueError, KeyError, TypeError, AttributeError):
        raise CloudAuthError("Encrypted login material failed verification") from None


def write_encrypted(path: Path, data: bytes, purpose: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(encrypt_bytes(data, purpose))
    temporary.replace(path)


def validate_state(state: object) -> dict:
    if (not isinstance(state, dict) or not isinstance(state.get("cookies"), list)
            or not isinstance(state.get("origins"), list)):
        raise CloudAuthError("Invalid browser storage state")
    return state


async def save_cloud_state(context, path: Path) -> None:
    state = validate_state(await context.storage_state(indexed_db=True))
    write_encrypted(path, json.dumps(state).encode("utf-8"), "browser-state")

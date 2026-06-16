"""Encryption helpers for ANI."""

import json
import os
from pathlib import Path
from typing import Any
from cryptography.fernet import Fernet


_DEFAULT_KEY_PATH = Path.home() / ".ani" / "encryption.key"
_FERNET_PREFIX = b"gAAAAA"


def get_fernet() -> Fernet:
    """Return a Fernet instance configured with the current key."""
    key = os.environ.get("ANI_ENCRYPTION_KEY")
    if not key:
        path = _DEFAULT_KEY_PATH
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            key = path.read_text().strip()
        else:
            key = Fernet.generate_key().decode()
            path.write_text(key)
            try:
                os.chmod(path, 0o600)
            except (OSError, AttributeError):
                pass
    if isinstance(key, str):
        key = key.encode()
    return Fernet(key)


def encrypt_bytes(data: bytes) -> bytes:
    return get_fernet().encrypt(data)


def decrypt_bytes(token: bytes) -> bytes:
    return get_fernet().decrypt(token)


def encrypt_json(obj: Any) -> bytes:
    return encrypt_bytes(json.dumps(obj).encode("utf-8"))


def decrypt_json(token: bytes) -> dict:
    return json.loads(decrypt_bytes(token).decode("utf-8"))


def is_fernet_token(data: bytes) -> bool:
    return data.startswith(_FERNET_PREFIX)


def get_key_path() -> Path:
    return _DEFAULT_KEY_PATH

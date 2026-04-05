"""Encrypt/decrypt provider credentials at rest using Fernet symmetric encryption."""

import base64
import hashlib
import json

from cryptography.fernet import Fernet

from . import config, db


def _get_key() -> bytes:
    """Derive a Fernet key from the licence key."""
    secret = config.LICENCE_KEY or db.get_setting("licence_key") or "bridge-bank-default"
    digest = hashlib.sha256(secret.encode()).digest()
    return base64.urlsafe_b64encode(digest)


def encrypt_credentials(credentials: dict) -> str:
    """Encrypt a credentials dict to a string for DB storage."""
    f = Fernet(_get_key())
    plaintext = json.dumps(credentials).encode()
    return f.encrypt(plaintext).decode()


def decrypt_credentials(encrypted: str) -> dict:
    """Decrypt a credentials string from DB back to a dict."""
    if not encrypted:
        return {}
    f = Fernet(_get_key())
    plaintext = f.decrypt(encrypted.encode())
    return json.loads(plaintext)

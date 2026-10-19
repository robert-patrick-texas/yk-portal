"""AES-256-GCM for secrets stored in the database (spec §22.3, §22.6).

An encrypted value is one self-describing blob:

    version (1 byte) | master key ID (8 bytes) | nonce (12 bytes) | ciphertext and tag

Nonces are random, from the operating system. Each value is bound to where it
is stored by associated data, such as "yubikey_credentials.aes_secret:<id>",
so a value copied to another row or column fails to decrypt.
"""

import functools
import hashlib
import hmac
import os
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .master_key import DerivedKeys, derive_keys, load_master_key

VERSION = 1
_KEY_ID_BYTES = 8
_NONCE_BYTES = 12
_TAG_BYTES = 16
_HEADER_BYTES = 1 + _KEY_ID_BYTES + _NONCE_BYTES


class DecryptionError(Exception):
    """A stored value can't be decrypted. The message never includes the value."""


class SecretBox:
    """Encrypts and decrypts stored values with one derived key."""

    def __init__(self, key: bytes, key_id: bytes) -> None:
        if len(key_id) != _KEY_ID_BYTES:
            raise ValueError("the key ID must be 8 bytes")
        self._aead = AESGCM(key)
        self.key_id = key_id

    def __repr__(self) -> str:
        return f"SecretBox(key_id={self.key_id.hex()})"

    def encrypt(self, plaintext: bytes, context: str) -> bytes:
        nonce = os.urandom(_NONCE_BYTES)
        header = bytes([VERSION]) + self.key_id + nonce
        return header + self._aead.encrypt(nonce, plaintext, _associated_data(header, context))

    def decrypt(self, blob: bytes, context: str) -> bytes:
        if len(blob) < _HEADER_BYTES + _TAG_BYTES or blob[0] != VERSION:
            raise DecryptionError(f"{context}: not an encrypted value of a known version")
        header, ciphertext = blob[:_HEADER_BYTES], blob[_HEADER_BYTES:]
        if header[1 : 1 + _KEY_ID_BYTES] != self.key_id:
            raise DecryptionError(f"{context}: encrypted with a different master key")
        nonce = header[1 + _KEY_ID_BYTES :]
        try:
            return self._aead.decrypt(nonce, ciphertext, _associated_data(header, context))
        except InvalidTag:
            raise DecryptionError(
                f"{context}: authentication failed (tampered with, or stored elsewhere)"
            ) from None


def _associated_data(header: bytes, context: str) -> bytes:
    if not context:
        raise ValueError("an encrypted value needs a context")
    return header + context.encode()


@functools.cache
def _keys_for(path: Path) -> tuple[DerivedKeys, SecretBox]:
    keys = derive_keys(load_master_key(path))
    return keys, SecretBox(keys.secrets, keys.key_id)


def _keys() -> tuple[DerivedKeys, SecretBox]:
    from django.conf import settings

    return _keys_for(Path(settings.YK_MASTER_KEY_PATH))


def derived_keys() -> DerivedKeys:
    """The keys derived from the master key named by the settings, such as the backup key."""
    return _keys()[0]


def secret_box() -> SecretBox:
    """The SecretBox for stored secrets, from the master key named by the settings."""
    return _keys()[1]


def lookup_digest(value: bytes, purpose: str) -> str:
    """HMAC-SHA256 of VALUE with a key derived from the master key, as hex.

    Stored next to an encrypted value, it lets a unique index cover the value
    without revealing it: unkeyed, a short value such as a 6-byte private ID
    could be found by trying every one. Master key rotation recomputes it.
    """
    message = purpose.encode() + b"\0" + value
    return hmac.new(derived_keys().lookup, message, hashlib.sha256).hexdigest()

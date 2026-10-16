"""The two password hashes of an account (addendum §2.2).

- The web password hash: Argon2id, through Django's Argon2 hasher (spec §12.1).
- The RADIUS password hash: SHA-512 crypt, for the export to radiator-yubikey.

Today both come from the same password (addendum §2.3).
"""

from dataclasses import dataclass, field

from django.contrib.auth.hashers import check_password, make_password

from yk_portal.core import sha512_crypt


@dataclass(frozen=True)
class PasswordHashes:
    web: str = field(repr=False)
    radius: str = field(repr=False)


def hash_web_password(password: str) -> str:
    """An Argon2id hash of PASSWORD, for yk-portal web logins and temporary passwords."""
    if not password:
        raise ValueError("a password can't be empty")
    return make_password(password)


def check_web_password(password: str, stored: str) -> bool:
    """Whether PASSWORD matches a stored Argon2id hash. An empty hash never matches."""
    return bool(stored) and check_password(password, stored)


def hash_password(password: str) -> PasswordHashes:
    """Both hashes of a permanent password, made together while the plain text is at hand."""
    return PasswordHashes(web=hash_web_password(password), radius=sha512_crypt.make_hash(password))

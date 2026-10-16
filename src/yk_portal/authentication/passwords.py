"""The two password hashes of an account (addendum §2.2).

- The web password hash: Argon2id, through Django's Argon2 hasher (spec §12.1).
- The RADIUS password hash: SHA-512 crypt, for the export to radiator-yubikey.

Today both come from the same password (addendum §2.3). Temporary passwords
get only the Argon2id hash (addendum §2.5).
"""

import secrets
import unicodedata
from dataclasses import dataclass, field

from django.contrib.auth.hashers import check_password, make_password
from django.core.exceptions import ValidationError

from yk_portal.core import sha512_crypt

MIN_LENGTH = 8
# RADIUS carries at most 128 bytes of password: PIN, ":" and the 44-character
# OTP must fit (spec §12). Characters outside ASCII take 2 to 4 bytes in UTF-8.
MAX_BYTES = 80

# Temporary passwords: lowercase letters and digits that are hard to mistake
# for one another (no 0 o 1 i l), in four groups of four: about 79 bits.
_TEMPORARY_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"


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


def validate_password(password: str) -> None:
    """Check a permanent password against the policy (spec §12, addendum §2.6).

    8 to 80 characters (80 bytes in UTF-8) with at least one letter and one
    number, not ending with ":" (Radiator reads PIN:OTP), and no control
    characters, which crypt(3) and login prompts can't take.

    Raises:
        ValidationError: With every rule the password breaks.
    """
    errors = []
    if len(password) < MIN_LENGTH:
        errors.append(ValidationError("Use at least 8 characters.", code="password_too_short"))
    elif len(password.encode()) > MAX_BYTES:
        message = "Use at most 80 characters"
        if len(password) <= MAX_BYTES:
            message += " (accented letters and other non-ASCII characters count as 2 to 4)"
        errors.append(ValidationError(message + ".", code="password_too_long"))
    if not any(c.isalpha() for c in password):
        errors.append(ValidationError("Include at least one letter.", code="password_no_letter"))
    if not any(c.isdecimal() for c in password):
        errors.append(ValidationError("Include at least one number.", code="password_no_number"))
    if password.endswith(":"):
        errors.append(ValidationError("Don't end the password with :", code="password_colon"))
    if any(unicodedata.category(c) == "Cc" for c in password):
        errors.append(
            ValidationError(
                "Don't use control characters such as tab or line break.",
                code="password_control_character",
            )
        )
    if errors:
        raise ValidationError(errors)


def generate_temporary_password() -> str:
    """A random temporary password, such as "k7mq-3xwe-p9fa-h2nt", that meets the policy."""
    while True:
        password = "-".join(
            "".join(secrets.choice(_TEMPORARY_ALPHABET) for _ in range(4)) for _ in range(4)
        )
        if any(c.isalpha() for c in password) and any(c.isdecimal() for c in password):
            return password

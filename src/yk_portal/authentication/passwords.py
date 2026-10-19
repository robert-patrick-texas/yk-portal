"""PINs and temporary passwords (addendum §2.2).

Each YubiKey has a PIN, typed before its OTP, with two hashes:

- Argon2id, through Django's Argon2 hasher (spec §12.1), for web logins;
- SHA-512 crypt, for the export to radiator-yubikey.

Both come from the same PIN (addendum §2.3). Temporary passwords get only the
Argon2id hash (addendum §2.5).
"""

import re
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
class PinHashes:
    web: str = field(repr=False)
    radius: str = field(repr=False)


def hash_web_password(password: str) -> str:
    """An Argon2id hash of PASSWORD, for yk-portal web logins: a PIN or a temporary
    password."""
    if not password:
        raise ValueError("a password can't be empty")
    return make_password(password)


def check_web_password(password: str, stored: str) -> bool:
    """Whether PASSWORD matches a stored Argon2id hash. An empty hash never matches."""
    return bool(stored) and check_password(password, stored)


def hash_pin(pin: str) -> PinHashes:
    """Both hashes of a PIN, made together while the plain text is at hand."""
    return PinHashes(web=hash_web_password(pin), radius=sha512_crypt.make_hash(pin))


def validate_pin(pin: str) -> None:
    """Check a PIN against the password policy (spec §12, addendum §2.6).

    8 to 80 characters (80 bytes in UTF-8) with at least one letter and one
    number, not ending with ":" (Radiator reads PIN:OTP), and no control
    characters, which crypt(3) and login prompts can't take.

    Raises:
        ValidationError: With every rule the PIN breaks.
    """
    errors = []
    if len(pin) < MIN_LENGTH:
        errors.append(ValidationError("Use at least 8 characters.", code="password_too_short"))
    elif len(pin.encode()) > MAX_BYTES:
        message = "Use at most 80 characters"
        if len(pin) <= MAX_BYTES:
            message += " (accented letters and other non-ASCII characters count as 2 to 4)"
        errors.append(ValidationError(message + ".", code="password_too_long"))
    if not any(c.isalpha() for c in pin):
        errors.append(ValidationError("Include at least one letter.", code="password_no_letter"))
    if not any(c.isdecimal() for c in pin):
        errors.append(ValidationError("Include at least one number.", code="password_no_number"))
    if pin.endswith(":"):
        errors.append(ValidationError("Don't end it with :", code="password_colon"))
    if any(unicodedata.category(c) == "Cc" for c in pin):
        errors.append(
            ValidationError(
                "Don't use control characters such as tab or line break.",
                code="password_control_character",
            )
        )
    if errors:
        raise ValidationError(errors)


def looks_like_temporary_password(text: str) -> bool:
    """Whether TEXT has the form of a generated temporary password."""
    return re.fullmatch(r"[a-z0-9]{4}(?:-[a-z0-9]{4}){3}", text) is not None


def generate_temporary_password() -> str:
    """A random temporary password, such as "k7mq-3xwe-p9fa-h2nt", that meets the policy."""
    while True:
        password = "-".join(
            "".join(secrets.choice(_TEMPORARY_ALPHABET) for _ in range(4)) for _ in range(4)
        )
        if any(c.isalpha() for c in password) and any(c.isdecimal() for c in password):
            return password

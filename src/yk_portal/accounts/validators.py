import re

from django.core.exceptions import ValidationError

# radiator-yubikey's username rule, lowercase only (addendum §9.1).
USERNAME = re.compile(r"[a-z0-9._@+-]{1,255}")

# Radiator sends these to service-account and anycast-check handling, never to
# YubiKey logins (addendum §9.2).
RESERVED_PREFIXES = ("svc.", "anycast-")


def validate_username(value: str) -> None:
    if not USERNAME.fullmatch(value):
        raise ValidationError(
            "Use 1 to 255 lowercase letters, digits and . _ @ + -", code="invalid_username"
        )
    if value.startswith(RESERVED_PREFIXES):
        raise ValidationError(
            "Usernames starting with svc. or anycast- are reserved for Radiator",
            code="reserved_username",
        )

import unicodedata

from django.core.exceptions import ValidationError

from . import modhex
from .otp import PUBLIC_ID_LENGTH

LABEL_LENGTH = 255


def validate_public_id(value: str) -> None:
    """12 lowercase ModHex characters: the only length Radiator looks up (addendum §8)."""
    if len(value) != PUBLIC_ID_LENGTH or not modhex.is_modhex(value):
        raise ValidationError(
            f"Use the {PUBLIC_ID_LENGTH} ModHex characters (cbdefghijklnrtuv) that start "
            "the YubiKey's OTP",
            code="invalid_public_id",
        )


def validate_label(value: str) -> None:
    """radiator-yubikey's label rule: up to 255 characters, no control characters."""
    if len(value) > LABEL_LENGTH:
        raise ValidationError(f"Use at most {LABEL_LENGTH} characters.", code="label_too_long")
    if any(unicodedata.category(c) == "Cc" for c in value):
        raise ValidationError(
            "Don't use control characters such as tab or line break.", code="invalid_label"
        )

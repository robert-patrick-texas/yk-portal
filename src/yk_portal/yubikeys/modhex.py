"""ModHex: the 16 letters a YubiKey types for the hex digits 0-f.

They sit on the same keys on most keyboard layouts, so an OTP types the same
everywhere. A YubiKey types them lowercase.
"""

import re

ALPHABET = "cbdefghijklnrtuv"
_TO_HEX = str.maketrans(ALPHABET, "0123456789abcdef")
_FROM_HEX = str.maketrans("0123456789abcdef", ALPHABET)
_MODHEX = re.compile(f"(?:[{ALPHABET}]{{2}})*")


def is_modhex(text: str) -> bool:
    """Whether TEXT is lowercase ModHex of whole bytes (an even number of characters)."""
    return _MODHEX.fullmatch(text) is not None


def decode(text: str) -> bytes:
    """The bytes TEXT encodes.

    Raises:
        ValueError: TEXT isn't lowercase ModHex of whole bytes.
    """
    if not is_modhex(text):
        raise ValueError("not ModHex")
    return bytes.fromhex(text.translate(_TO_HEX))


def encode(data: bytes) -> str:
    """DATA as ModHex, such as b"\\x01\\xff" -> "cbvv"."""
    return data.hex().translate(_FROM_HEX)

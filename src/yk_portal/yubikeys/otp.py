"""Yubico OTPs: parsing, AES-128 decryption, CRC and counters (spec §5.2, §17, §22.2).

An OTP is 44 ModHex characters: a 12-character public ID, then a 16-byte
token encrypted with the YubiKey's AES-128 key. The token holds:

    private ID (6) | usage counter (2, LE) | timestamp (3, LE) | session counter (1)
    | random (2) | CRC-16 (2)

Counters are read and compared exactly as radiator-yubikey and Radiator 4.30
do (addendum §8): the usage counter's top bit, set when the OTP was triggered
from a keyboard key, is ignored.
"""

import enum
import re
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from . import modhex

OTP_LENGTH = 44
PUBLIC_ID_LENGTH = 12
_OTP = re.compile(f"[{modhex.ALPHABET}]{{{OTP_LENGTH}}}")

# CRC-16 (ISO 13239) over a whole intact token, its own CRC included, leaves this.
CRC_RESIDUE = 0xF0B8
USAGE_COUNTER_MASK = 0x7FFF


class Rejection(enum.StrEnum):
    """Why an OTP was refused: for the audit log, never shown to the user (spec §16)."""

    MALFORMED = "malformed OTP"
    UNKNOWN_KEY = "unknown public ID"
    OTHER_USERS_KEY = "public ID of another user's YubiKey"
    DISABLED_KEY = "disabled YubiKey"
    BAD_CRC = "token does not decrypt (wrong AES key, or a mistyped OTP)"
    PRIVATE_ID_MISMATCH = "private ID mismatch"
    REPLAYED = "replayed or stale OTP"


class OtpRejected(Exception):
    """An OTP was refused. Each reason counts as a failed login (spec §18.1)."""

    def __init__(self, reason: Rejection) -> None:
        super().__init__(reason.value)
        self.reason = reason


@dataclass(frozen=True)
class Otp:
    public_id: str
    token: bytes = field(repr=False)  # still encrypted


@dataclass(frozen=True)
class Token:
    """A decrypted token with a valid CRC. repr() never shows the private ID."""

    private_id: bytes = field(repr=False)
    usage_counter: int
    session_counter: int
    timestamp: int


def parse_otp(text: str) -> Otp:
    """Split an OTP into its public ID and encrypted token.

    Raises:
        OtpRejected: TEXT isn't 44 lowercase ModHex characters (MALFORMED).
    """
    if not _OTP.fullmatch(text):
        raise OtpRejected(Rejection.MALFORMED)
    return Otp(text[:PUBLIC_ID_LENGTH], modhex.decode(text[PUBLIC_ID_LENGTH:]))


def decrypt_token(token: bytes, aes_key: bytes) -> Token:
    """Decrypt a 16-byte token with the YubiKey's AES-128 key and check its CRC.

    Raises:
        OtpRejected: The CRC doesn't check out: the wrong key, or a mistyped OTP (BAD_CRC).
    """
    # The Yubico OTP protocol encrypts its one 16-byte block with AES-128 in ECB mode
    # (spec §22.2); there is no chaining to choose.
    decryptor = Cipher(algorithms.AES128(aes_key), modes.ECB()).decryptor()  # noqa: S305
    plain = decryptor.update(token) + decryptor.finalize()
    if crc16(plain) != CRC_RESIDUE:
        raise OtpRejected(Rejection.BAD_CRC)
    return Token(
        private_id=plain[:6],
        usage_counter=int.from_bytes(plain[6:8], "little") & USAGE_COUNTER_MASK,
        timestamp=int.from_bytes(plain[8:11], "little"),
        session_counter=plain[11],
    )


def crc16(data: bytes) -> int:
    """CRC-16 as ISO 13239 defines it (reflected polynomial 0x8408, initial 0xffff)."""
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            lsb = crc & 1
            crc >>= 1
            if lsb:
                crc ^= 0x8408
    return crc


def is_newer(token: Token, last_usage_counter: int, last_session_counter: int) -> bool:
    """Whether TOKEN comes after the last accepted OTP (addendum §8.1).

    Its usage counter must be higher, or the same with a higher session counter.
    """
    return token.usage_counter > last_usage_counter or (
        token.usage_counter == last_usage_counter and token.session_counter > last_session_counter
    )

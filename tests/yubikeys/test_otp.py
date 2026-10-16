import pytest

from yk_portal.yubikeys import modhex
from yk_portal.yubikeys.otp import (
    CRC_RESIDUE,
    Rejection,
    Token,
    crc16,
    decrypt_token,
    is_newer,
    parse_otp,
)

K1 = "6b1f0a9d2c7e4f3a8b5d0c1e9f2a7b6d"
K2 = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
PUBLIC_ID = "vvccccbbcdef"
PRIVATE_ID = "4a6f8e2d1c3b"


def test_yubico_sample_otp():
    # From Yubico's libyubikey README; made independently of this code.
    otp = "dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh"
    key = bytes.fromhex("ecde18dbe76fbd0c33330f1c354871db")
    token = decrypt_token(modhex.decode(otp[-32:]), key)
    assert token.private_id == bytes.fromhex("8792ebfe26cc")
    assert token.usage_counter == 19
    assert token.session_counter == 17


def test_parse_otp(make_otp):
    text = make_otp(PUBLIC_ID, PRIVATE_ID, K1, 3, 1)
    otp = parse_otp(text)
    assert otp.public_id == PUBLIC_ID
    assert len(otp.token) == 16
    assert modhex.encode(otp.token) == text[12:]
    assert otp.token.hex() not in repr(otp)


@pytest.mark.parametrize(
    "text",
    [
        "",
        "vvccccbbcdef",
        "vvccccbbcdef" + "c" * 31,  # 43 characters
        "vvccccbbcdef" + "c" * 33,  # 45 characters
        "VVCCCCBBCDEF" + "c" * 32,  # uppercase
        "vvccccbbcdea" + "c" * 32,  # "a" isn't ModHex
        "vvccccbbcdef" + "c" * 31 + "\n",
    ],
)
def test_malformed_otps(rejected, text):
    with rejected(Rejection.MALFORMED):
        parse_otp(text)


def test_decrypt_token(make_otp):
    token = decrypt_token(
        parse_otp(make_otp(PUBLIC_ID, PRIVATE_ID, K1, 300, 7)).token, bytes.fromhex(K1)
    )
    assert token == Token(
        private_id=bytes.fromhex(PRIVATE_ID), usage_counter=300, session_counter=7, timestamp=0x3412
    )
    assert PRIVATE_ID not in repr(token)


def test_the_usage_counters_top_bit_is_ignored(make_otp):
    otp = parse_otp(make_otp(PUBLIC_ID, PRIVATE_ID, K1, 0x8005, 0))
    assert decrypt_token(otp.token, bytes.fromhex(K1)).usage_counter == 5


def test_wrong_aes_key_fails_the_crc(rejected, make_otp):
    otp = parse_otp(make_otp(PUBLIC_ID, PRIVATE_ID, K1, 3, 1))
    with rejected(Rejection.BAD_CRC):
        decrypt_token(otp.token, bytes.fromhex(K2))


@pytest.mark.parametrize("position", range(32))
def test_a_mistyped_character_fails_the_crc(rejected, make_otp, position):
    text = make_otp(PUBLIC_ID, PRIVATE_ID, K1, 3, 1)
    token = list(text[12:])
    token[position] = "c" if token[position] != "c" else "b"
    with rejected(Rejection.BAD_CRC):
        decrypt_token(modhex.decode("".join(token)), bytes.fromhex(K1))


def test_crc16():
    # The check value of CRC-16/IBM-SDLC (ISO 13239) is the complement of this.
    assert ~crc16(b"123456789") & 0xFFFF == 0x906E
    token = b"0123456789abcd"
    whole = token + (~crc16(token) & 0xFFFF).to_bytes(2, "little")
    assert crc16(whole) == CRC_RESIDUE


@pytest.mark.parametrize(
    ("last", "otp", "newer"),
    [
        ((0, 0), (1, 0), True),
        ((0, 0), (0, 1), True),
        ((0, 0), (0, 0), False),
        ((3, 1), (3, 1), False),  # the same OTP: a replay
        ((3, 1), (3, 2), True),  # next OTP in the session
        ((3, 1), (3, 0), False),
        ((3, 1), (2, 9), False),  # an older session
        ((3, 9), (4, 0), True),  # a new session
        ((32767, 255), (32767, 255), False),
    ],
)
def test_is_newer(last, otp, newer):
    token = Token(private_id=bytes(6), usage_counter=otp[0], session_counter=otp[1], timestamp=0)
    assert is_newer(token, *last) is newer

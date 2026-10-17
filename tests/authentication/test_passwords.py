import re

import pytest
from django.core.exceptions import ValidationError

from yk_portal.authentication.passwords import (
    check_web_password,
    generate_temporary_password,
    hash_pin,
    hash_web_password,
    validate_pin,
)
from yk_portal.core import sha512_crypt


def test_web_hash_is_argon2id():
    stored = hash_web_password("Passw0rd!")
    assert stored.startswith("argon2$argon2id$")
    assert check_web_password("Passw0rd!", stored)
    assert not check_web_password("Passw0rd", stored)


def test_web_hashes_are_salted():
    assert hash_web_password("same1") != hash_web_password("same1")


def test_empty_hash_never_matches():
    assert not check_web_password("", "")
    assert not check_web_password("Passw0rd!", "")


def test_empty_password_is_refused():
    with pytest.raises(ValueError, match="empty"):
        hash_web_password("")


def test_both_hashes_come_from_one_pin():
    hashes = hash_pin("Passw0rd!")
    assert check_web_password("Passw0rd!", hashes.web)
    assert sha512_crypt.check_hash("Passw0rd!", hashes.radius)
    assert hashes.web not in repr(hashes) and hashes.radius not in repr(hashes)


@pytest.mark.parametrize(
    "password",
    [
        "passw0rd",
        "12345678a",
        "Pass word 1",
        "pässwörd1",
        "a:b:c:d:1",
        "x" * 79 + "1",
        "é" * 30 + "1" * 20,  # 80 bytes in UTF-8
    ],
)
def test_valid_pins(password):
    validate_pin(password)


@pytest.mark.parametrize(
    ("password", "codes"),
    [
        ("abc123", ["password_too_short"]),
        ("abcdefgh", ["password_no_number"]),
        ("12345678", ["password_no_letter"]),
        ("passw0rd:", ["password_colon"]),
        ("x" * 80 + "1", ["password_too_long"]),
        ("é" * 31 + "1" * 19, ["password_too_long"]),  # 50 characters, 81 bytes
        ("pass\tw0rd", ["password_control_character"]),
        ("pass\0w0rd", ["password_control_character"]),
        ("ab:", ["password_too_short", "password_no_number", "password_colon"]),
        ("", ["password_too_short", "password_no_letter", "password_no_number"]),
    ],
)
def test_invalid_pins(password, codes):
    with pytest.raises(ValidationError) as excinfo:
        validate_pin(password)
    assert [e.code for e in excinfo.value.error_list] == codes


def test_bytes_over_the_limit_are_explained():
    with pytest.raises(ValidationError, match="count as 2 to 4"):
        validate_pin("é" * 31 + "1" * 19)
    with pytest.raises(ValidationError) as excinfo:
        validate_pin("x" * 81)
    assert excinfo.value.messages[0] == "Use at most 80 characters."


def test_temporary_passwords_meet_the_policy():
    passwords = {generate_temporary_password() for _ in range(50)}
    assert len(passwords) == 50
    for password in passwords:
        assert re.fullmatch(r"[a-hjkmnp-z2-9]{4}(-[a-hjkmnp-z2-9]{4}){3}", password)
        validate_pin(password)

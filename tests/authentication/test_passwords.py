import pytest

from yk_portal.authentication.passwords import (
    check_web_password,
    hash_password,
    hash_web_password,
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


def test_both_hashes_come_from_one_password():
    hashes = hash_password("Passw0rd!")
    assert check_web_password("Passw0rd!", hashes.web)
    assert sha512_crypt.check_hash("Passw0rd!", hashes.radius)
    assert hashes.web not in repr(hashes) and hashes.radius not in repr(hashes)

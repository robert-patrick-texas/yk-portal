import shutil
import subprocess

import pytest

from yk_portal.core import sha512_crypt

SALT = "abcdefghABCD./12"

# Made with `openssl passwd -6 -salt abcdefghABCD./12 PASSWORD`; Perl's crypt(),
# which radiator-yubikey uses, gives the same.
VECTORS = [
    (
        "Passw0rd!",
        "$6$abcdefghABCD./12$ne3bOyav3JxkDFW440ORLdjIdwRO06d6lDeTBYzRjuYZa676OvGd0p2HzEeNcPBEdvhhWs94CfZHOUcpH9dXS.",
    ),
    (
        "pin1234",
        "$6$abcdefghABCD./12$W.S7A6IbH9Y/yvQrrnjkqOCIUUDj3znBPJpF1WIVIYSveuS1prVWnjLMOAB7KzIOsZ3vCT0KRtqCYbAhXEZiS/",
    ),
    (
        "Ünïcode-pässwörd9",
        "$6$abcdefghABCD./12$usQBFNLnS4wmYWphztAkA/t3CuJqL0JD9aUFjbZudIcRtKcMuteoLiq8FK.A8W9b0Sq.1Ocjd1m7Z.CSlFUU.1",
    ),
]


@pytest.mark.parametrize(("password", "expected"), VECTORS)
def test_known_vectors(password, expected):
    assert sha512_crypt.crypt(password, f"$6${SALT}$") == expected
    assert sha512_crypt.check_hash(password, "{crypt}" + expected)


def test_new_hash_format():
    stored = sha512_crypt.make_hash("Passw0rd!")
    assert sha512_crypt.STORED_HASH.fullmatch(stored)
    prefix, salt, digest = stored.rsplit("$", 2)
    assert prefix == "{crypt}$6"
    assert len(salt) == 16 and set(salt) <= set(sha512_crypt.SALT_ALPHABET)
    assert len(digest) == 86


def test_salts_differ():
    assert sha512_crypt.make_hash("same") != sha512_crypt.make_hash("same")


def test_check_hash():
    stored = sha512_crypt.make_hash("Passw0rd!")
    assert sha512_crypt.check_hash("Passw0rd!", stored)
    assert not sha512_crypt.check_hash("Passw0rd", stored)
    assert not sha512_crypt.check_hash("Passw0rd!", stored.removeprefix("{crypt}"))
    assert not sha512_crypt.check_hash("Passw0rd!", "")
    assert not sha512_crypt.check_hash("x", "{crypt}$1$abc$def")
    assert not sha512_crypt.check_hash("x\0y", stored)


def test_rounds_in_a_stored_hash_are_honoured():
    expected = sha512_crypt.crypt("Passw0rd!", f"$6$rounds=10000${SALT}$")
    assert expected.startswith(f"$6$rounds=10000${SALT}$")
    assert sha512_crypt.check_hash("Passw0rd!", "{crypt}" + expected)


def test_nul_is_refused():
    with pytest.raises(ValueError, match="NUL"):
        sha512_crypt.make_hash("abc\0def")


@pytest.mark.parametrize(
    "command",
    [
        ["openssl", "passwd", "-6", "-salt", "{salt}", "{password}"],
        ["perl", "-e", "print crypt($ARGV[0], $ARGV[1])", "{password}", "$6${salt}$"],
    ],
    ids=["openssl", "perl"],
)
def test_matches_system_tools_for_random_passwords(command):
    if shutil.which(command[0]) is None:
        pytest.skip(f"{command[0]} not installed")
    for password in ["a1", "Correct-Horse-9", "pässwörd 7 ~!@#$%^&*()", "x" * 80]:
        stored = sha512_crypt.make_hash(password)
        salt = stored.split("$")[2]
        args = [a.format(salt=salt, password=password) for a in command]
        output = subprocess.run(args, check=True, capture_output=True, text=True).stdout.strip()
        assert "{crypt}" + output == stored

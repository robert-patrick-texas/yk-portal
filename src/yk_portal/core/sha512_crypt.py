"""SHA-512 crypt hashes in the form radiator-yubikey stores: {crypt}$6$<salt>$<hash>.

The hash is made by the system's crypt(3) from libxcrypt, the same library
Perl's crypt() uses in radiator-yubikey and Radiator, so Radiator can check
it (addendum §2.4). Python 3.13 removed its own crypt module. Salts are 16
characters from a cryptographically secure source, with the default 5000
rounds, as yubikey-db.sh makes them.
"""

import ctypes
import ctypes.util
import functools
import hmac
import re
import secrets
from collections.abc import Callable

PREFIX = "{crypt}"
SALT_ALPHABET = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
SALT_LENGTH = 16

# {crypt}$6$[rounds=N$]SALT$HASH, as Radiator and yubikey-db.sh accept them.
STORED_HASH = re.compile(
    r"\{crypt\}\$6\$(rounds=[0-9]{1,9}\$)?[./0-9A-Za-z]{1,16}\$[./0-9A-Za-z]{86}"
)

# sizeof(struct crypt_data) in libxcrypt's <crypt.h>.
_CRYPT_DATA_SIZE = 32768

type _CryptRn = Callable[[bytes, bytes, ctypes.Array[ctypes.c_char], int], bytes | None]


@functools.cache
def _crypt_rn() -> _CryptRn:
    library = ctypes.CDLL(ctypes.util.find_library("crypt") or "libcrypt.so.1")
    crypt_rn = library.crypt_rn
    crypt_rn.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_int]
    crypt_rn.restype = ctypes.c_char_p
    return crypt_rn


def crypt(password: str, setting: str) -> str:
    """crypt(3) of PASSWORD with SETTING: "$6$SALT$" or a whole stored $6$ hash."""
    phrase = password.encode()
    if b"\0" in phrase:
        # crypt(3) would stop at the NUL and hash only the part before it.
        raise ValueError("a password can't contain a NUL character")
    data = ctypes.create_string_buffer(_CRYPT_DATA_SIZE)
    try:
        result = _crypt_rn()(phrase, setting.encode("ascii"), data, _CRYPT_DATA_SIZE)
    finally:
        ctypes.memset(data, 0, _CRYPT_DATA_SIZE)
    if not result or result.startswith(b"*"):
        raise ValueError("crypt(3) refused the setting")
    return result.decode("ascii")


def make_hash(password: str) -> str:
    """A new {crypt}$6$ hash of PASSWORD, with a random salt."""
    salt = "".join(secrets.choice(SALT_ALPHABET) for _ in range(SALT_LENGTH))
    return PREFIX + crypt(password, f"$6${salt}$")


def check_hash(password: str, stored: str) -> bool:
    """Whether PASSWORD matches a stored {crypt}$6$ hash. Anything else never matches."""
    if not STORED_HASH.fullmatch(stored):
        return False
    hashed = stored.removeprefix(PREFIX)
    try:
        candidate = crypt(password, hashed)
    except ValueError:
        return False
    return hmac.compare_digest(candidate.encode(), hashed.encode())

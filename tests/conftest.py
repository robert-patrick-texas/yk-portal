import itertools
from collections.abc import Generator
from contextlib import contextmanager

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from yk_portal.accounts.models import AccountState, Role, User
from yk_portal.audit.service import Actor
from yk_portal.core.master_key import create_master_key
from yk_portal.yubikeys import modhex
from yk_portal.yubikeys.models import ProvisioningMethod, YubikeyCredential
from yk_portal.yubikeys.otp import OtpRejected, Rejection, crc16

_numbers = itertools.count(1)


@pytest.fixture
def actor() -> Actor:
    return Actor.cli()


@pytest.fixture(scope="session")
def master_key_path(tmp_path_factory) -> str:
    path = tmp_path_factory.mktemp("master-key") / "master.key"
    create_master_key(path)
    return str(path)


@pytest.fixture
def master_key(master_key_path, settings) -> str:
    """A master key for the test, for stored YubiKey secrets."""
    settings.YK_MASTER_KEY_PATH = master_key_path
    return master_key_path


@pytest.fixture
def make_user(db):
    """Make an account directly, without the services: fast, and without audit events.

    It has both password hashes (dummies) unless they are given.
    """

    def make(
        username: str = "",
        state: AccountState = AccountState.ACTIVE,
        admin: bool = False,
        **fields: object,
    ) -> User:
        fields.setdefault("password_hash", "argon2$dummy")
        fields.setdefault("radius_password_hash", "{crypt}$6$dummy")
        user = User.objects.create(
            username=username or f"user{next(_numbers)}", state=state, **fields
        )
        user.roles.add(*Role.objects.filter(name__in=[Role.USER, Role.ADMIN][: 1 + admin]))
        return user

    return make


# radiator-yubikey's test keys (tests/run-tests.sh, scenario_verify).
K1 = "6b1f0a9d2c7e4f3a8b5d0c1e9f2a7b6d"
K2 = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"

_public_ids = (f"vvcccccc{modhex.encode(n.to_bytes(2))}" for n in itertools.count(1))
_private_ids = (f"{n:012x}" for n in itertools.count(1))


def _make_otp(public_id: str, private_id: str, aes_key: str, counter: int, session: int = 0) -> str:
    """The OTP a YubiKey with these values types, built as radiator-yubikey's
    tests/make-otp.sh builds it: timestamp 0x003412, random 0xbeef."""
    token = (
        bytes.fromhex(private_id)
        + counter.to_bytes(2, "little")
        + bytes([0x12, 0x34, 0x00, session])
        + (0xBEEF).to_bytes(2, "little")
    )
    token += (~crc16(token) & 0xFFFF).to_bytes(2, "little")
    encryptor = Cipher(algorithms.AES128(bytes.fromhex(aes_key)), modes.ECB()).encryptor()  # noqa: S305
    return public_id + modhex.encode(encryptor.update(token) + encryptor.finalize())


@contextmanager
def _rejected(reason: Rejection) -> Generator[None]:
    with pytest.raises(OtpRejected) as excinfo:
        yield
    assert excinfo.value.reason == reason


@pytest.fixture
def rejected():
    """with rejected(Rejection.X): expect OtpRejected for reason X."""
    return _rejected


@pytest.fixture
def make_otp():
    return _make_otp


@pytest.fixture
def make_credential(master_key, make_user):
    """Make a credential directly, with its secrets encrypted under the test master key."""

    def make(
        user: User | None = None,
        public_id: str = "",
        private_id: str = "",
        aes_key: str = K1,
        **fields: object,
    ) -> YubikeyCredential:
        fields.setdefault("provisioning_method", ProvisioningMethod.ADMIN_PROVISIONED)
        credential = YubikeyCredential(
            user=user or make_user(), public_id=public_id or next(_public_ids), **fields
        )
        credential.set_secrets(
            bytes.fromhex(private_id or next(_private_ids)), bytes.fromhex(aes_key)
        )
        credential.save()
        return credential

    return make

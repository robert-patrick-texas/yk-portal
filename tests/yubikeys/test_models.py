import pytest
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction

from yk_portal.core.encryption import DecryptionError
from yk_portal.yubikeys.models import YubikeyCredential

pytestmark = pytest.mark.django_db

PRIVATE_ID = bytes.fromhex("4a6f8e2d1c3b")
AES_KEY = bytes.fromhex("6b1f0a9d2c7e4f3a8b5d0c1e9f2a7b6d")


def test_secrets_are_encrypted(make_credential):
    credential = make_credential(private_id=PRIVATE_ID.hex(), aes_key=AES_KEY.hex())
    stored = YubikeyCredential.objects.get(pk=credential.pk)
    assert stored.private_id() == PRIVATE_ID
    assert stored.aes_key() == AES_KEY
    assert PRIVATE_ID not in bytes(stored.encrypted_private_id)
    assert AES_KEY not in bytes(stored.encrypted_aes_secret)


def test_secrets_are_bound_to_their_column(make_credential):
    credential = make_credential()
    credential.encrypted_aes_secret = credential.encrypted_private_id
    with pytest.raises(DecryptionError):
        credential.aes_key()


def test_secrets_are_bound_to_their_row(make_credential):
    one, other = make_credential(), make_credential()
    other.encrypted_aes_secret = one.encrypted_aes_secret
    with pytest.raises(DecryptionError):
        other.aes_key()


@pytest.mark.parametrize(("private_id", "aes_key"), [(bytes(5), AES_KEY), (PRIVATE_ID, bytes(32))])
def test_secret_lengths(master_key, private_id, aes_key):
    with pytest.raises(ValueError, match="6 bytes"):
        YubikeyCredential().set_secrets(private_id, aes_key)


@pytest.mark.parametrize(
    "fields",
    [
        {"slot_number": 3},
        {"slot_number": 0},
        {"last_usage_counter": 0x8000},
        {"last_session_counter": 256},
        {"provisioning_method": "BORROWED"},
    ],
    ids=lambda f: next(iter(f)),
)
def test_database_constraints(make_credential, fields):
    with pytest.raises(IntegrityError), transaction.atomic():
        make_credential(**fields)


def test_public_ids_are_unique_across_users(make_credential):
    make_credential(public_id="vvccccbbcdef")
    with pytest.raises(IntegrityError), transaction.atomic():
        make_credential(public_id="vvccccbbcdef")


def test_slot_may_be_unknown(make_credential):
    assert make_credential(slot_number=None).slot_number is None
    assert make_credential(slot_number=2).slot_number == 2


@pytest.mark.parametrize(
    ("fields", "field"),
    [
        ({"public_id": "vvccccbbcde"}, "public_id"),
        ({"public_id": "VVCCCCBBCDEF"}, "public_id"),
        ({"public_id": "vvccccbbcdea"}, "public_id"),
        ({"label": "spare\tslot 2"}, "label"),
        ({"label": "x" * 256}, "label"),
    ],
)
def test_field_rules(make_credential, fields, field):
    credential = make_credential()
    for name, value in fields.items():
        setattr(credential, name, value)
    with pytest.raises(ValidationError) as excinfo:
        credential.full_clean()
    assert list(excinfo.value.message_dict) == [field]


def test_a_label_may_be_any_text(make_credential):
    credential = make_credential(label="Ersatz, Schlüssel 2 🔑")
    credential.full_clean()


def test_deleting_a_user_deletes_its_credentials(make_credential):
    credential = make_credential()
    credential.user.delete()
    assert not YubikeyCredential.objects.exists()

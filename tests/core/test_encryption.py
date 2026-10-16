import pytest

from yk_portal.core.encryption import DecryptionError, SecretBox, secret_box
from yk_portal.core.master_key import create_master_key, derive_keys

CONTEXT = "yubikey_credentials.aes_secret:0b7c7a54-0000-4000-8000-000000000001"
SECRET = bytes.fromhex("0123456789abcdef0123456789abcdef")


@pytest.fixture
def box() -> SecretBox:
    keys = derive_keys(bytes(range(32)))
    return SecretBox(keys.secrets, keys.key_id)


def test_round_trip(box):
    assert box.decrypt(box.encrypt(SECRET, CONTEXT), CONTEXT) == SECRET


def test_layout_and_fresh_nonce(box):
    a, b = box.encrypt(SECRET, CONTEXT), box.encrypt(SECRET, CONTEXT)
    assert a != b
    assert a[0] == 1 and a[1:9] == box.key_id
    assert a[9:21] != b[9:21]  # nonces differ
    assert len(a) == 1 + 8 + 12 + len(SECRET) + 16
    assert SECRET not in a


def test_value_moved_to_another_row_fails(box):
    blob = box.encrypt(SECRET, CONTEXT)
    with pytest.raises(DecryptionError, match="authentication failed"):
        box.decrypt(blob, CONTEXT.replace("0001", "0002"))


@pytest.mark.parametrize("position", [0 + 9, 9 + 5, 21, -1])  # nonce, ciphertext, tag
def test_tampering_fails(box, position):
    blob = bytearray(box.encrypt(SECRET, CONTEXT))
    blob[position] ^= 0x01
    with pytest.raises(DecryptionError):
        box.decrypt(bytes(blob), CONTEXT)


def test_other_master_key_is_named(box):
    other_keys = derive_keys(bytes(32))
    other = SecretBox(other_keys.secrets, other_keys.key_id)
    with pytest.raises(DecryptionError, match="different master key"):
        box.decrypt(other.encrypt(SECRET, CONTEXT), CONTEXT)


@pytest.mark.parametrize("blob", [b"", b"\x02" + bytes(40), b"\x01" + bytes(10)])
def test_unknown_or_short_values_fail(box, blob):
    with pytest.raises(DecryptionError, match="known version"):
        box.decrypt(blob, CONTEXT)


def test_error_messages_never_contain_the_secret(box):
    blob = bytearray(box.encrypt(SECRET, CONTEXT))
    blob[-1] ^= 0x01
    with pytest.raises(DecryptionError) as excinfo:
        box.decrypt(bytes(blob), CONTEXT)
    assert SECRET.hex() not in str(excinfo.value)


def test_context_is_required(box):
    with pytest.raises(ValueError, match="context"):
        box.encrypt(SECRET, "")


def test_repr_shows_only_the_key_id(box):
    assert repr(box) == f"SecretBox(key_id={box.key_id.hex()})"


def test_secret_box_uses_the_configured_master_key(tmp_path, settings):
    path = tmp_path / "master.key"
    create_master_key(path)
    settings.YK_MASTER_KEY_PATH = str(path)
    box = secret_box()
    assert box is secret_box()
    assert box.decrypt(box.encrypt(SECRET, CONTEXT), CONTEXT) == SECRET

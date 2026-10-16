import os
import stat

import pytest

from yk_portal.core.master_key import (
    MasterKeyError,
    create_master_key,
    derive_keys,
    load_master_key,
)


def test_create_writes_64_hex_characters_at_mode_0600(tmp_path):
    path = tmp_path / "master.key"
    old_umask = os.umask(0)  # the mode must not depend on the umask
    try:
        create_master_key(path)
    finally:
        os.umask(old_umask)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    text = path.read_text()
    assert len(text) == 65 and text.endswith("\n")
    assert len(load_master_key(path)) == 32


def test_create_never_replaces_a_file(tmp_path):
    path = tmp_path / "master.key"
    path.write_text("keep me")
    with pytest.raises(MasterKeyError, match="already exists"):
        create_master_key(path)
    assert path.read_text() == "keep me"


def test_create_refuses_to_follow_a_symlink(tmp_path):
    target = tmp_path / "elsewhere"
    link = tmp_path / "master.key"
    link.symlink_to(target)
    with pytest.raises(MasterKeyError, match="already exists"):
        create_master_key(link)
    assert not target.exists()


def test_each_key_is_new(tmp_path):
    create_master_key(tmp_path / "a")
    create_master_key(tmp_path / "b")
    assert load_master_key(tmp_path / "a") != load_master_key(tmp_path / "b")


def test_load_refuses_group_or_other_access(tmp_path):
    path = tmp_path / "master.key"
    create_master_key(path)
    path.chmod(0o640)
    with pytest.raises(MasterKeyError, match=r"mode 0640\); run: chmod 600"):
        load_master_key(path)


@pytest.mark.parametrize(
    "content",
    [b"", b"00" * 31 + b"\n", b"00" * 33 + b"\n", b"AB" * 32 + b"\n", b"zz" * 32, b"\xff" * 64],
)
def test_load_refuses_malformed_keys_without_showing_them(tmp_path, content):
    path = tmp_path / "master.key"
    path.write_bytes(content)
    path.chmod(0o600)
    with pytest.raises(MasterKeyError, match="not a master key") as excinfo:
        load_master_key(path)
    if content:
        assert content.decode("latin-1") not in str(excinfo.value)


def test_load_missing_file_says_how_to_create_it(tmp_path):
    with pytest.raises(MasterKeyError, match="yk-portal master-key-create"):
        load_master_key(tmp_path / "absent.key")


def test_load_refuses_a_directory(tmp_path):
    path = tmp_path / "dir.key"
    path.mkdir(mode=0o700)
    with pytest.raises(MasterKeyError, match="not a regular file"):
        load_master_key(path)


def test_derived_keys_are_distinct_and_repeatable():
    master = bytes(range(32))
    keys = derive_keys(master)
    assert keys == derive_keys(master)
    assert len(keys.key_id) == 8
    assert len({keys.secrets, keys.backup, bytes.fromhex(keys.django_secret_key)}) == 3
    assert master not in (keys.secrets, keys.backup)
    assert derive_keys(bytes(32)).secrets != keys.secrets


def test_derived_keys_repr_hides_the_keys():
    keys = derive_keys(bytes(range(32)))
    text = repr(keys)
    assert keys.secrets.hex() not in text and repr(keys.secrets) not in text
    assert keys.django_secret_key not in text


def test_derive_needs_32_bytes():
    with pytest.raises(ValueError, match="32 bytes"):
        derive_keys(bytes(16))

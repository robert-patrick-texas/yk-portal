import os
import stat
from datetime import UTC, datetime
from io import StringIO

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError

from yk_portal.accounts.models import AccountState
from yk_portal.audit.models import AuditEvent, EventType
from yk_portal.radiator import csvfile
from yk_portal.yubikeys.models import YubikeyCredential

pytestmark = [pytest.mark.django_db, pytest.mark.usefixtures("master_key")]

K1 = "6b1f0a9d2c7e4f3a8b5d0c1e9f2a7b6d"
HASH = "{crypt}$6$abcdefghijklmnop$" + "x" * 86
CREATED = datetime(2026, 1, 2, 3, 4, 5, 678, tzinfo=UTC)
USED = datetime(2026, 10, 16, 9, 0, 1, tzinfo=UTC)


def export(*args: str) -> tuple[str, str]:
    """Run radiator-export; its standard output and standard error."""
    out, err = StringIO(), StringIO()
    call_command("radiator-export", *args, stdout=out, stderr=err)
    return out.getvalue(), err.getvalue()


def lines(text: str) -> list[str]:
    assert text.endswith("\n") and "\r" not in text
    return text.removesuffix("\n").split("\n")


def make_key(make_user, make_credential, username, state=AccountState.ACTIVE, **fields):
    user = make_user(username, state=state)
    credential = make_credential(user, radius_pin_hash=HASH, **fields)
    YubikeyCredential.objects.filter(pk=credential.pk).update(created_at=CREATED)
    return credential


def test_export_rows(make_user, make_credential):
    key = make_key(
        make_user,
        make_credential,
        "alice",
        public_id="vvccccbbcdef",
        private_id="4a6f8e2d1c3b",
        aes_key=K1,
        label='spare, "slot 2"',
        last_usage_counter=12,
        last_session_counter=3,
        last_used_at=USED,
    )
    out, _ = export("-")
    assert lines(out) == [
        csvfile.HEADER,
        f"alice,vvccccbbcdef,4a6f8e2d1c3b,{K1},{HASH},1,2026-01-02 03:04:05,2026-10-16 09:00:01,"
        '12,3,0,"spare, ""slot 2"""',
    ]
    assert key.public_id in out


def test_only_an_active_accounts_enabled_keys_are_active(make_user, make_credential):
    for username, state in [
        ("a-active", AccountState.ACTIVE),
        ("b-provisioning", AccountState.PROVISIONING),
        ("c-locked", AccountState.LOCKED),
        ("d-disabled", AccountState.DISABLED),
    ]:
        make_key(make_user, make_credential, username, state)
    make_key(make_user, make_credential, "e-key-disabled", enabled=False)
    make_key(make_user, make_credential, "f-both", AccountState.LOCKED, enabled=False)
    out, err = export("-")
    assert [row.split(",")[5] for row in lines(out)[1:]] == ["1", "0", "0", "0", "0", "0"]
    public_ids = [row.split(",")[1] for row in lines(out)[1:]]
    assert lines(err) == [
        "Exported 6 YubiKeys to standard output, 5 inactive:",
        f"  b-provisioning {public_ids[1]}: account PROVISIONING",
        f"  c-locked {public_ids[2]}: account LOCKED",
        f"  d-disabled {public_ids[3]}: account DISABLED",
        f"  e-key-disabled {public_ids[4]}: YubiKey disabled",
        f"  f-both {public_ids[5]}: account LOCKED, YubiKey disabled",
    ]


def test_rows_are_ordered_by_username_and_public_id(make_user, make_credential):
    bob = make_user("bob")
    alice = make_user("alice")
    make_credential(bob, public_id="vvcccccccccb")
    make_credential(alice, public_id="vvcccccccccd")
    make_credential(alice, public_id="vvcccccccccc")
    out, _ = export("-")
    assert [row.split(",")[:2] for row in lines(out)[1:]] == [
        ["alice", "vvcccccccccc"],
        ["alice", "vvcccccccccd"],
        ["bob", "vvcccccccccb"],
    ]


def test_each_key_has_its_own_pin_or_an_empty_password(make_user, make_credential):
    alice = make_user("alice")
    make_credential(alice, public_id="vvcccccccccb", radius_pin_hash=HASH)
    make_credential(alice, public_id="vvcccccccccc", radius_pin_hash="{crypt}$6$other")
    make_credential(alice, public_id="vvcccccccccd", pin_hash="", radius_pin_hash="")
    out, _ = export("-")
    assert [row.split(",")[4] for row in lines(out)[1:]] == [HASH, "{crypt}$6$other", ""]


def test_accounts_without_keys_have_no_rows(make_user):
    make_user("alice")
    out, err = export("-")
    assert out == csvfile.HEADER + "\n"
    assert err == "Exported 0 YubiKeys to standard output.\n"


def test_export_to_a_file(tmp_path, make_user, make_credential, monkeypatch):
    make_key(make_user, make_credential, "alice")
    monkeypatch.chdir(tmp_path)
    umask = os.umask(0)  # even so, only the owner may read it
    try:
        out, err = export("radiator.csv")
    finally:
        os.umask(umask)
    path = tmp_path / "radiator.csv"
    assert out == ""
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert lines(path.read_text())[0] == csvfile.HEADER
    assert lines(err) == [
        "Exported 1 YubiKey to radiator.csv (mode 0600).",
        "It holds AES keys and private IDs in clear text: shred -u radiator.csv",
    ]
    assert list(tmp_path.iterdir()) == [path]
    event = AuditEvent.objects.get()
    assert event.event_type == EventType.RADIATOR_EXPORT_CREATED
    assert event.details == {"rows": 1, "inactive": 0, "destination": str(path)}
    assert event.actor_username_snapshot.startswith("cli:")


def test_an_existing_file_is_replaced_only_with_force(tmp_path, make_user, make_credential):
    make_key(make_user, make_credential, "alice")
    path = tmp_path / "radiator.csv"
    path.write_text("old")
    path.chmod(0o644)
    with pytest.raises(CommandError, match="already exists \\(use --force"):
        export(str(path))
    assert path.read_text() == "old"
    assert not AuditEvent.objects.exists()
    export("--force", str(path))
    assert lines(path.read_text())[0] == csvfile.HEADER
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert list(tmp_path.iterdir()) == [path]


def test_a_dangling_symlink_counts_as_existing(tmp_path):
    (tmp_path / "radiator.csv").symlink_to(tmp_path / "elsewhere")
    with pytest.raises(CommandError, match="already exists"):
        export(str(tmp_path / "radiator.csv"))
    assert not (tmp_path / "elsewhere").exists()


@pytest.mark.parametrize(
    ("name", "message"), [(".", "is a directory"), ("no/such.csv", "cannot write")]
)
def test_export_errors(tmp_path, name, message):
    with pytest.raises(CommandError, match=message):
        export(str(tmp_path / name))
    assert not AuditEvent.objects.exists()


def test_a_secret_that_cant_be_decrypted_stops_the_export(tmp_path, make_user, make_credential):
    credential = make_key(make_user, make_credential, "alice")
    other = make_credential()
    YubikeyCredential.objects.filter(pk=credential.pk).update(
        encrypted_aes_secret=other.encrypted_aes_secret
    )
    with pytest.raises(
        CommandError, match=f"alice {credential.public_id}: secrets can't be decrypted"
    ):
        export(str(tmp_path / "radiator.csv"))
    assert list(tmp_path.iterdir()) == []
    assert not AuditEvent.objects.exists()

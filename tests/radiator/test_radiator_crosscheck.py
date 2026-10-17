"""The export and the importer, cross-checked with radiator-yubikey, which is run but
never changed (addendum §6, §7).

radiator-yubikey must load yk-portal's export as it is, and give it back
unchanged; yk-portal must import radiator-yubikey's export, with its PINs and
counters. The checkout is ../radiator-yubikey, or $YK_PORTAL_RADIATOR_YUBIKEY;
the tests are skipped without it, sqlite3, openssl or Perl's Crypt::Rijndael.
"""

import os
import shutil
import subprocess
from io import StringIO
from pathlib import Path

import pytest
from django.core.management import call_command

from yk_portal.accounts.models import AccountState, User
from yk_portal.core import sha512_crypt
from yk_portal.yubikeys import management
from yk_portal.yubikeys.models import ProvisioningMethod, YubikeyCredential
from yk_portal.yubikeys.otp import OtpRejected, Rejection, parse_otp
from yk_portal.yubikeys.service import accept_otp

REPO = Path(__file__).resolve().parents[2]
RADIATOR = Path(os.environ.get("YK_PORTAL_RADIATOR_YUBIKEY", REPO.parent / "radiator-yubikey"))

K1 = "6b1f0a9d2c7e4f3a8b5d0c1e9f2a7b6d"
K2 = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
PIN = "Passw0rd!"  # noqa: S105 - a test password
ALICES_OTHER_PIN = "0ther-pin2"  # noqa: S105 - a test password
BOBS_PIN = "Bobs-pin-9"  # noqa: S105 - a test password
KEYS = {
    # public ID: (private ID, AES key)
    "vvccccbbcdef": ("4a6f8e2d1c3b", K1),
    "vvccccbbcdeg": ("4a6f8e2d1c3c", K2),
    "vvccccbbcdeh": ("4a6f8e2d1c3d", K1),
    "vvccccbbcdei": ("4a6f8e2d1c3e", K2),
}
PUB1, PUB2, PUB3, PUB4 = KEYS


def _missing() -> str | None:
    if not (RADIATOR / "yubikey-db.sh").is_file():
        return f"no radiator-yubikey checkout at {RADIATOR}"
    for tool in ("sqlite3", "openssl", "perl"):
        if not shutil.which(tool):
            return f"{tool} is not installed"
    if subprocess.run(["perl", "-MCrypt::Rijndael", "-e", "1"], capture_output=True).returncode:
        return "Perl's Crypt::Rijndael is not installed (libcrypt-rijndael-perl)"
    return None


pytestmark = [
    pytest.mark.skipif(_missing() is not None, reason=_missing() or ""),
    pytest.mark.django_db,
    pytest.mark.usefixtures("master_key"),
]


def otp(public_id: str, counter: int, session: int) -> str:
    """radiator-yubikey's tests/make-otp.sh, for one of KEYS."""
    private_id, aes_key = KEYS[public_id]
    result = subprocess.run(
        [
            RADIATOR / "tests" / "make-otp.sh",
            public_id,
            private_id,
            aes_key,
            str(counter),
            str(session),
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


class Radiator:
    """A throwaway radiator-yubikey SQLite database."""

    def __init__(self, path: Path) -> None:
        self.db = path
        self.run("init")

    def run(
        self, *args: str, stdin: str = "", check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [RADIATOR / "yubikey-db.sh", "-d", str(self.db), *args],
            input=stdin,
            capture_output=True,
            text=True,
            check=check,
        )

    def add(self, username: str, public_id: str, *options: str) -> None:
        private_id, aes_key = KEYS[public_id]
        self.run("add", "-u", username, "-P", public_id, "-p", private_id, "-k", aes_key, *options)

    def verify(
        self, username: str, public_id: str, counter: int, session: int, pin: str = PIN
    ) -> str:
        """ "accepted" if `verify` accepts PIN and the OTP, else its message."""
        result = self.run(
            "verify",
            "-u",
            username,
            stdin=f"{pin}\n{otp(public_id, counter, session)}\n",
            check=False,
        )
        return "accepted" if result.returncode == 0 else result.stderr.strip().splitlines()[-1]

    def export(self) -> str:
        return self.run("export", "-").stdout


def yk_portal_export(path: Path) -> str:
    call_command("radiator-export", str(path), stderr=StringIO())
    return path.read_text()


def yk_portal_import(path: Path, *args: str) -> list[str]:
    out = StringIO()
    call_command("radiator-import", *args, str(path), stdout=out)
    return out.getvalue().splitlines()


def yk_portal_accepts(public_id: str, counter: int, session: int) -> Rejection | None:
    credential = YubikeyCredential.objects.get(public_id=public_id)
    try:
        accept_otp(credential, parse_otp(otp(public_id, counter, session)))
    except OtpRejected as e:
        return e.reason
    return None


def add_key(user: User, public_id: str, **fields: object) -> YubikeyCredential:
    private_id, aes_key = KEYS[public_id]
    credential = YubikeyCredential(
        user=user,
        public_id=public_id,
        provisioning_method=ProvisioningMethod.ADMIN_PROVISIONED,
        **fields,
    )
    credential.set_secrets(bytes.fromhex(private_id), bytes.fromhex(aes_key))
    credential.save()
    return credential


def test_radiator_yubikey_loads_the_export_as_it_is(tmp_path, actor, make_user):
    alice = make_user("alice")
    first = add_key(
        alice, PUB1, label='spare, "slot 2"', last_usage_counter=5, last_session_counter=2
    )
    second = add_key(alice, PUB2)
    management.set_pin(alice, [first], PIN, actor)
    management.set_pin(alice, [second], ALICES_OTHER_PIN, actor)
    bob = make_user("bob", state=AccountState.LOCKED)
    management.set_pin(bob, [add_key(bob, PUB3)], PIN, actor)
    add_key(make_user("carol"), PUB4)  # no PIN
    exported = yk_portal_export(tmp_path / "yk-portal.csv")

    radiator = Radiator(tmp_path / "yubikeys.db")
    dry_run = radiator.run("import", "--from-export", "--dry-run", str(tmp_path / "yk-portal.csv"))
    assert "4 valid row(s), 0 invalid row(s)" in dry_run.stdout
    radiator.run("import", "--from-export", "--replace", str(tmp_path / "yk-portal.csv"))
    assert radiator.export() == exported

    # Each YubiKey's PIN, the counters and active=0 work in Radiator's check.
    assert radiator.verify("alice", PUB1, 5, 2).endswith("(replayed OTP)")
    assert radiator.verify("alice", PUB1, 5, 3) == "accepted"
    assert radiator.verify("alice", PUB2, 1, 0) != "accepted"  # PIN is PUB1's
    assert radiator.verify("alice", PUB2, 1, 0, ALICES_OTHER_PIN) == "accepted"
    assert "disabled" in radiator.verify("bob", PUB3, 1, 0)
    assert radiator.verify("carol", PUB4, 1, 0) != "accepted"


def test_yk_portal_imports_radiator_yubikeys_export(tmp_path):
    radiator = Radiator(tmp_path / "yubikeys.db")
    radiator.add("alice", PUB1, "-w", PIN, "-l", "spare, slot 2")
    radiator.add("alice", PUB2, "-w", ALICES_OTHER_PIN, "--inactive")
    radiator.add("bob", PUB3, "-w", BOBS_PIN)
    radiator.add("anycast-check1", PUB4, "-w", "x")
    assert radiator.verify("alice", PUB1, 7, 1) == "accepted"
    (tmp_path / "radiator.csv").write_text(radiator.export())

    output = yk_portal_import(tmp_path / "radiator.csv", "--skip-invalid")
    assert output == [
        f"line 2: alice {PUB1}: added, new account",
        f"line 3: alice {PUB2}: added, disabled",
        f"line 4: anycast-check1 {PUB4}: skipped: reserved username",
        f"line 5: bob {PUB3}: added, new account",
        "4 rows: 2 accounts created, 3 added, 1 skipped.",
    ]
    assert User.objects.get(username="alice").state == AccountState.ACTIVE
    first = YubikeyCredential.objects.get(public_id=PUB1)
    assert (first.label, first.slot_number, first.enabled) == ("spare, slot 2", 2, True)
    assert (first.last_usage_counter, first.last_session_counter) == (7, 1)
    assert first.last_used_at is not None
    assert sha512_crypt.check_hash(PIN, first.radius_pin_hash)
    second = YubikeyCredential.objects.get(public_id=PUB2)
    assert not second.enabled
    assert sha512_crypt.check_hash(ALICES_OTHER_PIN, second.radius_pin_hash)

    # The OTP Radiator accepted is used up in yk-portal too; the next one works.
    assert yk_portal_accepts(PUB1, 7, 1) == Rejection.REPLAYED
    assert yk_portal_accepts(PUB1, 7, 2) is None

    # Counter sync: bob signs in through Radiator.
    assert radiator.verify("bob", PUB3, 3, 0, BOBS_PIN) == "accepted"
    (tmp_path / "radiator.csv").write_text(radiator.export())
    output = yk_portal_import(tmp_path / "radiator.csv", "--counters-only")
    assert output[3].startswith(f"line 5: bob {PUB3}: counters 0/0 -> 3/0")
    assert output[0] == f"line 2: alice {PUB1}: unchanged"
    assert yk_portal_accepts(PUB3, 3, 0) == Rejection.REPLAYED

    # What yk-portal imported loads back into Radiator; bob's key with its new counters.
    yk_portal_export(tmp_path / "yk-portal.csv")
    radiator.run("import", "--from-export", "--replace", str(tmp_path / "yk-portal.csv"))
    assert radiator.verify("bob", PUB3, 3, 0, BOBS_PIN).endswith("(replayed OTP)")
    assert radiator.verify("alice", PUB1, 7, 2).endswith("(replayed OTP)")  # used in yk-portal
    assert radiator.verify("alice", PUB1, 7, 3) == "accepted"

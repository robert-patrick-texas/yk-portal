"""Cross-checks with radiator-yubikey, which is run but never changed (addendum §8.2).

OTPs made with its tests/make-otp.sh must get the same verdict, for the same
reason, and leave the same stored counters in yk-portal as `yubikey-db.sh
verify` gives and leaves in a radiator-yubikey database. The checkout is
../radiator-yubikey, or $YK_PORTAL_RADIATOR_YUBIKEY; the tests are skipped
without it, sqlite3, openssl or Perl's Crypt::Rijndael.
"""

import os
import random
import shutil
import sqlite3
import subprocess
from pathlib import Path

import pytest

from yk_portal.yubikeys.models import YubikeyCredential
from yk_portal.yubikeys.otp import OtpRejected, Rejection, parse_otp
from yk_portal.yubikeys.service import accept_otp

REPO = Path(__file__).resolve().parents[2]
RADIATOR = Path(os.environ.get("YK_PORTAL_RADIATOR_YUBIKEY", REPO.parent / "radiator-yubikey"))

PUBLIC_ID = "vvccccbbcdef"
PRIVATE_ID = "4a6f8e2d1c3b"
K1 = "6b1f0a9d2c7e4f3a8b5d0c1e9f2a7b6d"
K2 = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
PASSWORD = "s3cr3t"  # noqa: S105 - radiator-yubikey's test password

# yubikey-db.sh verify's reasons, as yk-portal names them.
REASONS = {
    "replayed OTP": Rejection.REPLAYED,
    "OTP": Rejection.BAD_CRC,
    "private ID": Rejection.PRIVATE_ID_MISMATCH,
}


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
]


def make_otp_sh(private_id: str, aes_key: str, counter: int, session: int) -> str:
    """radiator-yubikey's tests/make-otp.sh."""
    result = subprocess.run(
        [
            RADIATOR / "tests" / "make-otp.sh",
            PUBLIC_ID,
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
    """A throwaway radiator-yubikey SQLite database holding alice's YubiKey."""

    def __init__(self, path: Path) -> None:
        self.db = path
        self.run("init")
        self.run("add", "-u", "alice", "-P", PUBLIC_ID, "-p", PRIVATE_ID, "-k", K1, "-w", PASSWORD)

    def run(self, *args: str, stdin: str = "") -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [RADIATOR / "yubikey-db.sh", "-d", str(self.db), *args],
            input=stdin,
            capture_output=True,
            text=True,
            check=args[0] != "verify",
        )

    def verify(self, otp: str) -> Rejection | None:
        """None if `verify` accepts OTP, else its reason."""
        result = self.run("verify", "-u", "alice", stdin=f"{PASSWORD}\n{otp}\n")
        if result.returncode == 0:
            return None
        reason = result.stderr.strip().rpartition("rejected (")[2].removesuffix(")")
        return REASONS[reason]

    def counters(self) -> tuple[int, int]:
        with sqlite3.connect(self.db) as db:
            return db.execute(
                "SELECT counter, low FROM yubikeys WHERE tokenId = ?", (PUBLIC_ID,)
            ).fetchone()


def yk_portal_verify(credential: YubikeyCredential, otp: str) -> Rejection | None:
    try:
        accept_otp(credential, parse_otp(otp))
    except OtpRejected as e:
        return e.reason
    return None


def counters(credential: YubikeyCredential) -> tuple[int, int]:
    stored = YubikeyCredential.objects.get(pk=credential.pk)
    return stored.last_usage_counter, stored.last_session_counter


@pytest.mark.parametrize(
    ("private_id", "aes_key", "counter", "session"),
    [(PRIVATE_ID, K1, 3, 1), (PRIVATE_ID, K2, 0, 0), ("ffffffffffff", K1, 0xFFFF, 255)],
)
def test_test_otps_match_make_otp_sh(make_otp, private_id, aes_key, counter, session):
    assert make_otp(PUBLIC_ID, private_id, aes_key, counter, session) == make_otp_sh(
        private_id, aes_key, counter, session
    )


def run_both(tmp_path, make_credential, steps) -> None:
    radiator = Radiator(tmp_path / "yubikeys.db")
    credential = make_credential(public_id=PUBLIC_ID, private_id=PRIVATE_ID, aes_key=K1)
    for private_id, aes_key, counter, session in steps:
        otp = make_otp_sh(private_id, aes_key, counter, session)
        step = f"OTP counter {counter}, session {session}"
        assert yk_portal_verify(credential, otp) == radiator.verify(otp), step
        assert counters(credential) == radiator.counters(), step


def test_same_verdicts_and_counters(tmp_path, make_credential):
    run_both(
        tmp_path,
        make_credential,
        [
            (PRIVATE_ID, K1, 3, 1),  # accepted
            (PRIVATE_ID, K1, 3, 1),  # the same OTP again
            (PRIVATE_ID, K1, 2, 9),  # an older session
            (PRIVATE_ID, K1, 3, 2),  # next in the session
            (PRIVATE_ID, K2, 9, 0),  # wrong AES key
            ("111111111111", K1, 9, 0),  # wrong private ID
            (PRIVATE_ID, K1, 0x8005, 0),  # counter 5: the top bit is ignored
            (PRIVATE_ID, K1, 5, 0),
            (PRIVATE_ID, K1, 5, 255),
            (PRIVATE_ID, K1, 0x7FFF, 0),
            (PRIVATE_ID, K1, 0xFFFF, 255),  # 0x7fff, 255
            (PRIVATE_ID, K1, 0x8000, 0),  # counter 0
        ],
    )


def test_same_verdicts_and_counters_for_random_otps(tmp_path, make_credential):
    """A YubiKey's OTPs in order, with some typed again and some older ones replayed."""
    rng = random.Random(1)  # noqa: S311 - test data, not secrets
    made: list[tuple[int, int]] = []
    counter, session = 1, 0
    steps, kinds = [], set()
    for _ in range(16):
        draw = rng.random()
        if made and draw < 0.25:
            counter_session = made[-1]
            kinds.add("again")
        elif made and draw < 0.5:
            counter_session = rng.choice(made)
            kinds.add("older")
        else:
            if rng.random() < 0.3:
                counter, session = counter + 1, 0
            else:
                session += 1
            counter_session = (counter, session)
            made.append(counter_session)
        top_bit = rng.choice((0, 0x8000))
        steps.append((PRIVATE_ID, K1, counter_session[0] | top_bit, counter_session[1]))
    assert kinds == {"again", "older"}  # the seed gives both kinds of replay
    run_both(tmp_path, make_credential, steps)

"""The YubiKey step of onboarding, which completes it (spec §13.2, §14).

The user either adds a YubiKey and proves it with an OTP, or, when an admin
pre-provisioned one, tests it with an OTP (addendum §13 item 12). Either way
the account becomes ACTIVE in the same transaction, so a refused completion
leaves no YubiKey added and no OTP used.
"""

from django.db import transaction

from yk_portal.audit.service import Actor
from yk_portal.yubikeys.management import NewYubikey, add_yubikey, check_yubikey
from yk_portal.yubikeys.models import ProvisioningMethod, YubikeyCredential

from .models import User
from .services import check_ready_to_finish, complete_provisioning


def needs_new_yubikey(user: User) -> bool:
    """Whether the user adds a YubiKey, rather than testing an enabled one."""
    return not YubikeyCredential.objects.filter(user=user, enabled=True).exists()


def finish_with_new_yubikey(user: User, key: NewYubikey, test_otp: str, actor: Actor) -> None:
    """Add the user's first YubiKey, proven by TEST_OTP, and complete onboarding.

    Raises:
        ValidationError: The email address or password is missing, or add_yubikey refuses.
    """
    check_ready_to_finish(user)
    with transaction.atomic():
        add_yubikey(user, actor, key, ProvisioningMethod.SELF_PROVISIONED, test_otp)
        complete_provisioning(user, actor)


def finish_with_otp(user: User, otp_text: str, actor: Actor) -> YubikeyCredential:
    """Test one of the user's enabled YubiKeys with an OTP and complete onboarding.

    Raises:
        ValidationError: The email address or password is missing.
        OtpRejected: The OTP isn't good; nothing counts toward lockout.
    """
    check_ready_to_finish(user)
    with transaction.atomic():
        credential = check_yubikey(user, otp_text)
        complete_provisioning(user, actor)
    return credential

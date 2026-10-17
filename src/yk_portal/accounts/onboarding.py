"""The YubiKey step of onboarding, which completes it (spec §13.2, §14).

The user either adds a YubiKey and proves it with an OTP, or, when an admin
pre-provisioned one, tests it with an OTP (addendum §13 item 12), and sets
its PIN (addendum §2.2). Either way the account becomes ACTIVE in the same
transaction, so a refused completion leaves no YubiKey added and no OTP used.
"""

from django.db import transaction

from yk_portal.audit.service import Actor
from yk_portal.authentication.passwords import hash_pin, validate_pin
from yk_portal.yubikeys.management import NewYubikey, add_yubikey, check_yubikey, set_pin
from yk_portal.yubikeys.models import ProvisioningMethod, YubikeyCredential

from .models import User
from .services import check_ready_to_finish, complete_provisioning


def needs_new_yubikey(user: User) -> bool:
    """Whether the user adds a YubiKey, rather than testing an enabled one."""
    return not YubikeyCredential.objects.filter(user=user, enabled=True).exists()


def finish_with_new_yubikey(
    user: User, key: NewYubikey, test_otp: str, pin: str, actor: Actor
) -> None:
    """Add the user's first YubiKey with its PIN, proven by TEST_OTP, and complete
    onboarding.

    Raises:
        ValidationError: The email address is missing, the PIN breaks the policy, or
            add_yubikey refuses.
    """
    check_ready_to_finish(user)
    validate_pin(pin)
    hashes = hash_pin(pin)
    with transaction.atomic():
        add_yubikey(user, actor, key, ProvisioningMethod.SELF_PROVISIONED, test_otp, hashes)
        complete_provisioning(user, actor)


def finish_with_otp(user: User, otp_text: str, pin: str, actor: Actor) -> YubikeyCredential:
    """Test one of the user's enabled YubiKeys with an OTP, set its PIN, and complete
    onboarding.

    Raises:
        ValidationError: The email address is missing, or the PIN breaks the policy.
        OtpRejected: The OTP isn't good; nothing counts toward lockout.
    """
    check_ready_to_finish(user)
    validate_pin(pin)
    with transaction.atomic():
        credential = check_yubikey(user, otp_text)
        set_pin(user, [credential], pin, actor)
        complete_provisioning(user, actor)
    return credential

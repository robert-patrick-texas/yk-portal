"""Checking an OTP against a user's YubiKey credential (spec §16 steps 7-18, §17).

The login (spec Phase 4) calls find_credential, checks the password, then
calls accept_otp. Each refusal raises OtpRejected with its reason. A stored
secret that can't be decrypted raises DecryptionError: a fault on the server,
not a wrong OTP.
"""

import hmac

from django.db.models import Q
from django.utils import timezone

from yk_portal.accounts.models import User

from .models import YubikeyCredential
from .otp import Otp, OtpRejected, Rejection, Token, decrypt_token, is_newer


def find_credential(user: User, public_id: str) -> YubikeyCredential:
    """The enabled credential of USER with PUBLIC_ID.

    Raises:
        OtpRejected: No credential has that public ID (UNKNOWN_KEY), another user's
            does (OTHER_USERS_KEY), or it is disabled (DISABLED_KEY).
    """
    credential = YubikeyCredential.objects.filter(public_id=public_id, user=user).first()
    if credential is None:
        if YubikeyCredential.objects.filter(public_id=public_id).exists():
            raise OtpRejected(Rejection.OTHER_USERS_KEY)
        raise OtpRejected(Rejection.UNKNOWN_KEY)
    if not credential.enabled:
        raise OtpRejected(Rejection.DISABLED_KEY)
    return credential


def accept_otp(credential: YubikeyCredential, otp: Otp) -> Token:
    """Check OTP against CREDENTIAL and, if it is good, save its counters (spec §17).

    The token must decrypt with a valid CRC, carry the credential's private ID and
    be newer than the last accepted OTP. The counters are then saved by an UPDATE
    that applies only while they are still behind, so of two logins with the same
    OTP at once, exactly one succeeds. CREDENTIAL is updated to match.

    Raises:
        OtpRejected: BAD_CRC, PRIVATE_ID_MISMATCH or REPLAYED.
        DecryptionError: The stored private ID or AES key can't be decrypted.
    """
    if otp.public_id != credential.public_id:
        raise ValueError("the OTP is for another credential")
    token = decrypt_token(otp.token, credential.aes_key())
    if not hmac.compare_digest(token.private_id, credential.private_id()):
        raise OtpRejected(Rejection.PRIVATE_ID_MISMATCH)
    usage, session = token.usage_counter, token.session_counter
    if not is_newer(token, credential.last_usage_counter, credential.last_session_counter):
        raise OtpRejected(Rejection.REPLAYED)
    now = timezone.now()
    saved = (
        YubikeyCredential.objects.filter(pk=credential.pk, enabled=True)
        .filter(
            Q(last_usage_counter__lt=usage)
            | Q(last_usage_counter=usage, last_session_counter__lt=session)
        )
        .update(last_usage_counter=usage, last_session_counter=session, last_used_at=now)
    )
    if not saved:
        # A newer OTP was accepted (or the key disabled) since CREDENTIAL was read.
        raise OtpRejected(Rejection.REPLAYED)
    credential.last_usage_counter = usage
    credential.last_session_counter = session
    credential.last_used_at = now
    return token

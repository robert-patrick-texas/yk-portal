import uuid
from collections.abc import Mapping, MutableMapping

from django import forms

from yk_portal.accounts.models import Group, Theme
from yk_portal.core.db import CodePoint

from .service import NUMBER_RANGES

# Each number setting: its label and unit, for the label and the hint.
_NUMBERS = {
    "idle_timeout_minutes": ("Idle session timeout", "minutes"),
    "max_session_hours": ("Maximum session length", "hours"),
    "temp_password_hours": ("Temporary password lifetime", "hours"),
    "failed_login_limit": ("Failed logins before an account locks", "failed logins"),
    "address_failure_limit": (
        "Failed sign-ins from one address before it must wait",
        "failed sign-ins within the wait",
    ),
    "address_wait_minutes": ("Wait for an address with too many failed sign-ins", "minutes"),
    "max_yubikeys_per_user": ("Maximum YubiKeys per user", "YubiKeys"),
}


def _number_field(key: str) -> forms.IntegerField:
    label, unit = _NUMBERS[key]
    low, high = NUMBER_RANGES[key]
    # The range is checked by the settings service, so its message is the one shown.
    return forms.IntegerField(label=label, help_text=f"{low} to {high} {unit}.")


class SettingsForm(forms.Form):
    """Every run-time setting (addendum §3.2). Lengths and ranges are checked by the
    settings service."""

    portal_name = forms.CharField(
        label="Portal name",
        help_text="Replaces “yk-portal” everywhere users see the name. Plain text.",
    )
    login_notice = forms.CharField(
        label="Sign-in page notice",
        required=False,
        strip=False,
        widget=forms.Textarea(attrs={"rows": 4}),
        help_text="Such as an authorized-use banner. Plain text; line breaks are kept.",
    )
    idle_timeout_minutes = _number_field("idle_timeout_minutes")
    max_session_hours = _number_field("max_session_hours")
    temp_password_hours = _number_field("temp_password_hours")
    failed_login_limit = _number_field("failed_login_limit")
    address_failure_limit = _number_field("address_failure_limit")
    address_wait_minutes = _number_field("address_wait_minutes")
    max_yubikeys_per_user = _number_field("max_yubikeys_per_user")
    step_up_before_reveal = forms.BooleanField(
        required=False,
        label="Ask for the admin’s PIN and OTP again before revealing a YubiKey’s private ID "
        "or AES key",
    )
    default_group = forms.ChoiceField(
        label="Default group",
        required=False,
        help_text="New accounts get it. Changing it doesn’t change existing accounts.",
    )
    default_theme = forms.ChoiceField(
        label="Default theme",
        choices=Theme.choices,
        help_text="For users who haven’t chosen one.",
    )

    def __init__(
        self,
        data: Mapping[str, object] | None = None,
        initial: MutableMapping[str, object] | None = None,
    ) -> None:
        super().__init__(data, initial=initial)
        field = self.fields["default_group"]
        assert isinstance(field, forms.ChoiceField)  # noqa: S101 - declared above
        groups = Group.objects.order_by(CodePoint("name")).values_list("pk", "name")
        field.choices = [("", "None"), *((str(pk), name) for pk, name in groups)]

    def clean_login_notice(self) -> str:
        # Browsers send line breaks as CRLF.
        return self.cleaned_data["login_notice"].replace("\r\n", "\n")

    def clean_default_group(self) -> uuid.UUID | None:
        value = self.cleaned_data["default_group"]
        return uuid.UUID(value) if value else None

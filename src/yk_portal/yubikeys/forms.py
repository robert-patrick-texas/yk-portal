from django import forms
from django.core.exceptions import ValidationError

from .management import NewYubikey, parse_aes_key, parse_private_id
from .validators import validate_label, validate_public_id

SLOTS = [(1, "Slot 1 (short touch)"), (2, "Slot 2 (long touch)")]


def _otp_field() -> forms.CharField:
    return forms.CharField(
        label="OTP",
        max_length=64,
        widget=forms.TextInput(attrs={"autocomplete": "off", "spellcheck": "false"}),
        help_text="Click here, then touch the YubiKey: it types 44 letters.",
    )


def _secret_field(label: str, help_text: str) -> forms.CharField:
    # Masked, with a show/hide button; never sent back to the browser, not even after an
    # error.
    return forms.CharField(
        label=label,
        max_length=128,
        strip=False,
        widget=forms.PasswordInput(attrs={"autocomplete": "off", "data-reveal": True}),
        help_text=help_text,
    )


class YubikeyForm(forms.Form):
    """A YubiKey's values as ykman set them, its label and slot, and a test OTP."""

    public_id = forms.CharField(
        label="Public ID",
        max_length=12,
        widget=forms.TextInput(attrs={"autocomplete": "off", "spellcheck": "false"}),
        help_text="12 letters: the start of every OTP the YubiKey types.",
    )
    private_id = _secret_field("Private ID", "12 hex characters.")
    aes_key = _secret_field("AES key", "32 hex characters: the “Secret key” ykman shows.")
    label = forms.CharField(
        max_length=255, required=False, help_text="Optional, such as “spare” or “on my keyring”."
    )
    slot = forms.TypedChoiceField(choices=SLOTS, coerce=int, label="Slot", initial=2)
    otp = _otp_field()

    def clean_public_id(self) -> str:
        value = self.cleaned_data["public_id"].strip().lower()
        validate_public_id(value)
        return value

    def clean_private_id(self) -> bytes:
        return parse_private_id(self.cleaned_data["private_id"])

    def clean_aes_key(self) -> bytes:
        return parse_aes_key(self.cleaned_data["aes_key"])

    def clean_label(self) -> str:
        value = self.cleaned_data["label"]
        validate_label(value)
        return value

    def new_yubikey(self) -> NewYubikey:
        data = self.cleaned_data
        return NewYubikey(
            public_id=data["public_id"],
            private_id=data["private_id"],
            aes_key=data["aes_key"],
            label=data["label"],
            slot=data["slot"],
        )

    def add_service_error(self, error: ValidationError) -> None:
        """Show an error from add_yubikey beside the field it concerns."""
        fields = {
            "public_id_taken": "public_id",
            "private_id_taken": "private_id",
            "wrong_public_id": "otp",
            "malformed_otp": "otp",
            "wrong_aes_key": "aes_key",
            "wrong_private_id": "private_id",
        }
        self.add_error(fields.get(error.error_list[0].code or "", None), error)


class OtpForm(forms.Form):
    otp = _otp_field()


class YubikeyEditForm(forms.Form):
    label = forms.CharField(max_length=255, required=False)
    slot = forms.TypedChoiceField(
        choices=[("", "Not known"), *SLOTS], coerce=int, empty_value=None, required=False
    )

    def clean_label(self) -> str:
        value = self.cleaned_data["label"]
        validate_label(value)
        return value

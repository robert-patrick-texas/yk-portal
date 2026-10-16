from django import forms
from django.core.exceptions import ValidationError

from yk_portal.authentication.passwords import validate_password


class EmailForm(forms.Form):
    email = forms.EmailField(
        max_length=254, widget=forms.EmailInput(attrs={"autocomplete": "email"})
    )


class PasswordForm(forms.Form):
    password = forms.CharField(
        label="New password",
        max_length=200,
        strip=False,
        widget=forms.PasswordInput(attrs={"autocomplete": "new-password", "data-reveal": True}),
        help_text="8 to 80 characters, with at least one letter and one number, not ending "
        "with a colon. You type it before the YubiKey OTP, here and in Radiator.",
    )
    confirm = forms.CharField(
        label="New password again",
        max_length=200,
        strip=False,
        widget=forms.PasswordInput(attrs={"autocomplete": "new-password", "data-reveal": True}),
    )

    def clean(self) -> dict[str, object]:
        data = super().clean() or {}
        password, confirm = data.get("password"), data.get("confirm")
        if isinstance(password, str):
            try:
                validate_password(password)
            except ValidationError as e:
                self.add_error("password", e)
            if confirm is not None and password != confirm:
                self.add_error("confirm", "The two passwords differ.")
        return data

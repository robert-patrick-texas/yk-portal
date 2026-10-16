from django import forms


class LoginForm(forms.Form):
    username = forms.CharField(
        max_length=255,
        widget=forms.TextInput(attrs={"autocomplete": "username", "autofocus": True}),
    )
    # The password followed by a touch of the YubiKey; never trimmed.
    passcode = forms.CharField(
        max_length=256,
        strip=False,
        widget=forms.PasswordInput(attrs={"autocomplete": "off"}),
    )

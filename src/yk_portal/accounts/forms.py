from collections.abc import Mapping

from django import forms

from yk_portal.core.db import CodePoint

from .models import AccountState, Group


class EmailForm(forms.Form):
    email = forms.EmailField(
        max_length=254, widget=forms.EmailInput(attrs={"autocomplete": "email"})
    )


def _display_name_field() -> forms.CharField:
    return forms.CharField(
        label="Display name",
        max_length=255,
        required=False,
        widget=forms.TextInput(attrs={"autocomplete": "off"}),
        help_text="Optional, such as a full name, or “last, first”. For admins: the user "
        "doesn’t see it.",
    )


def _comment_field() -> forms.CharField:
    # Its length is checked by the service, after line breaks are counted as one.
    return forms.CharField(
        label="Comment",
        required=False,
        strip=False,
        widget=forms.Textarea(attrs={"rows": 3}),
        help_text="Optional notes, up to 1,000 characters. For admins: the user doesn’t see it.",
    )


def _groups_field() -> forms.ModelMultipleChoiceField:
    return forms.ModelMultipleChoiceField(
        queryset=Group.objects.order_by(CodePoint("name")),
        required=False,
        widget=forms.CheckboxSelectMultiple,
        help_text="Groups grant nothing in yk-portal.",
    )


class UserFilterForm(forms.Form):
    """Search and filters of the admin user list (spec §9)."""

    q = forms.CharField(
        required=False,
        label="Search",
        max_length=255,
        widget=forms.TextInput(
            attrs={"type": "search", "placeholder": "Username, display name or email"}
        ),
    )
    state = forms.ChoiceField(required=False, choices=[("", "Any state"), *AccountState.choices])
    role = forms.ChoiceField(
        required=False,
        choices=[("", "Any role"), ("admin", "Admins"), ("user", "Not admins")],
    )
    group = forms.ModelChoiceField(
        required=False, queryset=Group.objects.order_by(CodePoint("name")), empty_label="Any group"
    )


class UserCreateForm(forms.Form):
    """A new account (spec §10). Its temporary password is generated (addendum §14.1)."""

    username = forms.CharField(
        max_length=255,
        widget=forms.TextInput(attrs={"autocomplete": "off", "spellcheck": "false"}),
        help_text="Lowercase letters, digits and . _ @ + -",
    )
    email = forms.EmailField(
        max_length=254,
        required=False,
        help_text="Optional: the user can set it while setting up the account.",
    )
    display_name = _display_name_field()
    comment = _comment_field()
    admin = forms.BooleanField(required=False, label="Admin: may manage every account")
    groups = _groups_field()


class UserEditForm(forms.Form):
    username = forms.CharField(
        max_length=255,
        widget=forms.TextInput(attrs={"autocomplete": "off", "spellcheck": "false"}),
        help_text="Radiator gets the new username with the next export.",
    )
    email = forms.EmailField(max_length=254, required=False)
    display_name = _display_name_field()
    comment = _comment_field()
    groups = _groups_field()


class ConfirmUsernameForm(forms.Form):
    """Entering the username, typed or pasted, confirms a hard delete."""

    username = forms.CharField(
        max_length=255,
        label="Enter the username to confirm",
        widget=forms.TextInput(attrs={"autocomplete": "off", "spellcheck": "false"}),
    )

    def __init__(self, data: Mapping[str, object] | None = None, *, expected: str) -> None:
        super().__init__(data)
        self.expected = expected

    def clean_username(self) -> str:
        value = self.cleaned_data["username"].strip()
        if value != self.expected:
            raise forms.ValidationError(f"Enter {self.expected} exactly.")
        return value


class GroupForm(forms.Form):
    name = forms.CharField(
        max_length=64,
        widget=forms.TextInput(attrs={"autocomplete": "off", "spellcheck": "false"}),
        help_text="1 to 64 letters, digits and . _ - (as in Radiator), unique in any case.",
    )
    description = forms.CharField(
        required=False, max_length=1000, widget=forms.Textarea(attrs={"rows": 3})
    )


class AddMemberForm(forms.Form):
    username = forms.CharField(
        max_length=255,
        label="Add a member",
        widget=forms.TextInput(
            attrs={"autocomplete": "off", "spellcheck": "false", "placeholder": "Username"}
        ),
    )

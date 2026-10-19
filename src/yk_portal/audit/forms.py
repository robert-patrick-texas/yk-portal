from django import forms

from .models import EventType, Result


class EventFilterForm(forms.Form):
    """Search and filters of the audit log (addendum §17.3)."""

    q = forms.CharField(
        required=False,
        label="Search",
        max_length=255,
        widget=forms.TextInput(
            attrs={"type": "search", "placeholder": "Username, IP address, YubiKey or group"}
        ),
    )
    event_type = forms.ChoiceField(
        required=False, choices=[("", "Any event"), *((t, t) for t in EventType.values)]
    )
    result = forms.ChoiceField(required=False, choices=[("", "Any result"), *Result.choices])
    since = forms.DateField(
        required=False, label="From", widget=forms.DateInput(attrs={"type": "date"})
    )
    until = forms.DateField(
        required=False, label="To", widget=forms.DateInput(attrs={"type": "date"})
    )
    # An account's events, by ID, so they're found after a rename or hard delete.
    user = forms.UUIDField(required=False, widget=forms.HiddenInput)

    def clean(self) -> dict[str, object]:
        data = super().clean() or {}
        since, until = data.get("since"), data.get("until")
        if since and until and since > until:
            raise forms.ValidationError("The From date is after the To date.", code="dates")
        return data

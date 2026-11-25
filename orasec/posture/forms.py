import json

from django import forms

from orasec import site as site_profile
from orasec.posture.models import (
    Connector,
    ControlEvidence,
    ControlImplementation,
    InventoryAsset,
    PrioritySettings,
    RemediationCampaign,
    RiskRegisterEntry,
    TriageRule,
)

INPUT = "w-full rounded-md border border-gray-300 px-3 py-2 text-sm"


class StyledMixin:
    def _style(self):
        for f in self.fields.values():
            if isinstance(f.widget, (forms.CheckboxInput, forms.CheckboxSelectMultiple)):
                continue
            f.widget.attrs.setdefault("class", INPUT)


class ConnectorForm(StyledMixin, forms.ModelForm):
    secret_1 = forms.CharField(required=False, widget=forms.PasswordInput(render_value=False))
    secret_2 = forms.CharField(required=False, widget=forms.PasswordInput(render_value=False))
    secret_3 = forms.CharField(required=False, widget=forms.PasswordInput(render_value=False))
    options_json = forms.CharField(required=False, widget=forms.Textarea(attrs={"rows": 4, "class": INPUT + " font-mono"}),
                                   label="Options (JSON)")

    class Meta:
        model = Connector
        fields = ["name", "kind", "enabled", "base_url", "verify_tls", "username", "product", "engagement_name", "interval_minutes"]

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        from orasec.posture.connectors.base import get_connector_class  # noqa: PLC0415
        kind = self.instance.kind or self.data.get("kind") or self.initial.get("kind")
        fields = ()
        if kind:
            try:
                fields = get_connector_class(kind).secret_fields
            except Exception:  # noqa: BLE001
                fields = ()
        self.secret_names = list(fields)
        existing = self.instance.get_secrets() if self.instance.pk else {}
        for i, name in enumerate(fields[:3], 1):
            f = self.fields[f"secret_{i}"]
            f.label = name.replace("_", " ").capitalize()
            f.help_text = "Stored encrypted. Leave blank to keep the current value." if existing.get(name) else "Stored encrypted."
        for i in range(len(fields) + 1, 4):
            del self.fields[f"secret_{i}"]
        self.fields["options_json"].initial = json.dumps(self.instance.options or {}, indent=1)
        self._style()

    def clean_options_json(self):
        raw = self.cleaned_data.get("options_json") or "{}"
        try:
            val = json.loads(raw)
        except ValueError as e:
            raise forms.ValidationError(f"Invalid JSON: {e}") from e
        if not isinstance(val, dict):
            msg = "Options must be a JSON object."
            raise forms.ValidationError(msg)
        return val

    def save(self, commit=True):
        obj = super().save(commit=False)
        obj.options = self.cleaned_data.get("options_json") or {}
        secrets = obj.get_secrets() if obj.pk else {}
        for i, name in enumerate(self.secret_names[:3], 1):
            v = self.cleaned_data.get(f"secret_{i}")
            if v:
                secrets[name] = v
        obj.set_secrets(secrets)
        if commit:
            obj.save()
        return obj


class ControlImplementationForm(StyledMixin, forms.ModelForm):
    class Meta:
        model = ControlImplementation
        fields = ["applicable", "justification", "status", "owner", "implementation_notes", "last_reviewed", "review_due"]
        widgets = {"last_reviewed": forms.DateInput(attrs={"type": "date"}), "review_due": forms.DateInput(attrs={"type": "date"}),
                   "justification": forms.Textarea(attrs={"rows": 3}), "implementation_notes": forms.Textarea(attrs={"rows": 5})}

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._style()


class EvidenceForm(StyledMixin, forms.ModelForm):
    class Meta:
        model = ControlEvidence
        fields = ["title", "classification", "description", "url", "file", "valid_until"]
        widgets = {"valid_until": forms.DateInput(attrs={"type": "date"}), "description": forms.Textarea(attrs={"rows": 2})}

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._style()


class RiskForm(StyledMixin, forms.ModelForm):
    class Meta:
        model = RiskRegisterEntry
        fields = ["title", "description", "category", "scope", "product", "threat", "vulnerability", "evidence_note", "existing_controls",
                  "likelihood", "impact", "treatment", "treatment_plan", "residual_likelihood", "residual_impact", "owner", "status",
                  "review_date", "assessment", "controls"]
        widgets = {"review_date": forms.DateInput(attrs={"type": "date"}), "description": forms.Textarea(attrs={"rows": 3}),
                   "threat": forms.Textarea(attrs={"rows": 2}), "vulnerability": forms.Textarea(attrs={"rows": 2}),
                   "treatment_plan": forms.Textarea(attrs={"rows": 3}), "controls": forms.SelectMultiple(attrs={"size": 8}),
                   "evidence_note": forms.Textarea(attrs={"rows": 2}), "existing_controls": forms.Textarea(attrs={"rows": 2})}

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._style()


class AssetForm(StyledMixin, forms.ModelForm):
    class Meta:
        model = InventoryAsset
        fields = ["name", "asset_type", "product", "parent", "owner", "criticality", "internet_exposed", "scan_cadence_days", "retired"]

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._style()


class CampaignForm(StyledMixin, forms.ModelForm):
    class Meta:
        model = RemediationCampaign
        fields = ["name", "component", "product", "description", "owner", "target_date", "status"]
        widgets = {"target_date": forms.DateInput(attrs={"type": "date"}), "description": forms.Textarea(attrs={"rows": 3})}

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._style()


class TriageRuleForm(StyledMixin, forms.ModelForm):
    conditions_json = forms.CharField(widget=forms.Textarea(attrs={"rows": 7, "class": INPUT + " font-mono"}), label="Conditions (JSON)")
    actions_json = forms.CharField(widget=forms.Textarea(attrs={"rows": 7, "class": INPUT + " font-mono"}), label="Actions (JSON)")

    class Meta:
        model = TriageRule
        fields = ["name", "enabled", "order", "stop_processing"]

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.fields["conditions_json"].initial = json.dumps(self.instance.conditions or {"severity_in": ["Critical"], "kev": True}, indent=1)
        self.fields["actions_json"].initial = json.dumps(self.instance.actions or {"add_tags": ["kev-critical"], "notify_emails": list(site_profile.get("notify_emails") or [])}, indent=1)
        self._style()

    def _json(self, name):
        try:
            v = json.loads(self.cleaned_data.get(name) or "{}")
        except ValueError as e:
            raise forms.ValidationError(f"Invalid JSON: {e}") from e
        if not isinstance(v, dict):
            msg = "Must be a JSON object."
            raise forms.ValidationError(msg)
        return v

    def clean_conditions_json(self):
        return self._json("conditions_json")

    def clean_actions_json(self):
        return self._json("actions_json")

    def save(self, commit=True):
        obj = super().save(commit=False)
        obj.conditions = self.cleaned_data["conditions_json"]
        obj.actions = self.cleaned_data["actions_json"]
        if commit:
            obj.save()
        return obj


class PrioritySettingsForm(StyledMixin, forms.ModelForm):
    weights_json = forms.CharField(widget=forms.Textarea(attrs={"rows": 10, "class": INPUT + " font-mono"}), label="Weights (JSON)")
    bands_json = forms.CharField(widget=forms.Textarea(attrs={"rows": 4, "class": INPUT + " font-mono"}), label="Band thresholds (JSON)")
    sla_json = forms.CharField(widget=forms.Textarea(attrs={"rows": 5, "class": INPUT + " font-mono"}), label="SLA days per band (JSON)")

    class Meta:
        model = PrioritySettings
        fields = ["sla_start", "cap_at_kev_due"]

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        i = self.instance
        self.fields["weights_json"].initial = json.dumps({**PrioritySettings.DEFAULT_WEIGHTS, **(i.weights or {})}, indent=1)
        self.fields["bands_json"].initial = json.dumps({**PrioritySettings.DEFAULT_BANDS, **(i.bands or {})}, indent=1)
        self.fields["sla_json"].initial = json.dumps({**PrioritySettings.DEFAULT_SLA, **(i.sla_days or {})}, indent=1)
        self._style()

    def save(self, commit=True):
        obj = super().save(commit=False)
        obj.weights = json.loads(self.cleaned_data["weights_json"])
        obj.bands = json.loads(self.cleaned_data["bands_json"])
        obj.sla_days = json.loads(self.cleaned_data["sla_json"])
        if commit:
            obj.save()
        return obj


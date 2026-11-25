from django import forms

from orasec.posture.forms import StyledMixin
from orasec.posture.grc_models import (
    ChangeRequest,
    GovernanceException,
    ObjectiveAction,
    Nonconformity,
    Opportunity,
    RiskAssessment,
    RiskReview,
    SecurityObjective,
    Supplier,
    SupplierAssessment,
)
from orasec.posture.models import RiskRegisterEntry

DATE = forms.DateInput(attrs={"type": "date"})
INPUT = "w-full rounded-md border border-gray-300 px-3 py-2 text-sm"


def _ta(rows):
    return forms.Textarea(attrs={"rows": rows})


class _Styled(StyledMixin, forms.ModelForm):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._style()


class SupplierForm(_Styled):
    class Meta:
        model = Supplier
        fields = ["name", "service", "products", "data_shared", "classification", "personal_information", "tier", "data_location",
                  "assurance", "assurance_expiry", "contract", "breach_notification", "owner", "status", "next_review", "website", "notes"]
        widgets = {"service": _ta(2), "data_shared": _ta(2), "assurance": _ta(2), "contract": _ta(2), "notes": _ta(3),
                   "assurance_expiry": DATE, "next_review": DATE}


class SupplierAssessmentForm(_Styled):
    class Meta:
        model = SupplierAssessment
        fields = ["kind", "assessed_on", "assurance_ok", "data_location_ok", "breach_terms_ok", "encryption_ok", "access_ok",
                  "subprocessors_ok", "incidents", "findings", "likelihood", "impact", "recommendation", "conditions", "evidence"]
        widgets = {"assessed_on": DATE, "incidents": _ta(2), "findings": _ta(4), "conditions": _ta(2)}


class RiskAssessmentForm(_Styled):
    class Meta:
        model = RiskAssessment
        fields = ["title", "assessed_on", "scope", "method", "prepared_for", "summary", "file", "next_assessment"]
        widgets = {"assessed_on": DATE, "next_assessment": DATE, "scope": _ta(2), "method": _ta(2), "summary": _ta(4)}


class RiskReviewForm(_Styled):
    class Meta:
        model = RiskReview
        fields = ["likelihood", "impact", "residual_likelihood", "residual_impact", "status", "note", "next_review"]
        widgets = {"next_review": DATE, "note": _ta(3)}

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.fields["status"] = forms.ChoiceField(choices=RiskRegisterEntry.STATUS, widget=forms.Select(attrs={"class": INPUT}))
        self.fields["next_review"].required = True


class ExceptionForm(_Styled):
    class Meta:
        model = GovernanceException
        fields = ["kind", "title", "policy_ref", "risk", "control", "supplier", "description", "reason", "compensating_controls",
                  "likelihood", "impact", "start", "expiry"]
        widgets = {"start": DATE, "expiry": DATE, "description": _ta(3), "reason": _ta(2), "compensating_controls": _ta(3)}


class OpportunityForm(_Styled):
    class Meta:
        model = Opportunity
        fields = ["title", "benefit", "action", "owner", "status", "review_date", "assessment"]
        widgets = {"benefit": _ta(2), "action": _ta(2), "review_date": DATE}


class NonconformityForm(_Styled):
    class Meta:
        model = Nonconformity
        fields = ["title", "source", "control", "description", "correction", "cause", "corrective_action", "owner",
                  "due_date", "status", "effectiveness", "verified_by", "raised"]
        widgets = {"due_date": DATE, "raised": DATE, "description": _ta(3), "correction": _ta(2), "cause": _ta(2),
                   "corrective_action": _ta(2), "effectiveness": _ta(2)}


class DecisionForm(forms.Form):
    decision = forms.ChoiceField(choices=[])
    note = forms.CharField(required=False, widget=forms.Textarea(attrs={"rows": 2}))

    def __init__(self, *a, choices=None, **kw):
        super().__init__(*a, **kw)
        self.fields["decision"].choices = choices or [("approve", "Approve"), ("reject", "Reject")]
        for f in self.fields.values():
            f.widget.attrs.setdefault("class", INPUT)



class ObjectiveForm(_Styled):
    class Meta:
        model = SecurityObjective
        fields = ["title", "target", "owner", "plan", "due_date", "measure", "evidence_prefix", "evidence_max_days",
                  "applicable", "manual_met", "notes"]
        widgets = {"target": _ta(2), "plan": _ta(4), "notes": _ta(2), "due_date": DATE}


class ObjectiveActionForm(_Styled):
    class Meta:
        model = ObjectiveAction
        fields = ["title", "owner", "due_date"]
        widgets = {"due_date": DATE}


class ChangeForm(_Styled):
    class Meta:
        model = ChangeRequest
        fields = ["category", "change_type", "title", "reason", "impact", "resources", "plan", "risk_level", "systems", "link",
                  "owner", "planned_date"]
        widgets = {"reason": _ta(3), "impact": _ta(3), "resources": _ta(2), "plan": _ta(4), "planned_date": DATE}

    def clean(self):
        d = super().clean()
        if d.get("category") == "isms" and not (d.get("resources") or "").strip():
            self.add_error("resources", "For an ISMS change, say who does it and the time or cost needed (ISO 27001 6.3).")
        if d.get("change_type") in ("normal", "standard") and not (d.get("plan") or "").strip():
            self.add_error("plan", "Add the steps, how you will check it worked, and how to undo it.")
        return d


class ChangeStepForm(forms.Form):
    """Approve / reject, mark done, or review and close a change."""
    note = forms.CharField(required=False, widget=forms.Textarea(attrs={"rows": 2, "class": INPUT}))
    when = forms.DateTimeField(required=False, widget=forms.DateTimeInput(attrs={"type": "datetime-local", "class": INPUT}),
                               help_text="When it was done (leave empty for now).")
    result = forms.ChoiceField(required=False, choices=[("", "—")] + ChangeRequest.RESULT, widget=forms.Select(attrs={"class": INPUT}))

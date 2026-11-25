"""
OraSec GRC workflows: dashboard, supplier register and assessments, risk assessments,
risk reviews, exceptions and risk acceptances, opportunities.

Segregation of duties (FWK-001 5.3, POL-002 4.7, POL-015 3):
no one approves their own request, assessment or risk.
"""
import datetime

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db.models import Count
from django.shortcuts import get_object_or_404, redirect
from django.utils import timezone

from orasec.posture.grc_actions import (  # noqa: F401 -- rules shared with the connector endpoint
    DIRECTOR_GROUP,
    can_decide,
    change_action,
    change_permissions,
    exception_decide,
    exception_state,
    is_director,
)
from orasec.posture.grc_forms import (
    ChangeForm,
    ChangeStepForm,
    DecisionForm,
    ExceptionForm,
    ObjectiveActionForm,
    ObjectiveForm,
    NonconformityForm,
    OpportunityForm,
    RiskAssessmentForm,
    RiskReviewForm,
    SupplierAssessmentForm,
    SupplierForm,
)
from orasec.posture.grc_models import (
    ChangeRequest,
    GovernanceException,
    ObjectiveAction,
    Nonconformity,
    Opportunity,
    RiskAssessment,
    SecurityObjective,
    Supplier,
    SupplierAssessment,
    SupplierAssessmentDecision,
    risk_band,
)
from orasec.posture.models import ControlImplementation, RiskRegisterEntry
from orasec.posture.views import compliance_required, is_compliance_officer, render

GRC_CONTROLS = ["C6.1.1", "C6.1.2", "C6.2", "C6.3", "A.8.32", "C6.1.3", "C8.2", "C8.3", "A.5.19", "A.5.20", "A.5.22", "A.5.36"]


def _today():
    return timezone.now().date()


def _expire_exceptions():
    return GovernanceException.objects.filter(status="approved", expiry__lt=_today()).update(status="expired")


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
@login_required
def grc_dashboard(request):
    _expire_exceptions()
    today, soon = _today(), _today() + datetime.timedelta(days=30)
    risks = list(RiskRegisterEntry.objects.exclude(status="closed").select_related("owner"))
    by_band = dict.fromkeys(("Critical", "High", "Medium", "Low"), 0)
    by_res = dict.fromkeys(("Critical", "High", "Medium", "Low"), 0)
    heat = {(lk, im): 0 for lk in range(1, 6) for im in range(1, 6)}
    for r in risks:
        by_band[risk_band(r.inherent_score)] += 1
        if r.residual_score:
            by_res[risk_band(r.residual_score)] += 1
        heat[(r.likelihood, r.impact)] += 1
    grid = [[(lk, im, heat[(lk, im)], risk_band(lk * im)) for im in range(1, 6)] for lk in range(5, 0, -1)]
    review_overdue = [r for r in risks if r.review_date and r.review_date < today]
    review_soon = [r for r in risks if r.review_date and today <= r.review_date <= soon]
    top = sorted(risks, key=lambda r: (-(r.inherent_score), r.ref))[:8]

    exc_pending = GovernanceException.objects.filter(status="requested")
    exc_expiring = GovernanceException.objects.filter(status="approved", expiry__lte=soon)
    exc_expired = GovernanceException.objects.filter(status="expired")

    sup = Supplier.objects.exclude(status="exited")
    sup_tier = dict(sup.values_list("tier").annotate(n=Count("id")))
    sup_overdue = [s for s in sup.filter(status="active") if s.review_overdue and s.approved_assessment]
    sup_unassessed = [s for s in sup if not s.approved_assessment]
    sa_pending = SupplierAssessment.objects.filter(status="submitted").select_related("supplier")

    ra_latest = RiskAssessment.objects.filter(status="approved").first()
    ra_pending = RiskAssessment.objects.filter(status="submitted")
    opps = Opportunity.objects.exclude(status__in=["realised", "dropped"]).select_related("owner")
    objectives = SecurityObjective.objects.select_related("owner")

    u = request.user
    decider = can_decide(u)
    mine = {
        "exceptions": [e for e in exc_pending if decider and e.requested_by_id != u.id
                       and not (e.kind == "risk_acceptance" and e.risk and e.risk.owner_id == u.id)
                       and not e.decisions.filter(decided_by=u).exists()],
        "supplier_assessments": [a for a in sa_pending if decider and u.id not in (a.assessed_by_id, a.supplier.requested_by_id)
                                 and not a.decisions.filter(decided_by=u).exists()],
        "risk_assessments": [a for a in ra_pending if u.is_superuser and a.prepared_by_id != u.id],
        "my_risks_due": [r for r in risks if r.owner_id == u.id and r.review_date and r.review_date <= soon],
        "my_actions": list(ObjectiveAction.objects.filter(owner=u, status="open", due_date__lte=soon).select_related("objective")),
    }
    open_changes = list(ChangeRequest.objects.filter(status__in=["submitted", "approved", "implemented"]))
    mine["changes"] = [(c, "approve" if p["approve"] else "review") for c in open_changes
                       for p in [change_permissions(u, c)] if p["approve"] or p["review"]]
    chg = {"awaiting_approval": sum(1 for c in open_changes if c.status == "submitted" or not c.approved_by_id),
           "awaiting_review": sum(1 for c in open_changes if c.status == "implemented"),
           "overdue": sum(1 for c in open_changes if c.approval_overdue or c.review_overdue)}
    checks = ControlImplementation.objects.select_related("control").filter(control__ref__in=GRC_CONTROLS)
    checks = sorted(checks, key=lambda i: GRC_CONTROLS.index(i.control.ref))
    return render(request, "orasec/posture/grc_dashboard.html", {
        "by_band": by_band, "by_res": by_res, "grid": grid, "n_risks": len(risks), "top": top,
        "review_overdue": review_overdue, "review_soon": review_soon,
        "exc_pending": exc_pending, "exc_expiring": exc_expiring, "exc_expired": exc_expired,
        "sup_total": sup.count(), "sup_tier": sup_tier, "sup_overdue": sup_overdue,
        "sup_unassessed": sup_unassessed, "sa_pending": sa_pending,
        "ra_latest": ra_latest, "ra_pending": ra_pending, "opps": opps, "mine": mine, "checks": checks, "objectives": objectives,
        "can_compliance": is_compliance_officer(u), "chg": chg, "page_title": "GRC Dashboard"})


def _form_page(request, form, title, back, sub="", multipart=False):
    return render(request, "orasec/posture/grc_form.html", {"form": form, "title": title, "back": back, "sub": sub,
                                                             "multipart": multipart, "page_title": title})


# ---------------------------------------------------------------------------
# Suppliers
# ---------------------------------------------------------------------------
@login_required
def suppliers(request):
    qs = Supplier.objects.select_related("owner").annotate(n_assess=Count("assessments"))
    tier, st = request.GET.get("tier"), request.GET.get("status")
    if tier:
        qs = qs.filter(tier=tier)
    if st:
        qs = qs.filter(status=st)
    return render(request, "orasec/posture/suppliers.html", {"items": qs, "tier": tier, "st": st,
                  "tiers": Supplier.TIER, "statuses": Supplier.STATUS, "can_compliance": is_compliance_officer(request.user),
                  "page_title": "Supplier Register"})


@compliance_required
def supplier_edit(request, sid=None):
    obj = get_object_or_404(Supplier, id=sid) if sid else None
    form = SupplierForm(request.POST or None, instance=obj)
    if request.method == "POST" and form.is_valid():
        s = form.save(commit=False)
        if not obj:
            s.requested_by = request.user
        s.save()
        messages.success(request, f"Supplier {s.ref} saved.")
        return redirect("orasec_supplier", sid=s.id)
    return _form_page(request, form, f"{obj.ref} {obj.name}" if obj else "New supplier request",
                      "orasec_suppliers", "POL-015: no company data is shared with a supplier until its assessment is approved.")


@login_required
def supplier_detail(request, sid):
    s = get_object_or_404(Supplier, id=sid)
    return render(request, "orasec/posture/supplier_detail.html", {"s": s, "assessments": s.assessments.all(),
                  "exceptions": s.exceptions.all(), "risks": s.risks.all(), "can_compliance": is_compliance_officer(request.user),
                  "can_request": can_decide(request.user), "page_title": f"{s.ref} {s.name}"})


@compliance_required
def supplier_assess(request, sid):
    s = get_object_or_404(Supplier, id=sid)
    form = SupplierAssessmentForm(request.POST or None, request.FILES or None,
                                  initial={"kind": "onboarding" if s.status in ("proposed", "assessing") else "annual"})
    if request.method == "POST" and form.is_valid():
        a = form.save(commit=False)
        a.supplier, a.assessed_by = s, request.user
        a.save()
        if s.status == "proposed":
            s.status = "assessing"
            s.save(update_fields=["status", "updated"])
        messages.success(request, f"Assessment {a.ref} saved as draft. Submit it for approval when complete.")
        return redirect("orasec_supplier_assessment", aid=a.id)
    who = ("two approvers who are neither the requester nor the assessor" if s.tier == "critical"
           else "one approver who is not the assessor or requester")
    return _form_page(request, form, f"Assess {s.ref} {s.name}", "orasec_suppliers",
                      f"Tier {s.get_tier_display()}: approval by {who}.", multipart=True)


@login_required
def supplier_assessment(request, aid):
    a = get_object_or_404(SupplierAssessment.objects.select_related("supplier"), id=aid)
    u = request.user
    need = a.supplier.required_approvals()
    approvals = a.decisions.exclude(decision="reject").count()
    may_decide = (a.status == "submitted" and can_decide(u) and u.id not in (a.assessed_by_id, a.supplier.requested_by_id)
                  and not a.decisions.filter(decided_by=u).exists())
    can_submit = a.status == "draft" and (u.id == a.assessed_by_id or u.is_superuser)
    form = DecisionForm(request.POST or None, choices=SupplierAssessment.RECOMMEND) if may_decide else None
    if request.method == "POST":
        action = request.POST.get("action")
        if action == "submit" and can_submit:
            a.status, a.submitted_at = "submitted", timezone.now()
            a.save(update_fields=["status", "submitted_at"])
            messages.success(request, f"{a.ref} submitted for approval.")
        elif action == "decide" and form is not None and form.is_valid():
            d = form.cleaned_data["decision"]
            SupplierAssessmentDecision.objects.create(assessment=a, decided_by=u, decision=d, note=form.cleaned_data["note"])
            s = a.supplier
            if d == "reject":
                a.status, a.completed_at = "rejected", timezone.now()
                s.status = "exited" if a.kind == "onboarding" else "suspended"
                s.save(update_fields=["status", "updated"])
            elif approvals + 1 >= need:
                cond = d == "approve_conditions" or a.decisions.filter(decision="approve_conditions").exists()
                a.status, a.completed_at = ("approved_conditions" if cond else "approved"), timezone.now()
                s.status = "exited" if a.kind == "offboarding" else "active"
                s.last_review = a.assessed_on
                s.next_review = a.assessed_on + datetime.timedelta(days=365)
                s.save(update_fields=["status", "last_review", "next_review", "updated"])
            a.save(update_fields=["status", "completed_at"])
            messages.success(request, "Decision recorded.")
        else:
            messages.error(request, "That action is not allowed for you on this assessment.")
        return redirect("orasec_supplier_assessment", aid=a.id)
    return render(request, "orasec/posture/supplier_assessment.html", {"a": a, "need": need, "approvals": approvals,
                  "form": form, "decisions": a.decisions.select_related("decided_by"), "can_submit": can_submit,
                  "page_title": a.ref})


# ---------------------------------------------------------------------------
# Risk assessments and risk reviews
# ---------------------------------------------------------------------------
@login_required
def risk_assessments(request):
    items = RiskAssessment.objects.annotate(n_risks=Count("risks", distinct=True), n_opps=Count("opportunities", distinct=True))
    return render(request, "orasec/posture/risk_assessments.html", {"items": items,
                  "can_compliance": is_compliance_officer(request.user), "page_title": "Risk Assessments"})


@compliance_required
def risk_assessment_edit(request, aid=None):
    obj = get_object_or_404(RiskAssessment, id=aid) if aid else None
    form = RiskAssessmentForm(request.POST or None, request.FILES or None, instance=obj)
    if request.method == "POST" and form.is_valid():
        a = form.save(commit=False)
        if not obj:
            a.prepared_by = request.user
        a.save()
        messages.success(request, f"{a.ref} saved.")
        return redirect("orasec_risk_assessment", aid=a.id)
    return _form_page(request, form, obj.ref if obj else "New risk assessment", "orasec_risk_assessments",
                      "Prepared by the Compliance Officer; approved by the Director (top management), who is not the preparer.",
                      multipart=True)


@login_required
def risk_assessment_detail(request, aid):
    a = get_object_or_404(RiskAssessment, id=aid)
    u = request.user
    may_decide = a.status == "submitted" and u.is_superuser and u.id != a.prepared_by_id
    can_submit = a.status in ("draft", "returned") and is_compliance_officer(u)
    if request.method == "POST":
        action = request.POST.get("action")
        if action == "submit" and can_submit:
            a.status, a.submitted_at = "submitted", timezone.now()
            a.save(update_fields=["status", "submitted_at", "updated"])
            messages.success(request, f"{a.ref} submitted to the Director.")
        elif action in ("approve", "return") and may_decide:
            a.status = "approved" if action == "approve" else "returned"
            a.decided_by, a.decided_at, a.decision_note = u, timezone.now(), request.POST.get("note", "")
            a.save(update_fields=["status", "decided_by", "decided_at", "decision_note", "updated"])
            messages.success(request, "Decision recorded.")
        else:
            messages.error(request, "That action is not allowed for you on this assessment.")
        return redirect("orasec_risk_assessment", aid=a.id)
    return render(request, "orasec/posture/risk_assessment_detail.html", {
        "a": a, "risks": a.risks.select_related("owner").all(), "opps": a.opportunities.all(), "may_decide": may_decide,
        "can_submit": can_submit, "can_compliance": is_compliance_officer(u), "page_title": a.ref})


@login_required
def risk_detail(request, rid):
    r = get_object_or_404(RiskRegisterEntry.objects.select_related("owner", "assessment"), id=rid)
    u = request.user
    return render(request, "orasec/posture/risk_detail.html", {
        "r": r, "reviews": r.reviews.select_related("reviewed_by"), "exceptions": r.exceptions.all(),
        "suppliers": r.suppliers.all(), "can_compliance": is_compliance_officer(u),
        "can_review": is_compliance_officer(u) or r.owner_id == u.id, "can_request": can_decide(u), "page_title": r.ref})


@login_required
def risk_review(request, rid):
    r = get_object_or_404(RiskRegisterEntry, id=rid)
    if not (is_compliance_officer(request.user) or r.owner_id == request.user.id):
        messages.error(request, "Only the risk owner or the Compliance Officer can review this risk.")
        return redirect("orasec_risk", rid=r.id)
    form = RiskReviewForm(request.POST or None, initial={
        "likelihood": r.likelihood, "impact": r.impact, "residual_likelihood": r.residual_likelihood,
        "residual_impact": r.residual_impact, "status": r.status})
    if request.method == "POST" and form.is_valid():
        rv = form.save(commit=False)
        rv.risk, rv.reviewed_by = r, request.user
        rv.save()
        r.likelihood, r.impact = rv.likelihood, rv.impact
        r.residual_likelihood, r.residual_impact = rv.residual_likelihood, rv.residual_impact
        r.status, r.review_date, r.last_reviewed = rv.status, rv.next_review, _today()
        r.save()
        messages.success(request, f"Review of {r.ref} recorded.")
        return redirect("orasec_risk", rid=r.id)
    return _form_page(request, form, f"Review {r.ref} {r.title}", "orasec_risks",
                      "Re-score the risk with the controls in place now, note what changed, and set the next review date.")


# ---------------------------------------------------------------------------
# Exceptions and risk acceptances
# ---------------------------------------------------------------------------
@login_required
def exceptions(request):
    _expire_exceptions()
    items = GovernanceException.objects.select_related("requested_by", "risk")
    return render(request, "orasec/posture/exceptions.html", {"items": items, "can_request": can_decide(request.user),
                  "page_title": "Exceptions & Risk Acceptances"})


@login_required
def exception_new(request):
    if not can_decide(request.user):
        messages.error(request, "You cannot request exceptions.")
        return redirect("orasec_exceptions")
    initial = {"risk": request.GET.get("risk"), "supplier": request.GET.get("supplier"),
               "kind": request.GET.get("kind") or "policy_exception", "expiry": _today() + datetime.timedelta(days=90)}
    form = ExceptionForm(request.POST or None, initial=initial)
    if request.method == "POST" and form.is_valid():
        e = form.save(commit=False)
        e.requested_by = request.user
        e.save()
        messages.success(request, f"{e.ref} requested. It needs {e.required_approvals()} approval(s) from people other than you.")
        return redirect("orasec_exception", eid=e.id)
    return _form_page(request, form, "Request an exception or risk acceptance", "orasec_exceptions",
                      "Policy exception: two people who are not the requester, at most 90 days. Risk acceptance by residual band: "
                      "Critical cannot be accepted; High needs two approvers (6 months); Medium and Low one approver (12 months). "
                      "No one accepts a risk they own or requested.")


@login_required
def exception_detail(request, eid):
    e = get_object_or_404(GovernanceException.objects.select_related("risk", "requested_by"), id=eid)
    u = request.user
    st = exception_state(e, u)
    need, approvals, blocked, may_decide, can_close = (st[k] for k in ("need", "approvals", "blocked", "may_decide", "can_close"))
    form = DecisionForm(request.POST or None) if may_decide else None
    if request.method == "POST":
        action = request.POST.get("action")
        if action == "decide" and form is not None and form.is_valid():
            done, text = exception_decide(e, u, form.cleaned_data["decision"], form.cleaned_data["note"])
            (messages.success if done else messages.error)(request, text)
        elif action == "close" and can_close:
            e.status, e.closed_note = "closed", request.POST.get("note", "")
            e.save(update_fields=["status", "closed_note", "updated"])
            messages.success(request, f"{e.ref} closed.")
        else:
            messages.error(request, "That action is not allowed for you.")
        return redirect("orasec_exception", eid=e.id)
    return render(request, "orasec/posture/exception_detail.html", {"e": e, "need": need, "approvals": approvals, "form": form,
                  "blocked": blocked, "decisions": e.decisions.select_related("decided_by"), "can_close": can_close,
                  "page_title": e.ref})


# ---------------------------------------------------------------------------
# Opportunities
# ---------------------------------------------------------------------------
@login_required
def opportunities(request):
    return render(request, "orasec/posture/opportunities.html", {"items": Opportunity.objects.select_related("owner", "assessment"),
                  "can_compliance": is_compliance_officer(request.user), "page_title": "Opportunities"})


@compliance_required
def opportunity_edit(request, oid=None):
    obj = get_object_or_404(Opportunity, id=oid) if oid else None
    form = OpportunityForm(request.POST or None, instance=obj)
    if request.method == "POST" and form.is_valid():
        o = form.save()
        messages.success(request, f"{o.ref} saved.")
        return redirect("orasec_opportunities")
    return _form_page(request, form, f"{obj.ref} {obj.title}" if obj else "New opportunity", "orasec_opportunities",
                      "ISO/IEC 27001 6.1.1: opportunities to improve the ISMS or the business.")


# ---------------------------------------------------------------------------
# Nonconformities and corrective actions (ISO/IEC 27001 10.2)
# ---------------------------------------------------------------------------
@login_required
def nonconformities(request):
    return render(request, "orasec/posture/nonconformities.html", {"items": Nonconformity.objects.select_related("owner", "verified_by"),
                  "today": timezone.localdate(), "can_compliance": is_compliance_officer(request.user), "page_title": "Nonconformities"})


@compliance_required
def nonconformity_edit(request, nid=None):
    obj = get_object_or_404(Nonconformity, id=nid) if nid else None
    form = NonconformityForm(request.POST or None, instance=obj)
    if request.method == "POST" and form.is_valid():
        n = form.save()
        messages.success(request, f"{n.ref} saved.")
        return redirect("orasec_nonconformities")
    return _form_page(request, form, f"{obj.ref} {obj.title}" if obj else "New nonconformity", "orasec_nonconformities",
                      "ISO/IEC 27001 10.2: record what went wrong, fix it, find the cause, take corrective action and check it worked.")


# ---------------------------------------------------------------------------
# Security objectives (ISO/IEC 27001 6.2)
# ---------------------------------------------------------------------------
def _can_update_objective(u, obj):
    return is_compliance_officer(u) or obj.owner_id == u.id


@login_required
def objectives(request):
    if request.method == "POST" and request.POST.get("action") == "measure" and is_compliance_officer(request.user):
        from orasec.posture.objectives import measure_all  # noqa: PLC0415
        measure_all()
        messages.success(request, "Objectives measured.")
        return redirect("orasec_objectives")
    items = SecurityObjective.objects.select_related("owner").prefetch_related("actions")
    return render(request, "orasec/posture/objectives.html", {"items": items, "can_compliance": is_compliance_officer(request.user),
                  "page_title": "Security Objectives"})


@login_required
def objective_detail(request, oid):
    from orasec.posture.objectives import measure  # noqa: PLC0415
    o = get_object_or_404(SecurityObjective.objects.select_related("owner"), id=oid)
    u = request.user
    can_update = _can_update_objective(u, o)
    form = ObjectiveActionForm(request.POST or None, prefix="act", initial={"owner": o.owner_id}) if can_update else None
    if request.method == "POST":
        action = request.POST.get("action")
        if action == "add" and form is not None and form.is_valid():
            a = form.save(commit=False)
            a.objective = o
            a.save()
            measure(o)
            messages.success(request, "Action added.")
        elif action in ("done", "drop", "reopen"):
            a = get_object_or_404(ObjectiveAction, id=request.POST.get("aid"), objective=o)
            if can_update or a.owner_id == u.id:
                a.status = {"done": "done", "drop": "dropped", "reopen": "open"}[action]
                a.done_by, a.done_at = (u, timezone.now()) if action != "reopen" else (None, None)
                a.note = request.POST.get("note", a.note)
                a.save()
                measure(o)
                messages.success(request, "Action updated; objective re-measured.")
            else:
                messages.error(request, "Only the action owner, the objective owner or the Compliance Officer can update this action.")
        elif action == "measure":
            measure(o)
            messages.success(request, "Objective measured.")
        return redirect("orasec_objective", oid=o.id)
    return render(request, "orasec/posture/objective_detail.html", {"o": o, "actions": o.actions.select_related("owner", "done_by"),
                  "form": form, "can_update": can_update, "can_compliance": is_compliance_officer(u), "uid": u.id, "page_title": o.ref})


@compliance_required
def objective_edit(request, oid=None):
    from orasec.posture.objectives import measure  # noqa: PLC0415
    obj = get_object_or_404(SecurityObjective, id=oid) if oid else None
    form = ObjectiveForm(request.POST or None, instance=obj)
    if request.method == "POST" and form.is_valid():
        o = form.save(commit=False)
        if not o.ref:
            nums = [int(r[1:]) for r in SecurityObjective.objects.values_list("ref", flat=True) if r[1:].isdigit()]
            o.ref = f"O{(max(nums) + 1) if nums else 1}"
        o.save()
        measure(o)
        messages.success(request, f"{o.ref} saved.")
        return redirect("orasec_objective", oid=o.id)
    return _form_page(request, form, f"{obj.ref} {obj.title}" if obj else "New security objective", "orasec_objectives",
                      "ISO/IEC 27001 6.2: a measurable target with an owner, a plan and a due date. Automatic measures update every day.")


# ---------------------------------------------------------------------------
# Change register (ISO 27001 6.3 and A.8.32; FWK-001 8.4, PRC-003)
# ---------------------------------------------------------------------------
@login_required
def changes(request):
    qs = ChangeRequest.objects.select_related("requested_by", "owner", "approved_by")
    cat, st = request.GET.get("category", ""), request.GET.get("status", "")
    if cat:
        qs = qs.filter(category=cat)
    if st == "open":
        qs = qs.filter(status__in=["submitted", "approved", "implemented"])
    elif st:
        qs = qs.filter(status=st)
    allc = list(ChangeRequest.objects.all())
    kpi = {
        "awaiting_approval": sum(1 for c in allc if c.status == "submitted" or (c.status == "implemented" and not c.approved_by_id)),
        "approved": sum(1 for c in allc if c.status == "approved"),
        "awaiting_review": sum(1 for c in allc if c.status == "implemented"),
        "overdue": sum(1 for c in allc if c.approval_overdue or c.review_overdue),
        "year": sum(1 for c in allc if c.requested_at >= timezone.now() - datetime.timedelta(days=365)),
    }
    return render(request, "orasec/posture/changes.html", {
        "items": qs, "kpi": kpi, "category": cat, "status": st, "categories": ChangeRequest.CATEGORY,
        "can_raise": can_decide(request.user), "page_title": "Change Register"})


@login_required
def change_edit(request, cid=None):
    c = get_object_or_404(ChangeRequest, id=cid) if cid else None
    if c is None and not can_decide(request.user):
        messages.error(request, "You cannot raise changes.")
        return redirect("orasec_changes")
    if c is not None and not change_permissions(request.user, c)["edit"]:
        messages.error(request, "This change can no longer be edited.")
        return redirect("orasec_change", cid=c.id)
    initial = {"owner": request.user.id, "category": request.GET.get("category") or "infrastructure"}
    form = ChangeForm(request.POST or None, instance=c, initial=None if c else initial)
    if request.method == "POST" and form.is_valid():
        obj = form.save(commit=False)
        if c is None:
            obj.requested_by = request.user
        obj.save()
        if c is None:
            msg = f"{obj.ref} raised. Someone other than you must approve it before it is made."
            if obj.can_go_ahead_unapproved:
                msg = (f"{obj.ref} raised. You can mark it done straight away; it must be approved within "
                       f"{obj.APPROVAL_DAYS[obj.change_type]} business days of the change.")
            messages.success(request, msg)
        else:
            messages.success(request, f"{obj.ref} updated.")
        return redirect("orasec_change", cid=obj.id)
    return _form_page(request, form, f"Edit {c.ref}" if c else "Raise a change", "orasec_changes",
                      "Every ISMS change and every IT change (firewall, network, hosting, servers, releases, security tools, "
                      "access, suppliers) is raised here, approved by someone other than the requester, then reviewed after it is "
                      "done (FWK-001 8.4, PRC-003). Emergency: make the change, record it here, get approval within 2 "
                      "business days.")


@login_required
def change_detail(request, cid):
    c = get_object_or_404(ChangeRequest.objects.select_related("requested_by", "owner", "approved_by", "implemented_by",
                                                                "reviewed_by"), id=cid)
    u = request.user
    perm = change_permissions(u, c)
    form = ChangeStepForm(request.POST or None)
    if request.method == "POST":
        action = request.POST.get("action")
        ok = form.is_valid()
        if ok or action == "cancel":
            done, text = change_action(c, u, action, note=form.cleaned_data.get("note", "") if ok else "",
                                       when=form.cleaned_data.get("when") if ok else None,
                                       result=form.cleaned_data.get("result") if ok else "")
        else:
            done, text = False, "That action is not allowed for you."
        (messages.success if done else messages.error)(request, text)
        return redirect("orasec_change", cid=c.id)
    return render(request, "orasec/posture/change_detail.html", {"c": c, "perm": perm, "form": ChangeStepForm(),
                  "page_title": c.ref})

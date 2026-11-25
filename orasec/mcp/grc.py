"""
Read tools for governance records: changes, exceptions, risks, controls, check results, evidence titles.

Lists are paged (``limit`` / ``offset``). Evidence is titles only: never a file, a link or a description.
Evidence classed Restricted is left out unless ``ORASEC_MCP_RESTRICTED_EVIDENCE_TITLES`` is on.
"""
from __future__ import annotations

from typing import Any

from django.db.models import Q

from orasec.mcp import config
from orasec.ora import tools as ora_tools
from orasec.posture import grc_actions
from orasec.posture.grc_models import ChangeRequest, GovernanceException
from orasec.posture.models import ComplianceControl, ControlCheckResult, ControlEvidence, ControlImplementation, RiskRegisterEntry
from orasec.posture.views import is_compliance_officer

PAGE, PAGE_MAX = 20, 25
NOT_FOUND = {"error": "No record with that reference that you can see."}


def reader(user) -> bool:
    """Who may read governance records through the connector: the security team and the Compliance Officer."""
    return bool(user and user.is_active and (ora_tools.org_wide(user) or is_compliance_officer(user)))


def _name(u) -> str | None:
    return (u.get_full_name() or u.username) if u else None


def _iso(v):
    return v.isoformat() if v else None


def _txt(v, limit=1200) -> str:
    return (v or "")[:limit]


def _paged(qs, args: dict, row) -> dict[str, Any]:
    limit = ora_tools._int(args.get("limit"), PAGE, 1, PAGE_MAX)
    offset = ora_tools._int(args.get("offset"), 0, 0, 100000)
    total = qs.count()
    items = [row(x) for x in qs[offset:offset + limit]]
    nxt = offset + len(items)
    return {"total": total, "offset": offset, "items": items, "next_offset": nxt if nxt < total else None}


# ---------------------------------------------------------------------------
# Change Register
# ---------------------------------------------------------------------------
def _change_row(c) -> dict[str, Any]:
    return {"ref": c.ref, "kind": "change", "title": _txt(c.title, 160), "category": c.category, "type": c.change_type,
            "risk_level": c.risk_level, "status": c.status, "requested_by": _name(c.requested_by),
            "approved_by": _name(c.approved_by), "implemented_by": _name(c.implemented_by),
            "reviewed_by": _name(c.reviewed_by), "planned_date": _iso(c.planned_date), "path": f"/orasec/changes/{c.id}/"}


def _changes():
    return ChangeRequest.objects.select_related("requested_by", "owner", "approved_by", "implemented_by", "reviewed_by")


def find_change(ref: Any):
    r = ora_tools._str(ref, 30)
    return _changes().filter(ref__iexact=r).first() if r else None


def changes(user, args):
    qs = _changes()
    if args.get("status") in dict(ChangeRequest.STATUS):
        qs = qs.filter(status=args["status"])
    text = ora_tools._str(args.get("search"), 80)
    if text:
        qs = qs.filter(Q(title__icontains=text) | Q(ref__icontains=text) | Q(systems__icontains=text))
    return {**_paged(qs, args, _change_row), "path": "/orasec/changes/"}


def change(user, args):
    c = find_change(args.get("ref"))
    if not c:
        return NOT_FOUND
    perm = grc_actions.change_permissions(user, c, independent_review=True)
    return {**_change_row(c), "why": _txt(c.reason), "impact": _txt(c.impact), "plan": _txt(c.plan),
            "resources": _txt(c.resources, 400), "systems": _txt(c.systems, 300), "owner": _name(c.owner),
            "requested_at": _iso(c.requested_at), "approved_at": _iso(c.approved_at), "approval_note": _txt(c.approval_note, 600),
            "implemented_at": _iso(c.implemented_at), "implementation_note": _txt(c.implementation_note, 600),
            "reviewed_at": _iso(c.reviewed_at), "review_result": c.review_result or None, "review_note": _txt(c.review_note, 600),
            "you_may": {"approve_or_reject": perm["approve"], "review": perm["review"], "why_not": perm["why_not"] or None}}


# ---------------------------------------------------------------------------
# Exceptions and risk acceptances
# ---------------------------------------------------------------------------
def _exception_row(e) -> dict[str, Any]:
    return {"ref": e.ref, "kind": "exception", "type": e.kind, "title": _txt(e.title, 160), "policy_ref": _txt(e.policy_ref, 200) or None,
            "risk": e.risk.ref if e.risk_id else None, "score": e.score, "band": e.band, "status": e.status,
            "requested_by": _name(e.requested_by), "start": _iso(e.start), "expiry": _iso(e.expiry),
            "path": f"/orasec/exceptions/{e.id}/"}


def _exceptions():
    return GovernanceException.objects.select_related("requested_by", "risk", "control")


def find_exception(ref: Any):
    r = ora_tools._str(ref, 30)
    return _exceptions().filter(ref__iexact=r).first() if r else None


def exceptions(user, args):
    qs = _exceptions()
    if args.get("status") in dict(GovernanceException.STATUS):
        qs = qs.filter(status=args["status"])
    return {**_paged(qs, args, _exception_row), "path": "/orasec/exceptions/"}


def exception(user, args):
    e = find_exception(args.get("ref"))
    if not e:
        return NOT_FOUND
    st = grc_actions.exception_state(e, user)
    decisions = [{"by": _name(d.decided_by), "decision": d.decision, "at": _iso(d.decided_at)}
                 for d in e.decisions.select_related("decided_by")]
    return {**_exception_row(e), "description": _txt(e.description), "reason": _txt(e.reason, 800),
            "compensating_controls": _txt(e.compensating_controls, 800), "control": e.control.ref if e.control_id else None,
            "approvals_needed": st["need"], "approvals_so_far": st["approvals"], "decisions": decisions,
            "you_may": {"decide": st["may_decide"], "why_not": st["blocked"] or None}}


# ---------------------------------------------------------------------------
# Risk register (the list is the existing ``risk_register`` tool)
# ---------------------------------------------------------------------------
def risks(user, args):
    qs = RiskRegisterEntry.objects.select_related("owner")
    if args.get("status") in dict(RiskRegisterEntry.STATUS):
        qs = qs.filter(status=args["status"])

    def row(r):
        score = r.likelihood * r.impact
        return {"ref": r.ref, "kind": "risk", "title": _txt(r.title, 160), "score": score, "level": ora_tools._level(score),
                "treatment": r.treatment, "status": r.status, "owner": _name(r.owner), "review_due": _iso(r.review_date),
                "path": f"/orasec/risks/{r.id}/"}
    return {**_paged(qs, args, row), "path": "/orasec/risks/"}


def risk(user, args):
    ref = ora_tools._str(args.get("ref"), 30)
    r = RiskRegisterEntry.objects.select_related("owner").filter(ref__iexact=ref).first() if ref else None
    if not r:
        return NOT_FOUND
    score = r.likelihood * r.impact
    residual = (r.residual_likelihood or 0) * (r.residual_impact or 0) or None
    return {"ref": r.ref, "kind": "risk", "title": _txt(r.title, 200), "description": _txt(r.description), "category": r.category or None,
            "scope": _txt(r.scope, 200) or None, "threat": _txt(r.threat, 600), "weakness": _txt(r.vulnerability, 600),
            "existing_controls": _txt(r.existing_controls, 800), "likelihood": r.likelihood, "impact": r.impact, "score": score,
            "level": ora_tools._level(score), "residual_score": residual, "treatment": r.treatment,
            "treatment_plan": _txt(r.treatment_plan, 800), "status": r.status, "owner": _name(r.owner),
            "review_due": _iso(r.review_date), "last_reviewed": _iso(r.last_reviewed),
            "controls": list(r.controls.values_list("ref", flat=True)[:30]),
            "exceptions": list(r.exceptions.values_list("ref", flat=True)[:10]), "path": f"/orasec/risks/{r.id}/"}


# ---------------------------------------------------------------------------
# Controls, check results, evidence titles
# ---------------------------------------------------------------------------
def _control_row(i) -> dict[str, Any]:
    c = i.control
    return {"ref": c.ref, "kind": "control", "title": _txt(c.title, 160), "category": c.category, "applicable": i.applicable,
            "status": i.status, "check": i.auto_status, "owner": _name(i.owner), "review_due": _iso(i.review_due),
            "path": f"/orasec/compliance/controls/{c.id}/"}


def _implementations():
    return ControlImplementation.objects.select_related("control", "owner").order_by("control__sort_key", "control__ref")


def controls(user, args):
    qs = _implementations()
    if args.get("status") in dict(ControlImplementation.STATUS_CHOICES):
        qs = qs.filter(status=args["status"])
    if args.get("check") in dict(ControlImplementation.AUTO_CHOICES):
        qs = qs.filter(auto_status=args["check"])
    text = ora_tools._str(args.get("search"), 80)
    if text:
        qs = qs.filter(Q(control__ref__icontains=text) | Q(control__title__icontains=text))
    return {**_paged(qs, args, _control_row), "path": "/orasec/compliance/"}


def _evidence_qs(control=None):
    qs = ControlEvidence.objects.select_related("control")
    if control is not None:
        qs = qs.filter(control=control)
    return qs


def _evidence_rows(qs, args) -> dict[str, Any]:
    withheld = 0
    if not config.restricted_evidence_titles():
        withheld = qs.filter(classification="restricted").count()
        qs = qs.exclude(classification="restricted")
    out = _paged(qs, args, lambda e: {"title": _txt(e.title, 200), "control": e.control.ref, "classification": e.classification,
                                      "source": e.source, "collected": _iso(e.collected_at), "valid_until": _iso(e.valid_until)})
    out["restricted_items_withheld"] = withheld
    out["note"] = "Titles only. Files, links and descriptions of evidence are never returned here."
    return out


def control(user, args):
    ref = ora_tools._str(args.get("ref"), 20)
    i = _implementations().filter(control__ref__iexact=ref).first() if ref else None
    if not i:
        return NOT_FOUND
    c = i.control
    checks = [{"at": _iso(r.evaluated_at), "result": r.result, "detail": _txt(r.detail, 300)} for r in c.check_results.all()[:5]]
    ev = _evidence_rows(_evidence_qs(c), {"limit": 15})
    return {**_control_row(i), "summary": _txt(c.summary, 600), "why_included_or_excluded": _txt(i.justification, 600),
            "implementation_notes": _txt(i.implementation_notes, 1000), "check_detail": _txt(i.auto_detail, 400),
            "checked_at": _iso(i.auto_evaluated_at), "last_reviewed": _iso(i.last_reviewed), "recent_checks": checks,
            "evidence_titles": ev["items"], "evidence_total": ev["total"], "restricted_items_withheld": ev["restricted_items_withheld"]}


def check_results(user, args):
    ref = ora_tools._str(args.get("control"), 20)
    if ref:
        c = ComplianceControl.objects.filter(ref__iexact=ref).first()
        if not c:
            return NOT_FOUND
        qs = ControlCheckResult.objects.filter(control=c)
        return {"control": c.ref, **_paged(qs, args, lambda r: {"at": _iso(r.evaluated_at), "result": r.result,
                                                                 "detail": _txt(r.detail, 300)})}
    wanted = [args["result"]] if args.get("result") in ("pass", "warn", "fail") else ["fail", "warn"]
    qs = _implementations().filter(applicable=True, auto_status__in=wanted)
    return {"showing": wanted, **_paged(qs, args, lambda i: {"ref": i.control.ref, "kind": "control", "title": _txt(i.control.title, 160),
                                                             "result": i.auto_status, "detail": _txt(i.auto_detail, 300),
                                                             "checked_at": _iso(i.auto_evaluated_at),
                                                             "path": f"/orasec/compliance/controls/{i.control_id}/"})}


def evidence(user, args):
    ref = ora_tools._str(args.get("control"), 20)
    c = None
    if ref:
        c = ComplianceControl.objects.filter(ref__iexact=ref).first()
        if not c:
            return NOT_FOUND
    return _evidence_rows(_evidence_qs(c), args)

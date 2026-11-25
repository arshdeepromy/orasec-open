"""
Approval rules and decision steps for the Change Register and for exceptions.

One place for the rules, used by the web pages (``grc_views``) and by the connector
endpoint (``orasec.mcp``), so a decision follows the same checks however it is made.

Segregation of duties (FWK-001 5.3): no one approves or reviews their own change,
and no one decides an exception they requested or a risk they own.
"""
import datetime

from django.db import transaction
from django.utils import timezone

from orasec.posture.grc_models import ExceptionDecision
from orasec.posture.views import is_compliance_officer

DIRECTOR_GROUP = "Director"
NOT_ALLOWED = "That action is not allowed for you."


def can_decide(u):
    """People who may approve: the Director (superuser), staff and the Compliance Officer role."""
    return bool(u.is_authenticated and u.is_active and (u.is_superuser or u.is_staff or is_compliance_officer(u)))


def is_director(u):
    return bool(u.is_authenticated and u.is_active and u.is_superuser and u.groups.filter(name=DIRECTOR_GROUP).exists())


def change_permissions(u, c, *, independent_review=False):
    """What this person may do with this change. Nobody approves or reviews a change they raised or made:
    the Director's changes are approved by the Cloud Infrastructure Engineer and the other way round.

    ``independent_review=True`` also keeps the requester and the approver from reviewing the change,
    so requester, approver and reviewer are three different people."""
    p = {"approve": False, "implement": False, "review": False, "cancel": False, "edit": False, "why_not": ""}
    if not (u.is_authenticated and u.is_active):
        return p
    own = u.id == c.requested_by_id
    awaiting_approval = c.status == "submitted" or (c.status == "implemented" and not c.approved_by_id)
    if awaiting_approval and can_decide(u):
        if own:
            p["why_not"] = "You raised this change, so someone else must approve it."
        elif u.id == c.implemented_by_id:
            p["why_not"] = "You made this change, so someone else must approve it."
        else:
            p["approve"] = True
    worker = own or u.id == c.owner_id or u.is_superuser or u.is_staff
    p["implement"] = bool(worker and (c.status == "approved" or (c.status == "submitted" and c.can_go_ahead_unapproved)))
    if c.status == "implemented" and c.approved_by_id and can_decide(u):
        self_approved = c.requested_by_id and c.requested_by_id == c.approved_by_id
        if u.id == c.implemented_by_id:
            p["why_not"] = p["why_not"] or "You made this change, so someone else reviews it."
        elif self_approved and u.id == c.requested_by_id:
            p["why_not"] = p["why_not"] or "You raised and approved this change, so someone else reviews it."
        elif independent_review and u.id == c.requested_by_id:
            p["why_not"] = p["why_not"] or "You raised this change, so someone else reviews it."
        elif independent_review and u.id == c.approved_by_id:
            p["why_not"] = p["why_not"] or "You approved this change, so someone else reviews it."
        else:
            p["review"] = True
    p["cancel"] = c.status in ("submitted", "approved") and (own or u.is_superuser)
    p["edit"] = c.status == "submitted" and (own or is_compliance_officer(u))
    return p


def change_action(c, u, action, *, note="", when=None, result="", independent_review=False):
    """Apply one step (approve, reject, implement, review, cancel) to a change as this person.

    Returns ``(done, message)``. Nothing is saved unless ``change_permissions`` allows the step."""
    perm = change_permissions(u, c, independent_review=independent_review)
    now = timezone.now()
    when = when or now
    if action in ("approve", "reject") and perm["approve"]:
        if action == "reject":
            if c.status == "implemented":
                return False, "This change is already done. Approve it, or raise a new change to undo it."
            c.status, c.approved_at = "rejected", now
            c.approval_note = f"Rejected by {u.get_full_name() or u.username}. {note}".strip()
        else:
            if c.status == "submitted":
                c.status = "approved"
            c.approved_by, c.approved_at, c.approval_note = u, now, note
        c.save()
        return True, f"{c.ref} {'approved' if action == 'approve' else 'rejected'}."
    if action == "implement" and perm["implement"]:
        if when > now + datetime.timedelta(minutes=5):
            return False, "The change cannot be done in the future."
        c.status, c.implemented_by, c.implemented_at, c.implementation_note = "implemented", u, when, note
        c.save()
        return True, f"{c.ref} marked done." + ("" if c.approved_by_id else
                                                 f" It still needs approval by {c.approval_due:%d %b %Y}.")
    if action == "review" and perm["review"]:
        if not result or not note.strip():
            return False, "Choose the result and say how you checked it."
        c.status, c.reviewed_by, c.reviewed_at, c.review_result, c.review_note = "closed", u, now, result, note
        c.save()
        return True, f"{c.ref} reviewed and closed."
    if action == "cancel" and perm["cancel"]:
        c.status = "cancelled"
        c.review_note = note or c.review_note
        c.save()
        return True, f"{c.ref} cancelled."
    return False, NOT_ALLOWED


def exception_state(e, u):
    """What this person may do with this exception or risk acceptance."""
    need = e.required_approvals()
    approvals = e.decisions.filter(decision="approve").count()
    blocked = ""
    if u.id == e.requested_by_id:
        blocked = "You requested this, so you cannot decide it."
    elif e.kind == "risk_acceptance" and e.risk and e.risk.owner_id == u.id:
        blocked = "You own this risk, so you cannot accept it."
    may_decide = bool(e.status == "requested" and can_decide(u) and not blocked and need
                      and not e.decisions.filter(decided_by=u).exists())
    can_close = e.status in ("approved", "expired") and (is_compliance_officer(u) or u.id == e.requested_by_id)
    return {"need": need, "approvals": approvals, "blocked": blocked, "may_decide": may_decide, "can_close": can_close}


@transaction.atomic
def exception_decide(e, u, decision, note=""):
    """Record this person's decision (approve or reject). Returns ``(done, message)``."""
    st = exception_state(e, u)
    if not st["may_decide"] or decision not in ("approve", "reject"):
        return False, st["blocked"] or NOT_ALLOWED
    ExceptionDecision.objects.create(exception=e, decided_by=u, decision=decision, note=note)
    if decision == "reject":
        e.status = "rejected"
    elif st["approvals"] + 1 >= st["need"]:
        e.status = "approved"
        if e.kind == "risk_acceptance" and e.risk:
            e.risk.status = "accepted"
            e.risk.save(update_fields=["status", "updated"])
    e.save(update_fields=["status", "updated"])
    return True, "Decision recorded."

"""
Two-step writes: propose, then confirm.

``propose`` checks the request against the person's permissions and returns a preview with a
one-time proposal id. The id belongs to that person and expires after a few minutes.
``confirm`` runs the proposal once, through the same helpers the web pages use
(``orasec.ora.actions.execute`` and ``orasec.posture.grc_actions``), and every permission is
checked again at that moment. The write is recorded under the person's name.
"""
from __future__ import annotations

import datetime
import logging
import uuid
from typing import Any

import crum
from django.core.exceptions import ObjectDoesNotExist
from django.db import transaction
from django.utils import timezone

from orasec.mcp import config, grc
from orasec.mcp.models import McpProposal
from orasec.ora import actions as ora_actions
from orasec.ora import guardrails
from orasec.ora.vault import Vault
from orasec.posture import grc_actions
from orasec.posture.grc_models import ChangeRequest, GovernanceException

logger = logging.getLogger(__name__)
MARK = " [via connector]"
VIA = "Connector"
# The data level each kind of change belongs to (a kind is offered only when its level is switched on).
ORA_KIND_LEVEL = {
    "assign": "findings", "note": "findings", "close": "findings", "create_risk": "findings", "link_risk": "findings",
    "campaign": "findings", "recompute_priorities": "status", "run_connector": "status",
    "start_leaver": "people", "leaver_step": "people", "leaver_reassign": "people", "leaver_signoff": "people",
}
GRC_KINDS = ("change_approve", "change_reject", "change_review", "exception_approve", "exception_reject")
REVIEW_RESULTS = dict(ChangeRequest.RESULT)


class Declined(Exception):  # noqa: N818 -- an answer to the caller, not a program error
    pass


def ora_kinds(user) -> list[str]:
    on = config.levels()
    return [k for k in ora_actions.allowed_kinds(user) if ORA_KIND_LEVEL.get(k) in on]


def may_decide(user) -> bool:
    return "grc" in config.levels() and grc_actions.can_decide(user) and grc.reader(user)


def _store(ctx, kind: str, card: dict, payload: dict) -> dict[str, Any]:
    minutes = config.proposal_minutes()
    prop = McpProposal.objects.create(user=ctx.user, kind=kind, card=card, payload=payload, client_name=ctx.client_name[:120],
                                      expires_at=timezone.now() + datetime.timedelta(minutes=minutes))
    return {"proposal_id": str(prop.id), "expires_in_seconds": minutes * 60, "preview": card,
            "next_step": "Nothing has changed yet. Show this preview to the person; call confirm_action with the "
                         "proposal_id only if they agree. The id works once and only for this person."}


def propose_action(ctx, args) -> dict[str, Any]:
    kind = str(args.get("kind") or "")
    if kind not in ora_kinds(ctx.user):
        return {"error": "That action is not available to you."}
    params = args.get("params") if isinstance(args.get("params"), dict) else {}
    try:
        card, payload = ora_actions.build(kind, params, ctx.user, Vault())
    except ora_actions.Clarify as c:
        return {"error": c.message}
    except PermissionError:
        return {"error": "You are not allowed to do that."}
    return _store(ctx, kind, card, payload)


def propose_decision(ctx, args) -> dict[str, Any]:
    user = ctx.user
    if not may_decide(user):
        return {"error": "You cannot decide changes or exceptions."}
    ref = str(args.get("ref") or "").strip().upper()
    decision = args.get("decision")
    note = guardrails.scrub_secrets(str(args.get("note") or "").strip())[:2000]
    if ref.startswith("CHG-"):
        c = grc.find_change(ref)
        if not c:
            return grc.NOT_FOUND
        perm = grc_actions.change_permissions(user, c, independent_review=True)
        if decision in ("approve", "reject"):
            if not perm["approve"]:
                return {"error": perm["why_not"] or grc_actions.NOT_ALLOWED}
            if decision == "reject" and c.status == "implemented":
                return {"error": "This change is already done. Approve it, or raise a new change to undo it."}
            lines = [{"label": "Change", "value": f"{c.ref} {c.title[:120]}"}, {"label": "Raised by", "value": grc._name(c.requested_by) or "—"}]
            payload = {"change_id": c.id, "note": note}
        elif decision == "review":
            if not perm["review"]:
                return {"error": perm["why_not"] or grc_actions.NOT_ALLOWED}
            result = args.get("result")
            if result not in REVIEW_RESULTS or not note:
                return {"error": "A review needs a result (successful, issues, failed or rolled_back) and a note saying how you checked it."}
            lines = [{"label": "Change", "value": f"{c.ref} {c.title[:120]}"}, {"label": "Result", "value": REVIEW_RESULTS[result]}]
            payload = {"change_id": c.id, "note": note, "result": result}
        else:
            return {"error": "For a change, the decision is approve, reject or review."}
        if note:
            lines.append({"label": "Note", "value": note})
        card = {"title": f"{decision.capitalize()} {c.ref}", "lines": lines, "confirm": decision.capitalize(),
                "danger": decision == "reject"}
        return _store(ctx, f"change_{decision}", card, payload)
    if ref.startswith("EXC-"):
        e = grc.find_exception(ref)
        if not e:
            return grc.NOT_FOUND
        if decision not in ("approve", "reject"):
            return {"error": "For an exception, the decision is approve or reject."}
        st = grc_actions.exception_state(e, user)
        if not st["may_decide"]:
            return {"error": st["blocked"] or grc_actions.NOT_ALLOWED}
        lines = [{"label": "Exception", "value": f"{e.ref} {e.title[:120]}"},
                 {"label": "Requested by", "value": grc._name(e.requested_by) or "—"},
                 {"label": "Approvals", "value": f"{st['approvals']} of {st['need']} so far"}]
        if note:
            lines.append({"label": "Note", "value": note})
        card = {"title": f"{decision.capitalize()} {e.ref}", "lines": lines, "confirm": decision.capitalize(),
                "danger": decision == "reject"}
        return _store(ctx, f"exception_{decision}", card, {"exception_id": e.id, "note": note})
    return {"error": "Give the reference of a change (CHG-…) or an exception (EXC-…)."}


def _run(prop: McpProposal, user) -> dict[str, Any]:
    kind, p = prop.kind, prop.payload or {}
    if kind in ORA_KIND_LEVEL:
        if kind not in ora_kinds(user):
            raise PermissionError(kind)
        return ora_actions.execute(prop, user, via=VIA)
    if kind in GRC_KINDS:
        if not may_decide(user):
            raise PermissionError(kind)
        note = ((p.get("note") or "") + MARK).strip()
        with crum.impersonate(user):
            if kind.startswith("change_"):
                c = ChangeRequest.objects.select_for_update().get(id=p["change_id"])
                done, text = grc_actions.change_action(c, user, kind.removeprefix("change_"), note=note,
                                                       result=p.get("result") or "", independent_review=True)
                path = f"/orasec/changes/{c.id}/"
            else:
                e = GovernanceException.objects.select_for_update().get(id=p["exception_id"])
                done, text = grc_actions.exception_decide(e, user, kind.removeprefix("exception_"), note)
                path = f"/orasec/exceptions/{e.id}/"
        if not done:
            raise Declined(text)
        return {"ok": True, "message": text, "path": path}
    raise PermissionError(kind)


def confirm_action(ctx, args) -> dict[str, Any]:
    user = ctx.user
    try:
        pid = uuid.UUID(str(args.get("proposal_id") or ""))
    except ValueError:
        return {"error": "There is no such proposal for you."}
    now = timezone.now()
    with transaction.atomic():
        prop = McpProposal.objects.select_for_update().filter(id=pid, user=user).first()
        if not prop:
            return {"error": "There is no such proposal for you."}
        if prop.status != "pending":
            return {"error": "This proposal was already used. Propose the change again if it is still needed."}
        if prop.expires_at <= now:
            prop.status = "expired"
            prop.save(update_fields=["status"])
            return {"error": "This proposal has expired. Propose the change again."}
        # Used from this moment on, whatever happens next: a proposal id never works twice.
        prop.status, prop.decided_at = "confirmed", now
        prop.save(update_fields=["status", "decided_at"])
    try:
        with transaction.atomic():
            result = _run(prop, user)
    except (PermissionError, ObjectDoesNotExist):   # also: the record is no longer one this person can see
        result = {"error": "You are not allowed to do that (any more)."}
    except Declined as d:
        result = {"error": str(d)}
    except Exception:  # noqa: BLE001 -- the caller gets a plain answer, the log gets the detail
        logger.exception("mcp: proposal %s (%s) failed", prop.id, prop.kind)
        result = {"error": "The change could not be made. Nothing was changed."}
    prop.result = result
    if "error" in result:
        prop.status = "failed"
    prop.save(update_fields=["result", "status"])
    return {**result, "kind": prop.kind, "made_as": user.get_full_name() or user.username, "made_through": "connector"}

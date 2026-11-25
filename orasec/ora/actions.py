"""Changes Ora can prepare. Nothing runs until the user presses Confirm on the card.

``build`` turns the AI's proposal into a checked card (ids must exist and be
visible to the user, values in range, permission held); ``execute`` runs a
confirmed proposal with the same helpers the web pages use, attributed to the
user. Permissions mirror the web UI: risk register, campaigns and connectors
are superuser-only; assigning to someone else and recomputing priorities need
security-team access; notes and closing need edit rights on the finding.
"""
from __future__ import annotations

import datetime
import logging
import re
from typing import Any

from django.db import transaction
from django.utils import timezone

from orasec.ora import guardrails, tools
from orasec.ora.models import OraProposal

logger = logging.getLogger(__name__)
MAX_FINDINGS = 50
REASONS = {"mitigated": "Mitigated (fixed)", "false_positive": "False positive", "out_of_scope": "Out of scope"}
TREATMENTS = {"mitigate", "accept", "transfer", "avoid"}


class Clarify(Exception):  # noqa: N818 -- a question back to the user, not an error
    def __init__(self, message: str, quick_replies: list[dict[str, str]] | None = None):
        super().__init__(message)
        self.message = message
        self.quick_replies = quick_replies or []


def allowed_kinds(user) -> list[str]:
    kinds = ["assign", "note", "close"]
    if tools.org_wide(user):
        kinds.append("recompute_priorities")
    if user.is_superuser:
        kinds += ["create_risk", "link_risk", "campaign", "run_connector",
                  "start_leaver", "leaver_step", "leaver_reassign", "leaver_signoff"]
    return kinds


def _can_edit(user, f) -> bool:
    if tools.org_wide(user):
        return True
    try:
        from orasec.authorization.authorization import user_has_permission  # noqa: PLC0415
        from orasec.authorization.roles_permissions import Permissions  # noqa: PLC0415

        return user_has_permission(user, f, Permissions.Finding_Edit)
    except Exception:  # noqa: BLE001
        return False


def _ids(v) -> list[int]:
    if isinstance(v, (int, str)):
        v = [v]
    out = []
    for x in v if isinstance(v, list) else []:
        m = re.match(r"^\s*(?:F-)?(\d{1,9})\s*$", str(x))
        if m and int(m.group(1)) not in out:
            out.append(int(m.group(1)))
    return out


def _findings(user, ids: list[int], *, active: bool | None = True):
    if not ids:
        raise Clarify("Which findings? Tell me the finding numbers, or ask me to look them up first.")
    if len(ids) > MAX_FINDINGS:
        raise Clarify(f"I can do up to {MAX_FINDINGS} findings in one go. For more, use bulk edit on the findings list.")
    qs = tools.findings_for(user).filter(id__in=ids).select_related("test__engagement__product", "priority")
    if active is not None:
        qs = qs.filter(active=active)
    fs = list(qs)
    missing = sorted(set(ids) - {f.id for f in fs})
    if missing:
        what = "open findings you can see" if active else "findings you can see"
        raise Clarify(f"I couldn't find {', '.join('F-' + str(i) for i in missing[:5])} among the {what}.")
    return fs


def _clean(text: Any, limit: int) -> str:
    return guardrails.scrub(str(text or "").strip())[:limit]


def _person(user, who: Any, vault):
    from orasec.models import OraSec_User  # noqa: PLC0415

    w = str(who or "").strip()
    if not w or w.lower() in ("me", "myself", "i"):
        return user
    real = vault.lookup(w) if w.startswith("[") else None
    if w.startswith("[") and not real:
        raise Clarify("Who should I assign them to? Tell me their name.")
    name = (real or w).strip()
    qs = OraSec_User.objects.filter(is_active=True)
    first, _, last = name.partition(" ")
    hit = list(qs.filter(username__iexact=name)[:2]) or \
        (list(qs.filter(first_name__iexact=first, last_name__iexact=last)[:2]) if last else []) or \
        list(qs.filter(first_name__iexact=name)[:2])
    if len(hit) != 1:
        raise Clarify("I couldn't tell which person you mean. Give me their username or full name.")
    return hit[0]


def _name(u) -> str:
    return u.get_full_name() or u.username


def _rows(fs) -> list[dict[str, Any]]:
    return [{"ref": f"F-{f.id}", "title": f.title[:120], "severity": f.severity, "path": f"/finding/{f.id}"} for f in fs[:8]]


def build(kind: str, p: dict[str, Any], user, vault) -> tuple[dict[str, Any], dict[str, Any]]:
    """(card, payload) for a proposal, or raises Clarify / PermissionError."""
    if kind not in allowed_kinds(user):
        raise PermissionError(kind)

    if kind == "assign":
        fs = _findings(user, _ids(p.get("finding_ids")))
        who = _person(user, p.get("assignee"), vault)
        if who != user and not tools.org_wide(user):
            raise PermissionError("assign_others")
        payload = {"finding_ids": [f.id for f in fs], "assignee_id": who.id}
        card = {"title": f"Assign {len(fs)} finding{'s' if len(fs) != 1 else ''}",
                "lines": [{"label": "To", "value": "You" if who == user else _name(who)}],
                "items": _rows(fs), "confirm": "Assign"}
        return card, payload

    if kind == "note":
        fs = _findings(user, _ids(p.get("finding_id")), active=None)
        text = _clean(p.get("text"), 2000)
        if not text:
            raise Clarify("What should the note say?")
        if not _can_edit(user, fs[0]):
            raise PermissionError("note")
        return ({"title": f"Add a note to F-{fs[0].id}", "lines": [{"label": "Note", "value": text}],
                 "items": _rows(fs), "confirm": "Add note"}, {"finding_id": fs[0].id, "text": text})

    if kind == "close":
        fs = _findings(user, _ids(p.get("finding_ids")))
        reason = p.get("reason") if p.get("reason") in REASONS else None
        note = _clean(p.get("note"), 2000)
        if not reason:
            raise Clarify("Why are they being closed?", [{"label": REASONS[r], "text": f"Close them as {REASONS[r].lower()}"} for r in REASONS])
        if not note:
            raise Clarify("Add a short note: how was it fixed, or why is it a false positive / out of scope?")
        if any(not _can_edit(user, f) for f in fs):
            raise PermissionError("close")
        return ({"title": f"Close {len(fs)} finding{'s' if len(fs) != 1 else ''}", "danger": True,
                 "lines": [{"label": "Reason", "value": REASONS[reason]}, {"label": "Note", "value": note}],
                 "items": _rows(fs), "confirm": "Close findings",
                 "warning": "They leave the open counts. If a later scan still finds them, they reopen."},
                {"finding_ids": [f.id for f in fs], "reason": reason, "note": note})

    if kind == "create_risk":
        title = _clean(p.get("title"), 300)
        try:
            lik, imp = int(p.get("likelihood")), int(p.get("impact"))
        except (TypeError, ValueError):
            lik = imp = 0
        if not title:
            raise Clarify("What should the risk be called?")
        if not (1 <= lik <= 5 and 1 <= imp <= 5):
            raise Clarify("What likelihood and impact (1-5 each)? I can evaluate it from the findings if you like.",
                          [{"label": "Evaluate it", "text": "Evaluate the risk from the findings"}])
        treat = p.get("treatment") if p.get("treatment") in TREATMENTS else "mitigate"
        fids = _ids(p.get("finding_ids"))
        fs = _findings(user, fids, active=None) if fids else []
        prods = {f.test.engagement.product_id for f in fs}
        payload = {"title": title, "description": _clean(p.get("description"), 4000), "likelihood": lik, "impact": imp,
                   "treatment": treat, "treatment_plan": _clean(p.get("treatment_plan"), 2000),
                   "finding_ids": [f.id for f in fs], "product_id": prods.pop() if len(prods) == 1 else None}
        score = lik * imp
        lines = [{"label": "Rating", "value": f"Likelihood {lik} × impact {imp} = {score} ({tools._level(score)})"},
                 {"label": "Treatment", "value": treat.capitalize()}]
        if payload["treatment_plan"]:
            lines.append({"label": "Plan", "value": payload["treatment_plan"]})
        lines.append({"label": "Owner", "value": "You (change it on the risk page)"})
        return ({"title": f"Add risk: {title[:90]}", "lines": lines, "items": _rows(fs), "confirm": "Add to register"}, payload)

    if kind == "link_risk":
        from orasec.posture.models import RiskRegisterEntry  # noqa: PLC0415

        rid = str(p.get("risk_id") or "").strip()
        risk = (RiskRegisterEntry.objects.filter(id=int(rid)).first() if rid.isdigit() else
                RiskRegisterEntry.objects.filter(ref__iexact=rid).first())
        if not risk:
            raise Clarify("Which risk? Give me its reference, like R-004.")
        fs = _findings(user, _ids(p.get("finding_ids")), active=None)
        return ({"title": f"Link {len(fs)} finding{'s' if len(fs) != 1 else ''} to {risk.ref}",
                 "lines": [{"label": "Risk", "value": f"{risk.ref} {risk.title[:100]}"}], "items": _rows(fs),
                 "confirm": "Link"}, {"risk_id": risk.id, "finding_ids": [f.id for f in fs]})

    if kind == "campaign":
        name = _clean(p.get("name"), 200)
        comp = _clean(p.get("component"), 200)
        try:
            target = datetime.date.fromisoformat(str(p.get("target_date")))
        except ValueError:
            target = None
        if not name:
            raise Clarify("What should the campaign be called?")
        if not target or target < timezone.localdate():
            raise Clarify("What's the target date (a future date)?")
        n = tools._open(tools.findings_for(user)).filter(component_name=comp).count() if comp else 0
        return ({"title": f"Start campaign: {name[:90]}",
                 "lines": [{"label": "Component", "value": comp or "—"}, {"label": "Open findings now", "value": str(n)},
                           {"label": "Target", "value": target.isoformat()}, {"label": "Owner", "value": "You"}],
                 "confirm": "Start campaign"},
                {"name": name, "component": comp, "target_date": target.isoformat(),
                 "description": _clean(p.get("description"), 2000)})

    if kind == "run_connector":
        from orasec.posture.models import Connector  # noqa: PLC0415

        c = Connector.objects.filter(id=tools._int(p.get("connector_id"), 0)).first()
        if not c:
            raise Clarify("Which connector? Ask me for the connector health first and I'll list them.")
        return ({"title": f"Run {c.name} now", "lines": [{"label": "Last status", "value": c.last_status or "never run"}],
                 "confirm": "Run now"}, {"connector_id": c.id})

    if kind in ("start_leaver", "leaver_step", "leaver_reassign", "leaver_signoff"):
        return _leaver_card(kind, p, user, vault)

    if kind == "recompute_priorities":
        return ({"title": "Recalculate priorities", "lines": [{"label": "What", "value":
                 "Refresh KEV/EPSS on findings, re-score every open finding and re-run triage rules (takes a few minutes)."}],
                 "confirm": "Recalculate"}, {})

    raise PermissionError(kind)


def _leaver_rec(p):
    from orasec.posture.grc_models import LeaverRecord  # noqa: PLC0415
    r = LeaverRecord.objects.filter(ref__iexact=str(p.get("ref") or "").strip()).select_related("person").first()
    if not r:
        raise Clarify("Which leaver record (LVR-…)? Ask me to list the open leaver records first.")
    return r


def _leaver_card(kind, p, user, vault):
    from orasec.posture import leavers  # noqa: PLC0415
    from orasec.posture.grc_models import LEAVER_STEPS  # noqa: PLC0415
    if kind == "start_leaver":
        who = _person(user, p.get("person"), vault)
        if who == user:
            raise Clarify("You can't start your own leaver record; ask another admin.")
        kind_ = "mover" if str(p.get("type") or "").lower() == "mover" else "leaver"
        try:
            date = datetime.date.fromisoformat(str(p.get("leaving_date"))) if p.get("leaving_date") else timezone.localdate()
        except ValueError:
            raise Clarify("What is the leaving date (YYYY-MM-DD)?") from None
        assets = leavers.owned_assets(who)
        return ({"title": f"Start {kind_} record: {_name(who)}",
                 "lines": [{"label": "Leaving", "value": date.isoformat()},
                           {"label": "Assets to hand over", "value": str(len(assets))},
                           {"label": "Checklist", "value": f"{len(LEAVER_STEPS)} steps (FRM-002)"},
                           {"label": "Note", "value": "Does not deactivate the account; do that in user settings."}],
                 "confirm": "Start record"},
                {"person_id": who.id, "kind": kind_, "leaving_date": date.isoformat(), "reason": _clean(p.get("reason"), 500)})
    r = _leaver_rec(p)
    if r.status != "open":
        raise Clarify(f"{r.ref} is already {r.get_status_display().lower()}.")
    if kind == "leaver_step":
        key = str(p.get("step") or "")
        step = next((s for s in r.steps if s["key"] == key), None)
        if not step:
            raise Clarify("Which step? " + ", ".join(f"{s['key']} ({s['label'][:40]})" for s in r.steps if not s["done"]))
        if user.id == r.person_id:
            raise PermissionError(kind)
        return ({"title": f"{r.ref}: mark step done", "lines": [{"label": "Step", "value": step["label"]},
                 {"label": "Note", "value": _clean(p.get("note"), 300) or "—"}], "confirm": "Mark done"},
                {"ref": r.ref, "step": key, "note": _clean(p.get("note"), 500)})
    if kind == "leaver_reassign":
        who = _person(user, p.get("new_owner"), vault)
        pend = leavers.pending_assets(r)
        if not pend:
            raise Clarify(f"No assets on {r.ref} need a new owner.")
        return ({"title": f"{r.ref}: move {len(pend)} asset{'s' if len(pend) != 1 else ''} to {_name(who)}",
                 "lines": [{"label": "From", "value": _name(r.person)}, {"label": "To", "value": _name(who)}],
                 "items": [{"ref": f"A-{a.id}", "title": a.name, "path": f"/orasec/inventory/{a.id}/"} for a in pend[:20]],
                 "confirm": "Move assets"}, {"ref": r.ref, "new_owner_id": who.id})
    if kind == "leaver_signoff":
        if user.id in (r.person_id, r.started_by_id):
            raise Clarify("Sign-off must be by someone other than the leaver and whoever started the record.")
        if not r.complete:
            raise Clarify(f"{r.ref} still has {len(r.steps) - r.done_count} open step(s).")
        return ({"title": f"Sign off {r.ref} ({_name(r.person)})",
                 "lines": [{"label": "Checklist", "value": f"{r.done_count}/{len(r.steps)} done"}], "confirm": "Sign off"},
                {"ref": r.ref, "note": _clean(p.get("note"), 500)})
    raise PermissionError(kind)


def _leaver_exec(kind, p, user):
    from orasec.models import OraSec_User  # noqa: PLC0415
    from orasec.posture import leavers  # noqa: PLC0415
    try:
        if kind == "start_leaver":
            who = OraSec_User.objects.get(id=p["person_id"])
            r = leavers.start(who, by=user, kind=p["kind"], leaving_date=datetime.date.fromisoformat(p["leaving_date"]),
                              reason=p.get("reason", ""))
            return _result(f"{r.ref} started for {_name(who)}; {len(r.assets)} asset(s) flagged for a new owner.", f"/orasec/leavers/{r.id}/")
        r = _leaver_rec(p)
        if kind == "leaver_step":
            leavers.tick(r, p["step"], user, p.get("note", ""))
            return _result(f"{r.ref}: step done ({r.done_count}/{len(r.steps)}).", f"/orasec/leavers/{r.id}/")
        if kind == "leaver_reassign":
            n = leavers.reassign(r, OraSec_User.objects.get(id=p["new_owner_id"], is_active=True), user)
            return _result(f"{r.ref}: {n} asset(s) moved.", f"/orasec/leavers/{r.id}/")
        if kind == "leaver_signoff":
            leavers.sign_off(r, user, p.get("note", ""))
            return _result(f"{r.ref} signed off.", f"/orasec/leavers/{r.id}/")
    except leavers.Refused as e:
        return {"ok": False, "message": str(e), "path": "/orasec/leavers/"}
    raise PermissionError(kind)


def create(conversation, user, kind: str, card: dict, payload: dict) -> OraProposal:
    # A new card replaces any older pending one of the same kind in this chat.
    OraProposal.objects.filter(conversation=conversation, kind=kind, status="pending").update(status="expired")
    return OraProposal.objects.create(conversation=conversation, user=user, kind=kind, card=card, payload=payload)


def _result(message: str, path: str | None = None, **extra) -> dict[str, Any]:
    return {"ok": True, "message": message, "path": path, **extra}


@transaction.atomic
def execute(prop: OraProposal, user, via: str = "Ora") -> dict[str, Any]:
    """Run a confirmed proposal as ``user``. ``via`` marks notes with where the change came from."""
    import crum  # noqa: PLC0415

    kind, p = prop.kind, prop.payload or {}
    if kind not in allowed_kinds(user):
        raise PermissionError(kind)
    now = timezone.now()
    with crum.impersonate(user):
        if kind == "assign":
            from orasec.models import OraSec_User  # noqa: PLC0415
            from orasec.posture.models import FindingAssignment  # noqa: PLC0415

            who = OraSec_User.objects.get(id=p["assignee_id"], is_active=True)
            if who != user and not tools.org_wide(user):
                raise PermissionError(kind)
            fs = list(tools.findings_for(user).filter(id__in=p["finding_ids"], active=True))
            for f in fs:
                FindingAssignment.objects.update_or_create(finding=f, defaults={"assignee": who, "assigned_by": user,
                                                                                "assigned_at": now})
            return _result(f"Assigned {len(fs)} finding{'s' if len(fs) != 1 else ''} to {'you' if who == user else _name(who)}.",
                           "/orasec/my-work/" if who == user else "/orasec/remediation/")
        if kind == "note":
            from orasec.models import Notes  # noqa: PLC0415

            f = tools.findings_for(user).get(id=p["finding_id"])
            if not _can_edit(user, f):
                raise PermissionError(kind)
            note = Notes.objects.create(entry=f"[{via}] {p['text']}"[:5000], author=user)
            f.notes.add(note)
            f.last_reviewed, f.last_reviewed_by = now, user
            f.save(update_fields=["last_reviewed", "last_reviewed_by"])
            return _result(f"Note added to F-{f.id}.", f"/finding/{f.id}")
        if kind == "close":
            from orasec.finding.helper import close_finding  # noqa: PLC0415

            fs = list(tools.findings_for(user).filter(id__in=p["finding_ids"], active=True))
            r = p["reason"]
            for f in fs:
                if not _can_edit(user, f):
                    raise PermissionError(kind)
                close_finding(finding=f, user=user, is_mitigated=r == "mitigated", mitigated=now, mitigated_by=user,
                              false_p=r == "false_positive", out_of_scope=r == "out_of_scope", duplicate=False,
                              note_entry=f"[{via}] {p['note']}"[:5000])
            return _result(f"Closed {len(fs)} finding{'s' if len(fs) != 1 else ''} as {REASONS[r].lower()}.",
                           f"/finding/{fs[0].id}" if len(fs) == 1 else "/finding/closed")
        if kind == "create_risk":
            from orasec.posture.models import RiskRegisterEntry  # noqa: PLC0415

            r = RiskRegisterEntry(title=p["title"], description=p.get("description", ""), likelihood=p["likelihood"],
                                  impact=p["impact"], treatment=p["treatment"], treatment_plan=p.get("treatment_plan", ""),
                                  owner=user, product_id=p.get("product_id"),
                                  review_date=timezone.localdate() + datetime.timedelta(days=90))
            r.save()
            if p.get("finding_ids"):
                r.findings.add(*tools.findings_for(user).filter(id__in=p["finding_ids"]))
            return _result(f"Added {r.ref} to the risk register (review in 90 days).", f"/orasec/risks/{r.id}/", ref=r.ref)
        if kind == "link_risk":
            from orasec.posture.models import RiskRegisterEntry  # noqa: PLC0415

            r = RiskRegisterEntry.objects.get(id=p["risk_id"])
            fs = list(tools.findings_for(user).filter(id__in=p["finding_ids"]))
            r.findings.add(*fs)
            return _result(f"Linked {len(fs)} finding{'s' if len(fs) != 1 else ''} to {r.ref}.", f"/orasec/risks/{r.id}/")
        if kind == "campaign":
            from orasec.posture.models import RemediationCampaign  # noqa: PLC0415

            base = tools._open(tools.findings_for(user)).filter(component_name=p["component"]).count() if p["component"] else 0
            c = RemediationCampaign.objects.create(name=p["name"], component=p["component"], owner=user,
                                                   target_date=datetime.date.fromisoformat(p["target_date"]),
                                                   description=p.get("description", ""), status="active",
                                                   baseline_open=base)
            return _result(f"Campaign '{c.name}' started with {base} open findings.", "/orasec/remediation/")
        if kind == "run_connector":
            from orasec.posture.models import Connector  # noqa: PLC0415
            from orasec.posture.tasks import run_connector_task  # noqa: PLC0415

            c = Connector.objects.get(id=p["connector_id"])
            transaction.on_commit(lambda: run_connector_task.delay(c.id, "manual", user.id))
            return _result(f"{c.name} is queued. The run shows on its page in a minute or two.", f"/orasec/connectors/{c.id}/")
        if kind in ("start_leaver", "leaver_step", "leaver_reassign", "leaver_signoff"):
            return _leaver_exec(kind, p, user)
        if kind == "recompute_priorities":
            from orasec.posture.tasks import refresh_priorities  # noqa: PLC0415

            transaction.on_commit(lambda: refresh_priorities.delay())
            return _result("Recalculation started. Scores update in a few minutes.", "/orasec/vulnerabilities/")
    raise PermissionError(kind)


def describe_for_context(conversation) -> list[dict[str, Any]]:
    """Cards in this chat, so follow-ups ("do the same for the next one") have context."""
    out = []
    for pr in conversation.proposals.order_by("-created")[:6]:
        out.append({"kind": pr.kind, "status": pr.status, "title": (pr.card or {}).get("title"),
                    "result": (pr.result or {}).get("message")})
    return out


"""Two-way sync between OraSec and the policy tool (an ISMS document tool with a REST API).

How it works
* Event driven. An OraSec save pushes that record within seconds (isms_signals). The policy tool's
  (Slack-format) webhook tells OraSec something changed; OraSec then pulls and merges. A full
  reconciliation runs nightly at 02:30 and can be started from the Policy tool sync page.
* Three-way, field-level merge against the values both sides last agreed (IsmsLink.snapshot). A field
  changed on one side only is copied to the other. The same field changed differently on both sides is a
  conflict: OraSec's value is kept on both sides and the conflict is listed for a person to resolve.
* Values are compared as canonical keys, so equivalent statuses (OraSec "treating" and the tool's "open")
  do not bounce back and forth.
* Decisions belong to OraSec, which enforces segregation of duties (no one approves their own change).
  An approval, rejection or "done" made in the policy tool is passed to OraSec and applied there as the
  person who made it, but only if OraSec's rules allow that person to do it; otherwise the policy tool is
  reset to OraSec's value and the attempt is listed. If both tools record different decisions at the same
  time, the record stays not approved and both people are told.
* Approved documents (markdown in the tool's git repository) become control evidence in OraSec on the
  ISO 27001 controls listed in their frontmatter; see isms_docs.
* The sync never deletes. A record removed on one side is archived or closed on the other.
* Writes made by the sync are flagged so they do not trigger another sync (no echo loops); webhook events
  caused by the sync's own API user are ignored.
"""
import contextlib
import datetime
import json
import logging
import re
import threading

import requests
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.db import transaction
from django.utils import timezone

from orasec import site as site_profile

logger = logging.getLogger(__name__)
_state = threading.local()
class _ToolName:
    """Formats as the policy tool's display name from the site profile (key policy_tool.name)."""

    def __format__(self, spec):
        return format(str(self), spec)

    def __str__(self):
        return site_profile.get("policy_tool.name") or "the policy tool"


TOOL_NAME = _ToolName()


def syncing():
    return getattr(_state, "active", False)


@contextlib.contextmanager
def sync_writes():
    prev = syncing()
    _state.active = True
    try:
        yield
    finally:
        _state.active = prev


class IsmsError(Exception):
    pass


class Busy(Exception):
    """Another sync holds the lock; the caller retries shortly."""


# ---------------------------------------------------------------------------
# API client
# ---------------------------------------------------------------------------
class Client:
    def __init__(self, conn):
        self.base = conn.base_url.rstrip("/") + "/api/v1"
        self.s = requests.Session()
        self.s.headers.update({"Authorization": "Bearer " + conn.get_secrets().get("token", ""),
                               "Content-Type": "application/json", "Accept": "application/json"})
        self.verify = conn.verify_tls

    def _req(self, method, path, body=None, params=None):
        r = self.s.request(method, self.base + path, data=json.dumps(body) if body is not None else None, params=params,
                           timeout=20, verify=self.verify)
        if r.status_code >= 400:
            raise IsmsError(f"{method} {path}: HTTP {r.status_code} {r.text[:300]}")
        if not r.content:
            return {}
        try:
            return r.json()
        except ValueError as e:
            raise IsmsError(f"{method} {path}: not a JSON answer (wrong URL?)") from e

    def list(self, path):
        out, page = [], 1
        while page <= 200:
            d = self._req("GET", path, params={"page": page})
            data = d.get("data", []) if isinstance(d, dict) else (d or [])
            out.extend(data)
            total = d.get("total") if isinstance(d, dict) else None
            if total is None or not data or len(out) >= total:
                break
            page += 1
        return out

    def get(self, path, rid):
        return self._req("GET", f"{path}/{rid}")

    def create(self, path, body):
        return self._req("POST", path, body)

    def update(self, path, rid, body):
        return self._req("PUT", f"{path}/{rid}", body) if body else {}

    def set_status(self, path, rid, status):
        return self._req("PUT", f"{path}/{rid}/status", {"status": status})

    def members(self):
        d = self._req("GET", "/admin/members")
        return d.get("data", []) if isinstance(d, dict) else d


def connector():
    from orasec.posture.models import Connector  # noqa: PLC0415
    return Connector.objects.filter(kind="isms", enabled=True).first()


# ---------------------------------------------------------------------------
# People: OraSec users <-> policy tool members
# ---------------------------------------------------------------------------
class Ctx:
    """Per-run context: the client plus the people mapping."""

    def __init__(self, conn, client=None):
        self.conn = conn
        self.client = client or Client(conn)
        opts = conn.options or {}
        self.sync_email = (conn.username or opts.get("sync_user") or "").lower()
        self.user_map = {k.lower(): v.lower() for k, v in (opts.get("user_map") or {}).items()}  # OraSec username -> tool email
        self._program = opts.get("program_id")
        members = [m for m in self.client.members() if m.get("active", True)]
        self.by_email = {(m.get("email") or "").lower(): m for m in members if m.get("email")}
        self.by_name = {(m.get("name") or "").strip().lower(): m for m in members if m.get("name")}

    def tool_email(self, u):
        if not u:
            return ""
        mapped = self.user_map.get(u.username.lower())
        if mapped:
            return mapped if mapped in self.by_email else ""
        e = (u.email or "").lower()
        if e in self.by_email and e != self.sync_email:
            return e
        m = self.by_name.get((u.get_full_name() or "").strip().lower())
        return (m.get("email") or "").lower() if m else ""

    def remote(self, email):
        e = (email or "").lower()
        return "" if not e or e == self.sync_email else e

    def orasec_user(self, email):
        e = self.remote(email)
        if not e:
            return None
        users = get_user_model().objects.filter(is_active=True)
        for uname, te in self.user_map.items():
            if te == e:
                u = users.filter(username__iexact=uname).first()
                if u:
                    return u
        u = users.filter(email__iexact=e).first()
        if u:
            return u
        m = self.by_email.get(e)
        name = (m.get("name") or "").strip().lower() if m else ""
        if name:
            for u in users:
                if (u.get_full_name() or "").strip().lower() == name:
                    return u
        return None

    def program_id(self):
        if self._program:
            return self._program
        progs = self.client.list("/programs")
        p = next((x for x in progs if (x.get("key") or "").upper() == "SEC"), None)
        if not p:
            p = self.client.create("/programs", {"key": "SEC", "title": "Information security objectives",
                                                 "description": "ISMS objectives, kept in sync with OraSec."})
        self._program = p["id"]
        return self._program


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _epoch(d):
    return int(datetime.datetime(d.year, d.month, d.day, tzinfo=datetime.UTC).timestamp()) if d else None


def _date(e):
    return datetime.datetime.fromtimestamp(int(e), tz=datetime.UTC).date() if e else None


def _int(v):
    try:
        return int(v) if v not in (None, "") else None
    except (TypeError, ValueError):
        return None


def _inv(m):
    out = {}
    for k, v in m.items():
        out.setdefault(v, k)
    return out


def _notify(title, desc, usernames=None):
    try:
        from orasec.notifications.helper import create_notification  # noqa: PLC0415
        users = get_user_model().objects.filter(is_active=True)
        names = set(usernames or [])
        names |= set(users.filter(is_superuser=True).values_list("username", flat=True))
        names |= set(users.filter(groups__name="Compliance Officer").values_list("username", flat=True))
        names.discard("orasec-automation")
        create_notification(event="other", title=title[:150], description=desc, recipients=sorted(names),
                            icon="arrows-rotate", url="/orasec/isms/sync/")
    except Exception:  # noqa: BLE001
        logger.warning("isms-sync: notification failed", exc_info=True)


def _record_conflict(spec, obj, rec, field, ours, theirs, kind="field", note="", usernames=None):
    from orasec.posture.models import IsmsConflict  # noqa: PLC0415
    label = spec.label(obj)
    if IsmsConflict.objects.filter(entity=spec.entity, orasec_id=obj.pk, field=field, kind=kind, resolved=False,
                                   isms_value=json.dumps(theirs, default=str)).exists():
        return
    IsmsConflict.objects.create(entity=spec.entity, orasec_id=obj.pk, isms_id=rec.get("id"), label=label[:300], field=field,
                                kind=kind, orasec_value=json.dumps(ours, default=str), isms_value=json.dumps(theirs, default=str))
    if kind == "field":
        _notify(f"Sync conflict: {label}",
                f"'{field}' was changed in both OraSec and {TOOL_NAME}. OraSec's value was kept on both sides; "
                "open Policy tool sync in OraSec to keep it or take the other value.", usernames)
    else:
        _notify(f"Decision not applied: {label}", note or f"'{field}' was set to '{theirs}' in {TOOL_NAME}; "
                "this decision must be made in OraSec. The policy tool was reset.", usernames)


# ---------------------------------------------------------------------------
# Field specifications. Canonical values are "keys" both sides map to, so equivalent values compare equal.
# ---------------------------------------------------------------------------
class Spec:
    entity = path = ""
    two_way = True
    signals = True
    decision_fields = ()   # changes made in the tool go through decide()
    owned_fields = ()      # OraSec's value always wins, silently (e.g. measured status)
    status_endpoint = False  # status changes use PUT {path}/{id}/status
    STATUS_TOOL = {}       # canonical key -> tool status

    def queryset(self):
        return self.model.objects.all()

    def label(self, obj):
        return f"{getattr(obj, 'ref', '') or ''} {getattr(obj, 'title', '') or getattr(obj, 'name', '')}".strip()

    def payload(self, vals, ctx):
        """Canonical values -> tool request body (status handled separately when status_endpoint)."""
        out = {}
        for k, v in vals.items():
            if k in ("owner", "assigned_to", "assignee") and not v:
                continue  # cannot unset an owner in the tool
            if k == "status":
                v = self.STATUS_TOOL.get(v, v)
            if v is None:
                continue
            out[self.REMOTE_NAMES.get(k, k) if hasattr(self, "REMOTE_NAMES") else k] = v
        return out

    def push(self, ctx, rid, vals):
        vals = dict(vals)
        status = vals.pop("status", None) if self.status_endpoint else None
        body = self.payload(vals, ctx)
        if body:
            ctx.client.update(self.path, rid, body)
        if status is not None:
            ctx.client.set_status(self.path, rid, self.STATUS_TOOL.get(status, status))

    def create_remote(self, ctx, obj):
        vals = self.from_orasec(obj, ctx)
        status = vals.pop("status", None) if self.status_endpoint else None
        rec = ctx.client.create(self.path, self.payload(vals, ctx))
        if status is not None and self.STATUS_TOOL.get(status, status) != rec.get("status"):
            ctx.client.set_status(self.path, rec["id"], self.STATUS_TOOL.get(status, status))
            rec = ctx.client.get(self.path, rec["id"])
        return rec

    def archive_remote(self, ctx, rid, rec):
        pass

    def decide(self, ctx, obj, rec, field, ours, theirs, base):
        """A decision field changed in the tool. Default: not accepted; reset the tool and record it."""
        _record_conflict(self, obj, rec, field, ours, theirs, kind="decision")
        return ours

    def apply_owner(self, o, attr, email, ctx):
        u = ctx.orasec_user(email)
        if u:
            setattr(o, attr, u)


class RiskSpec(Spec):
    entity, path = "risk", "/risks"
    decision_fields = ("status",)  # accepting or closing a risk is a decision recorded in OraSec
    owned_fields = ("next_review",)  # review dates come from OraSec's risk reviews
    KEY = {"open": "open", "treating": "open", "accepted": "accepted", "closed": "closed"}
    STATUS_TOOL = {"open": "open", "accepted": "accepted", "closed": "closed"}
    FROM_TOOL = {"draft": "open", "open": "open", "accepted": "accepted", "closed": "closed"}
    REMOTE_NAMES = {"likelihood": "current_likelihood", "impact": "current_impact"}
    TREATMENTS = ("mitigate", "accept", "transfer", "avoid")

    @property
    def model(self):
        from orasec.posture.models import RiskRegisterEntry  # noqa: PLC0415
        return RiskRegisterEntry

    def from_orasec(self, o, ctx):
        return {"title": o.title, "description": o.description or "", "status": self.KEY.get(o.status, "open"),
                "owner": ctx.tool_email(o.owner), "likelihood": o.likelihood, "impact": o.impact,
                "treatment": o.treatment or "mitigate", "next_review": _epoch(o.review_date)}

    def from_isms(self, r, ctx):
        return {"title": r.get("title") or "", "description": r.get("description") or "",
                "status": self.FROM_TOOL.get(r.get("status") or "open", "open"), "owner": ctx.remote(r.get("owner")),
                "likelihood": _int(r.get("current_likelihood")), "impact": _int(r.get("current_impact")),
                "treatment": r.get("treatment") or "mitigate", "next_review": _int(r.get("next_review"))}

    def apply(self, o, vals, ctx):
        for k, v in vals.items():
            if k == "owner":
                self.apply_owner(o, "owner", v, ctx)
            elif k in ("likelihood", "impact"):
                if v and 1 <= int(v) <= 5:
                    setattr(o, k, int(v))
            elif k == "treatment":
                if v in self.TREATMENTS:
                    o.treatment = v
            elif k == "next_review":
                o.review_date = _date(v)
            elif k in ("title", "description"):
                setattr(o, k, v or "")

    def new_orasec(self, rec, ctx):
        o = self.model(title=rec.get("title") or "Untitled risk", status="open", likelihood=3, impact=3,
                       raised_on=timezone.localdate(), source_ref=rec.get("identifier") or "")
        self.apply(o, {k: v for k, v in self.from_isms(rec, ctx).items() if k != "status"}, ctx)
        return o

    def archive_remote(self, ctx, rid, rec):
        if rec.get("status") != "closed":
            ctx.client.update(self.path, rid, {"status": "closed"})


class SupplierSpec(Spec):
    entity, path = "supplier", "/suppliers"
    owned_fields = ("next_review",)  # set by OraSec's supplier assessments
    decision_fields = ("status",)    # activating a supplier needs an approved assessment in OraSec
    KEY = {"proposed": "review", "assessing": "review", "active": "active", "suspended": "suspended", "exited": "terminated"}
    STATUS_TOOL = {"review": "under_review", "active": "active", "suspended": "suspended", "terminated": "terminated"}
    FROM_TOOL = _inv(STATUS_TOOL)
    TIER_KEY = {"critical": "critical", "high": "high", "standard": "standard"}
    TIER_TOOL = {"critical": "critical", "high": "high", "standard": "medium"}
    TIER_FROM_TOOL = {"critical": "critical", "high": "high", "medium": "standard", "low": "standard"}

    @property
    def model(self):
        from orasec.posture.models import Supplier  # noqa: PLC0415
        return Supplier

    def label(self, o):
        return f"{o.ref} {o.name}"

    def from_orasec(self, o, ctx):
        return {"name": o.name, "status": self.KEY.get(o.status, "review"), "criticality": o.tier or "standard",
                "owner": ctx.tool_email(o.owner), "next_review": _epoch(o.next_review), "data_access": bool(o.personal_information)}

    def from_isms(self, r, ctx):
        return {"name": r.get("name") or "", "status": self.FROM_TOOL.get(r.get("status") or "active", "active"),
                "criticality": self.TIER_FROM_TOOL.get(r.get("criticality") or "medium", "standard"),
                "owner": ctx.remote(r.get("owner")), "next_review": _int(r.get("next_review")), "data_access": bool(r.get("data_access"))}

    def payload(self, vals, ctx):
        vals = dict(vals)
        if "criticality" in vals:
            vals["criticality"] = self.TIER_TOOL.get(vals["criticality"], "medium")
        return super().payload(vals, ctx)

    def apply(self, o, vals, ctx):
        for k, v in vals.items():
            if k == "owner":
                self.apply_owner(o, "owner", v, ctx)
            elif k == "status":
                if v == "review":
                    if o.status not in ("proposed", "assessing"):
                        o.status = "assessing"
                else:
                    o.status = {"active": "active", "suspended": "suspended", "terminated": "exited"}.get(v, o.status)
            elif k == "criticality":
                o.tier = v if v in self.TIER_KEY else o.tier
            elif k == "next_review":
                o.next_review = _date(v)
            elif k == "data_access":
                o.personal_information = bool(v)
            elif k == "name":
                o.name = v or o.name

    def new_orasec(self, rec, ctx):
        o = self.model(name=rec.get("name") or "Unnamed supplier", status="proposed",
                       service=f"Added in {TOOL_NAME} ({rec.get('identifier') or ''}); complete the supplier record in OraSec.")
        self.apply(o, {k: v for k, v in self.from_isms(rec, ctx).items() if k != "status"}, ctx)
        return o

    def archive_remote(self, ctx, rid, rec):
        if rec.get("status") != "terminated":
            ctx.client.update(self.path, rid, {"status": "terminated"})

    def decide(self, ctx, obj, rec, field, ours, theirs, base):
        if theirs in ("review", "suspended", "terminated"):
            if ours != base:
                _record_conflict(self, obj, rec, field, ours, theirs)
                return ours
            with sync_writes():
                self.apply(obj, {"status": theirs}, ctx)
                obj.save()
            return self.from_orasec(obj, ctx)["status"]
        _record_conflict(self, obj, rec, field, ours, theirs, kind="decision",
                         note=f"{obj.ref} {obj.name} was set to active in {TOOL_NAME}. A supplier becomes active in OraSec when its "
                              "due-diligence assessment is approved (POL-015). The policy tool was reset.")
        return ours


class ChangeSpec(Spec):
    entity, path = "change", "/changes"
    decision_fields = ("status",)
    status_endpoint = True
    KEY = {"submitted": "pending", "approved": "approved", "rejected": "rejected", "implemented": "implemented",
           "closed": "closed", "cancelled": "closed"}
    STATUS_TOOL = {"pending": "proposed", "approved": "approved", "rejected": "rejected", "implemented": "implemented",
                   "closed": "closed"}
    FROM_TOOL = {"proposed": "pending", "approved": "approved", "in_progress": "approved", "rejected": "rejected",
                 "implemented": "implemented", "closed": "closed"}
    REMOTE_NAMES = {"owner": "assigned_to"}
    # transitions the policy tool allows (rejected and closed are final there)
    GRAPH = {"proposed": ["approved", "rejected", "closed"], "approved": ["proposed", "rejected", "in_progress", "implemented"],
             "in_progress": ["proposed", "rejected", "implemented"], "implemented": ["in_progress", "closed"],
             "rejected": [], "closed": []}

    @property
    def model(self):
        from orasec.posture.models import ChangeRequest  # noqa: PLC0415
        return ChangeRequest

    def _path(self, cur, target):
        if cur == target:
            return []
        seen, queue = {cur}, [(cur, [])]
        while queue:
            node, path = queue.pop(0)
            for nxt in self.GRAPH.get(node, []):
                if nxt == target:
                    return path + [nxt]
                if nxt not in seen:
                    seen.add(nxt)
                    queue.append((nxt, path + [nxt]))
        return None

    def push(self, ctx, rid, vals):
        vals = dict(vals)
        status = vals.pop("status", None)
        body = self.payload(vals, ctx)
        if body:
            ctx.client.update(self.path, rid, body)
        if status is None:
            return
        rec = ctx.client.get(self.path, rid)
        cur, target = rec.get("status"), self.STATUS_TOOL.get(status, status)
        if self.FROM_TOOL.get(cur) == status:
            return
        path = self._path(cur, target)
        if path is None:
            logger.warning("isms-sync: change %s cannot move from %s to %s in the policy tool", rid, cur, target)
            return
        for step in path:
            ctx.client.set_status(self.path, rid, step)

    def create_remote(self, ctx, obj):
        vals = self.from_orasec(obj, ctx)
        status = vals.pop("status", None)
        rec = ctx.client.create(self.path, self.payload(vals, ctx))
        if status and status != "pending":
            self.push(ctx, rec["id"], {"status": status})
            rec = ctx.client.get(self.path, rec["id"])
        return rec

    def from_orasec(self, o, ctx):
        return {"title": o.title, "description": o.reason or "", "status": self.KEY.get(o.status, "pending"),
                "owner": ctx.tool_email(o.owner), "risk_level": o.risk_level or "low"}

    def from_isms(self, r, ctx):
        return {"title": r.get("title") or "", "description": r.get("description") or "",
                "status": self.FROM_TOOL.get(r.get("status") or "proposed", "pending"), "owner": ctx.remote(r.get("assigned_to")),
                "risk_level": r.get("risk_level") if r.get("risk_level") in ("low", "medium", "high") else
                ("high" if r.get("risk_level") == "critical" else "low")}

    def apply(self, o, vals, ctx):
        for k, v in vals.items():
            if k == "title":
                o.title = v or o.title
            elif k == "description":
                o.reason = v or o.reason
            elif k == "owner":
                self.apply_owner(o, "owner", v, ctx)
            elif k == "risk_level":
                o.risk_level = v

    def new_orasec(self, rec, ctx):
        requester = ctx.orasec_user(rec.get("requested_by"))
        o = self.model(title=rec.get("title") or "Untitled change", reason=rec.get("description") or rec.get("title") or "",
                       impact=f"Raised in {TOOL_NAME} as {rec.get('identifier') or ''}; complete the impact in OraSec.",
                       status="submitted", category="other", requested_by=requester)
        self.apply(o, {k: v for k, v in self.from_isms(rec, ctx).items() if k != "status"}, ctx)
        return o

    def archive_remote(self, ctx, rid, rec):
        if rec.get("status") != "closed":
            ctx.client.set_status(self.path, rid, "closed")

    def decide(self, ctx, obj, rec, field, ours, theirs, base):
        from orasec.posture.grc_views import change_permissions  # noqa: PLC0415
        actor_email = cache.get(f"isms-actor:change:{rec.get('id')}") or (rec.get("approved_by") if theirs == "approved" else "")
        user = ctx.orasec_user(actor_email)
        who = (user.get_full_name() or user.username) if user else (actor_email or "someone")
        notify_to = [user.username] if user else []
        if ours != base:  # both tools decided, differently: the record stays not approved
            note = (f"{obj.ref}: OraSec recorded '{ours}' while {who} recorded '{theirs}' in {TOOL_NAME}. "
                    "The change is left not approved; decide again in OraSec.")
            if theirs == "rejected" and user and obj.status in ("approved", "submitted") and change_permissions(
                    user, self.model(pk=obj.pk, status="submitted", requested_by_id=obj.requested_by_id,
                                     implemented_by_id=obj.implemented_by_id))["approve"]:
                with sync_writes():
                    obj.status, obj.approved_by, obj.approved_at = "rejected", None, timezone.now()
                    obj.approval_note = (obj.approval_note + " | " if obj.approval_note else "") + \
                        f"Rejected by {who} in {TOOL_NAME} while it was being approved in OraSec; left rejected (not approved)."
                    obj.save()
                if obj.requested_by:
                    notify_to.append(obj.requested_by.username)
                _record_conflict(self, obj, rec, field, ours, theirs, kind="decision", note=note.replace(
                    "left not approved", "left rejected"), usernames=notify_to)
                return "rejected"
            if obj.status == "approved":
                with sync_writes():
                    obj.status, obj.approved_by, obj.approved_at = "submitted", None, None
                    obj.approval_note = (obj.approval_note + " | " if obj.approval_note else "") + \
                        f"Approval withdrawn {timezone.localdate():%d %b %Y}: a different decision was made in the policy tool at the same time."
                    obj.save()
            if obj.requested_by:
                notify_to.append(obj.requested_by.username)
            _record_conflict(self, obj, rec, field, ours, theirs, kind="decision", note=note, usernames=notify_to)
            return self.KEY.get(obj.status, "pending")
        if user and theirs in ("approved", "rejected"):
            perm = change_permissions(user, obj)
            if perm["approve"] and not (theirs == "rejected" and obj.status == "implemented"):
                now = timezone.now()
                with sync_writes():
                    if theirs == "rejected":
                        obj.status, obj.approved_at = "rejected", now
                        obj.approval_note = f"Rejected by {who} in {TOOL_NAME}."
                    else:
                        if obj.status == "submitted":
                            obj.status = "approved"
                        obj.approved_by, obj.approved_at = user, now
                        obj.approval_note = f"Approved by {who} in {TOOL_NAME}."
                    obj.save()
                return self.KEY.get(obj.status)
            why = perm["why_not"] or f"{who} may not approve this change."
            _record_conflict(self, obj, rec, field, ours, theirs, kind="decision", usernames=notify_to,
                             note=f"{obj.ref}: {who} set '{theirs}' in {TOOL_NAME}, but OraSec's rules do not allow it: {why} "
                                  "The policy tool was reset.")
            return ours
        if user and theirs == "implemented":
            perm = change_permissions(user, obj)
            if perm["implement"]:
                with sync_writes():
                    obj.status, obj.implemented_by, obj.implemented_at = "implemented", user, timezone.now()
                    obj.implementation_note = obj.implementation_note or f"Marked done by {who} in {TOOL_NAME}."
                    obj.save()
                return "implemented"
        _record_conflict(self, obj, rec, field, ours, theirs, kind="decision", usernames=notify_to,
                         note=f"{obj.ref}: '{theirs}' was set in {TOOL_NAME}" + (f" by {who}" if user else "") +
                              ". This step must be done in OraSec (approval, done and review are recorded there). The policy tool was reset.")
        return ours


class CorrectiveSpec(Spec):
    entity, path = "nonconformity", "/corrective-actions"
    decision_fields = ("status",)  # closing needs an independent effectiveness check in OraSec
    status_endpoint = True
    KEY = {"open": "open", "action": "action", "verify": "verify", "closed": "closed", "dropped": "closed"}
    STATUS_TOOL = {"open": "todo", "action": "implementation", "verify": "monitoring", "closed": "resolved"}
    FROM_TOOL = {"todo": "open", "assessment": "open", "awaiting_approval": "action", "implementation": "action",
                 "monitoring": "verify", "resolved": "closed"}
    REMOTE_NAMES = {"owner": "assignee"}
    SOURCE_TOOL = {"audit": "internal_audit", "incident": "security_incident", "check": "other", "review": "feedback", "other": "other"}
    SOURCE_FROM_TOOL = {"internal_audit": "audit", "external_audit": "audit", "security_incident": "incident", "risk_assessment": "other",
                        "objective": "other", "feedback": "review", "other": "other"}

    @property
    def model(self):
        from orasec.posture.models import Nonconformity  # noqa: PLC0415
        return Nonconformity

    def from_orasec(self, o, ctx):
        return {"title": o.title, "description": o.description or "", "status": self.KEY.get(o.status, "open"),
                "owner": ctx.tool_email(o.owner), "due_date": _epoch(o.due_date)}

    def from_isms(self, r, ctx):
        return {"title": r.get("title") or "", "description": r.get("description") or "",
                "status": self.FROM_TOOL.get(r.get("status") or "todo", "open"), "owner": ctx.remote(r.get("assignee")),
                "due_date": _int(r.get("due_date"))}

    def create_remote(self, ctx, obj):
        rec = super().create_remote(ctx, obj)
        src = self.SOURCE_TOOL.get(obj.source, "other")
        if rec.get("source") != src:
            ctx.client.update(self.path, rec["id"], {"source": src})
        return rec

    def apply(self, o, vals, ctx):
        for k, v in vals.items():
            if k in ("title", "description"):
                setattr(o, k, v or ("" if k == "description" else o.title))
            elif k == "owner":
                self.apply_owner(o, "owner", v, ctx)
            elif k == "due_date":
                o.due_date = _date(v)

    def new_orasec(self, rec, ctx):
        o = self.model(title=rec.get("title") or "Untitled nonconformity",
                       source=self.SOURCE_FROM_TOOL.get(rec.get("source") or "other", "other"), status="open")
        self.apply(o, {k: v for k, v in self.from_isms(rec, ctx).items() if k != "status"}, ctx)
        return o

    def archive_remote(self, ctx, rid, rec):
        if rec.get("status") != "resolved":
            ctx.client.set_status(self.path, rid, "resolved")

    def decide(self, ctx, obj, rec, field, ours, theirs, base):
        if theirs in ("open", "action", "verify") and ours != "closed":
            if ours != base:  # both moved: OraSec wins, listed
                _record_conflict(self, obj, rec, field, ours, theirs)
                return ours
            with sync_writes():
                obj.status = theirs
                obj.save()
            return theirs
        _record_conflict(self, obj, rec, field, ours, theirs, kind="decision",
                         note=f"{obj.ref}: '{theirs}' was set in {TOOL_NAME}. Closing a nonconformity needs the effectiveness "
                              "check recorded in OraSec by someone other than the owner. The policy tool was reset.")
        return ours


class ObjectiveSpec(Spec):
    entity, path = "objective", "/objectives"
    owned_fields = ("status",)  # measured by OraSec
    KEY = {"met": "met", "on_track": "on_track", "off_track": "off_track", "not_measured": "not_measured",
           "not_applicable": "not_applicable"}
    STATUS_TOOL = {"met": "complete", "on_track": "active", "off_track": "at_risk", "not_measured": "active",
                   "not_applicable": "paused"}
    FROM_TOOL = {"complete": "met", "active": "on_track", "at_risk": "off_track", "paused": "not_applicable", "draft": "not_measured"}

    @property
    def model(self):
        from orasec.posture.models import SecurityObjective  # noqa: PLC0415
        return SecurityObjective

    def label(self, o):
        return f"{o.ref} {o.title}"

    def from_orasec(self, o, ctx):
        return {"title": f"{o.ref} {o.title}", "description": o.target or "", "owner": ctx.tool_email(o.owner),
                "status": self.STATUS_TOOL.get(o.status, "active")}

    def from_isms(self, r, ctx):
        return {"title": r.get("title") or "", "description": r.get("description") or "", "owner": ctx.remote(r.get("owner")),
                "status": r.get("status") or "active"}

    def payload(self, vals, ctx):
        out = {k: v for k, v in vals.items() if not (k == "owner" and not v) and v is not None}
        return out

    def create_remote(self, ctx, obj):
        body = self.payload(self.from_orasec(obj, ctx), ctx)
        body.update({"program_id": ctx.program_id(), "target_operator": "eq", "target_value": 1, "unit": "met"})
        return ctx.client.create(self.path, body)

    def apply(self, o, vals, ctx):
        for k, v in vals.items():
            if k == "title":
                t = (v or "").strip()
                if t.startswith(o.ref + " "):
                    t = t[len(o.ref) + 1:]
                o.title = (t or o.title)[:200]
            elif k == "description":
                o.target = v or o.target
            elif k == "owner":
                self.apply_owner(o, "owner", v, ctx)

    def new_orasec(self, rec, ctx):
        n = 1
        refs = set(self.model.objects.values_list("ref", flat=True))
        while f"O{n}" in refs:
            n += 1
        o = self.model(ref=f"O{n}", title=(rec.get("title") or "Untitled objective")[:200],
                       target=rec.get("description") or rec.get("title") or "", measure="manual", status="not_measured",
                       notes=f"Added in {TOOL_NAME} ({rec.get('display_id') or rec.get('identifier') or ''}).")
        self.apply_owner(o, "owner", rec.get("owner"), ctx)
        return o

    def archive_remote(self, ctx, rid, rec):
        if rec.get("status") != "paused":
            ctx.client.update(self.path, rid, {"status": "paused"})


class AssetSpec(Spec):
    """OraSec -> policy tool only: the inventory is fed automatically by Wazuh, PatchMon, UniFi, AWS ..."""
    entity, path = "asset", "/assets"
    two_way = False
    signals = False  # assets are touched by every connector run; they go across in the full sync
    TYPE = {"server": "infrastructure", "workstation": "processing_devices", "firewall": "network", "switch": "network",
            "access_point": "network", "network_device": "network", "client": "processing_devices",
            "cloud_instance": "infrastructure", "container": "software", "application": "software", "other": "other"}

    @property
    def model(self):
        from orasec.posture.models import InventoryAsset  # noqa: PLC0415
        return InventoryAsset

    def queryset(self):
        return self.model.objects.filter(retired=False)

    def label(self, o):
        return o.name

    def from_orasec(self, o, ctx):
        # no IP addresses, hostnames or MAC addresses: the policy tool is reachable from the internet
        bits = [o.get_asset_type_display(), " ".join(x for x in (o.os_name, o.os_version) if x),
                f"criticality {o.criticality}/5", "internet-exposed" if o.internet_exposed else ""]
        return {"name": o.name[:250], "owner": ctx.tool_email(o.owner), "asset_type": self.TYPE.get(o.asset_type, "other"),
                "description": " | ".join(b for b in bits if b) + " (from the OraSec inventory)"}

    def from_isms(self, r, ctx):
        return {"name": r.get("name") or "", "owner": ctx.remote(r.get("owner")), "asset_type": r.get("asset_type") or "other",
                "description": r.get("description") or ""}

    def payload(self, vals, ctx):
        return {k: v for k, v in vals.items() if not (k == "owner" and not v) and v is not None}

    def archive_remote(self, ctx, rid, rec):
        if rec.get("status") != "archived":
            ctx.client.update(self.path, rid, {"status": "archived"})


SPECS = [RiskSpec(), SupplierSpec(), ChangeSpec(), CorrectiveSpec(), ObjectiveSpec(), AssetSpec()]
SPEC = {s.entity: s for s in SPECS}


# ---------------------------------------------------------------------------
# Merge
# ---------------------------------------------------------------------------
def merge3(base, ours, theirs, spec):
    """Return (agreed, to_isms, to_orasec, conflicts, decisions); all values canonical.
    ours = OraSec, theirs = policy tool, base = last agreed snapshot."""
    agreed, to_isms, to_orasec, conflicts, decisions = {}, {}, {}, [], []
    base = base or {}
    for f in ours:
        o, t = ours.get(f), theirs.get(f)
        b = base.get(f, o)
        if o == t:
            agreed[f] = o
            continue
        if f in spec.owned_fields and o in (None, ""):
            agreed[f] = t  # OraSec has no value: the tool's own default stands, nothing moves
        elif f in spec.owned_fields or not spec.two_way:
            agreed[f], to_isms[f] = o, o
        elif f in spec.decision_fields:
            if t != b:
                decisions.append((f, o, t, b))
            else:
                agreed[f], to_isms[f] = o, o
        elif t != b and o == b:
            agreed[f], to_orasec[f] = t, t
        elif o != b and t == b:
            agreed[f], to_isms[f] = o, o
        else:  # both changed, differently: OraSec's value is kept, the conflict is listed
            conflicts.append((f, o, t))
            agreed[f], to_isms[f] = o, o
    return agreed, to_isms, to_orasec, conflicts, decisions


def sync_pair(ctx, spec, obj, rec, link):
    from orasec.posture.models import IsmsLink  # noqa: PLC0415
    ours, theirs = spec.from_orasec(obj, ctx), spec.from_isms(rec, ctx)
    agreed, to_i, to_o, conflicts, decisions = merge3(link.snapshot if link else ours, ours, theirs, spec)
    for f, o, t in conflicts:
        _record_conflict(spec, obj, rec, f, o, t)
    for f, o, t, b in decisions:
        final = spec.decide(ctx, obj, rec, f, o, t, b)
        agreed[f] = final
        if final != t:
            to_i[f] = final
    if to_o:
        with sync_writes():
            spec.apply(obj, to_o, ctx)
            obj.save()
        agreed.update({k: v for k, v in spec.from_orasec(obj, ctx).items() if k in to_o})
    if to_i:
        spec.push(ctx, rec["id"], to_i)
    with sync_writes():
        IsmsLink.objects.update_or_create(entity=spec.entity, orasec_id=obj.pk, defaults={
            "isms_id": rec["id"], "snapshot": agreed, "synced_at": timezone.now(), "archived": False})
    return {"to_isms": len(to_i), "to_orasec": len(to_o), "conflicts": len(conflicts), "decisions": len(decisions)}


LOCK = "isms-sync-lock"


def _acquire(ttl=600):
    return cache.add(LOCK, timezone.now().isoformat(), ttl)


def _release():
    cache.delete(LOCK)


def _sync_entity(ctx, spec, st):
    from orasec.posture.models import IsmsLink  # noqa: PLC0415

    def failed(what, e):
        st.setdefault("errors", []).append(f"{what}: {e}"[:300])
        logger.warning("isms-sync %s %s failed: %s", spec.entity, what, e)

    remote = {r["id"]: r for r in ctx.client.list(spec.path)}
    links = {l.orasec_id: l for l in IsmsLink.objects.filter(entity=spec.entity)}
    by_isms = {l.isms_id: l for l in links.values()}
    objs = {o.pk: o for o in spec.queryset()}
    for pk, obj in objs.items():
        try:
            link = links.get(pk)
            rec = remote.get(link.isms_id) if link else None
            if link and rec is None:
                if not link.archived:  # removed in the policy tool: never delete in OraSec; unlink and list it
                    link.archived = True
                    link.save(update_fields=["archived"])
                    st["archived"] += 1
                    _notify(f"Removed in the policy tool: {spec.label(obj)}",
                            f"{spec.label(obj)} was deleted in {TOOL_NAME}. It is kept in OraSec and is no longer linked; "
                            "delete or retire it in OraSec too if it is no longer needed.")
                continue
            if not link:
                rec = spec.create_remote(ctx, obj)
                with sync_writes():
                    IsmsLink.objects.update_or_create(entity=spec.entity, orasec_id=pk, defaults={
                        "isms_id": rec["id"], "snapshot": spec.from_orasec(obj, ctx), "synced_at": timezone.now(), "archived": False})
                st["created_isms"] += 1
                r = sync_pair(ctx, spec, obj, rec, IsmsLink.objects.get(entity=spec.entity, orasec_id=pk))  # settle tool defaults
                st["to_orasec"] += r["to_orasec"]
                continue
            r = sync_pair(ctx, spec, obj, rec, link)
            for k in ("to_isms", "to_orasec", "conflicts", "decisions"):
                st[k] += r[k]
        except (IsmsError, requests.RequestException) as e:
            failed(spec.label(obj), e)
    for rid, rec in remote.items():
        try:
            link = by_isms.get(rid)
            if link:
                if link.orasec_id not in objs and not link.archived:  # deleted or retired in OraSec: archive in the tool
                    spec.archive_remote(ctx, rid, rec)
                    link.archived = True
                    link.save(update_fields=["archived"])
                    st["archived"] += 1
                continue
            if not spec.two_way:
                continue
            with sync_writes(), transaction.atomic():
                obj = spec.new_orasec(rec, ctx)
                obj.save()
                IsmsLink.objects.create(entity=spec.entity, orasec_id=obj.pk, isms_id=rid,
                                        snapshot=spec.from_orasec(obj, ctx), synced_at=timezone.now())
            st["created_orasec"] += 1
            r2 = sync_pair(ctx, spec, obj, rec, IsmsLink.objects.get(entity=spec.entity, orasec_id=obj.pk))
            st["to_isms"] += r2["to_isms"]
            st["decisions"] += r2["decisions"]
        except (IsmsError, requests.RequestException) as e:
            failed(rec.get("identifier") or str(rid), e)


def reconcile(kind="full", entities=None, wait=False):
    """Compare every mapped record on both sides and repair. Small registers, so events use it too."""
    from orasec.posture.models import IsmsSyncRun  # noqa: PLC0415
    conn = connector()
    if not conn:
        return None
    if not _acquire():
        if wait:
            raise Busy
        return None
    run = IsmsSyncRun.objects.create(kind=kind)
    stats = {}
    try:
        ctx = Ctx(conn)
        for spec in SPECS:
            if entities and spec.entity not in entities:
                continue
            if kind == "event" and not spec.two_way:
                continue
            st = {k: 0 for k in ("created_isms", "created_orasec", "to_isms", "to_orasec", "conflicts", "decisions", "archived")}
            try:
                _sync_entity(ctx, spec, st)
            except (IsmsError, requests.RequestException) as e:  # one register failing does not stop the others
                st.setdefault("errors", []).append(f"{e}"[:300])
            finally:
                stats[spec.entity] = st
        if not entities:  # approved documents -> control evidence (one way)
            from orasec.posture.isms_docs import sync_documents  # noqa: PLC0415
            st = {}
            try:
                sync_documents(ctx, st)
            except Exception as e:  # noqa: BLE001  documents must not stop the register sync
                logger.exception("isms-sync documents failed")
                st.setdefault("errors", []).append(f"{e}"[:300])
            finally:
                stats["documents"] = st
        errors = [f"{k}: {e}" for k, v in stats.items() for e in v.get("errors", [])]
        run.ok = not errors
        if errors:
            run.error = "; ".join(errors)[:2000]
        if kind == "full":
            IsmsSyncRun.objects.filter(started__lt=timezone.now() - datetime.timedelta(days=30)).delete()
    except Exception as e:  # noqa: BLE001
        logger.exception("isms-sync failed")
        run.error = f"{e.__class__.__name__}: {e}"[:2000]
    finally:
        run.stats, run.finished = stats, timezone.now()
        run.save()
        _release()
    return run


def push_one(entity, pk):
    """Push one OraSec record right after it was saved (raises Busy if a sync is running; the task retries)."""
    from orasec.posture.models import IsmsLink, IsmsSyncRun  # noqa: PLC0415
    conn, spec = connector(), SPEC.get(entity)
    if not conn or not spec:
        return None
    link = IsmsLink.objects.filter(entity=entity, orasec_id=pk).first()
    obj = spec.queryset().filter(pk=pk).first()
    if not link or obj is None:  # new in OraSec, or deleted/retired: let the entity reconcile create or archive it
        return reconcile("event", entities=[entity], wait=True)
    if not _acquire(120):
        raise Busy
    run = IsmsSyncRun.objects.create(kind="push")
    try:
        ctx = Ctx(conn)
        try:
            rec = ctx.client.get(spec.path, link.isms_id)
        except IsmsError as e:
            if "HTTP 404" not in str(e):
                raise
            _release()
            run.finished, run.ok, run.stats = timezone.now(), True, {entity: {"missing_in_tool": 1}}
            run.save()
            return reconcile("event", entities=[entity], wait=True)
        run.stats = {entity: sync_pair(ctx, spec, obj, rec, link)}
        run.ok = True
    except Exception as e:  # noqa: BLE001
        logger.exception("isms-sync push failed")
        run.error = f"{e.__class__.__name__}: {e}"[:2000]
    finally:
        if not run.finished:
            run.finished = timezone.now()
            run.save()
        _release()
    return run


def resolve_conflict(conflict, choice, user):
    """choice 'orasec' (already applied on both sides) or 'isms': take the policy tool's value into OraSec."""
    spec = SPEC.get(conflict.entity)
    if choice == "isms" and conflict.kind == "field" and spec and spec.two_way and conflict.field not in spec.decision_fields:
        obj = spec.queryset().filter(pk=conflict.orasec_id).first()
        conn = connector()
        if obj is not None and conn:
            try:
                val = json.loads(conflict.isms_value)
            except ValueError:
                val = conflict.isms_value
            spec.apply(obj, {conflict.field: val}, Ctx(conn))
            obj.save()  # a normal save: the value is pushed back to the policy tool
    conflict.resolved, conflict.resolution, conflict.resolved_by, conflict.resolved_at = True, choice, user, timezone.now()
    conflict.save()


# ---------------------------------------------------------------------------
# Webhook parsing (Slack format): "*<actor email>* RISK-2 updated", "... Change #2 status changed to approved"
# ---------------------------------------------------------------------------
_ACTOR = re.compile(r"\*([^*\s]+@[^*\s]+)\*")
_CHANGE = re.compile(r"(?:Change #|CR-)(\d+)")


def parse_event(payload):
    """Returns (actor_email, text). Remembers who acted on which change, for decisions."""
    text = ""
    if isinstance(payload, dict):
        text = payload.get("text") or ""
        if not text:
            for b in payload.get("blocks") or []:
                text += " " + ((b.get("text") or {}).get("text") or "")
    m = _ACTOR.search(text)
    actor = m.group(1).lower() if m else ""
    for cid in _CHANGE.findall(text):
        if actor:
            cache.set(f"isms-actor:change:{cid}", actor, 3600)
    return actor, text.strip()


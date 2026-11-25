"""JSON API for the OraSec mobile app (`/api/v2/orasec/mobile/...`).

Reads come from the same sources as the web pages (the cached dashboard document, the finding tables, the posture
models); writes go through the same helpers as the web UI (close_finding, notes, assignment), attributed to the
linked user.
"""
import datetime
import json
import logging

import crum
from django.db import transaction
from django.db.models import Count, Q
from django.http import JsonResponse
from django.utils import timezone

from orasec.home import metrics
from orasec.mobile.auth import client_ip, error, mobile_api, org_wide, rate_limited
from orasec.mobile.models import PUSH_KINDS, MobileDevice, MobileLinkCode, MobilePushPrefs, normalise_code, sha256

logger = logging.getLogger(__name__)
SEVS = ["Critical", "High", "Medium", "Low", "Info"]
MIN_APP_VERSION = "1.0.0"


def _json(request):
    try:
        return json.loads(request.body or b"{}")
    except (ValueError, UnicodeDecodeError):
        return {}


def _ok(data, status=200):
    return JsonResponse(data, status=status, json_dumps_params={"default": str})


def _iso(v):
    return v.isoformat() if v else None


def _user(u):
    return {"id": u.id, "username": u.username, "name": u.get_full_name() or u.username, "email": u.email,
            "superuser": u.is_superuser}


def _dashboard():
    data = metrics.get()
    if data is not None and metrics.is_stale(data):
        from orasec.home.views import _kick_refresh  # noqa: PLC0415
        _kick_refresh()
    return data


# ---------------------------------------------------------------------------
# Linking and session
# ---------------------------------------------------------------------------
@mobile_api(("POST",), auth=False)
def link(request):
    ip = client_ip(request) or "-"
    if rate_limited("link-ip", ip, 10, 600):
        return error("Too many attempts. Wait 10 minutes and create a new code in OraSec.", 429)
    body = _json(request)
    code = normalise_code(body.get("code", ""))
    if len(code) != 10:
        return error("Enter the 10-character code shown in OraSec (Profile menu → Mobile app).")
    link_code = MobileLinkCode.objects.select_related("user").filter(code_hash=sha256(code)).first()
    now = timezone.now()
    if not link_code or link_code.used_at or link_code.expires < now:
        return error("That code is wrong or has expired. Create a new one in OraSec.", 400, code="bad_code")
    if not org_wide(link_code.user):
        return error("Your OraSec account does not have organisation-wide access.", 403, code="no_access")
    with transaction.atomic():
        # single use, even if two requests race
        updated = MobileLinkCode.objects.filter(pk=link_code.pk, used_at=None).update(used_at=now)
        if not updated:
            return error("That code has already been used. Create a new one in OraSec.", 400, code="bad_code")
        device, token = MobileDevice.issue(user=link_code.user, name=str(body.get("device_name") or "Phone"),
                                           platform=str(body.get("platform") or "android"), app_version=str(body.get("app_version") or ""), ip=ip)
        MobileLinkCode.objects.filter(pk=link_code.pk).update(device=device)
    logger.info("mobile device %s linked for %s from %s", device.pk, link_code.user, ip)
    return _ok({"token": token, "device": {"id": device.id, "name": device.name}, "user": _user(link_code.user)}, 201)


@mobile_api(("POST",))
def logout(request):
    MobileDevice.objects.filter(pk=request.mobile_device.pk).update(revoked_at=timezone.now(), push_token="")
    return _ok({"ok": True})


@mobile_api()
def me(request):
    d = request.mobile_device
    return _ok({"user": _user(request.user), "device": {"id": d.id, "name": d.name, "platform": d.platform, "linked": _iso(d.created)},
                "server_time": _iso(timezone.now()), "min_app_version": MIN_APP_VERSION,
                "push": {"available": _push_available(d)}, "plugins": _plugins()})


def _plugins():
    from orasec.plugins import registry  # noqa: PLC0415
    return registry.active_map()


@mobile_api()
def plugins(request):
    """Every plugin with its state, for the app's Data sources screen. Read only: plugins are switched on the web."""
    from orasec.plugins import registry  # noqa: PLC0415
    keep = ("key", "name", "group", "on", "available", "active")
    return _ok({"plugins": [{k: row[k] for k in keep} for row in registry.snapshot()]})


@mobile_api(auth=False)
def server_info(request):
    """What the app asks before linking, to check that the address someone typed is an OraSec server. No sign-in, no data."""
    if rate_limited("info-ip", client_ip(request) or "-", 60, 60):
        return error("Too many requests. Try again in a minute.", 429)
    return _ok({"product": "OraSec", "api": 1, "min_app_version": MIN_APP_VERSION})


# ---------------------------------------------------------------------------
# Push notifications (orasec/mobile/push.py sends them, orasec/mobile/notify.py decides what and to whom)
# ---------------------------------------------------------------------------
PUSH_TOKEN_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789:_-.")


def _push_available(device):
    from orasec.mobile import push  # noqa: PLC0415
    return bool(push.configured().get(device.push_kind or "", False))


def _push_state(request):
    device = MobileDevice.objects.get(pk=request.mobile_device.pk)
    prefs = MobilePushPrefs.objects.filter(user=request.user).first()
    return {"available": _push_available(device), "registered": bool(device.push_token),
            "settings": prefs.as_dict() if prefs else dict.fromkeys(PUSH_KINDS, True)}


@mobile_api(("POST",))
def push_register(request):
    """The app hands over the address Google or Apple gave this install. It replaces the one stored before."""
    from orasec.mobile import notify  # noqa: PLC0415
    token = str(_json(request).get("token") or "").strip()
    if not (16 <= len(token) <= 512) or not set(token) <= PUSH_TOKEN_CHARS:
        return error("That is not a notification address.")
    device = request.mobile_device
    if device.push_kind is None:
        return error("This device type has no notifications.")
    now = timezone.now()
    was_on = MobileDevice.objects.filter(user=request.user, revoked_at=None).exclude(push_token="").exists()
    # one install, one linked device: a re-linked phone keeps its address, the old link must not get its notifications
    MobileDevice.objects.filter(push_token=token).exclude(pk=device.pk).update(push_token="", push_updated=now)
    MobileDevice.objects.filter(pk=device.pk).update(push_token=token, push_updated=now)
    prefs, created = MobilePushPrefs.objects.get_or_create(user=request.user)
    if created or not was_on:
        # switched on (or back on): what came in while this person had no notifications is not news
        notify.seed(request.user, [kind for kind in PUSH_KINDS if getattr(prefs, kind)], now)
    return _ok(_push_state(request))


@mobile_api(("POST",))
def push_unregister(request):
    MobileDevice.objects.filter(pk=request.mobile_device.pk).update(push_token="", push_updated=timezone.now())
    return _ok(_push_state(request))


@mobile_api(("GET", "POST"))
def push_settings(request):
    """Which of the four kinds this person wants. A kind that is switched back on starts from now."""
    from orasec.mobile import notify  # noqa: PLC0415
    if request.method == "POST":
        body = _json(request)
        prefs, created = MobilePushPrefs.objects.get_or_create(user=request.user)
        turned_on = list(PUSH_KINDS) if created else []
        for kind in PUSH_KINDS:
            if isinstance(body.get(kind), bool) and body[kind] != getattr(prefs, kind):
                setattr(prefs, kind, body[kind])
                if body[kind]:
                    turned_on.append(kind)
        prefs.save()
        if turned_on:
            notify.seed(request.user, turned_on)
    return _ok(_push_state(request))


@mobile_api(("POST",))
def push_test(request):
    """Send one test notification to this phone, so a person can see that it arrives."""
    from orasec.mobile import push  # noqa: PLC0415
    device = MobileDevice.objects.get(pk=request.mobile_device.pk)
    if rate_limited("push-test", device.pk, 3, 600):
        return error("You have sent a few tests already. Wait 10 minutes.", 429)
    if not device.push_token:
        return error("Notifications are not switched on for this phone.", 400, code="not_registered")
    result = push.send(device.push_kind, device.push_token, "OraSec test",
                       "Notifications work on this phone.", {"kind": "test", "path": "/settings/notifications"}, ttl=300)
    if result.gone:
        MobileDevice.objects.filter(pk=device.pk).update(push_token="", push_updated=timezone.now())
    if not result.ok:
        logger.warning("mobile push: test to device %s failed: %s", device.pk, result.detail)
    return _ok({"ok": result.ok, "detail": "" if result.ok else "The notification service did not accept it. Try again later."})


# ---------------------------------------------------------------------------
# Overview
# ---------------------------------------------------------------------------
@mobile_api()
def dashboard(request):
    data = _dashboard()
    if data is None:
        return _ok({"pending": True}, 202)
    out = {k: v for k, v in data.items() if k != "assets_all"}
    for a in out.get("assets", []):
        a.pop("tests", None)
    return _ok(out)


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------
def _finding_qs():
    from orasec.models import Finding  # noqa: PLC0415
    return Finding.objects.filter(duplicate=False)


def _finding_row(f):
    pr = getattr(f, "priority", None)
    return {"id": f.id, "title": f.title, "severity": f.severity, "cve": f.cve, "component": f.component_name,
            "component_version": f.component_version, "kev": bool(f.known_exploited), "epss": f.epss_score,
            "active": f.active, "mitigated": bool(f.is_mitigated), "date": _iso(f.date),
            "asset": f.test.title if f.test_id else None, "product": f.test.engagement.product.name if f.test_id else None,
            "band": pr.band if pr else None, "score": pr.score if pr else None, "due": _iso(pr.due_date) if pr else None,
            "overdue": bool(pr and pr.due_date and pr.due_date < timezone.localdate() and f.active)}


@mobile_api()
def findings(request):
    g = request.GET
    qs = _finding_qs().select_related("test__engagement__product", "priority")
    status = g.get("status", "open")
    if status == "closed":
        qs = qs.filter(is_mitigated=True)
    elif status != "all":
        qs = qs.filter(active=True)
    sev = [s for s in g.get("severity", "").split(",") if s in SEVS]
    if sev:
        qs = qs.filter(severity__in=sev)
    if g.get("kev") == "1":
        qs = qs.filter(known_exploited=True)
    if g.get("epss") == "1":
        qs = qs.filter(epss_score__gte=metrics.EPSS_LIKELY)
    if g.get("overdue") == "1":
        qs = qs.filter(priority__due_date__lt=timezone.localdate())
    if g.get("mine") == "1":
        qs = qs.filter(assignment__assignee=request.user)
    if g.get("asset"):
        data = _dashboard() or {}
        row = next((a for a in data.get("assets_all", []) if a.get("key") == g["asset"].lower()), None)
        qs = qs.filter(test_id__in=row["tests"] if row else [])
    if g.get("product"):
        qs = qs.filter(test__engagement__product__name=g["product"])
    q = (g.get("q") or "").strip()
    if q:
        qs = qs.filter(Q(title__icontains=q) | Q(cve__icontains=q) | Q(component_name__icontains=q) | Q(test__title__icontains=q))
    order = g.get("sort", "priority")
    qs = qs.order_by("-mitigated", "-id") if status == "closed" else (
        qs.order_by("-date", "-id") if order == "newest" else qs.order_by("-priority__score", "numerical_severity", "-id"))
    try:
        offset = max(0, int(g.get("offset", 0)))
        limit = min(50, max(1, int(g.get("limit", 25))))
    except ValueError:
        offset, limit = 0, 25
    total = qs.count()
    rows = [_finding_row(f) for f in qs[offset:offset + limit]]
    return _ok({"total": total, "offset": offset, "limit": limit, "next": offset + limit if offset + limit < total else None, "results": rows})


def _get_finding(fid):
    return _finding_qs().select_related("test__engagement__product", "test__test_type", "priority", "mitigated_by").filter(pk=fid).first()


def _finding_detail(f, user):
    row = _finding_row(f)
    notes = []
    for n in f.notes.select_related("author").order_by("-date")[:20]:
        if n.private and not (user.is_superuser or n.author_id == user.id):
            continue
        notes.append({"id": n.id, "text": n.entry, "author": n.author.get_full_name() or n.author.username, "date": _iso(n.date)})
    try:
        assignee = f.assignment.assignee
    except Exception:  # noqa: BLE001 - reverse one-to-one missing
        assignee = None
    row.update({
        "description": f.description, "mitigation": f.mitigation, "impact": f.impact, "references": f.references,
        "cwe": f.cwe, "cvss": f.cvssv3_score, "epss_percentile": f.epss_percentile, "ransomware": bool(f.ransomware_used),
        "file_path": f.file_path, "line": f.line, "fix_version": getattr(f, "fix_version", None), "verified": f.verified,
        "false_positive": f.false_p, "risk_accepted": f.risk_accepted, "scanner": f.test.test_type.name if f.test_id else None,
        "test_id": f.test_id, "created": _iso(f.created), "mitigated_at": _iso(f.mitigated),
        "mitigated_by": (f.mitigated_by.get_full_name() or f.mitigated_by.username) if f.mitigated_by_id else None,
        "sla_basis": f.priority.sla_basis if hasattr(f, "priority") and f.priority else None,
        "assignee": (assignee.get_full_name() or assignee.username) if assignee else None,
        "assigned_to_me": bool(assignee and assignee.id == user.id), "notes": notes,
        "web_url": f"/finding/{f.id}",
    })
    return row


@mobile_api(("GET",))
def finding_detail(request, fid):
    f = _get_finding(fid)
    if not f:
        return error("Finding not found.", 404)
    return _ok(_finding_detail(f, request.user))


@mobile_api(("POST",))
def finding_note(request, fid):
    from orasec.models import Notes  # noqa: PLC0415
    f = _get_finding(fid)
    if not f:
        return error("Finding not found.", 404)
    text = str(_json(request).get("text", "")).strip()
    if not text:
        return error("Write a note first.")
    with crum.impersonate(request.user):
        note = Notes.objects.create(entry=text[:5000], author=request.user)
        f.notes.add(note)
        f.last_reviewed, f.last_reviewed_by = timezone.now(), request.user
        f.save(update_fields=["last_reviewed", "last_reviewed_by"])
    return _ok(_finding_detail(_get_finding(fid), request.user), 201)


@mobile_api(("POST",))
def finding_close(request, fid):
    from orasec.finding.helper import close_finding  # noqa: PLC0415
    f = _get_finding(fid)
    if not f:
        return error("Finding not found.", 404)
    if not f.active:
        return error("This finding is already closed.", 409)
    body = _json(request)
    reason = body.get("reason", "mitigated")
    note = str(body.get("note", "")).strip()
    if not note:
        return error("Add a short note saying how it was fixed.")
    with crum.impersonate(request.user):
        close_finding(finding=f, user=request.user, is_mitigated=reason == "mitigated", mitigated=timezone.now(), mitigated_by=request.user,
                      false_p=reason == "false_positive", out_of_scope=reason == "out_of_scope", duplicate=False,
                      note_entry=f"[OraSec app] {note}"[:5000])
    return _ok(_finding_detail(_get_finding(fid), request.user))


@mobile_api(("POST",))
def finding_assign(request, fid):
    from orasec.posture.models import FindingAssignment  # noqa: PLC0415
    f = _get_finding(fid)
    if not f:
        return error("Finding not found.", 404)
    if _json(request).get("unassign"):
        FindingAssignment.objects.filter(finding=f, assignee=request.user).delete()
    else:
        FindingAssignment.objects.update_or_create(finding=f, defaults={"assignee": request.user, "assigned_by": request.user,
                                                                         "assigned_at": timezone.now()})
    return _ok(_finding_detail(_get_finding(fid), request.user))


# ---------------------------------------------------------------------------
# Assets, attacks, code
# ---------------------------------------------------------------------------
@mobile_api()
def assets(request):
    data = _dashboard() or {}
    rows = [{k: v for k, v in a.items() if k != "tests"} for a in data.get("assets_all", [])]
    q = (request.GET.get("q") or "").lower().strip()
    if q:
        rows = [r for r in rows if q in r["name"].lower() or q in (r.get("product") or "").lower() or q in r["kind"].lower()]
    return _ok({"total": len(rows), "results": rows, "generated": data.get("generated")})


@mobile_api()
def asset_detail(request, key):
    data = _dashboard() or {}
    row = next((a for a in data.get("assets_all", []) if a.get("key") == key.lower()), None)
    if not row:
        return error("Asset not found.", 404)
    from orasec.posture.models import InventoryAsset  # noqa: PLC0415
    inv = InventoryAsset.find(row.get("key") or row["name"]) or InventoryAsset.find(row["name"])
    out = {k: v for k, v in row.items() if k != "tests"}
    if inv:
        out["inventory"] = {"id": inv.id, "type": inv.get_asset_type_display(), "hostname": inv.hostname, "ip": inv.ip_address,
                            "os": f"{inv.os_name} {inv.os_version}".strip(), "vendor": inv.vendor, "model": inv.model,
                            "online": inv.online, "exposed": inv.internet_exposed, "criticality": inv.criticality,
                            "owner": (inv.owner.get_full_name() or inv.owner.username) if inv.owner_id else None,
                            "last_seen": _iso(inv.last_seen), "last_scanned": _iso(inv.last_scanned_at)}
    top = (_finding_qs().filter(active=True, test_id__in=row["tests"]).select_related("test__engagement__product", "priority")
           .order_by("-priority__score", "numerical_severity")[:10])
    out["top_findings"] = [_finding_row(f) for f in top]
    return _ok(out)


@mobile_api()
def attacks(request):
    from orasec.posture import views as posture_views  # noqa: PLC0415
    rng = request.GET.get("range", "7d")
    request.GET = request.GET.copy()
    request.GET["range"] = rng if rng in {"24h", "7d", "30d", "90d"} else "7d"
    response = posture_views.attacks_api(request)
    data = json.loads(response.content)
    data["ips"] = data.get("ips", [])[:60]
    # Security alerts come first in "Latest": blocked traffic arrives by the hundred and would push them off the list.
    alerts = data.get("alerts", [])[:20]
    for a in alerts:
        a["ip"] = a["ip"] or "Host alert"  # the list shows the address as the heading; an alert on a machine has none
    shown = {(a["t"], a["source"], a["rule"][:120]) for a in alerts}
    data["alerts"] = alerts
    data["recent"] = (alerts + [e for e in data.get("recent", []) if (e["t"], e["source"], e["rule"]) not in shown])[:60]
    data["countries"] = data.get("countries", [])[:30]
    for c in data["countries"]:
        c.pop("sources", None)
    return _ok(data)


@mobile_api()
def code(request):
    data = _dashboard() or {}
    return _ok({"products": data.get("code", []), "categories": data.get("code_cats", []), "generated": data.get("generated")})


# ---------------------------------------------------------------------------
# Governance
# ---------------------------------------------------------------------------
def _risk_row(r, today):
    is_open = r.status not in {"closed", "accepted"}
    return {"id": r.id, "ref": r.ref, "title": r.title, "product": r.product.name if r.product_id else None,
            "likelihood": r.likelihood, "impact": r.impact, "score": r.likelihood * r.impact,
            "residual": (r.residual_likelihood * r.residual_impact) if r.residual_likelihood and r.residual_impact else None,
            "treatment": r.get_treatment_display(), "status": r.status, "status_label": r.get_status_display(),
            "owner": (r.owner.get_full_name() or r.owner.username) if r.owner_id else None, "review": _iso(r.review_date),
            "review_overdue": bool(r.review_date and r.review_date < today and is_open), "open": is_open}


@mobile_api()
def risks(request):
    from orasec.posture.models import RiskRegisterEntry  # noqa: PLC0415
    today = timezone.localdate()
    rows = [_risk_row(r, today) for r in RiskRegisterEntry.objects.select_related("owner", "product")]
    rows.sort(key=lambda r: (not r["open"], -r["score"]))
    data = _dashboard() or {}
    return _ok({"results": rows, "heat": (data.get("risk") or {}).get("heat", [])})


@mobile_api()
def risk_detail(request, rid):
    from orasec.posture.models import RiskRegisterEntry  # noqa: PLC0415
    r = RiskRegisterEntry.objects.select_related("owner", "product").filter(pk=rid).first()
    if not r:
        return error("Risk not found.", 404)
    out = _risk_row(r, timezone.localdate())
    out.update({"description": r.description, "threat": r.threat, "vulnerability": r.vulnerability, "treatment_plan": r.treatment_plan,
                "controls": [{"ref": c.ref, "title": c.title} for c in r.controls.all()[:30]],
                "findings": [_finding_row(f) for f in r.findings.select_related("test__engagement__product", "priority")[:20]],
                "updated": _iso(r.updated)})
    return _ok(out)


@mobile_api()
def compliance(request):
    from orasec.posture import compliance as comp  # noqa: PLC0415
    from orasec.posture.models import ControlImplementation  # noqa: PLC0415
    summary = comp.summary()
    by_cat = {}
    attention = []
    for i in (ControlImplementation.objects.filter(control__framework__code=comp.CODE).select_related("control", "owner")
              .order_by("control__sort_key")):
        c = i.control
        cat = by_cat.setdefault(c.category, {"category": c.category, "total": 0, "implemented": 0, "fail": 0, "pass": 0})
        cat["total"] += 1
        cat["implemented"] += 1 if i.status == "implemented" else 0
        cat["fail"] += 1 if i.auto_status == "fail" else 0
        cat["pass"] += 1 if i.auto_status == "pass" else 0
        if i.auto_status in {"fail", "warn"}:
            attention.append({"ref": c.ref, "title": c.title, "category": c.category, "auto_status": i.auto_status,
                              "detail": (i.auto_detail or "")[:400], "status": i.get_status_display(),
                              "owner": (i.owner.get_full_name() or i.owner.username) if i.owner_id else None,
                              "evaluated": _iso(i.auto_evaluated_at)})
    attention.sort(key=lambda a: (a["auto_status"] != "fail", a["ref"]))
    return _ok({"summary": summary, "categories": list(by_cat.values()), "attention": attention})


@mobile_api()
def connectors(request):
    from orasec.posture.models import Connector, IntelFeed  # noqa: PLC0415
    from orasec.plugins import registry as plugins  # noqa: PLC0415
    now = timezone.now()
    rows = []
    for c in Connector.objects.order_by("name"):
        plugin_on = plugins.source_on(c.kind)
        healthy = bool(plugin_on and c.enabled and c.last_status in {"ok", "warning"} and c.last_success_at
                       and now - c.last_success_at < datetime.timedelta(minutes=c.interval_minutes * 2 + 60))
        rows.append({"id": c.id, "name": c.name, "kind": c.get_kind_display(), "enabled": bool(c.enabled and plugin_on), "plugin_on": plugin_on,
                     "status": c.last_status,
                     "healthy": healthy, "last_run": _iso(c.last_run_at), "last_success": _iso(c.last_success_at),
                     "message": (c.last_message or "")[:300], "interval_minutes": c.interval_minutes})
    feeds = [{"name": f.name.upper(), "status": f.status, "records": f.records, "last": _iso(f.last_refreshed)} for f in IntelFeed.objects.all()]
    return _ok({"connectors": rows, "feeds": feeds})


@mobile_api()
def my_work(request):
    qs = (_finding_qs().filter(active=True).filter(Q(assignment__assignee=request.user) | Q(priority__due_date__lt=timezone.localdate()))
          .select_related("test__engagement__product", "priority").order_by("priority__due_date", "-priority__score")[:50])
    rows = [_finding_row(f) for f in qs]
    counts = _finding_qs().filter(active=True).aggregate(
        mine=Count("id", filter=Q(assignment__assignee=request.user)),
        overdue=Count("id", filter=Q(priority__due_date__lt=timezone.localdate())),
        due7=Count("id", filter=Q(priority__due_date__gte=timezone.localdate(), priority__due_date__lte=timezone.localdate() + datetime.timedelta(days=7))))
    return _ok({"counts": counts, "results": rows})


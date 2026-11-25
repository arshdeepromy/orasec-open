"""Ora's insight tools. Every figure is computed here, in code -- the AI only explains it.

Each tool returns a dict that goes to the AI as TOOL_RESULT (after scrubbing,
vault placeholders and injection cleaning) and to the UI as the source of the
rows it renders. List-shaped answers carry ``items``: each has a stable
``ref`` ("F-123", "A-dev-box", "R-001", "CVE-2024-1234", "C-OpenSSL") plus the
title / severity / path the app shows. The AI picks refs; it never makes rows up.

Access: findings come from ``get_authorized_findings`` for the user. The
organisation-wide views (posture, attacks, connectors, compliance, risk
register) need the same access as the dashboard (staff or superuser).
"""
from __future__ import annotations

import datetime
import logging
import re
from typing import Any, Callable

from django.db.models import Count, Max, Min, Q
from django.utils import timezone

logger = logging.getLogger(__name__)

SEVS = ["Critical", "High", "Medium", "Low", "Info"]
SEV_RANK = {s: i for i, s in enumerate(SEVS)}
BANDS = ["Urgent", "Needs Action", "Medium", "Low"]
DENIED = {"denied": True, "summary": "This needs organisation-wide access (security team). Ask an OraSec admin."}


def org_wide(user) -> bool:
    return bool(user and user.is_active and (user.is_superuser or user.is_staff))


def _today() -> datetime.date:
    return timezone.localdate()


def _iso(v):
    return v.isoformat() if v else None


def _int(v, default=None, lo=None, hi=None):
    try:
        n = int(v)
    except (TypeError, ValueError):
        return default
    if lo is not None:
        n = max(lo, n)
    if hi is not None:
        n = min(hi, n)
    return n


def _str(v, limit=120) -> str:
    return str(v).strip()[:limit] if isinstance(v, (str, int, float)) and str(v).strip() else ""


def _dashboard() -> dict[str, Any]:
    from orasec.home import metrics  # noqa: PLC0415

    try:
        return metrics.get(allow_sync=False) or {}
    except TypeError:
        return metrics.get() or {}
    except Exception:  # noqa: BLE001
        logger.warning("ora: dashboard document unavailable", exc_info=True)
        return {}


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

def findings_for(user):
    from orasec.authorization.roles_permissions import Permissions  # noqa: PLC0415
    from orasec.finding.queries import get_authorized_findings  # noqa: PLC0415
    from orasec.models import Finding  # noqa: PLC0415

    qs = Finding.objects.all() if org_wide(user) else get_authorized_findings(Permissions.Finding_View, user=user)
    return qs.filter(duplicate=False)


def _open(qs):
    return qs.filter(active=True)


def _asset_q(asset: str) -> Q | None:
    """Findings on an asset: by product name, endpoint host, or the dashboard's host→tests map."""
    a = (asset or "").strip()
    if not a:
        return None
    q = Q(test__engagement__product__name__icontains=a)
    try:
        q |= Q(endpoints__host__icontains=a)
    except Exception:  # noqa: BLE001
        pass
    tests = []
    for row in _dashboard().get("assets_all", []):
        if a.lower() in (row.get("name") or "").lower() or a.lower() == (row.get("key") or "").lower():
            tests += row.get("tests") or []
    if tests:
        q |= Q(test_id__in=tests)
    return q


_FACTOR_WORDS = {
    "kev": "known exploited (CISA KEV)",
    "ransomware": "used in ransomware",
    "exposure": "internet-facing",
    "fix_available": "fix available",
    "overdue": "past its SLA due date",
}


def factor_text(f) -> list[str]:
    p = getattr(f, "priority", None) if hasattr(f, "priority") else None
    try:
        factors = (p.factors or {}) if p else {}
    except Exception:  # noqa: BLE001
        factors = {}
    out = []
    for k in ("kev", "ransomware", "exposure", "overdue"):
        if k in factors:
            out.append(_FACTOR_WORDS[k])
    if f.epss_percentile:
        out.append(f"EPSS {round(f.epss_percentile * 100)}th percentile")
    if "criticality" in factors:
        out.append(f"asset criticality {round(factors['criticality'] / 2)}/5")
    if f.fix_available or "fix_available" in factors:
        out.append(_FACTOR_WORDS["fix_available"])
    return out


def _priority(f):
    try:
        return f.priority
    except Exception:  # noqa: BLE001 -- RelatedObjectDoesNotExist
        return None


def finding_item(f) -> dict[str, Any]:
    p = _priority(f)
    prod = f.test.engagement.product if f.test_id else None
    cve = f.cve or (f.vuln_id_from_tool if (f.vuln_id_from_tool or "").upper().startswith("CVE-") else None)
    due = p.due_date if p else f.sla_expiration_date
    return {
        "ref": f"F-{f.id}", "kind": "finding", "id": f.id, "title": (f.title or "")[:160],
        "severity": f.severity, "band": p.band if p else None, "score": p.score if p else None,
        "cve": cve, "component": f.component_name or None, "fix_version": f.fix_version or None,
        "asset": prod.name if prod else None, "kev": bool(f.known_exploited),
        "epss_pct": round(f.epss_percentile * 100) if f.epss_percentile else None,
        "due": _iso(due), "overdue": bool(due and f.active and due < _today()),
        "status": "open" if f.active else ("accepted" if f.risk_accepted else "closed"),
        "factors": factor_text(f), "path": f"/finding/{f.id}",
    }


def _rows(qs, limit):
    qs = qs.select_related("test__engagement__product", "priority")
    return [finding_item(f) for f in qs[:limit]]


def _by_priority(qs):
    return qs.order_by(
        "-priority__score", "priority__due_date", "-known_exploited", "-epss_percentile", "id")


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

def t_posture_summary(user, args):
    if not org_wide(user):
        mine = _open(findings_for(user))
        sev = dict(mine.order_by().values_list("severity").annotate(n=Count("id")))
        return {"scope": "findings you can see", "open": mine.count(),
                "severity": {s: sev.get(s, 0) for s in SEVS},
                "kev": mine.filter(known_exploited=True).count(),
                "summary": "Organisation-wide posture needs security-team access; these are the findings you can see."}
    d = _dashboard()
    if not d:
        return {"summary": "The dashboard figures are still being computed. Try again in a minute."}
    kpi, sla, ex, att, risk, comp = (d.get(k) or {} for k in ("kpi", "sla", "exploit", "attacks", "risk", "compliance"))
    posture = d.get("posture") or {}
    trend = posture.get("trend") or []
    delta = (trend[-1]["score"] - trend[-2]["score"]) if len(trend) > 1 else None
    unhealthy = [c["name"] for c in d.get("connectors") or [] if not c.get("healthy")]
    feeds_bad = [f["name"] for f in d.get("feeds") or [] if f.get("status") != "ok"]
    return {
        "as_of": d.get("generated"),
        "posture": {"score": posture.get("score"), "out_of": 1000, "vulnerability": posture.get("vuln"),
                    "compliance": posture.get("compliance"), "hygiene": posture.get("hygiene"), "change_since_last": delta},
        "open_findings": kpi.get("open"), "severity": {r["name"]: r["n"] for r in d.get("severity") or []},
        "bands": {r["name"]: r["n"] for r in d.get("bands") or []},
        "new_7d": kpi.get("new7"), "resolved_30d": kpi.get("resolved30"),
        "assets": kpi.get("assets"), "internet_exposed_assets": kpi.get("exposed"),
        "exploitable": {"kev_findings": ex.get("kev_findings"), "kev_cves": ex.get("kev_cves"),
                        "ransomware": ex.get("ransomware"), "epss_likely_findings": ex.get("epss_likely"),
                        "assets_affected": ex.get("assets_affected")},
        "sla": {"overdue": sla.get("overdue"), "due_in_7d": sla.get("due7"), "within_sla_pct": sla.get("within_pct"),
                "targets_days": sla.get("targets")},
        "attacks_blocked": {"last_24h": att.get("h24"), "last_7d": att.get("d7"), "last_30d": att.get("d30"),
                            "unique_sources_7d": att.get("ips7")},
        "risk_register": {"open": risk.get("open"), "high": risk.get("high"), "review_overdue": risk.get("review_overdue")},
        "compliance": {"score": comp.get("score"), "checks_failing": comp.get("fail"), "checks_warning": comp.get("warn"),
                       "applicable_controls": comp.get("applicable"), "implemented": comp.get("implemented")},
        "unhealthy_connectors": unhealthy, "intel_feeds_with_errors": feeds_bad,
        "path": "/dashboard",
    }


_SCOPES = {"all", "mine", "kev", "exposed", "overdue"}


def t_prioritise(user, args):
    scope = args.get("scope") if args.get("scope") in _SCOPES else "all"
    limit = _int(args.get("limit"), 5, 1, 10)
    qs = _open(findings_for(user)).exclude(severity="Info")
    asset = _str(args.get("asset"))
    if asset:
        aq = _asset_q(asset)
        qs = qs.filter(aq).distinct() if aq is not None else qs
    if scope == "mine":
        qs = qs.filter(assignment__assignee=user)
    elif scope == "kev":
        qs = qs.filter(known_exploited=True)
    elif scope == "exposed":
        qs = qs.filter(Q(priority__factors__has_key="exposure") | Q(test__engagement__product__internet_accessible=True))
    elif scope == "overdue":
        qs = qs.filter(priority__due_date__lt=_today())
    total = qs.count()
    bands = dict(qs.order_by().values_list("priority__band").annotate(n=Count("id")))
    items = _rows(_by_priority(qs), limit)
    # Components whose single update clears the most risk in this scope.
    comp = (qs.exclude(component_name=None).exclude(component_name="").order_by().values("component_name")
            .annotate(findings=Count("id", distinct=True), kev=Count("id", filter=Q(known_exploited=True), distinct=True),
                      urgent=Count("id", filter=Q(priority__band__in=["Urgent", "Needs Action"]), distinct=True),
                      top=Max("priority__score"), fix=Max("fix_version"))
            .order_by("-kev", "-urgent", "-findings")[:3])
    fix_first = [{"ref": f"C-{c['component_name']}", "kind": "component", "component": c["component_name"],
                  "findings": c["findings"], "kev": c["kev"], "high_priority": c["urgent"], "fix_version": c["fix"],
                  "path": "/orasec/remediation/"} for c in comp if c["findings"] > 1]
    from orasec.posture.models import PrioritySettings  # noqa: PLC0415

    ps = PrioritySettings.load()
    return {
        "scope": scope, "asset": asset or None, "open_in_scope": total,
        "bands": {b: bands.get(b, 0) for b in BANDS},
        "how_scored": "score 0-100 from severity, KEV, ransomware, EPSS percentile, internet exposure, asset "
                      "criticality, fix availability and overdue SLA; bands Urgent / Needs Action / Medium / Low",
        "sla_days": {**PrioritySettings.DEFAULT_SLA, **(ps.sla_days or {})},
        "items": items, "fix_first": fix_first,
        "path": "/orasec/vulnerabilities/" if scope != "mine" else "/orasec/my-work/",
    }


def _level(score: int) -> str:
    return "Critical" if score >= 20 else "High" if score >= 15 else "Medium" if score >= 8 else "Low"


def _asset_criticality(f) -> tuple[int, bool, str | None]:
    """(criticality 1-5, internet exposed, asset name) for a finding."""
    from orasec.posture.intel import CRITICALITY_POINTS  # noqa: PLC0415
    from orasec.posture.models import InventoryAsset  # noqa: PLC0415

    prod = f.test.engagement.product
    crit = CRITICALITY_POINTS.get((prod.business_criticality or "").lower(), 3)
    exposed = bool(prod.internet_accessible)
    name = prod.name
    try:
        hosts = [h.lower() for h in f.endpoints.values_list("host", flat=True) if h]
    except Exception:  # noqa: BLE001
        hosts = []
    if hosts:
        for a in InventoryAsset.objects.filter(hostname__in=hosts).only("criticality", "internet_exposed", "name"):
            if a.criticality >= crit:
                crit, name = a.criticality, a.name
            exposed = exposed or a.internet_exposed
    p = _priority(f)
    if p and "exposure" in (p.factors or {}):
        exposed = True
    return crit, exposed, name


def assess(findings: list) -> dict[str, Any]:
    """Likelihood and impact (1-5) with the evidence for each, from the worst findings."""
    if not findings:
        return {}
    best = None
    for f in findings:
        evidence, lik = [], {"Critical": 3, "High": 3, "Medium": 2, "Low": 1}.get(f.severity, 1)
        if f.known_exploited:
            lik = 5
            evidence.append("known exploited in the wild (CISA KEV)")
        elif f.epss_percentile and f.epss_percentile >= 0.95:
            lik = max(lik, 4)
            evidence.append(f"EPSS {round(f.epss_percentile * 100)}th percentile: likely to be exploited soon")
        elif f.epss_percentile and f.epss_percentile >= 0.7:
            lik = max(lik, 3)
            evidence.append(f"EPSS {round(f.epss_percentile * 100)}th percentile")
        crit, exposed, asset = _asset_criticality(f)
        if exposed:
            lik = min(5, lik + 1)
            evidence.append("reachable from the internet")
        imp = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}.get(f.severity, 1)
        imp = max(1, min(5, round((imp + crit) / 2 + (1 if f.ransomware_used else 0) + 0.01)))
        evidence.append(f"{f.severity} severity on {asset} (criticality {crit}/5)")
        if f.ransomware_used:
            evidence.append("used in ransomware campaigns")
        p = _priority(f)
        if p and p.due_date and p.due_date < _today():
            evidence.append(f"past its SLA due date ({p.due_date.isoformat()})")
        if f.fix_available or f.fix_version:
            evidence.append(f"fix available{(' in ' + f.fix_version) if f.fix_version else ''}")
        cand = {"likelihood": lik, "impact": imp, "score": lik * imp, "evidence": evidence, "finding": f,
                "fix": bool(f.fix_available or f.fix_version), "asset": asset}
        if best is None or cand["score"] > best["score"]:
            best = cand
    lvl = _level(best["score"])
    if lvl in ("Critical", "High"):
        treat = "mitigate" if best["fix"] else "mitigate"
        plan = ("Patch / upgrade now" if best["fix"] else "No fix yet: add compensating controls (block exposure, "
                "WAF / firewall rule, isolate the host) and track the vendor fix") + \
               (" -- within the Urgent SLA." if lvl == "Critical" else " -- within the Needs Action SLA.")
    elif lvl == "Medium":
        treat, plan = "mitigate", "Schedule the fix in the next patch cycle; accept only with an expiry date and owner."
    else:
        treat, plan = "accept", "Low risk: accept with an expiry date or fix during routine maintenance."
    f = best["finding"]
    return {"likelihood": best["likelihood"], "impact": best["impact"], "score": best["score"], "level": lvl,
            "scale": "likelihood x impact, each 1-5; 15+ High, 20+ Critical, 8-14 Medium",
            "evidence": best["evidence"][:6], "treatment": treat, "treatment_plan": plan,
            "worst_finding": f"F-{f.id}", "asset": best["asset"]}


def _matching_risks(finding_ids: list[int], words: list[str]) -> list[dict[str, Any]]:
    from orasec.posture.models import RiskRegisterEntry  # noqa: PLC0415

    q = Q(findings__id__in=finding_ids) if finding_ids else Q(pk__in=[])
    for w in words:
        if w and len(w) >= 4:
            q |= Q(title__icontains=w)
    out = []
    for r in RiskRegisterEntry.objects.filter(q).exclude(status="closed").distinct()[:5]:
        out.append({"ref": r.ref, "kind": "risk", "id": r.id, "title": r.title[:160], "likelihood": r.likelihood,
                    "impact": r.impact, "score": r.likelihood * r.impact, "level": _level(r.likelihood * r.impact),
                    "status": r.status, "path": f"/orasec/risks/{r.id}/"})
    return out


def t_evaluate_risk(user, args):
    from orasec.posture.models import RiskRegisterEntry  # noqa: PLC0415

    base = _open(findings_for(user)).select_related("test__engagement__product", "priority")
    fid, cve = _int(args.get("finding_id")), _str(args.get("cve"), 40).upper()
    asset, rid = _str(args.get("asset")), _int(args.get("risk_id"))
    risk = None
    if rid:
        if not org_wide(user):
            return DENIED
        risk = RiskRegisterEntry.objects.filter(id=rid).first() or RiskRegisterEntry.objects.filter(ref__iexact=str(args.get("risk_id"))).first()
        if not risk:
            return {"error": "No risk with that id."}
        fs = list(risk.findings.filter(active=True).select_related("test__engagement__product", "priority")[:200])
        subject = f"risk {risk.ref}"
    elif fid:
        fs = list(findings_for(user).filter(id=fid).select_related("test__engagement__product", "priority"))
        if not fs:
            return {"error": "No finding with that id that you can see."}
        subject = f"finding F-{fid}"
    elif cve:
        if not re.match(r"^CVE-\d{4}-\d{3,}$", cve):
            return {"error": "That doesn't look like a CVE id."}
        fs = list(base.filter(Q(cve__iexact=cve) | Q(vuln_id_from_tool__iexact=cve) | Q(vulnerability_id__vulnerability_id__iexact=cve)).distinct()[:300])
        subject = cve
    elif asset:
        aq = _asset_q(asset)
        fs = list(_by_priority(base.filter(aq).distinct())[:300]) if aq is not None else []
        subject = f"asset {asset}"
    else:
        return {"error": "Tell me which finding, CVE, asset or risk to evaluate."}
    if not fs:
        out = {"subject": subject, "open_findings": 0, "summary": "No open findings, so there is no current exposure from it."}
        if risk:
            out["recorded"] = {"likelihood": risk.likelihood, "impact": risk.impact,
                               "score": risk.likelihood * risk.impact, "ref": risk.ref}
        return out
    a = assess(fs)
    assets = sorted({x.test.engagement.product.name for x in fs})
    kev = sum(1 for x in fs if x.known_exploited)
    out = {"subject": subject, "open_findings": len(fs), "assets": assets[:10], "assets_count": len(assets),
           "kev_findings": kev, **a, "items": [finding_item(x) for x in sorted(
               fs, key=lambda x: -((_priority(x).score if _priority(x) else 0)))[:5]]}
    words = [cve, asset] + ([fs[0].component_name] if fs[0].component_name else [])
    out["matching_risks"] = _matching_risks([x.id for x in fs][:500], [w for w in words if w]) if org_wide(user) else []
    if risk:
        rec = risk.likelihood * risk.impact
        out["recorded"] = {"ref": risk.ref, "likelihood": risk.likelihood, "impact": risk.impact, "score": rec,
                           "level": _level(rec), "treatment": risk.treatment}
        out["rerate_hint"] = ("evidence is higher than recorded" if a["score"] > rec else
                              "evidence is lower than recorded" if a["score"] < rec else "matches the recorded rating")
    out["suggested_risk"] = {"title": (f"{subject[:1].upper()}{subject[1:]}: {fs[0].title[:120]}" if subject.upper() not in fs[0].title.upper() else fs[0].title[:160]) if not risk else risk.title,
                             "likelihood": a["likelihood"], "impact": a["impact"], "treatment": a["treatment"],
                             "treatment_plan": a["treatment_plan"], "finding_ids": [x.id for x in fs][:50]}
    return out


def t_find_findings(user, args):
    qs = findings_for(user)
    status = args.get("status") if args.get("status") in ("open", "closed", "accepted", "all") else "open"
    if status == "open":
        qs = qs.filter(active=True)
    elif status == "closed":
        qs = qs.filter(active=False, is_mitigated=True)
    elif status == "accepted":
        qs = qs.filter(risk_accepted=True)
    text = _str(args.get("text"), 80)
    if text:
        if re.match(r"^CVE-\d{4}-\d+$", text, re.I):
            qs = qs.filter(Q(cve__iexact=text) | Q(vuln_id_from_tool__iexact=text) | Q(vulnerability_id__vulnerability_id__iexact=text))
        elif text.isdigit():
            qs = qs.filter(id=int(text))
        else:
            qs = qs.filter(Q(title__icontains=text) | Q(component_name__icontains=text) | Q(file_path__icontains=text))
    if args.get("severity") in SEVS:
        qs = qs.filter(severity=args["severity"])
    if args.get("band") in BANDS:
        qs = qs.filter(priority__band=args["band"])
    if args.get("kev") is True:
        qs = qs.filter(known_exploited=True)
    asset = _str(args.get("asset"))
    if asset:
        aq = _asset_q(asset)
        if aq is not None:
            qs = qs.filter(aq)
    qs = qs.distinct()
    total = qs.count()
    offset = _int(args.get("offset"), 0, 0, 100000)
    sev = dict(qs.order_by().values_list("severity").annotate(n=Count("id", distinct=True)))
    return {"status": status, "matching": total, "severity": {s: sev.get(s, 0) for s in SEVS if sev.get(s)},
            "offset": offset, "items": _rows(_by_priority(qs)[offset:], _int(args.get("limit"), 8, 1, 15)),
            "path": "/finding/open" if status == "open" else "/finding/closed" if status == "closed" else "/finding/accepted"}


def t_finding_detail(user, args):
    fid = _int(args.get("finding_id"))
    f = findings_for(user).filter(id=fid).select_related("test__engagement__product", "test__test_type", "priority").first() if fid else None
    if not f:
        return {"error": "No finding with that id that you can see."}
    item = finding_item(f)
    a = assess([f])
    assignee = None
    try:
        assignee = f.assignment.assignee.get_full_name() or f.assignment.assignee.username
    except Exception:  # noqa: BLE001
        pass
    notes = [n.entry[:300] for n in f.notes.filter(private=False).order_by("-date")[:3]]
    return {**item, "description": (f.description or "")[:1200], "mitigation": (f.mitigation or "")[:800],
            "impact_text": (f.impact or "")[:400], "file_path": f.file_path or None, "line": f.line,
            "scanner": f.test.test_type.name if f.test_id else None, "found": _iso(f.date),
            "component_version": f.component_version or None, "assigned_to": assignee,
            "risk": {k: a[k] for k in ("likelihood", "impact", "score", "level", "evidence", "treatment_plan")},
            "recent_notes": notes}


def t_asset_detail(user, args):
    if not org_wide(user):
        return DENIED
    name = _str(args.get("asset")).lower()
    if not name:
        return {"error": "Which asset?"}
    rows = _dashboard().get("assets_all") or []
    match = [r for r in rows if name == (r.get("key") or "").lower() or name == (r.get("name") or "").lower()] or \
            [r for r in rows if name in (r.get("name") or "").lower()]
    from orasec.posture.models import InventoryAsset  # noqa: PLC0415

    inv = InventoryAsset.find(name) or \
        InventoryAsset.objects.filter(Q(name__icontains=name) | Q(hostname__icontains=name)).first()
    if not match and not inv:
        return {"error": "No asset by that name.", "path": "/orasec/inventory/"}
    out: dict[str, Any] = {}
    if match:
        r = match[0]
        out.update({"name": r["name"], "kind": r.get("kind"), "product": r.get("product"),
                    "open": r.get("total"), "severity": dict(zip(SEVS, r.get("sev") or [])), "kev": r.get("kev"),
                    "epss_likely": r.get("epss"), "overdue": r.get("overdue"), "criticality": r.get("criticality"),
                    "internet_exposed": r.get("exposed"), "oldest_open_days": r.get("oldest_days"),
                    "path": r.get("url") or "/orasec/inventory/"})
    if inv:
        out.update({"asset_id": inv.id, "type": inv.asset_type, "os": " ".join(x for x in (inv.os_name, inv.os_version) if x) or None,
                    "owner": (inv.owner.get_full_name() or inv.owner.username) if inv.owner_id else None,
                    "criticality": inv.criticality, "internet_exposed": inv.internet_exposed, "online": inv.online,
                    "last_seen": _iso(inv.last_seen), "last_scanned": _iso(inv.last_scanned_at),
                    "path": f"/orasec/inventory/{inv.id}/"})
    top = t_prioritise(user, {"asset": out.get("name") or name, "limit": 5})
    out["items"], out["fix_first"] = top["items"], top["fix_first"]
    return out


def t_sla_status(user, args):
    qs = _open(findings_for(user))
    today = _today()
    overdue = qs.filter(priority__due_date__lt=today)
    soon = qs.filter(priority__due_date__gte=today, priority__due_date__lte=today + datetime.timedelta(days=7))
    by_band = dict(overdue.order_by().values_list("priority__band").annotate(n=Count("id")))
    oldest = overdue.aggregate(d=Min("priority__due_date"))["d"]
    return {"overdue": overdue.count(), "due_in_7_days": soon.count(), "overdue_by_band": by_band,
            "oldest_due": _iso(oldest), "items": _rows(overdue.order_by("priority__due_date", "-priority__score"), 8),
            "path": "/orasec/remediation/"}


def t_my_work(user, args):
    qs = _open(findings_for(user)).filter(assignment__assignee=user)
    today = _today()
    return {"assigned_open": qs.count(), "overdue": qs.filter(priority__due_date__lt=today).count(),
            "items": _rows(_by_priority(qs), 8), "path": "/orasec/my-work/"}


def t_attacks(user, args):
    if not org_wide(user):
        return DENIED
    from orasec.posture.models import AttackEvent  # noqa: PLC0415

    days = _int(args.get("days"), 7, 1, 30)
    since = timezone.now() - datetime.timedelta(days=days)
    qs = AttackEvent.objects.filter(occurred_at__gte=since)
    from django.db.models import Sum  # noqa: PLC0415

    total = qs.aggregate(n=Sum("hits"))["n"] or 0
    prev = AttackEvent.objects.filter(occurred_at__gte=since - datetime.timedelta(days=days), occurred_at__lt=since) \
        .aggregate(n=Sum("hits"))["n"] or 0

    def top(field, n=5):
        return [{"value": r[field], "hits": r["n"]} for r in
                qs.exclude(**{field: ""}).exclude(**{f"{field}__isnull": True}).order_by().values(field).annotate(n=Sum("hits")).order_by("-n")[:n]]

    return {"days": days, "blocked_hits": total, "previous_period": prev,
            "change_pct": round((total - prev) * 100 / prev) if prev else None,
            "by_source": top("source"), "countries": top("src_country"), "top_sources": top("src_ip"),
            "targets": top("target"), "ports": [{"port": r["dst_port"], "hits": r["n"]} for r in
                                               qs.exclude(dst_port=None).order_by().values("dst_port").annotate(n=Sum("hits")).order_by("-n")[:5]],
            "rules": top("rule", 3), "path": "/orasec/attacks/"}


def t_code_security(user, args):
    if not org_wide(user):
        return DENIED
    d = _dashboard()
    cats = d.get("code_cats") or []
    prod = _str(args.get("product")).lower()
    rows = []
    for r in d.get("code") or []:
        if prod and prod not in r["product"].lower():
            continue
        rows.append({"product": r["product"], "open": r["open"], "severity": dict(zip(SEVS, r.get("sev") or [])),
                     "by_type": dict(zip(cats, r.get("cats") or [])), "resolved": r.get("resolved"),
                     "resolved_30d": r.get("resolved30"), "fixed_pct": r.get("fixed_pct")})
    return {"products": rows[:10], "path": "/orasec/code/"}


def t_compliance_status(user, args):
    if not org_wide(user):
        return DENIED
    from orasec.posture.models import ControlImplementation  # noqa: PLC0415

    d = (_dashboard().get("compliance") or {})
    today = _today()
    impl = ControlImplementation.objects.select_related("control")
    failing = [{"ref": i.control.ref, "kind": "control", "title": i.control.title[:120], "detail": (i.auto_detail or "")[:160],
                "path": f"/orasec/compliance/controls/{i.control_id}/"} for i in impl.filter(auto_status="fail")[:8]]
    review_due = impl.filter(applicable=True, review_due__lt=today).count()
    no_evidence = impl.filter(applicable=True).annotate(ev=Count("control__evidence")).filter(ev=0).count() \
        if hasattr(ControlImplementation, "control") else None
    status = dict(impl.filter(applicable=True).order_by().values_list("status").annotate(n=Count("id")))
    return {"score": d.get("score"), "applicable": d.get("applicable"), "status": status,
            "automated_checks": {"pass": d.get("pass"), "warn": d.get("warn"), "fail": d.get("fail")},
            "evidence_items": d.get("evidence"), "controls_without_evidence": no_evidence,
            "reviews_overdue": review_due, "items": failing, "path": "/orasec/compliance/"}


def t_risk_register(user, args):
    if not org_wide(user):
        return DENIED
    from orasec.posture.models import RiskRegisterEntry  # noqa: PLC0415

    qs = RiskRegisterEntry.objects.select_related("owner", "product").annotate(nf=Count("findings", filter=Q(findings__active=True)))
    if args.get("status") != "all":
        qs = qs.exclude(status="closed")
    today = _today()
    items = []
    for r in qs:
        s = r.likelihood * r.impact
        items.append({"ref": r.ref, "kind": "risk", "id": r.id, "title": r.title[:160], "likelihood": r.likelihood,
                      "impact": r.impact, "score": s, "level": _level(s), "treatment": r.treatment, "status": r.status,
                      "owner": (r.owner.get_full_name() or r.owner.username) if r.owner_id else None,
                      "open_findings": r.nf, "review_due": _iso(r.review_date),
                      "review_overdue": bool(r.review_date and r.review_date < today), "path": f"/orasec/risks/{r.id}/"})
    items.sort(key=lambda x: (-x["score"], x["ref"]))
    return {"total": len(items), "high_or_critical": sum(1 for i in items if i["score"] >= 15),
            "reviews_overdue": sum(1 for i in items if i["review_overdue"]), "items": items[:10], "path": "/orasec/risks/"}


def t_connectors_health(user, args):
    if not org_wide(user):
        return DENIED
    from orasec.posture.models import Connector, IntelFeed  # noqa: PLC0415

    items = []
    for c in Connector.objects.order_by("name"):
        items.append({"ref": f"K-{c.id}", "kind": "connector", "id": c.id, "title": c.name, "type": c.kind,
                      "enabled": c.enabled, "status": c.last_status or "never run",
                      "last_success": _iso(c.last_success_at), "message": (c.last_message or "")[:160],
                      "path": f"/orasec/connectors/{c.id}/"})
    feeds = [{"name": f.name, "status": f.status, "records": f.records, "last": _iso(f.last_refreshed),
              "message": (f.message or "")[:120]} for f in IntelFeed.objects.all()]
    bad = [i for i in items if i["enabled"] and i["status"] not in ("ok", "warning")]
    return {"connectors": len(items), "failing": len(bad), "items": (bad + [i for i in items if i not in bad])[:10],
            "intel_feeds": feeds, "path": "/orasec/connectors/"}


def t_asset_inventory(user, args):
    if not org_wide(user):
        return DENIED
    from orasec.posture import asset_inventory  # noqa: PLC0415
    d = asset_inventory.report_data(_str(args.get("group"), 40) or None)
    d["assets"] = d["assets"][:60]
    return d


def t_leavers(user, args):
    if not org_wide(user):
        return DENIED
    from orasec.posture import leavers  # noqa: PLC0415
    from orasec.posture.grc_models import LeaverRecord  # noqa: PLC0415
    qs = LeaverRecord.objects.select_related("person", "started_by", "signed_off_by")
    ref = _str(args.get("ref"), 20)
    if ref:
        qs = qs.filter(ref__iexact=ref)
    elif args.get("status") != "all":
        qs = qs.filter(status="open")
    items = [leavers.summary(r) for r in qs[:10]]
    from django.contrib.auth import get_user_model  # noqa: PLC0415
    people = [{"id": u.id, "name": leavers.display(u)} for u in get_user_model().objects.filter(is_active=True).order_by("username")[:20]]
    return {"records": items, "count": len(items), "active_people": people, "path": "/orasec/leavers/",
            "note": "Start / tick / move assets / sign off are proposals the user confirms. Sign-off needs someone other "
                    "than the leaver and whoever started the record. Deactivating accounts is done by a person, not Ora."}


TOOLS: dict[str, Callable[[Any, dict], dict]] = {
    "posture_summary": t_posture_summary, "prioritise": t_prioritise, "evaluate_risk": t_evaluate_risk,
    "find_findings": t_find_findings, "finding_detail": t_finding_detail, "asset_detail": t_asset_detail,
    "sla_status": t_sla_status, "my_work": t_my_work, "attacks": t_attacks, "code_security": t_code_security,
    "compliance_status": t_compliance_status, "risk_register": t_risk_register,
    "connectors_health": t_connectors_health, "asset_inventory": t_asset_inventory, "leavers": t_leavers,
}
TOOLS["prioritize"] = t_prioritise


def run_tool(name: str, args: Any, user) -> dict[str, Any]:
    fn = TOOLS.get(name or "")
    if not fn:
        return {"error": "unknown tool"}
    try:
        return fn(user, args if isinstance(args, dict) else {})
    except Exception:  # noqa: BLE001 -- a tool bug must not break the chat
        logger.exception("ora: tool %s failed", name)
        return {"error": "That lookup failed. Try again, or open the page directly."}


# ---------------------------------------------------------------------------
# Answer-first: obvious questions run their tool before the first AI call
# ---------------------------------------------------------------------------
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{3,}\b", re.I)
_FID_RE = re.compile(r"\b(?:finding|F-)\s*#?(\d{1,9})\b", re.I)

_GUESS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b(?:evaluat|assess|rate|how (?:risky|bad|serious|dangerous))\w*", re.I), "evaluate_risk"),
    (re.compile(r"\b(?:priori[tsz]\w*|fix first|what should (?:i|we) (?:fix|patch|work on)|most (?:urgent|important)|top (?:\d+ )?(?:risks?|vulns?|vulnerabilities|findings))\b", re.I), "prioritise"),
    (re.compile(r"\b(?:assigned to me|my work|my findings|my tasks|my queue)\b", re.I), "my_work"),
    (re.compile(r"\b(?:overdue|sla|breach\w*|due (?:soon|this week))\b", re.I), "sla_status"),
    (re.compile(r"\b(?:attacks?|blocked|crowdsec|waf|brute.?force|who is attacking)\b", re.I), "attacks"),
    (re.compile(r"\b(?:posture|security score|how are we doing|overall|summary|status report|briefing)\b", re.I), "posture_summary"),
    (re.compile(r"\b(?:leavers?|movers?|offboard\w*|leaving|left the company|return of assets|hand(?:ed)? back|lvr-\d+)\b", re.I), "leavers"),
    (re.compile(r"\b(?:asset inventory|inventory|our assets|what assets|asset owners?|who owns|cloud services we use|information assets)\b", re.I), "asset_inventory"),
    (re.compile(r"\b(?:risk register|our risks|open risks|risks? (?:list|review))\b", re.I), "risk_register"),
    (re.compile(r"\b(?:iso|27001|compliance|controls?|evidence|soa)\b", re.I), "compliance_status"),
    (re.compile(r"\b(?:connectors?|integrations?|feeds?|sync(?:ing)?)\b.*\b(?:fail\w*|broken|health\w*|status|working|down|error\w*)\b", re.I), "connectors_health"),
    (re.compile(r"\b(?:code|repo\w*|sast|secrets? (?:found|leak\w*)|dependabot)\b.*\b(?:vuln\w*|findings?|issues?|security)\b", re.I), "code_security"),
]
_WHERE_RE = re.compile(r"\b(?:where (?:is|are|do|can|to)|take me|how do i (?:get|find|open)|show me the page|navigate)\b", re.I)


def guess(question: str, page: dict[str, Any] | None) -> tuple[str, dict[str, Any]] | None:
    """A tool to run before the first AI call when the question plainly needs it (saves a round trip)."""
    q = question or ""
    if _WHERE_RE.search(q) and not re.search(r"\b(?:priori|evaluat|assess)", q, re.I):
        return None
    for rx, name in _GUESS:
        if not rx.search(q):
            continue
        args: dict[str, Any] = {}
        cve, fid = _CVE_RE.search(q), _FID_RE.search(q)
        if name == "evaluate_risk":
            if cve:
                args["cve"] = cve.group(0).upper()
            elif fid:
                args["finding_id"] = int(fid.group(1))
            elif page and page.get("finding_id"):
                args["finding_id"] = page["finding_id"]
            elif page and page.get("risk_id"):
                args["risk_id"] = page["risk_id"]
            else:
                return None  # let the AI work out what to evaluate
        if name == "prioritise":
            if re.search(r"\b(?:kev|known exploited|exploited)\b", q, re.I):
                args["scope"] = "kev"
            elif re.search(r"\b(?:mine|my|assigned to me)\b", q, re.I):
                args["scope"] = "mine"
            elif re.search(r"\b(?:internet|exposed|external|public)\b", q, re.I):
                args["scope"] = "exposed"
            if page and page.get("asset"):
                args["asset"] = page["asset"]
        return name, args
    if _CVE_RE.search(q):
        return "evaluate_risk", {"cve": _CVE_RE.search(q).group(0).upper()}
    return None


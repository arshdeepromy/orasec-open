"""
Security dashboard metrics.

Everything the dashboard shows is computed here in one pass, stored in the shared cache (Valkey) and refreshed in the
background by Celery beat (orasec.home.tasks.refresh_dashboard). The dashboard view only reads the cached document, so
opening the page never runs the heavy aggregation queries.
"""
import datetime
import logging
import re
import statistics
import time

from django.core.cache import cache
from django.db.models import Count, Max, Min, Q, Sum
from django.db.models.functions import TruncDate, TruncWeek
from django.utils import timezone

logger = logging.getLogger(__name__)

CACHE_KEY = "orasec:dashboard:v2"
LOCK_KEY = "orasec:dashboard:lock"
CACHE_TTL = 60 * 60 * 6      # keep the last good document for 6 h; beat refreshes it every 5 min
STALE_AFTER = 60 * 10         # older than this -> the view asks the worker for a refresh
SEVS = ["Critical", "High", "Medium", "Low", "Info"]
EPSS_LIKELY = 0.1             # EPSS >= 10 %: likely to be exploited in the next 30 days
BLOCK_ACTIONS = ("block", "drop", "reject", "deny", "challenge")


# ---------------------------------------------------------------------------
# Asset and scanner classification (findings carry the scanned target in the test title)
# ---------------------------------------------------------------------------
_PAREN = re.compile(r"^(.*?)\s*\(([^)]+)\)\s*$")


def _asset_of(title, test_type):
    """('Wazuh vulnerabilities: dev-box', 'Wazuh') -> ('dev-box', 'Host', None)"""
    t = (title or "").strip()
    tail = t.split(": ", 1)[1] if ": " in t else t
    where = None
    m = _PAREN.match(tail)
    if m:
        tail, where = m.group(1).strip(), m.group(2).strip()
    tt = (test_type or "").lower()
    tl = t.lower()
    if "wazuh" in tt:
        kind = "Host"
    elif "trivy" in tt:
        kind = "Container" if tl.startswith("trivy image") else "Code"
    elif any(k in tt for k in ("semgrep", "gitleaks", "bandit", "snyk", "dependency check")):
        kind = "Code"
    elif "github" in tt:
        kind = "Repository"
    elif "zap" in tt or "nuclei" in tt or "nikto" in tt:
        kind = "Web app"
    elif "nmap" in tt:
        kind = "Network"
    elif "opnsense" in tt or "unifi" in tt:
        kind = "Network device"
    elif "aws" in tt:
        kind = "Cloud"
    elif "cloudflare" in tt:
        kind = "Edge"
    elif "patchmon" in tt:
        kind = "Patching"
    else:
        kind = "Other"
    return tail or t or "Unknown", kind, where


def _code_category(test_type, title):
    tt, ti = (test_type or "").lower(), (title or "").lower()
    if "semgrep" in tt or "bandit" in tt:
        return "SAST"
    if "gitleaks" in tt:
        return "Secrets"
    if "trivy" in tt:
        return "Containers" if ti.startswith("trivy image") else "Dependencies"
    if "dependency check" in tt or "snyk" in tt:
        return "Dependencies"
    if "github" in tt:
        return "GitHub"
    return None


CODE_CATS = ["SAST", "Secrets", "Dependencies", "Containers", "GitHub"]


def _iso(v):
    return v.isoformat() if v else None


# ---------------------------------------------------------------------------
# The computation
# ---------------------------------------------------------------------------
def compute():
    from orasec.models import Finding  # noqa: PLC0415
    from orasec.posture import compliance, geo, services  # noqa: PLC0415
    from orasec.posture.models import (  # noqa: PLC0415
        AttackEvent,
        Connector,
        FindingPriority,
        IntelFeed,
        InventoryAsset,
        KevEntry,
        PostureSnapshot,
        PrioritySettings,
        RiskRegisterEntry,
    )

    t0 = time.monotonic()
    now = timezone.now()
    today = timezone.localdate()
    tz = timezone.get_current_timezone()
    findings = Finding.objects.filter(duplicate=False).order_by()
    active = findings.filter(active=True)

    # ---- severity + priority bands --------------------------------------------------------------------------------
    sev = dict(active.values_list("severity").annotate(n=Count("id")))
    severity = [{"name": s, "n": sev.get(s, 0)} for s in SEVS]
    open_total = sum(sev.values())
    fp_active = FindingPriority.objects.filter(finding__active=True, finding__duplicate=False).order_by()
    band_n = dict(fp_active.values_list("band").annotate(n=Count("id")))
    bands = [{"name": b, "n": band_n.get(b, 0)} for b in ("Urgent", "Needs Action", "Medium", "Low")]

    # ---- per-finding pass: assets, ages, exploitability ----------------------------------------------------------
    rows = active.values_list("id", "severity", "date", "known_exploited", "epss_score", "cve", "test_id", "test__title",
                              "test__test_type__name", "test__engagement__product__name")
    due = dict(fp_active.exclude(due_date=None).values_list("finding_id", "due_date"))
    assets = {}
    age_buckets = {s: [0, 0, 0, 0] for s in SEVS}          # <=7d, 8-30d, 31-90d, >90d
    epss_buckets = [0, 0, 0, 0]                            # <1 %, 1-10 %, 10-50 %, >=50 %
    exploit_assets = set()
    for fid, s, d, kev, epss, _cve, test_id, title, tt, product in rows:
        name, kind, where = _asset_of(title, tt)
        key = name.lower()
        a = assets.get(key)
        if a is None:
            a = assets[key] = {"name": name, "kind": kind, "where": where, "product": product, "tests": {}, "sev": dict.fromkeys(SEVS, 0),
                               "kev": 0, "epss": 0, "overdue": 0, "oldest": None, "total": 0}
        if kind == "Host":
            a["kind"] = "Host"
        a["tests"][test_id] = a["tests"].get(test_id, 0) + 1
        a["sev"][s] = a["sev"].get(s, 0) + 1
        a["total"] += 1
        if kev:
            a["kev"] += 1
        if epss is not None and epss >= EPSS_LIKELY:
            a["epss"] += 1
        if kev or (epss is not None and epss >= EPSS_LIKELY):
            exploit_assets.add(key)
        dd = due.get(fid)
        if dd and dd < today:
            a["overdue"] += 1
        if d:
            if a["oldest"] is None or d < a["oldest"]:
                a["oldest"] = d
            age = (today - d).days
            age_buckets.setdefault(s, [0, 0, 0, 0])[0 if age <= 7 else 1 if age <= 30 else 2 if age <= 90 else 3] += 1
        if epss is not None:
            epss_buckets[0 if epss < 0.01 else 1 if epss < 0.1 else 2 if epss < 0.5 else 3] += 1

    inv = {}
    for ia in InventoryAsset.objects.filter(retired=False).only("id", "name", "hostname", "criticality", "internet_exposed", "asset_type", "attributes"):
        for k in {x.lower() for x in (ia.name, ia.hostname, *((ia.attributes or {}).get("aliases") or [])) if x}:
            inv.setdefault(k, ia)
    asset_rows = []
    for key, a in assets.items():
        direct = inv.get(key)
        ia = direct or (inv.get(a["where"].lower()) if a["where"] else None)
        crit = ia.criticality if ia else 3
        risk = (a["kev"] * 40 + a["epss"] * 15 + a["sev"]["Critical"] * 10 + a["sev"]["High"] * 4 + a["sev"]["Medium"] * 0.6
                + a["sev"]["Low"] * 0.05 + a["overdue"] * 2) * (0.6 + crit * 0.2) * (1.25 if ia and ia.internet_exposed else 1)
        top_test = max(a["tests"], key=a["tests"].get)
        asset_rows.append({
            "key": key, "tests": sorted(a["tests"]), "name": direct.name if direct and a["kind"] == "Host" else a["name"], "kind": a["kind"], "where": a["where"], "product": a["product"], "sev": [a["sev"].get(s, 0) for s in SEVS],
            "total": a["total"], "kev": a["kev"], "epss": a["epss"], "overdue": a["overdue"], "criticality": crit,
            "exposed": bool(ia and ia.internet_exposed), "oldest_days": (today - a["oldest"]).days if a["oldest"] else None,
            "risk": round(risk, 1), "mix": " · ".join(f"{s} {a['sev'].get(s, 0):,}" for s in SEVS if a["sev"].get(s)),
            "url": f"/orasec/inventory/{ia.id}/" if ia else f"/test/{top_test}",
        })
    asset_rows.sort(key=lambda r: -r["risk"])

    # ---- exploitability --------------------------------------------------------------------------------------------
    kev_q = Q(known_exploited=True)
    kev_rows = list(active.filter(kev_q).exclude(cve=None).values("cve").annotate(
        n=Count("id"), tests=Count("test", distinct=True), epss=Max("epss_score"), sev=Min("numerical_severity"), comp=Max("component_name")))
    kev_meta = {k.cve: k for k in KevEntry.objects.filter(cve__in=[r["cve"] for r in kev_rows])}
    kev_list = []
    for r in kev_rows:
        k = kev_meta.get(r["cve"])
        kev_list.append({"cve": r["cve"], "findings": r["n"], "assets": r["tests"], "epss": r["epss"], "component": r["comp"],
                         "severity": {"S0": "Critical", "S1": "High", "S2": "Medium", "S3": "Low"}.get(r["sev"], "Info"),
                         "name": (k.name if k else "") or (f"{k.vendor} {k.product}".strip() if k else ""),
                         "due": _iso(k.due_date) if k else None, "ransomware": bool(k and k.ransomware),
                         "overdue": bool(k and k.due_date and k.due_date < today)})
    kev_list.sort(key=lambda r: (not r["overdue"], r["due"] or "9999", -r["findings"]))
    epss_top = list(active.filter(epss_score__gte=EPSS_LIKELY).exclude(cve=None).values("cve").annotate(
        epss=Max("epss_score"), pct=Max("epss_percentile"), n=Count("id"), tests=Count("test", distinct=True), comp=Max("component_name"),
        kev=Count("id", filter=kev_q)).order_by("-epss")[:8])
    exploit = {
        "kev_findings": active.filter(kev_q).count(),
        "kev_cves": len(kev_rows),
        "kev_catalog": KevEntry.objects.count(),
        "ransomware": active.filter(ransomware_used=True).count() + sum(1 for r in kev_list if r["ransomware"]),
        "epss_likely": active.filter(epss_score__gte=EPSS_LIKELY).count(),
        "epss_likely_cves": active.filter(epss_score__gte=EPSS_LIKELY).exclude(cve=None).values("cve").distinct().count(),
        "open_cves": active.exclude(cve=None).values("cve").distinct().count(),
        "assets_affected": len(exploit_assets),
        "assets_total": len(assets),
        "epss_buckets": epss_buckets,
        "kev": kev_list[:10],
        "epss_top": [{"cve": r["cve"], "epss": r["epss"], "pct": r["pct"], "findings": r["n"], "assets": r["tests"], "component": r["comp"],
                      "kev": bool(r["kev"])} for r in epss_top],
    }

    # ---- attacks ---------------------------------------------------------------------------------------------------
    since30 = now - datetime.timedelta(days=30)
    ev = AttackEvent.objects.order_by()
    blocked = ev.filter(action__in=BLOCK_ACTIONS)

    def hits(qs):
        return qs.aggregate(n=Sum("hits"))["n"] or 0

    daily = dict(blocked.filter(occurred_at__gte=since30).annotate(d=TruncDate("occurred_at", tzinfo=tz)).values("d")
                 .annotate(n=Sum("hits")).values_list("d", "n"))
    days = [today - datetime.timedelta(days=i) for i in range(29, -1, -1)]
    attacks = {
        "h24": hits(blocked.filter(occurred_at__gte=now - datetime.timedelta(hours=24))),
        "d7": hits(blocked.filter(occurred_at__gte=now - datetime.timedelta(days=7))),
        "d30": hits(blocked.filter(occurred_at__gte=since30)),
        "prev30": hits(blocked.filter(occurred_at__gte=now - datetime.timedelta(days=60), occurred_at__lt=since30)),
        "alerts30": hits(ev.filter(occurred_at__gte=since30, action="alert")),
        "ips7": blocked.filter(occurred_at__gte=now - datetime.timedelta(days=7)).exclude(src_ip=None).values("src_ip").distinct().count(),
        "daily": [{"d": d.isoformat(), "n": daily.get(d, 0)} for d in days],
        "by_source": [{"source": r["source"], "n": r["n"]} for r in blocked.filter(occurred_at__gte=since30).values("source").annotate(n=Sum("hits")).order_by("-n")],
        "countries": [{"cc": r["src_country"], "flag": geo.flag(r["src_country"]), "n": r["n"]}
                      for r in blocked.filter(occurred_at__gte=since30).exclude(src_country="").values("src_country").annotate(n=Sum("hits")).order_by("-n")[:6]],
        "ports": [{"port": r["dst_port"], "n": r["n"]}
                  for r in blocked.filter(occurred_at__gte=since30).exclude(dst_port=None).values("dst_port").annotate(n=Sum("hits")).order_by("-n")[:6]],
    }

    # ---- code vulnerabilities per product --------------------------------------------------------------------------
    code = {}
    since30d = now - datetime.timedelta(days=30)
    for prod, tt, title, s, is_active, is_mit, mitigated in findings.filter(
            Q(active=True) | Q(is_mitigated=True)).values_list(
            "test__engagement__product__name", "test__test_type__name", "test__title", "severity", "active", "is_mitigated", "mitigated"):
        cat = _code_category(tt, title)
        if not cat:
            continue
        p = code.setdefault(prod or "—", {"product": prod or "—", "open": 0, "sev": dict.fromkeys(SEVS, 0), "cats": dict.fromkeys(CODE_CATS, 0),
                                           "resolved": 0, "resolved30": 0})
        if is_active:
            p["open"] += 1
            p["sev"][s] = p["sev"].get(s, 0) + 1
            p["cats"][cat] += 1
        elif is_mit:
            p["resolved"] += 1
            if mitigated and mitigated >= since30d:
                p["resolved30"] += 1
    code_rows = []
    for p in sorted(code.values(), key=lambda p: (-(p["sev"]["Critical"] * 100 + p["sev"]["High"] * 10 + p["open"]))):
        seen = p["open"] + p["resolved"]
        code_rows.append({"product": p["product"], "open": p["open"], "sev": [p["sev"].get(s, 0) for s in SEVS],
                          "cats": [p["cats"][c] for c in CODE_CATS], "resolved": p["resolved"], "resolved30": p["resolved30"],
                          "fixed_pct": round(100 * p["resolved"] / seen) if seen else None})

    # ---- resolution time after detection ---------------------------------------------------------------------------
    settings_obj = PrioritySettings.load()
    sla_days = (getattr(settings_obj, "sla_days", None) or {}) or PrioritySettings.DEFAULT_SLA
    closed = findings.filter(is_mitigated=True, mitigated__gte=now - datetime.timedelta(days=365)).exclude(mitigated=None)
    dur = {s: [] for s in SEVS}
    for s, d, m in closed.values_list("severity", "date", "mitigated"):
        if d and m:
            dur.setdefault(s, []).append(max(0, (m.date() - d).days))  # finding.date is a UTC date
    sev_sla = {"Critical": sla_days.get("Urgent", 7), "High": sla_days.get("Needs Action", 30), "Medium": sla_days.get("Medium", 90),
               "Low": sla_days.get("Low", 180), "Info": sla_days.get("Low", 180)}
    resolution = []
    for s in SEVS:
        xs = sorted(dur.get(s, []))
        within = sum(1 for x in xs if x <= sev_sla[s])
        resolution.append({"severity": s, "closed": len(xs), "mean": round(statistics.fmean(xs), 1) if xs else None,
                           "median": statistics.median(xs) if xs else None, "p90": xs[min(len(xs) - 1, int(len(xs) * 0.9))] if xs else None,
                           "sla": sev_sla[s], "within_pct": round(100 * within / len(xs)) if xs else None,
                           "buckets": [sum(1 for x in xs if x <= 7), sum(1 for x in xs if 7 < x <= 30), sum(1 for x in xs if 30 < x <= 90),
                                       sum(1 for x in xs if x > 90)],
                           "open_age": age_buckets.get(s, [0, 0, 0, 0])})
    all_d = [x for v in dur.values() for x in v]
    with_sla = fp_active.exclude(due_date=None)
    sla_tracked = with_sla.count()
    overdue = with_sla.filter(due_date__lt=today).count()
    sla = {"tracked": sla_tracked, "overdue": overdue, "due7": with_sla.filter(due_date__gte=today, due_date__lte=today + datetime.timedelta(days=7)).count(),
           "within_pct": round(1000 * (sla_tracked - overdue) / sla_tracked) / 10 if sla_tracked else None,
           "mttr": round(statistics.fmean(all_d), 1) if all_d else None, "closed365": len(all_d), "targets": sla_days}

    # ---- weekly opened vs resolved ---------------------------------------------------------------------------------
    start = today - datetime.timedelta(weeks=12)
    opened_w = dict(findings.filter(date__gte=start).annotate(w=TruncWeek("date")).values("w").annotate(n=Count("id")).values_list("w", "n"))
    closed_w = dict(findings.filter(is_mitigated=True, mitigated__date__gte=start).annotate(w=TruncWeek("mitigated", tzinfo=tz))
                    .values("w").annotate(n=Count("id")).values_list("w", "n"))

    def _wk(v):
        return v.date() if isinstance(v, datetime.datetime) else v
    opened_w = {_wk(k): v for k, v in opened_w.items()}
    closed_w = {_wk(k): v for k, v in closed_w.items()}
    monday = today - datetime.timedelta(days=today.weekday())
    weeks = [monday - datetime.timedelta(weeks=i) for i in range(12, -1, -1)]
    trend = [{"w": w.isoformat(), "opened": opened_w.get(w, 0), "closed": closed_w.get(w, 0)} for w in weeks]

    # ---- risk register ---------------------------------------------------------------------------------------------
    risks_qs = RiskRegisterEntry.objects.select_related("owner", "product")
    heat = [[0] * 5 for _ in range(5)]   # [likelihood-1][impact-1], open risks only
    risk_rows = []
    status_n = {}
    for r in risks_qs:
        status_n[r.status] = status_n.get(r.status, 0) + 1
        is_open = r.status not in {"closed", "accepted"}
        if is_open:
            heat[max(1, min(5, r.likelihood)) - 1][max(1, min(5, r.impact)) - 1] += 1
        inherent = r.likelihood * r.impact
        residual = (r.residual_likelihood * r.residual_impact) if r.residual_likelihood and r.residual_impact else None
        risk_rows.append({"id": r.id, "ref": r.ref, "title": r.title, "product": r.product.name if r.product else None,
                          "likelihood": r.likelihood, "impact": r.impact, "score": inherent, "residual": residual,
                          "treatment": r.get_treatment_display(), "status": r.status, "status_label": r.get_status_display(),
                          "owner": (r.owner.get_full_name() or r.owner.username) if r.owner else None,
                          "review": _iso(r.review_date), "review_overdue": bool(r.review_date and r.review_date < today and is_open),
                          "open": is_open})
    risk_rows.sort(key=lambda r: (not r["open"], -r["score"]))
    heat_rows = [{"likelihood": li, "cells": [{"n": heat[li - 1][im - 1], "lvl": "hi" if li * im >= 15 else "md" if li * im >= 8 else "lo"}
                                              for im in range(1, 6)]} for li in range(5, 0, -1)]
    risk = {"total": len(risk_rows), "open": sum(1 for r in risk_rows if r["open"]), "high": sum(1 for r in risk_rows if r["open"] and r["score"] >= 15),
            "review_overdue": sum(1 for r in risk_rows if r["review_overdue"]), "status": status_n, "heat": heat_rows, "rows": risk_rows[:8]}

    # ---- posture, compliance, coverage, connectors -----------------------------------------------------------------
    p = services.posture()
    comp = compliance.summary()
    snaps = list(PostureSnapshot.objects.order_by("-date")[:30])[::-1]
    inv_qs = InventoryAsset.objects.filter(retired=False)
    conns = []
    for c in Connector.objects.filter(enabled=True).order_by("name"):
        healthy = c.last_status in {"ok", "warning"} and c.last_success_at and now - c.last_success_at < datetime.timedelta(minutes=c.interval_minutes * 2 + 60)
        conns.append({"name": c.name, "kind": c.kind, "status": c.last_status, "healthy": bool(healthy), "last": _iso(c.last_success_at)})
    feeds = [{"name": f.name.upper(), "status": f.status, "records": f.records, "last": _iso(f.last_refreshed)} for f in IntelFeed.objects.all()]
    fix_first = [{"component": r["component_name"], "findings": r["findings"], "kev": r["kev"], "critical": r["critical"], "high": r["high"],
                  "hosts": r["hosts"] or r["assets"], "fix": r.get("fix")} for r in services.root_causes(limit=5)]

    return {
        "generated": now.isoformat(),
        "compute_ms": None,
        "posture": {"score": p["score"], "vuln": p["vuln"], "compliance": p["compliance"], "hygiene": p["hygiene"],
                    "trend": [{"d": s.date.isoformat(), "score": s.score} for s in snaps]},
        "kpi": {
            "open": open_total, "critical": sev.get("Critical", 0), "high": sev.get("High", 0),
            "new7": findings.filter(created__gte=now - datetime.timedelta(days=7)).count(),
            "resolved30": findings.filter(is_mitigated=True, mitigated__gte=since30).count(),
            "resolved_total": findings.filter(is_mitigated=True).count(),
            "assets": inv_qs.exclude(asset_type="client").count(), "exposed": inv_qs.filter(internet_exposed=True).count(),
            "scanned_assets": len(assets),
        },
        "severity": severity, "bands": bands, "assets": asset_rows[:14], "asset_count": len(asset_rows), "assets_all": asset_rows,
        "exploit": exploit, "attacks": attacks, "code": code_rows, "code_cats": CODE_CATS,
        "resolution": resolution, "sla": sla, "trend": trend, "risk": risk,
        "compliance": {"implemented": comp.get("implemented", 0), "applicable": comp.get("applicable", 0), "in_progress": comp.get("in_progress", 0),
                       "pass": comp.get("auto_pass", 0), "warn": comp.get("auto_warn", 0), "fail": comp.get("auto_fail", 0),
                       "evidence": comp.get("evidence", 0), "score": comp.get("score", 0)},
        "connectors": conns, "feeds": feeds, "fix_first": fix_first,
        "_t": round((time.monotonic() - t0) * 1000),
    }


# ---------------------------------------------------------------------------
# Cache access
# ---------------------------------------------------------------------------
def refresh():
    """Recompute and store. Returns the document (or None if another worker is already computing)."""
    if not cache.add(LOCK_KEY, 1, 300):
        return None
    try:
        data = compute()
    except Exception:
        logger.exception("dashboard metrics refresh failed")
        raise
    else:
        data["compute_ms"] = data.pop("_t", None)
        cache.set(CACHE_KEY, data, CACHE_TTL)
        return data
    finally:
        cache.delete(LOCK_KEY)


def get(*, allow_sync=True):
    """Cached document; computes inline only when there is none at all (first ever load / cache flushed)."""
    data = cache.get(CACHE_KEY)
    if data is None and allow_sync:
        data = refresh()
        if data is None:  # someone else is computing: wait briefly for their result
            for _ in range(40):
                time.sleep(0.5)
                data = cache.get(CACHE_KEY)
                if data is not None:
                    break
    return data


def is_stale(data):
    try:
        return (timezone.now() - datetime.datetime.fromisoformat(data["generated"])).total_seconds() > STALE_AFTER
    except (KeyError, TypeError, ValueError):
        return True

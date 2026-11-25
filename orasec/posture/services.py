"""Posture score, daily brief, triage rules, root causes, vulnerability explorer, scan cadence, risk-acceptance governance."""
import datetime
import json
import logging
import math

import requests
from django.core.mail import send_mail
from django.db.models import Count, Max, Min, Q, Sum
from django.utils import timezone

from orasec.posture import compliance
from orasec.posture.models import (
    Connector,
    FindingAssignment,
    FindingPriority,
    IntelFeed,
    InventoryAsset,
    PostureSnapshot,
    ProductScanCadence,
    RiskAcceptanceApproval,
    TriageRule,
    TriageRuleHit,
)

logger = logging.getLogger(__name__)
BAND_PENALTY = {"Urgent": 25.0, "Needs Action": 6.0, "Medium": 0.6, "Low": 0.05}
DEFAULT_CADENCE_DAYS = 7


def _active_findings():
    from orasec.models import Finding  # noqa: PLC0415
    return Finding.objects.filter(active=True, duplicate=False)


# ---------------------------------------------------------------------------
# Posture score (0-1000) = 60% vulnerability exposure + 25% ISO 27001 compliance + 15% operational hygiene
# ---------------------------------------------------------------------------
def vuln_score():
    from orasec.models import Endpoint, Product  # noqa: PLC0415
    bands = dict(FindingPriority.objects.filter(finding__active=True, finding__duplicate=False)
                 .order_by().values_list("band").annotate(n=Count("id")))
    # asset base: inventory (excluding clients), else hosts referenced by findings, else products
    assets = max(1, InventoryAsset.objects.filter(retired=False).exclude(asset_type="client").count()
                 or Endpoint.objects.filter(findings__active=True).values("host").distinct().count()
                 or Product.objects.count())
    overdue = FindingPriority.objects.filter(finding__active=True, finding__duplicate=False, due_date__lt=timezone.now().date()).count()
    penalty = sum(BAND_PENALTY[b] * n for b, n in bands.items()) + 3.0 * overdue
    # diminishing returns per asset: 0 -> 1000, 400 penalty points per asset -> ~370
    per_asset = penalty / assets
    return int(round(1000 * math.exp(-per_asset / 400))), {"bands": bands, "overdue": overdue, "assets": assets, "penalty_per_asset": round(per_asset, 1)}


def hygiene_score():
    parts = []
    conns = list(Connector.objects.filter(enabled=True))
    if conns:
        healthy = sum(1 for c in conns if c.last_status in ("ok", "warning") and c.last_success_at
                      and timezone.now() - c.last_success_at < datetime.timedelta(minutes=c.interval_minutes * 2 + 60))
        parts.append(healthy / len(conns))
    feeds = list(IntelFeed.objects.all())
    if feeds:
        parts.append(sum(1 for f in feeds if f.status == "ok" and f.last_refreshed and timezone.now() - f.last_refreshed < datetime.timedelta(hours=48)) / len(feeds))
    cad = scan_cadence()
    if cad:
        parts.append(sum(1 for r in cad if r["state"] == "on_time") / len(cad))
    return int(round(1000 * (sum(parts) / len(parts)))) if parts else 0


def posture():
    v, vdetail = vuln_score()
    c = compliance.compliance_score()
    h = hygiene_score()
    total = int(round(0.6 * v + 0.25 * c + 0.15 * h))
    return {"score": total, "vuln": v, "compliance": c, "hygiene": h, "vuln_detail": vdetail}


def snapshot():
    p = posture()
    counts = {
        "active": _active_findings().count(),
        "critical": _active_findings().filter(severity="Critical").count(),
        "high": _active_findings().filter(severity="High").count(),
        "kev": _active_findings().filter(known_exploited=True).count(),
        "bands": p["vuln_detail"]["bands"],
        "overdue": p["vuln_detail"]["overdue"],
        "assets": InventoryAsset.objects.filter(retired=False).count(),
    }
    obj, _ = PostureSnapshot.objects.update_or_create(date=timezone.now().date(), defaults={
        "score": p["score"], "vuln_score": p["vuln"], "compliance_score": p["compliance"], "hygiene_score": p["hygiene"], "counts": counts})
    return obj


def daily_brief():
    from orasec.models import Finding  # noqa: PLC0415
    since = timezone.now() - datetime.timedelta(hours=24)
    today = timezone.now().date()
    new = Finding.objects.filter(created__gte=since, duplicate=False)
    closed = Finding.objects.filter(mitigated__gte=since)
    snaps = list(PostureSnapshot.objects.all()[:8])
    delta = (snaps[0].score - snaps[1].score) if len(snaps) > 1 else None
    return {
        "new_24h": new.count(), "new_critical_high_24h": new.filter(severity__in=["Critical", "High"]).count(),
        "new_kev_24h": new.filter(known_exploited=True).count(), "closed_24h": closed.count(),
        "breaching_7d": FindingPriority.objects.filter(finding__active=True, due_date__gte=today, due_date__lte=today + datetime.timedelta(days=7)).count(),
        "overdue": FindingPriority.objects.filter(finding__active=True, due_date__lt=today).count(),
        "connectors_failing": list(Connector.objects.filter(enabled=True, last_status="error").values_list("name", flat=True)),
        "pending_approvals": RiskAcceptanceApproval.objects.filter(status="pending").count(),
        "score_delta": delta,
    }


# ---------------------------------------------------------------------------
# Remediation analytics
# ---------------------------------------------------------------------------
def root_causes(product_id=None, limit=50):
    """Group active findings by the component whose update would clear them, ranked by impact."""
    qs = _active_findings().exclude(component_name=None).exclude(component_name="")
    if product_id:
        qs = qs.filter(test__engagement__product_id=product_id)
    rows = (qs.values("component_name")
            .annotate(findings=Count("id", distinct=True),
                      assets=Count("test__engagement__product", distinct=True),
                      hosts=Count("endpoints__host", distinct=True),
                      critical=Count("id", filter=Q(severity="Critical"), distinct=True),
                      high=Count("id", filter=Q(severity="High"), distinct=True),
                      kev=Count("id", filter=Q(known_exploited=True), distinct=True),
                      urgent=Count("id", filter=Q(priority__band="Urgent"), distinct=True),
                      max_score=Max("priority__score"),
                      earliest_due=Min("priority__due_date"),
                      fix=Max("fix_version"))
            .order_by("-urgent", "-kev", "-max_score", "-findings")[:limit])
    out = []
    for r in rows:
        r["impact"] = r["urgent"] * 30 + r["kev"] * 25 + r["critical"] * 10 + r["high"] * 4 + r["findings"]
        out.append(r)
    return sorted(out, key=lambda r: -r["impact"])


def vulnerability_explorer(q=None, kev=None, limit=300):
    qs = _active_findings().exclude(cve=None).exclude(cve="")
    if q:
        qs = qs.filter(Q(cve__icontains=q) | Q(component_name__icontains=q) | Q(title__icontains=q))
    if kev:
        qs = qs.filter(known_exploited=True)
    rows = (qs.values("cve")
            .annotate(findings=Count("id", distinct=True), products=Count("test__engagement__product", distinct=True),
                      hosts=Count("endpoints__host", distinct=True), kev=Count("id", filter=Q(known_exploited=True), distinct=True),
                      epss=Max("epss_score"), pct=Max("epss_percentile"), cvss=Max("cvssv3_score"),
                      severity=Min("numerical_severity"), score=Max("priority__score"),
                      due=Min("priority__due_date"), first=Min("date"))
            .order_by("-kev", "-score", "-epss", "-findings")[:limit])
    sev = {"S0": "Critical", "S1": "High", "S2": "Medium", "S3": "Low", "S4": "Info"}
    out = []
    for r in rows:
        r["vulnerability_id"] = r.pop("cve")
        r["severity_label"] = sev.get(r["severity"], r["severity"])
        out.append(r)
    return out


def scan_cadence():
    """Per product: expected scan interval vs the most recent import (ISO 27001 A.8.8 / A.8.29)."""
    from orasec.models import Product, Test  # noqa: PLC0415
    expected = {c.product_id: c.expected_days for c in ProductScanCadence.objects.all()}
    last = dict(Test.objects.values("engagement__product").annotate(last=Max("updated")).values_list("engagement__product", "last"))
    out = []
    now = timezone.now()
    for p in Product.objects.all().order_by("name"):
        days = expected.get(p.id, DEFAULT_CADENCE_DAYS)
        ts = last.get(p.id)
        if ts is None:
            state = "never"
        elif now - ts <= datetime.timedelta(days=days):
            state = "on_time"
        elif now - ts <= datetime.timedelta(days=days * 2):
            state = "due"
        else:
            state = "overdue"
        out.append({"product": p, "expected_days": days, "last": ts, "state": state,
                    "age_days": (now - ts).days if ts else None})
    for a in InventoryAsset.objects.filter(retired=False, asset_type__in=["server", "firewall", "cloud_instance"]):
        days = a.scan_cadence_days or DEFAULT_CADENCE_DAYS
        ts = a.last_scanned_at
        state = "never" if ts is None else ("on_time" if now - ts <= datetime.timedelta(days=days) else
                                             "due" if now - ts <= datetime.timedelta(days=days * 2) else "overdue")
        out.append({"asset": a, "expected_days": days, "last": ts, "state": state, "age_days": (now - ts).days if ts else None})
    return out


# ---------------------------------------------------------------------------
# Triage rules engine
# ---------------------------------------------------------------------------
def _rule_queryset(rule):
    c = rule.conditions or {}
    qs = _active_findings()
    if c.get("severity_in"):
        qs = qs.filter(severity__in=c["severity_in"])
    if c.get("band_in"):
        qs = qs.filter(priority__band__in=c["band_in"])
    if c.get("kev") is True:
        qs = qs.filter(known_exploited=True)
    if c.get("epss_percentile_gte") not in (None, ""):
        qs = qs.filter(epss_percentile__gte=float(c["epss_percentile_gte"]))
    if c.get("product_ids"):
        qs = qs.filter(test__engagement__product_id__in=c["product_ids"])
    if c.get("scan_type_in"):
        qs = qs.filter(test__test_type__name__in=c["scan_type_in"])
    if c.get("title_contains"):
        qs = qs.filter(title__icontains=c["title_contains"])
    if c.get("component_contains"):
        qs = qs.filter(component_name__icontains=c["component_contains"])
    if c.get("age_days_gte") not in (None, ""):
        qs = qs.filter(date__lte=timezone.now().date() - datetime.timedelta(days=int(c["age_days_gte"])))
    return qs


def preview_rule(rule, limit=25):
    qs = _rule_queryset(rule)
    return qs.count(), list(qs.order_by("numerical_severity", "-id")[:limit])


def run_triage_rules(dry_run=False):
    from orasec.models import Finding, OraSec_User  # noqa: PLC0415
    summary = {}
    claimed = set()
    for rule in TriageRule.objects.filter(enabled=True):
        qs = _rule_queryset(rule).exclude(id__in=TriageRuleHit.objects.filter(rule=rule).values("finding_id"))
        if claimed:
            qs = qs.exclude(id__in=claimed)
        ids = list(qs.values_list("id", flat=True)[:5000])
        summary[rule.name] = len(ids)
        if dry_run or not ids:
            continue
        a = rule.actions or {}
        fs = Finding.objects.filter(id__in=ids)
        if a.get("mark_false_positive"):
            fs.update(false_p=True, active=False, verified=False)
        if a.get("mark_out_of_scope"):
            fs.update(out_of_scope=True, active=False)
        if a.get("planned_remediation_days"):
            fs.update(planned_remediation_date=timezone.now().date() + datetime.timedelta(days=int(a["planned_remediation_days"])))
        if a.get("add_tags"):
            for f in fs:
                f.tags.add(*a["add_tags"])
        if a.get("assign_to"):
            user = OraSec_User.objects.filter(id=a["assign_to"]).first()
            if user:
                for fid in ids:
                    FindingAssignment.objects.update_or_create(finding_id=fid, defaults={"assignee": user, "assigned_by": None})
        titles = list(fs.values_list("id", "title", "severity")[:50])
        body = f"OraSec triage rule '{rule.name}' matched {len(ids)} finding(s):\n\n" + "\n".join(f"- [{s}] #{i} {t}" for i, t, s in titles)
        if a.get("notify_emails"):
            try:
                send_mail(f"[OraSec] {rule.name}: {len(ids)} finding(s)", body, None, a["notify_emails"], fail_silently=True)
            except Exception:
                logger.exception("rule email failed")
        if a.get("notify_webhook"):
            try:
                requests.post(a["notify_webhook"], data=json.dumps({"text": body}), headers={"Content-Type": "application/json"}, timeout=10)
            except requests.RequestException:
                logger.exception("rule webhook failed")
        TriageRuleHit.objects.bulk_create([TriageRuleHit(rule=rule, finding_id=i) for i in ids], ignore_conflicts=True)
        rule.match_count += len(ids)
        rule.last_matched_at = timezone.now()
        rule.save(update_fields=["match_count", "last_matched_at"])
        if rule.stop_processing:
            claimed.update(ids)
    return summary


# ---------------------------------------------------------------------------
# Governed risk acceptance: no self-approval, approval required before findings are accepted
# ---------------------------------------------------------------------------
def hold_for_approval(ra, requested_by):
    """Called when a risk acceptance is created/extended: keep its findings active until approved."""
    from orasec.models import Finding  # noqa: PLC0415
    ids = list(ra.accepted_findings.values_list("id", flat=True))
    appr, _ = RiskAcceptanceApproval.objects.update_or_create(risk_acceptance=ra, defaults={
        "status": "pending", "requested_by": requested_by, "requested_at": timezone.now(), "decided_by": None,
        "decided_at": None, "decision_note": "", "pending_findings": ids})
    Finding.objects.filter(id__in=ids).update(risk_accepted=False, active=True)
    return appr


def decide(appr, user, approve, note=""):
    from orasec.models import Finding  # noqa: PLC0415
    if appr.requested_by_id and appr.requested_by_id == user.id:
        msg = "You cannot approve or reject your own risk acceptance request."
        raise PermissionError(msg)
    appr.status = "approved" if approve else "rejected"
    appr.decided_by, appr.decided_at, appr.decision_note = user, timezone.now(), note
    appr.save()
    ids = appr.pending_findings or list(appr.risk_acceptance.accepted_findings.values_list("id", flat=True))
    if approve:
        Finding.objects.filter(id__in=ids).update(risk_accepted=True, active=False)
    else:
        appr.risk_acceptance.accepted_findings.clear()
        Finding.objects.filter(id__in=ids).update(risk_accepted=False, active=True)
    return appr


def auto_cover_new_findings():
    """Approved acceptances with auto-cover also cover new findings with the same title + CVE on the same asset."""
    from orasec.models import Finding  # noqa: PLC0415
    n = 0
    for appr in RiskAcceptanceApproval.objects.filter(status="approved", auto_cover_new=True).select_related("risk_acceptance"):
        ra = appr.risk_acceptance
        if ra.expiration_date and ra.expiration_date < timezone.now():
            continue
        accepted = list(ra.accepted_findings.values("title", "cve", "test__engagement__product_id"))
        for spec in accepted:
            new = Finding.objects.filter(active=True, risk_accepted=False, duplicate=False, title=spec["title"], cve=spec["cve"],
                                         test__engagement__product_id=spec["test__engagement__product_id"]).exclude(risk_acceptance=ra)
            from orasec.posture.signals import bypass  # noqa: PLC0415
            with bypass():
                for f in new:
                    ra.accepted_findings.add(f)
                    n += 1
            new.update(risk_accepted=True, active=False)
    return n



# ---------------------------------------------------------------------------
# Command Center (flow view, KPI strip, insights) for a time range
# ---------------------------------------------------------------------------
SOURCE_GROUPS = [  # (label, icon, test-type keywords)
    ("Wazuh SIEM", "fa-shield-virus", ("wazuh",)),
    ("Code (Semgrep · Gitleaks · GitHub)", "fa-code", ("semgrep", "gitleaks", "github")),
    ("Containers (Trivy)", "fa-box", ("trivy",)),
    ("Web & network scans", "fa-satellite-dish", ("zap", "nuclei", "nmap", "nikto")),
    ("Firewalls (OPNsense · UniFi)", "fa-fire-flame-curved", ("opnsense", "unifi")),
    ("Cloud (AWS · Cloudflare)", "fa-cloud", ("aws", "cloudflare")),
    ("Patching (PatchMon)", "fa-screwdriver-wrench", ("patchmon",)),
]


def _source_of(test_type):
    t = (test_type or "").lower()
    for label, _icon, keys in SOURCE_GROUPS:
        if any(k in t for k in keys):
            return label
    return "Other scanners"


def command_center(days=30):  # noqa: PLR0914
    from orasec.models import Finding  # noqa: PLC0415
    from orasec.posture.models import AttackEvent, ComplianceControl  # noqa: PLC0415
    now = timezone.now()
    since = now - datetime.timedelta(days=days)
    p = posture()
    active = _active_findings()

    # ---- flow: sources -> posture -> outcome bands
    band_by_finding = dict(FindingPriority.objects.filter(finding__active=True, finding__duplicate=False).values_list("finding_id", "band"))
    flows, src_tot = {}, {}
    for fid, tt in active.values_list("id", "test__test_type__name"):
        s = _source_of(tt)
        b = band_by_finding.get(fid, "Low")
        src_tot[s] = src_tot.get(s, 0) + 1
        flows.setdefault(s, {}).setdefault(b, 0)
        flows[s][b] += 1
    icons = {label: icon for label, icon, _ in SOURCE_GROUPS}
    sources = [{"label": s, "icon": icons.get(s, "fa-magnifying-glass"), "count": n, "bands": flows.get(s, {})}
               for s, n in sorted(src_tot.items(), key=lambda x: -x[1])]
    bands = p["vuln_detail"]["bands"]
    outcomes = [{"band": b, "count": bands.get(b, 0)} for b in ("Urgent", "Needs Action", "Medium", "Low")]

    # ---- KPIs for the range
    closed = Finding.objects.filter(is_mitigated=True, mitigated__gte=since, duplicate=False)
    closed_n = closed.count()
    durations = [(m - (timezone.make_aware(datetime.datetime.combine(d, datetime.time())) if d else m)).days
                 for m, d in closed.values_list("mitigated", "date")[:5000] if m]
    mttr = round(sum(durations) / len(durations), 1) if durations else None
    new_n = Finding.objects.filter(created__gte=since, duplicate=False).count()
    fp = FindingPriority.objects.filter(finding__active=True, finding__duplicate=False)
    with_sla = fp.exclude(due_date=None)
    within = with_sla.filter(due_date__gte=now.date()).count()
    sla_pct = math.floor(1000 * within / with_sla.count()) / 10 if with_sla.count() else None
    kev_open = active.filter(known_exploited=True).count()
    attacks = AttackEvent.objects.filter(occurred_at__gte=since).aggregate(n=Sum("hits"))["n"] or 0
    top_attack = (AttackEvent.objects.filter(occurred_at__gte=since).exclude(src_country="").values("src_country")
                  .annotate(n=Sum("hits")).order_by("-n").first())
    ctrl = ComplianceControl.objects.filter(framework__code=compliance.CODE)
    comp = compliance.summary()
    assets = InventoryAsset.objects.filter(retired=False).count()
    snaps = list(PostureSnapshot.objects.filter(date__gte=since.date()).order_by("date"))
    delta = (p["score"] - snaps[0].score) if snaps and snaps[0].date < now.date() else None
    kpis = [
        {"label": "Open findings", "value": active.count(), "hint": f"{new_n:,} new · {closed_n:,} closed in range"},
        {"label": "Mean time to remediate", "value": f"{mttr} d" if mttr is not None else "—", "hint": f"{len(durations):,} fixes in range"},
        {"label": "Within SLA", "value": f"{sla_pct}%" if sla_pct is not None else "—", "hint": f"{p['vuln_detail'].get('overdue', 0)} overdue"},
        {"label": "Known exploited (KEV)", "value": kev_open if kev_open is not None else "—", "hint": "CISA KEV, open"},
        {"label": "ISO 27001 implemented", "value": f"{comp.get('implemented', 0)}/{comp.get('applicable', 0) or ctrl.count()}",
         "hint": f"{comp.get('auto_pass', 0)} checks pass · {comp.get('auto_fail', 0)} fail"},
        {"label": "Assets monitored", "value": assets, "hint": f"{Connector.objects.filter(enabled=True).count()} connectors"},
        {"label": "Attacks blocked", "value": attacks, "hint": f"top origin {top_attack['src_country']}" if top_attack else "edge + firewalls"},
    ]

    for k in kpis:
        if isinstance(k["value"], int):
            k["value"] = f"{k['value']:,}"
    # ---- insights (plain-language, ranked)
    insights = []
    rc = root_causes(limit=25)
    if rc:
        r = rc[0]
        insights.append({"tone": "action", "title": f"Update {r['component_name']} to clear {r['findings']:,} findings",
                         "body": f"One update{' to ' + r['fix'] if r.get('fix') else ''} removes {r['findings']:,} open findings"
                                 f"{f' ({r[chr(107) + chr(101) + chr(118)]} known-exploited)' if r['kev'] else ''}"
                                 f" across {r['hosts'] or r['assets']} host{'s' if (r['hosts'] or r['assets']) != 1 else ''}.",
                         "link": "/orasec/remediation/"})
    od = p["vuln_detail"].get("overdue", 0)
    if od:
        insights.append({"tone": "risk", "title": f"{od} findings past their SLA", "body": "Known-exploited vulnerabilities are capped at the CISA due date.",
                         "link": "/orasec/my-work/"})
    failing = [c.name for c in Connector.objects.filter(enabled=True, last_status__in=["error", "fail"])]
    if failing:
        insights.append({"tone": "risk", "title": f"{len(failing)} connector(s) failing", "body": ", ".join(failing)[:160], "link": "/orasec/diagnostics/"})
    if comp.get("auto_fail"):
        insights.append({"tone": "gov", "title": f"{comp['auto_fail']} ISO 27001 automated checks failing",
                         "body": "Evidence is collected automatically; failing controls need an owner and a treatment.", "link": "/orasec/compliance/"})
    if delta is not None:
        insights.append({"tone": "good" if delta >= 0 else "risk", "title": f"Posture {'up' if delta >= 0 else 'down'} {abs(delta)} points",
                         "body": f"From {snaps[0].score} on {snaps[0].date:%d %b} to {p['score']} today.", "link": "/orasec/insights/executive/"})
    if top_attack:
        insights.append({"tone": "info", "title": f"{attacks:,} attacks blocked", "body": f"Most from {top_attack['src_country']}. Open the attack map for origins and IPs.",
                         "link": "/orasec/attacks/"})
    return {"posture": p, "sources": sources, "outcomes": outcomes, "kpis": kpis, "insights": insights[:6], "days": days,
            "trend": [{"d": s.date.isoformat(), "score": s.score, "vuln": s.vuln_score, "compliance": s.compliance_score} for s in snaps],
            "generated": now.isoformat()}

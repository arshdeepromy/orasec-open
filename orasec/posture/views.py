import csv
import datetime
import io
import json
import logging

from django.contrib import messages
from django.contrib.auth.decorators import login_required, user_passes_test
from django.core.paginator import Paginator
from django.contrib.postgres.aggregates import ArrayAgg
from django.db.models import Count, Min, Q
from django.http import HttpResponse, HttpResponseForbidden, JsonResponse
from django.shortcuts import get_object_or_404, redirect
from django.shortcuts import render as _django_render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.http import require_POST

from orasec import site as site_profile
from orasec.posture import compliance, services
from orasec.posture.forms import (
    AssetForm,
    CampaignForm,
    ConnectorForm,
    ControlImplementationForm,
    EvidenceForm,
    PrioritySettingsForm,
    RiskForm,
    TriageRuleForm,
)
from orasec.posture.models import (
    ComplianceControl,
    Connector,
    ConnectorRun,
    ControlImplementation,
    FindingAssignment,
    FindingPriority,
    IntelFeed,
    InventoryAsset,
    PostureSnapshot,
    PrioritySettings,
    RemediationCampaign,
    RiskAcceptanceApproval,
    RiskRegisterEntry,
    TriageRule,
    PatchDeployment,
)

TITLES = {
    "command_center": "Command Center", "insights": "Insights", "connectors": "Connectors", "connector_form": "Connector",
    "connector_detail": "Connector", "run_detail": "Connector run", "diagnostics": "Diagnostics", "inventory": "Asset Inventory",
    "asset_detail": "Asset", "vulnerabilities": "Vulnerability Explorer", "vulnerability_detail": "Vulnerability",
    "remediation": "Remediation Center", "my_work": "My Work", "risk_acceptances": "Risk Acceptances", "compliance": "ISO 27001 Compliance",
    "control_detail": "Control", "risks": "Risk Register", "risk_form": "Risk", "triage_rules": "Triage Rules", "triage_rule_form": "Triage Rule",
    "scan_cadence": "Scan Cadence", "priority_settings": "Prioritisation & SLA", "patch_center": "Patch Center", "patch_deployment": "Patch run", "topology": "Network Topology", "attacks": "Attack Map", "code_security": "Code & Repositories",
}


def render(request, template, ctx=None):
    from orasec.utils import add_breadcrumb  # noqa: PLC0415
    key = template.rsplit("/", 1)[-1].removesuffix(".html")
    add_breadcrumb(title=(ctx or {}).get("page_title") or TITLES.get(key, "OraSec"), top_level=True, request=request)
    return _django_render(request, template, ctx or {})


superuser_required = user_passes_test(lambda u: u.is_active and u.is_superuser)
logger = logging.getLogger(__name__)
approver_required = user_passes_test(lambda u: u.is_active and (u.is_superuser or u.is_staff))

COMPLIANCE_GROUP = "Compliance Officer"


def is_compliance_officer(u):
    """Superusers, or members of the 'Compliance Officer' role (group)."""
    return bool(u.is_authenticated and u.is_active and (u.is_superuser or u.groups.filter(name=COMPLIANCE_GROUP).exists()))


compliance_required = user_passes_test(is_compliance_officer)


def _findings():
    from orasec.models import Finding  # noqa: PLC0415
    return Finding.objects.filter(active=True, duplicate=False)


def _ensure_seeded():
    if not ComplianceControl.objects.filter(framework__code=compliance.CODE).exists():
        compliance.seed()


# ---------------------------------------------------------------------------
# Command Center and insights
# ---------------------------------------------------------------------------
@login_required
def command_center(request):
    _ensure_seeded()
    days = {"7d": 7, "30d": 30, "90d": 90, "365d": 365}.get(request.GET.get("range", "30d"), 30)
    cc = services.command_center(days)
    top = (FindingPriority.objects.filter(finding__active=True, finding__duplicate=False)
           .select_related("finding__test__engagement__product").order_by("-score", "due_date")[:10])
    ctx = {
        "cc": cc, "cc_json": {k: cc[k] for k in ("sources", "outcomes", "trend", "posture")},
        "ranges": [("7d", 7), ("30d", 30), ("90d", 90), ("365d", 365)], "today": timezone.now().date(),
        "top": top, "connectors": Connector.objects.all(), "feeds": IntelFeed.objects.all(), "wall": request.GET.get("wall") == "1",
    }
    return render(request, "orasec/posture/command_center.html", ctx)


@login_required
def insights(request, view="executive"):
    _ensure_seeded()
    f = _findings()
    ctx = {"view": view, "posture": services.posture()}
    if view == "executive":
        snaps = list(PostureSnapshot.objects.all()[:180])[::-1]
        ctx["trend"] = json.dumps({"labels": [s.date.isoformat() for s in snaps], "score": [s.score for s in snaps],
                                   "critical": [s.counts.get("critical", 0) for s in snaps], "high": [s.counts.get("high", 0) for s in snaps]})
        ctx["by_product"] = list(f.values("test__engagement__product__name").annotate(
            n=Count("id"), crit=Count("id", filter=Q(severity="Critical")), high=Count("id", filter=Q(severity="High")),
            kev=Count("id", filter=Q(known_exploited=True))).order_by("-crit", "-high"))
        ctx["compliance"] = compliance.summary()
    elif view == "priority":
        ctx["bands"] = list(FindingPriority.objects.filter(finding__active=True).values("band").annotate(n=Count("id")))
        ctx["kev"] = f.filter(known_exploited=True).select_related("test__engagement__product")[:100]
        ctx["epss_top"] = f.filter(epss_percentile__gte=0.9).order_by("-epss_score")[:50]
        ctx["matrix"] = list(FindingPriority.objects.filter(finding__active=True).values("band", "finding__severity").annotate(n=Count("id")))
    elif view == "program":
        today = timezone.now().date()
        start = today - datetime.timedelta(days=90)
        from orasec.models import Finding  # noqa: PLC0415
        weeks = []
        for i in range(13):
            ws = start + datetime.timedelta(days=7 * i)
            we = ws + datetime.timedelta(days=7)
            weeks.append({"week": ws.isoformat(), "opened": Finding.objects.filter(date__gte=ws, date__lt=we, duplicate=False).count(),
                          "closed": Finding.objects.filter(mitigated__date__gte=ws, mitigated__date__lt=we).count()})
        ctx["weeks"] = json.dumps(weeks)
        mttr = []
        for sev in ("Critical", "High", "Medium", "Low"):
            closed = Finding.objects.filter(severity=sev, is_mitigated=True, mitigated__isnull=False, mitigated__date__gte=start)
            days = [(x.mitigated.date() - x.date).days for x in closed.only("mitigated", "date")[:2000]]
            mttr.append({"severity": sev, "closed": len(days), "mttr": round(sum(days) / len(days), 1) if days else None})
        ctx["mttr"] = mttr
        pr = FindingPriority.objects.filter(finding__active=True)
        ctx["sla"] = {"tracked": pr.count(), "overdue": pr.filter(due_date__lt=today).count(),
                      "due_7d": pr.filter(due_date__gte=today, due_date__lte=today + datetime.timedelta(days=7)).count()}
    elif view == "remediation":
        ctx["root_causes"] = services.root_causes(limit=25)
        ctx["campaigns"] = RemediationCampaign.objects.exclude(status="cancelled")
    elif view == "tool":
        ctx["tools"] = list(f.values("test__test_type__name").annotate(
            n=Count("id"), crit=Count("id", filter=Q(severity="Critical")), high=Count("id", filter=Q(severity="High")),
            products=Count("test__engagement__product", distinct=True)).order_by("-n"))
        ctx["cadence"] = services.scan_cadence()
        ctx["connectors"] = Connector.objects.all()
    return render(request, "orasec/posture/insights.html", ctx)


# ---------------------------------------------------------------------------
# Connectors and diagnostics
# ---------------------------------------------------------------------------
@login_required
def connectors(request):
    return render(request, "orasec/posture/connectors.html", {"connectors": Connector.objects.select_related("product")})


@superuser_required
def connector_edit(request, cid=None):
    obj = get_object_or_404(Connector, id=cid) if cid else None
    initial = {"kind": request.GET.get("kind")} if not obj else None
    form = ConnectorForm(request.POST or None, instance=obj, initial=initial)
    if request.method == "POST" and form.is_valid():
        c = form.save()
        messages.success(request, f"Connector '{c.name}' saved.")
        return redirect("orasec_connector_detail", cid=c.id)
    # "kind" is worked out here: in a template, ``x|default:request.GET.kind`` raises when the address has no ?kind=
    kind = form.instance.kind or request.GET.get("kind") or ""
    return render(request, "orasec/posture/connector_form.html", {"form": form, "obj": obj, "kinds": Connector.KIND_CHOICES, "kind": kind})


@login_required
def connector_detail(request, cid):
    c = get_object_or_404(Connector, id=cid)
    runs = c.runs.all()[:30]
    return render(request, "orasec/posture/connector_detail.html", {"c": c, "runs": runs, "last": runs[0] if runs else None})


@superuser_required
@require_POST
def connector_test(request, cid):
    from orasec.posture.connectors.base import get_connector_class  # noqa: PLC0415
    c = get_object_or_404(Connector, id=cid)
    try:
        msg = get_connector_class(c.kind)(c).test()
        messages.success(request, f"Connection OK: {msg}")
    except Exception as e:  # noqa: BLE001 shown to the admin
        messages.error(request, f"Connection failed: {e}")
    return redirect("orasec_connector_detail", cid=c.id)


@superuser_required
@require_POST
def connector_run(request, cid):
    from orasec.posture.tasks import run_connector_task  # noqa: PLC0415
    c = get_object_or_404(Connector, id=cid)
    from orasec.plugins import registry as plugins  # noqa: PLC0415
    if not plugins.source_on(c.kind):
        messages.warning(request, f"'{c.name}' was not run: the {c.get_kind_display()} plugin is off. Turn it on under Automation, Plugins.")
        return redirect("orasec_connector_detail", cid=c.id)
    run_connector_task.delay(c.id, "manual", request.user.id)
    messages.info(request, f"'{c.name}' queued. Refresh in a minute to see the run.")
    return redirect("orasec_connector_detail", cid=c.id)


@login_required
def connector_run_detail(request, rid):
    run = get_object_or_404(ConnectorRun, id=rid)
    return render(request, "orasec/posture/run_detail.html", {"run": run, "stats": json.dumps(run.stats, indent=1, default=str)})


@login_required
def diagnostics(request):
    from orasec.models import Test_Import  # noqa: PLC0415
    from orasec.posture.models import TriageRuleHit  # noqa: PLC0415
    ctx = {
        "connectors": Connector.objects.all(),
        "errors": ConnectorRun.objects.filter(status__in=["error", "warning"]).select_related("connector")[:30],
        "feeds": IntelFeed.objects.all(),
        "imports": Test_Import.objects.select_related("test__engagement__product").order_by("-created")[:20],
        "rules": TriageRule.objects.all(),
        "rule_hits_24h": TriageRuleHit.objects.filter(applied_at__gte=timezone.now() - datetime.timedelta(hours=24)).count(),
        "priorities": FindingPriority.objects.order_by("-computed_at").first(),
        "pending_approvals": RiskAcceptanceApproval.objects.filter(status="pending").count(),
        "control_checks": ControlImplementation.objects.exclude(auto_status__in=["na"]).order_by("-auto_evaluated_at")[:1],
    }
    return render(request, "orasec/posture/diagnostics.html", ctx)


@superuser_required
@require_POST
def run_job(request, job):
    from orasec.posture import tasks  # noqa: PLC0415
    jobs = {"intel": tasks.refresh_intel, "priorities": tasks.refresh_priorities, "posture": tasks.daily_posture,
            "connectors": tasks.run_due_connectors}
    if job not in jobs:
        return HttpResponseForbidden()
    jobs[job].delay()
    messages.info(request, f"Job '{job}' queued.")
    return redirect(request.POST.get("next") or "orasec_diagnostics")


# ---------------------------------------------------------------------------
# Inventory
# ---------------------------------------------------------------------------
@login_required
def inventory(request):
    qs = InventoryAsset.objects.select_related("product", "owner", "parent")
    t = request.GET.get("type")
    q = request.GET.get("q")
    if t:
        qs = qs.filter(asset_type=t)
    elif request.GET.get("clients") != "1":
        qs = qs.exclude(asset_type="client")
    if q:
        qs = qs.filter(Q(name__icontains=q) | Q(hostname__icontains=q) | Q(ip_address__icontains=q) | Q(mac_address__icontains=q))
    if request.GET.get("retired") != "1":
        qs = qs.filter(retired=False)
    counts = dict(InventoryAsset.objects.filter(retired=False).order_by().values_list("asset_type").annotate(n=Count("id")))
    hosts = {a.hostname.lower() for a in qs if a.hostname} | {a.name.lower() for a in qs}
    from orasec.models import Endpoint  # noqa: PLC0415
    fc = dict(Endpoint.objects.filter(host__in=list(hosts), findings__active=True, findings__duplicate=False)
              .order_by().values_list("host").annotate(n=Count("findings", distinct=True)))
    page = Paginator(qs, 100).get_page(request.GET.get("page"))
    for a in page:
        a.open_findings = fc.get(a.hostname.lower(), 0) or fc.get(a.name.lower(), 0) if a.hostname or a.name else 0
    return render(request, "orasec/posture/inventory.html", {"page": page, "counts": counts, "types": InventoryAsset.TYPE_CHOICES})


@login_required
def asset_detail(request, aid):
    a = get_object_or_404(InventoryAsset, id=aid)
    form = None
    if request.user.is_superuser:
        form = AssetForm(request.POST or None, instance=a)
        if request.method == "POST" and form.is_valid():
            form.save()
            messages.success(request, "Asset updated.")
            return redirect("orasec_asset", aid=a.id)
    names = {x.lower() for x in (a.hostname, a.name) if x}
    findings = _findings().filter(endpoints__host__in=list(names)).select_related("priority", "test__test_type").distinct().order_by("numerical_severity")[:200]
    return render(request, "orasec/posture/asset_detail.html", {"a": a, "form": form, "findings": findings,
                                                                 "attrs": json.dumps(a.attributes, indent=1, default=str)})


# ---------------------------------------------------------------------------
# Vulnerabilities, remediation, my work
# ---------------------------------------------------------------------------
@login_required
def vulnerabilities(request):
    rows = services.vulnerability_explorer(q=request.GET.get("q"), kev=request.GET.get("kev") == "1")
    return render(request, "orasec/posture/vulnerabilities.html", {"rows": rows})


@login_required
def vulnerability_detail(request, vid):
    from orasec.models import Finding  # noqa: PLC0415
    findings = (Finding.objects.filter(Q(cve__iexact=vid) | Q(vulnerability_id__vulnerability_id__iexact=vid), duplicate=False).distinct()
                .select_related("test__engagement__product", "priority").prefetch_related("endpoints").order_by("-active", "numerical_severity"))
    from orasec.posture.models import EpssScore, KevEntry  # noqa: PLC0415
    return render(request, "orasec/posture/vulnerability_detail.html", {"vid": vid, "findings": findings,
                  "kev": KevEntry.objects.filter(cve=vid).first(), "epss": EpssScore.objects.filter(cve=vid).first()})


@login_required
def remediation(request):
    product_id = request.GET.get("product")
    form = CampaignForm(request.POST or None) if request.user.is_superuser else None
    if request.method == "POST" and form and form.is_valid():
        c = form.save(commit=False)
        c.baseline_open = _findings().filter(component_name=c.component, **({"test__engagement__product": c.product} if c.product else {})).count()
        c.save()
        messages.success(request, f"Campaign '{c.name}' created.")
        return redirect("orasec_remediation")
    campaigns = []
    for c in RemediationCampaign.objects.exclude(status="cancelled").select_related("owner", "product"):
        qs = _findings().filter(component_name=c.component)
        if c.product_id:
            qs = qs.filter(test__engagement__product_id=c.product_id)
        c.open_now = qs.count()
        c.progress = int(100 * (1 - c.open_now / c.baseline_open)) if c.baseline_open else (100 if c.open_now == 0 else 0)
        campaigns.append(c)
    from orasec.models import Product  # noqa: PLC0415
    return render(request, "orasec/posture/remediation.html", {
        "roots": services.root_causes(product_id=product_id or None), "campaigns": campaigns, "form": form,
        "products": Product.objects.all().order_by("name"), "product_id": product_id})


@login_required
def my_work(request):
    u = request.user
    from orasec.models import Finding  # noqa: PLC0415
    ctx = {
        "assigned": FindingAssignment.objects.filter(assignee=u, finding__active=True).select_related("finding__priority", "finding__test__engagement__product")[:200],
        "reviews": Finding.objects.filter(reviewers=u, under_review=True)[:100],
        "approvals": RiskAcceptanceApproval.objects.filter(status="pending").exclude(requested_by=u).select_related("risk_acceptance")
        if (u.is_superuser or u.is_staff) else [],
        "my_requests": RiskAcceptanceApproval.objects.filter(requested_by=u).select_related("risk_acceptance")[:50],
        "controls": ControlImplementation.objects.filter(owner=u).select_related("control"),
        "risks": RiskRegisterEntry.objects.filter(owner=u).exclude(status="closed"),
        "campaigns": RemediationCampaign.objects.filter(owner=u, status__in=["planned", "active"]),
    }
    return render(request, "orasec/posture/my_work.html", ctx)


@login_required
@require_POST
def assign_finding(request, fid):
    from orasec.models import Finding, OraSec_User  # noqa: PLC0415
    f = get_object_or_404(Finding, id=fid)
    uid = request.POST.get("assignee")
    if uid:
        FindingAssignment.objects.update_or_create(finding=f, defaults={"assignee": get_object_or_404(OraSec_User, id=uid), "assigned_by": request.user})
    else:
        FindingAssignment.objects.filter(finding=f).delete()
    return redirect(request.POST.get("next") or reverse("view_finding", args=[f.id]))


# ---------------------------------------------------------------------------
# Risk acceptances (instance-wide, approval workflow)
# ---------------------------------------------------------------------------
@login_required
def risk_acceptances(request):
    from orasec.models import Risk_Acceptance  # noqa: PLC0415
    status = request.GET.get("status", "")
    qs = Risk_Acceptance.objects.select_related("owner", "approval__requested_by", "approval__decided_by").annotate(n=Count("accepted_findings")).order_by("-created")
    if status:
        qs = qs.filter(approval__status=status)
    return render(request, "orasec/posture/risk_acceptances.html", {"items": qs[:300], "status": status,
                  "pending": RiskAcceptanceApproval.objects.filter(status="pending").count()})


@approver_required
@require_POST
def risk_acceptance_decide(request, aid):
    appr = get_object_or_404(RiskAcceptanceApproval, id=aid)
    try:
        services.decide(appr, request.user, request.POST.get("decision") == "approve", request.POST.get("note", ""))
        messages.success(request, f"Risk acceptance {appr.status}.")
    except PermissionError as e:
        messages.error(request, str(e))
    return redirect(request.POST.get("next") or "orasec_risk_acceptances")


# ---------------------------------------------------------------------------
# Compliance and risk register
# ---------------------------------------------------------------------------
@login_required
def compliance_home(request):
    _ensure_seeded()
    qs = ComplianceControl.objects.filter(framework__code=compliance.CODE).select_related("implementation__owner").annotate(n_evidence=Count("evidence"))
    cat, st = request.GET.get("category"), request.GET.get("status")
    if cat:
        qs = qs.filter(category=cat)
    if st:
        qs = qs.filter(Q(implementation__status=st) | Q(implementation__auto_status=st))
    return render(request, "orasec/posture/compliance.html", {"controls": qs, "summary": compliance.summary(),
                  "categories": ["Clause", "Organizational", "People", "Physical", "Technological"], "category": cat, "st": st,
                  "can_compliance": is_compliance_officer(request.user)})


@login_required
def control_detail(request, cid):
    c = get_object_or_404(ComplianceControl, id=cid)
    impl, _ = ControlImplementation.objects.get_or_create(control=c)
    # Superusers edit any control. The Compliance Officer role adds evidence to any control
    # and edits the controls it owns (it cannot reassign ownership).
    can_evidence = is_compliance_officer(request.user)
    can_edit = request.user.is_superuser or (can_evidence and impl.owner_id == request.user.id)
    form = ControlImplementationForm(request.POST or None, instance=impl) if can_edit else None
    if form is not None and not request.user.is_superuser:
        form.fields["owner"].disabled = True
    ev_form = EvidenceForm(request.POST or None, request.FILES or None, prefix="ev") if can_evidence else None
    if request.method == "POST" and (form is not None or ev_form is not None):
        if "save_impl" in request.POST and form is not None and form.is_valid():
            form.save()
            messages.success(request, "Control updated.")
            return redirect("orasec_control", cid=c.id)
        if "add_evidence" in request.POST and ev_form is not None and ev_form.is_valid():
            ev = ev_form.save(commit=False)
            ev.control, ev.created_by = c, request.user
            ev.save()
            messages.success(request, "Evidence added.")
            return redirect("orasec_control", cid=c.id)
    return render(request, "orasec/posture/control_detail.html", {"c": c, "impl": impl, "form": form, "ev_form": ev_form,
                  "checks": c.check_results.all()[:20], "risks": c.risks.all()})


@compliance_required
@require_POST
def compliance_evaluate(request):
    _ensure_seeded()
    res = compliance.evaluate_all()
    messages.success(request, f"Evaluated {len(res)} automated controls.")
    return redirect("orasec_compliance")


@login_required
def soa_export(request, fmt="xlsx"):
    _ensure_seeded()
    rows = [("Ref", "Control", "Theme", "Applicable", "Justification", "Status", "Automated check", "Check detail", "Owner",
             "Evidence items", "Last reviewed")]
    for c in ComplianceControl.objects.filter(framework__code=compliance.CODE).select_related("implementation__owner").annotate(n=Count("evidence")):
        i = c.implementation
        rows.append((c.ref, c.title, c.category, "Yes" if i.applicable else "No", i.justification, i.get_status_display(),
                     i.get_auto_status_display(), i.auto_detail, i.owner.get_full_name() or i.owner.username if i.owner else "",
                     c.n, i.last_reviewed.isoformat() if i.last_reviewed else ""))
    stamp = timezone.now().strftime("%Y%m%d")
    if fmt == "csv":
        buf = io.StringIO()
        csv.writer(buf).writerows(rows)
        resp = HttpResponse(buf.getvalue(), content_type="text/csv")
        resp["Content-Disposition"] = f'attachment; filename="OraSec-SoA-ISO27001-{stamp}.csv"'
        return resp
    from openpyxl import Workbook  # noqa: PLC0415
    from openpyxl.styles import Alignment, Font, PatternFill  # noqa: PLC0415
    wb = Workbook()
    ws = wb.active
    ws.title = "Statement of Applicability"
    for r in rows:
        ws.append(r)
    for cell in ws[1]:
        cell.font = Font(bold=True, color="FFFFFF")
        cell.fill = PatternFill("solid", fgColor="00796B")
    for col, w in zip("ABCDEFGHIJK", (8, 48, 15, 11, 50, 14, 16, 60, 18, 10, 13)):
        ws.column_dimensions[col].width = w
    for row in ws.iter_rows(min_row=2):
        for cell in row:
            cell.alignment = Alignment(wrap_text=True, vertical="top")
    ws.freeze_panes = "C2"
    ws.auto_filter.ref = ws.dimensions
    buf = io.BytesIO()
    wb.save(buf)
    resp = HttpResponse(buf.getvalue(), content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    resp["Content-Disposition"] = f'attachment; filename="OraSec-SoA-ISO27001-{stamp}.xlsx"'
    return resp


@login_required
def risks(request):
    items = RiskRegisterEntry.objects.select_related("owner", "product").prefetch_related("controls")
    heat = {(l, i): 0 for l in range(1, 6) for i in range(1, 6)}
    for r in items.exclude(status="closed"):
        heat[(r.likelihood, r.impact)] += 1
    grid = [[(l, i, heat[(l, i)], l * i) for i in range(1, 6)] for l in range(5, 0, -1)]
    return render(request, "orasec/posture/risks.html", {"items": items, "grid": grid, "can_compliance": is_compliance_officer(request.user)})


@compliance_required
def risk_edit(request, rid=None):
    obj = get_object_or_404(RiskRegisterEntry, id=rid) if rid else None
    form = RiskForm(request.POST or None, instance=obj)
    if request.method == "POST" and form.is_valid():
        r = form.save()
        messages.success(request, f"Risk {r.ref} saved.")
        return redirect("orasec_risks")
    return render(request, "orasec/posture/risk_form.html", {"form": form, "obj": obj})


# ---------------------------------------------------------------------------
# Triage rules, scan cadence, priority settings
# ---------------------------------------------------------------------------
@login_required
def triage_rules(request):
    return render(request, "orasec/posture/triage_rules.html", {"rules": TriageRule.objects.all()})


@superuser_required
def triage_rule_edit(request, rid=None):
    obj = get_object_or_404(TriageRule, id=rid) if rid else None
    form = TriageRuleForm(request.POST or None, instance=obj)
    preview = None
    if request.method == "POST" and form.is_valid():
        if "preview" in request.POST:
            tmp = form.save(commit=False)
            preview = services.preview_rule(tmp)
        else:
            r = form.save(commit=False)
            r.created_by = r.created_by or request.user
            r.save()
            messages.success(request, f"Rule '{r.name}' saved. It runs hourly with priority refresh.")
            return redirect("orasec_triage_rules")
    return render(request, "orasec/posture/triage_rule_form.html", {"form": form, "obj": obj, "preview": preview})


@login_required
def scan_cadence(request):
    return render(request, "orasec/posture/scan_cadence.html", {"rows": services.scan_cadence()})


@superuser_required
def priority_settings(request):
    obj = PrioritySettings.load()
    form = PrioritySettingsForm(request.POST or None, instance=obj)
    if request.method == "POST" and form.is_valid():
        form.save()
        from orasec.posture.tasks import refresh_priorities  # noqa: PLC0415
        refresh_priorities.delay()
        messages.success(request, "Prioritisation settings saved; priorities are being recalculated.")
        return redirect("orasec_priority_settings")
    return render(request, "orasec/posture/priority_settings.html", {"form": form})


@login_required
def posture_api(request):
    """Small JSON API for wall screens and integrations."""
    p = services.posture()
    return JsonResponse({"score": p["score"], "vuln": p["vuln"], "compliance": p["compliance"], "hygiene": p["hygiene"],
                         "bands": p["vuln_detail"]["bands"], "brief": services.daily_brief(), "generated": timezone.now().isoformat()})



# ---------------------------------------------------------------------------
# Patch Center (Semaphore / Ansible)
# ---------------------------------------------------------------------------
@login_required
def patch_center(request):
    from orasec.posture import patching  # noqa: PLC0415
    return render(request, "orasec/posture/patch_center.html", {
        "connector": patching.semaphore_connector(), "assets": patching.patchable_assets(),
        "deployments": PatchDeployment.objects.select_related("asset", "requested_by")[:40],
        "patchmon": Connector.objects.filter(kind="patchmon").first()})


@superuser_required
@require_POST
def patch_deploy(request, aid):
    from orasec.posture import patching  # noqa: PLC0415
    from orasec.posture.tasks import patch_deployment_task  # noqa: PLC0415
    a = get_object_or_404(InventoryAsset, id=aid)
    if request.POST.get("confirm") != "yes":
        messages.error(request, "Tick the confirmation box to start a patch run.")
        return redirect(request.POST.get("next") or "orasec_patch_center")
    try:
        dep = patching.request_deployment(a, request.user, request.POST.get("mode", "apply"), request.POST.get("change_ref", ""), request.POST.get("reason", ""))
    except ValueError as e:
        messages.error(request, str(e))
        return redirect(request.POST.get("next") or "orasec_patch_center")
    patch_deployment_task.delay(dep.id)
    messages.success(request, f"Patch run for {a.name} sent to Semaphore.")
    return redirect("orasec_patch_deployment", did=dep.id)


@login_required
def patch_deployment(request, did):
    dep = get_object_or_404(PatchDeployment.objects.select_related("asset", "connector", "requested_by"), id=did)
    if request.GET.get("format") == "json":
        return JsonResponse({"status": dep.status, "label": dep.get_status_display(), "summary": dep.summary, "output": dep.output[-20000:],
                             "active": dep.is_active})
    return render(request, "orasec/posture/patch_deployment.html", {"d": dep})


# ---------------------------------------------------------------------------
# Network topology and attack map
# ---------------------------------------------------------------------------
RANGES = {"24h": 1, "7d": 7, "30d": 30, "90d": 90, "365d": 365}


@login_required
def topology_view(request):
    return render(request, "orasec/posture/topology.html", {"page_title": "Network Topology"})


def _org_wide(u):
    return u.is_active and (u.is_superuser or u.is_staff)


@login_required
def topology_api(request):
    from orasec.posture import topology  # noqa: PLC0415
    g = topology.build()
    g["can_edit"] = g["can_health"] = _org_wide(request.user)
    if not g["can_health"]:  # live host health and workloads are organisation-wide data
        for n in g["nodes"]:
            n.pop("health", None)
            if n.get("asset_id"):
                n.pop("live", None)
                n["detail"] = ""
    return JsonResponse(g)


@login_required
def topology_health_api(request):
    if not _org_wide(request.user):
        return JsonResponse({"error": "Organisation-wide access needed."}, status=403)
    from orasec.posture import topology  # noqa: PLC0415
    return JsonResponse(topology.health_only())


TOPOLOGY_CONNECTOR_KINDS_SKIPPED = ("isms", "github")  # not shown on the map


@login_required
@require_POST
def topology_refresh(request):
    """Ask every connected tool for its current state now, so the map shows changes (new, stopped or removed machines)
    without waiting for the next scheduled run. Limited to one refresh a minute."""
    if not _org_wide(request.user):
        return JsonResponse({"error": "Organisation-wide access needed."}, status=403)
    from django.core.cache import cache  # noqa: PLC0415

    from orasec.posture.models import Connector  # noqa: PLC0415
    from orasec.posture.tasks import run_connector_task  # noqa: PLC0415
    if not cache.add("orasec-topology-refresh", request.user.id, 60):
        return JsonResponse({"queued": 0, "wait": True})
    ids = [c.id for c in Connector.objects.filter(enabled=True).exclude(kind__in=TOPOLOGY_CONNECTOR_KINDS_SKIPPED)
           if c.last_status != "running"]
    for cid in ids:
        run_connector_task.delay(cid, "topology refresh", request.user.id)
    return JsonResponse({"queued": len(ids), "wait": False})


@login_required
def topology_node_api(request, aid):
    """One machine: identity, agents, open findings and the last hour of health."""
    if not _org_wide(request.user):
        return JsonResponse({"error": "Organisation-wide access needed."}, status=403)
    from orasec.posture import health  # noqa: PLC0415
    from orasec.posture.topology import _asset_status, _role  # noqa: PLC0415
    a = get_object_or_404(InventoryAsset, id=aid)
    attrs = a.attributes or {}
    out = {"asset_id": a.id, "name": a.name, "hostname": a.hostname, "ip": a.ip_address, "type": a.get_asset_type_display(),
           "role": (attrs.get("topology") or {}).get("role", ""), "detail": _role(a), "aliases": attrs.get("aliases", []),
           "agents": _asset_status(a), "url": f"/orasec/inventory/{a.id}/", "criticality": a.criticality}
    try:
        from orasec.home import metrics  # noqa: PLC0415
        rows = (metrics.get(allow_sync=False) or {}).get("assets_all") or []
        names = {x.lower() for x in (a.name, a.hostname, *(attrs.get("aliases") or [])) if x}
        hit = [r for r in rows if r.get("key") in names and r.get("kind") == "Host"]
        if hit:
            out["findings"] = {"open": sum(r["total"] for r in hit), "kev": sum(r["kev"] for r in hit), "overdue": sum(r["overdue"] for r in hit),
                               "mix": " · ".join(r["mix"] for r in hit if r.get("mix"))}
    except Exception:  # the dashboard cache is optional here
        logger.debug("no dashboard data for asset %s", a.id, exc_info=True)
    sid = (attrs.get("beszel") or {}).get("system_id")
    out["health"] = health.detail(sid) if sid else {"error": "No health agent on this machine."}
    return JsonResponse(out)


@login_required
@require_POST
def topology_node_edit(request, aid):
    """Rename a machine (display name) and set its role note. Old names are kept as aliases so lookups keep working."""
    if not _org_wide(request.user):
        return JsonResponse({"error": "Organisation-wide access needed."}, status=403)
    a = get_object_or_404(InventoryAsset, id=aid)
    try:
        body = json.loads(request.body or "{}")
    except ValueError:
        return JsonResponse({"error": "Bad request."}, status=400)
    name = " ".join(str(body.get("name", a.name)).split())[:120]
    role = " ".join(str(body.get("role", "")).split())[:300]
    if not name:
        return JsonResponse({"error": "Name can't be empty."}, status=400)
    old = a.name
    if name != old:
        a.name = name
        a.add_aliases(old)
    attrs = dict(a.attributes or {})
    topo = dict(attrs.get("topology") or {})
    if role:
        topo["role"] = role
    else:
        topo.pop("role", None)
    attrs["topology"] = topo
    attrs["aliases"] = (a.attributes or {}).get("aliases", [])
    a.attributes = attrs
    a.save(update_fields=["name", "attributes"])
    return JsonResponse({"ok": True, "name": a.name, "role": topo.get("role", "")})


@login_required
def attacks_view(request):
    target = site_profile.get("attack_map_target") or {}
    return render(request, "orasec/posture/attacks.html", {"page_title": "Attack Map", "ranges": list(RANGES),
                                                           "attack_target": {"lon": float(target.get("lon") or 0), "lat": float(target.get("lat") or 0),
                                                                             "country": str(target.get("country") or "")[:2].upper()}})


@login_required
def attacks_api(request):
    from django.db.models import Max, Sum  # noqa: PLC0415
    from django.db.models.functions import TruncDay, TruncHour  # noqa: PLC0415

    from orasec.posture import geo, security_alerts  # noqa: PLC0415
    from orasec.posture.models import AttackEvent  # noqa: PLC0415
    rng = request.GET.get("range", "7d")
    days = RANGES.get(rng, 7)
    since = timezone.now() - datetime.timedelta(days=days)
    qs = AttackEvent.objects.filter(occurred_at__gte=since)
    src = request.GET.get("source")
    if src:
        qs = qs.filter(source=src)
    total = qs.aggregate(n=Sum("hits"))["n"] or 0
    countries = list(qs.exclude(src_country="").values("src_country").annotate(hits=Sum("hits"), ips=Count("src_ip", distinct=True), last=Max("occurred_at"))
                     .order_by("-hits")[:250])
    for c in countries:
        c["flag"] = geo.flag(c["src_country"])
        c["sources"] = sorted(set(qs.filter(src_country=c["src_country"]).values_list("source", flat=True)))
    by_source = list(qs.values("source").annotate(hits=Sum("hits"), events=Count("id")).order_by("-hits"))
    by_action = list(qs.values("action").annotate(hits=Sum("hits")).order_by("-hits"))
    ips = list(qs.exclude(src_ip=None).values("src_ip", "src_country", "src_asn", "src_org").annotate(
        hits=Sum("hits"), last=Max("occurred_at"), first=Min("occurred_at"), sources=ArrayAgg("source", distinct=True),
        targets=ArrayAgg("target", distinct=True), ports=ArrayAgg("dst_port", distinct=True), rules=ArrayAgg("rule", distinct=True),
        actions=ArrayAgg("action", distinct=True)).order_by("-last")[:300])
    for r in ips:
        r["flag"] = geo.flag(r["src_country"])
        r["ports"] = [p for p in r["ports"] if p][:6]
        r["targets"] = [t for t in r["targets"] if t][:4]
        r["rules"] = [x for x in r["rules"] if x][:3]
    trunc = TruncHour if days <= 7 else TruncDay
    timeline = [{"t": x["b"].isoformat(), "hits": x["hits"]} for x in qs.annotate(b=trunc("occurred_at")).values("b").annotate(hits=Sum("hits")).order_by("b")]
    recent = [{"t": e.occurred_at.isoformat(), "ip": e.src_ip, "cc": e.src_country, "flag": geo.flag(e.src_country), "source": e.source,
               "action": e.action, "target": e.target, "port": e.dst_port, "rule": e.rule[:120], "hits": e.hits}
              for e in qs.order_by("-occurred_at")[:150]]
    conns = {c.kind: {"name": c.name, "status": c.last_status, "last_run": c.last_run_at.isoformat() if c.last_run_at else None}
             for c in Connector.objects.filter(kind__in=["cloudflare", "opnsense", "unifi", "wazuh", "aws"])}
    return JsonResponse({"range": rng, "since": since.isoformat(), "total": total, "unique_ips": len({r["src_ip"] for r in ips}), "countries": countries,
                         "by_source": by_source, "by_action": by_action, "ips": ips, "timeline": timeline, "recent": recent, "connectors": conns,
                         "alerts": security_alerts.rows(qs), "alert_feed": security_alerts.feed_status(),
                         "target": site_profile.get("attack_map_target"),
                         "generated": timezone.now().isoformat()}, json_dumps_params={"default": str})


# ---------------------------------------------------------------------------
# Code & Repositories
# ---------------------------------------------------------------------------
CODE_SCAN_TYPES = ["Semgrep JSON Report", "Gitleaks Scan", "Trivy Scan", "OraSec GitHub", "Bandit Scan", "Snyk Scan", "Dependency Check Scan"]


def _gh_connector():
    return Connector.objects.filter(kind="github").first()


def _excluded_repos(gh):
    return {x.lower() for x in ((gh.options or {}).get("exclude_repos") or [])} if gh else set()


@login_required
def code_security(request):  # noqa: PLR0914
    from orasec.models import Finding, Test  # noqa: PLC0415
    gh = _gh_connector()
    excluded = _excluded_repos(gh)
    run = gh.runs.filter(status__in=["ok", "warning"]).first() if gh else None
    feats = (run.stats or {}).get("features", {}) if run else {}
    sev_order = ["Critical", "High", "Medium", "Low", "Info"]
    gh_open = {}
    for uid, sev in _findings().filter(test__test_type__name="OraSec GitHub").values_list("unique_id_from_tool", "severity"):
        parts = (uid or "").split(":")
        if len(parts) > 1:
            gh_open.setdefault(parts[1], {}).setdefault(sev, 0)
            gh_open[parts[1]][sev] += 1
    repos = []
    for a in InventoryAsset.objects.filter(retired=False, attributes__has_key="github").order_by("name"):
        g, full = a.attributes.get("github") or {}, a.name
        monitored = full.lower() not in excluded
        f = feats.get(full, {}) if monitored else {}
        counts = gh_open.get(full, {}) if monitored else {}
        repos.append({"asset": a, "full": full, "private": g.get("private"), "language": g.get("language") or "—", "branch": g.get("default_branch"),
                      "pushed": g.get("pushed_at"), "url": g.get("url") or f"https://github.com/{full}", "features": f, "monitored": monitored,
                      "open": sum(counts.values()), "sev": [(s, counts.get(s, 0)) for s in sev_order if counts.get(s)]})
    repos.sort(key=lambda r: (not r["monitored"], r["full"].lower()))
    live = [r for r in repos if r["monitored"]]
    tests = []
    for t in (Test.objects.filter(test_type__name__in=[x for x in CODE_SCAN_TYPES if x != "OraSec GitHub"])
              .select_related("test_type", "engagement__product").order_by("engagement__product__name", "title")):
        qs = _findings().filter(test=t)
        sev = dict(qs.order_by().values_list("severity").annotate(n=Count("id")))
        tests.append({"t": t, "kind": "Container image" if "image" in t.title.lower() else ("Secrets" if "gitleaks" in t.test_type.name.lower()
                      else ("SAST" if "semgrep" in t.test_type.name.lower() else "Dependencies & IaC")),
                      "open": sum(sev.values()), "sev": [(s, sev.get(s, 0)) for s in sev_order if sev.get(s)], "updated": t.updated})
    kpi = {"repos": len(live), "private": sum(1 for r in live if r["private"]), "off": len(repos) - len(live),
           "unprotected": sum(1 for r in live if r["features"].get("branch_protection") is False),
           "dependabot_off": sum(1 for r in live if r["features"].get("dependabot") is False),
           "secrets": _findings().filter(Q(test__test_type__name="Gitleaks Scan") | Q(unique_id_from_tool__contains=":secret:")).count(),
           "code_open": sum(x["open"] for x in tests), "gh_open": sum(r["open"] for r in live)}
    return render(request, "orasec/posture/code_security.html", {"repos": repos, "tests": tests, "kpi": kpi, "gh": gh, "run": run,
                                                                 "can_edit": request.user.is_superuser, "page_title": "Code & Repositories"})


def _set_repo_findings(full, user, *, monitored):
    """Switching a repo off closes its open GitHub findings as out of scope; switching it back on clears that flag
    so the next GitHub run re-opens whatever is still true."""
    from orasec.models import Finding  # noqa: PLC0415
    qs = Finding.objects.filter(test__test_type__name="OraSec GitHub", unique_id_from_tool__startswith=f"github:{full}:")
    if not monitored:
        return qs.filter(active=True).update(active=False, out_of_scope=True, is_mitigated=True, mitigated=timezone.now(),
                                            mitigated_by=user, last_status_update=timezone.now())
    return qs.filter(out_of_scope=True).update(out_of_scope=False, last_status_update=timezone.now())


@superuser_required
@require_POST
def code_scope(request):
    """Save which GitHub repositories OraSec monitors (checkboxes on the Code & Repositories page)."""
    from orasec.posture.tasks import run_connector_task  # noqa: PLC0415
    gh = _gh_connector()
    if not gh:
        messages.error(request, "Add the GitHub connector first.")
        return redirect("orasec_code")
    names = list(InventoryAsset.objects.filter(attributes__has_key="github").values_list("name", flat=True))
    keep = {x.lower() for x in request.POST.getlist("monitor")}
    before = _excluded_repos(gh)
    # repos not shown on the page (none yet) keep whatever they had
    after = {n.lower() for n in names if n.lower() not in keep} | (before - {n.lower() for n in names})
    turned_off = [n for n in names if n.lower() in after - before]
    turned_on = [n for n in names if n.lower() in before - after]
    if not turned_off and not turned_on:
        messages.info(request, "No changes.")
        return redirect("orasec_code")
    opts = dict(gh.options or {})
    opts["exclude_repos"] = sorted(n for n in names if n.lower() in after) + sorted(x for x in after if x not in {n.lower() for n in names})
    gh.options = opts
    gh.save(update_fields=["options"])
    closed = 0
    for full in turned_off:
        closed += _set_repo_findings(full, request.user, monitored=False)
        InventoryAsset.objects.filter(name=full).update(last_scanned_at=None)
    for full in turned_on:
        _set_repo_findings(full, request.user, monitored=True)
    parts = []
    if turned_off:
        parts.append(f"Stopped monitoring {len(turned_off)} repo(s): {', '.join(turned_off)} ({closed} open finding(s) closed as out of scope)")
    if turned_on:
        run_connector_task.delay(gh.id, "manual", request.user.id)
        parts.append(f"Monitoring {len(turned_on)} repo(s) again: {', '.join(turned_on)}. A GitHub check is running now, refresh in a minute")
    messages.success(request, ". ".join(parts) + ".")
    return redirect("orasec_code")


def code_scope_api(request):
    """JSON list of monitored / switched-off repos for the nightly code-scan script (API token or session)."""
    from rest_framework.authentication import TokenAuthentication  # noqa: PLC0415
    from rest_framework.exceptions import AuthenticationFailed  # noqa: PLC0415
    user = request.user if getattr(request, "user", None) and request.user.is_authenticated else None
    if user is None:
        try:
            got = TokenAuthentication().authenticate(request)
        except AuthenticationFailed:
            got = None
        user = got[0] if got else None
    if user is None:
        return JsonResponse({"error": "authentication required"}, status=401)
    gh = _gh_connector()
    excluded = _excluded_repos(gh)
    names = sorted(InventoryAsset.objects.filter(retired=False, attributes__has_key="github").values_list("name", flat=True), key=str.lower)
    return JsonResponse({"monitored": [n for n in names if n.lower() not in excluded],
                         "excluded": sorted(((gh.options or {}).get("exclude_repos") or []) if gh else [], key=str.lower)})

"""Readiness checks for controls that run mainly through approved procedures.

Each check confirms what OraSec can see for itself:
* an approved, in-date document in the policy tool sets out the practice for the control (the document link
  evidence that the policy-tool sync keeps current, see isms_docs), and
* any operational signal OraSec already holds for that control: connector evidence that is still valid, another
  automated check, or the records the procedure requires (with the first due date taken from the approval date).

The detail text says exactly which of these was found, so a pass is never wider than the evidence behind it.
"""
import datetime

from django.utils import timezone

from orasec import site as site_profile

POLICY_PREFIX = "Policy tool: "
ROLES = ("CTO", "Cloud Infrastructure Engineer", "Compliance Officer")


def _today():
    return timezone.localdate()


def _policy_docs(ref):
    from orasec.posture.models import ControlEvidence  # noqa: PLC0415
    today = _today()
    q = ControlEvidence.objects.filter(control__framework__code="iso27001-2022", control__ref=ref, source="auto",
                                       title__startswith=POLICY_PREFIX)
    # a newer approved version marks the older link superseded (valid until the day it was replaced)
    return [e for e in q if (e.valid_until is None or e.valid_until >= today) and "Superseded on" not in (e.description or "")]


def _doc_id(e):
    return e.title[len(POLICY_PREFIX):].split(" ")[0]


def _approved_on(docs):
    """Approval date of the governing documents (one year before their next review)."""
    dates = [e.valid_until for e in docs if e.valid_until]
    return (min(dates) - datetime.timedelta(days=365)) if dates else _today()


def connector_evidence(ref, prefix, label):
    """Signal: connector-collected evidence on this control that is still within its validity."""
    from orasec.posture.models import ControlEvidence  # noqa: PLC0415
    today = _today()
    e = (ControlEvidence.objects.filter(control__ref=ref, title__startswith=prefix)
         .filter(valid_until__gte=today).order_by("-collected_at").first())
    if e:
        return label, "pass", f"{label} collected {timezone.localtime(e.collected_at):%d %b %Y}"
    return label, "fail", f"{label}: no current automated evidence"


def other_check(name, label):
    """Signal: the result of another automated check."""
    from orasec.posture import compliance  # noqa: PLC0415
    try:
        res, det, _m = getattr(compliance, "check_" + name)()
    except Exception as e:  # noqa: BLE001
        return label, "warn", f"{label}: check error {e.__class__.__name__}"
    return label, res, f"{label}: {det.rstrip('.')}"


def record_due(prefix, label, every_days, first_due_days=None, first_due=None):
    """Signal factory: a record titled '<prefix>…' is needed every `every_days`; the first one is due
    `first_due_days` after the governing document was approved, or on the fixed date `first_due`."""
    def sig(ref, docs):
        from orasec.posture.models import ControlEvidence  # noqa: PLC0415
        today = _today()
        last = ControlEvidence.objects.filter(title__istartswith=prefix).order_by("-collected_at").first()
        if last:
            due = timezone.localtime(last.collected_at).date() + datetime.timedelta(days=every_days)
            if due < today:
                return label, "fail", f"{label} overdue since {due:%d %b %Y}"
            if due <= today + datetime.timedelta(days=14):
                return label, "warn", f"{label} due {due:%d %b %Y}"
            return label, "pass", f"last {label.lower()} {timezone.localtime(last.collected_at):%d %b %Y}, next due {due:%d %b %Y}"
        due = first_due or (_approved_on(docs) + datetime.timedelta(days=first_due_days if first_due_days is not None else every_days))
        if due < today:
            return label, "fail", f"no {label.lower()} recorded; first one was due {due:%d %b %Y}"
        if due <= today + datetime.timedelta(days=14):
            return label, "warn", f"no {label.lower()} recorded yet; first one due {due:%d %b %Y}"
        return label, "pass", f"first {label.lower()} due {due:%d %b %Y} (record titled '{prefix} …')"
    return sig


def per_role_record(prefix, label):
    """Signal factory: one record per team role, titled '<prefix> <role> …' (one-off, kept)."""
    def sig(ref, docs):
        from orasec.posture.models import ControlEvidence  # noqa: PLC0415
        missing = [r for r in ROLES if not ControlEvidence.objects.filter(title__istartswith=f"{prefix} {r}").exists()]
        if missing:
            return label, "fail", f"{label} missing for: {', '.join(missing)} (record titled '{prefix} <role> …')"
        return label, "pass", f"{label} recorded for all {len(ROLES)} roles"
    return sig


def documented(ref, signals=()):
    docs = _policy_docs(ref)
    ids = sorted({_doc_id(e) for e in docs})
    nexts = sorted(e.valid_until for e in docs if e.valid_until)
    m = {"control": ref, "documents": ids, "next_review": nexts[0].isoformat() if nexts else None, "signals": []}
    if not docs:
        return "fail", f"No approved, in-date document in the policy tool covers {ref}.", m
    results = []
    for s in signals:
        label, res, det = s(ref, docs) if callable(s) else s
        results.append((res, det))
        m["signals"].append({"signal": label, "result": res, "detail": det})
    base = f"Approved procedure in place ({', '.join(ids[:4])}{' …' if len(ids) > 4 else ''}; next review {nexts[0]:%d %b %Y})" \
        if nexts else f"Approved procedure in place ({', '.join(ids[:4])})"
    fails = [d for r, d in results if r == "fail"]
    warns = [d for r, d in results if r == "warn"]
    soon = nexts and nexts[0] <= _today() + datetime.timedelta(days=30)
    if fails:
        return "fail", base + ". Not met: " + "; ".join(fails) + ".", m
    passes = [d for r, d in results if r == "pass"]
    tail = ("; " + "; ".join(passes)) if passes else ""
    if warns or soon:
        return "warn", base + tail + ". Attention: " + "; ".join(warns + (["document review due within 30 days"] if soon else [])) + ".", m
    return "pass", base + tail + ".", m


def accepted_risk(label):
    """Signal factory: an approved, unexpired risk acceptance or policy exception (EXC-) is recorded on this control."""
    def sig(ref, docs):
        from orasec.posture.grc_models import GovernanceException  # noqa: PLC0415
        today = _today()
        e = (GovernanceException.objects.filter(control__ref=ref, status="approved", expiry__gte=today)
             .order_by("-expiry").first())
        if not e:
            return label, "fail", f"no approved {label.lower()} recorded on {ref}"
        if e.expiry <= today + datetime.timedelta(days=14):
            return label, "warn", f"{e.ref} expires {e.expiry:%d %b %Y}"
        return label, "pass", f"{e.ref} approved, valid until {e.expiry:%d %b %Y}"
    return sig


def physical_monitoring_signal(ref, docs):
    from orasec.posture.models import InventoryAsset  # noqa: PLC0415
    from django.db.models import Q  # noqa: PLC0415
    n = InventoryAsset.objects.filter(retired=False).filter(
        Q(attributes__device_role="camera") | Q(name__iregex=r"camera|doorbell|\bcam\b")).count()
    if n:
        return "Cameras", "pass", f"{n} camera device(s) in the asset inventory"
    return "Cameras", "warn", "no camera device found in the asset inventory"


# --- the checks -------------------------------------------------------------------------------------------------
AWS_IAM = ("Access control: IAM users, MFA and keys", "AWS IAM evidence")
RESTORE = record_due("Restore test", "Restore test", 365)
DR_EXERCISE = record_due("DR exercise", "Full DR exercise", 365)
BC_TABLETOP = record_due("BC tabletop", "BC tabletop exercise", 365)


def check_info_transfer():
    return documented("A.5.14")


def check_access_control():
    return documented("A.5.15", [connector_evidence("A.5.15", *AWS_IAM)])


def check_identity_management():
    return documented("A.5.16", [other_check("return_of_assets", "Leaver process")])


def check_authentication_information():
    return documented("A.5.17")


def check_access_review():
    # PRC-002: quarterly user access review, first opened in the first two weeks of January
    return documented("A.5.18", [record_due("Access review", "User access review", 92, first_due_days=61)])


def check_ict_supply_chain():
    return documented("A.5.21", [connector_evidence("A.8.4", "Access to source code", "GitHub dependency and code scanning")])


def check_cloud_services():
    return documented("A.5.23", [connector_evidence("A.5.23", "Information security for use of cloud services: AWS CSPM", "AWS CSPM evidence"),
                                 connector_evidence("A.5.23", "Information security for use of cloud services: Cloudflare", "Cloudflare evidence")])


def check_incident_planning():
    return documented("A.5.24", [other_check("communication", "Security contact")])


def check_incident_assessment():
    return documented("A.5.25", [other_check("monitoring", "SIEM alerting")])


def check_incident_response():
    return documented("A.5.26", [other_check("communication", "Security contact")])


def check_incident_learning():
    return documented("A.5.27")


def check_evidence_collection():
    return documented("A.5.28", [other_check("logging", "Log collection")])


def check_disruption():
    return documented("A.5.29", [BC_TABLETOP])


def check_ict_continuity():
    return documented("A.5.30", [RESTORE, DR_EXERCISE])


def check_legal_requirements():
    return documented("A.5.31")


def check_intellectual_property():
    return documented("A.5.32")


def check_records_protection():
    return documented("A.5.33")


def check_privacy():
    return documented("A.5.34")


def check_screening():
    return documented("A.6.1", [per_role_record("Screening:", "Screening record")])


def check_employment_terms():
    return documented("A.6.2", [per_role_record("Confidentiality undertaking:", "Signed FRM-014 undertaking")])


def check_disciplinary():
    return documented("A.6.4")


def check_after_termination():
    return documented("A.6.5", [other_check("return_of_assets", "Leaver process")])


def check_confidentiality_agreements():
    return documented("A.6.6", [per_role_record("Confidentiality undertaking:", "Signed FRM-014 undertaking")])


def check_remote_working():
    return documented("A.6.7", [other_check("agent_coverage", "Endpoint agents")])


def check_event_reporting():
    return documented("A.6.8", [other_check("communication", "Reporting route")])


def check_physical_perimeter():
    return documented("A.7.1")


def check_physical_entry():
    return documented("A.7.2")


def check_secure_offices():
    return documented("A.7.3")


def check_physical_monitoring():
    return documented("A.7.4", [physical_monitoring_signal])


def check_environmental_threats():
    return documented("A.7.5")


def check_secure_areas():
    return documented("A.7.6")


def check_clear_desk():
    return documented("A.7.7")


def check_equipment_siting():
    return documented("A.7.8")


def check_offsite_assets():
    return documented("A.7.9")


def check_supporting_utilities():
    return documented("A.7.11")


def check_cabling():
    return documented("A.7.12")


def check_equipment_maintenance():
    return documented("A.7.13")


def check_secure_disposal():
    return documented("A.7.14")


def check_privileged_access():
    # PRC-002: monthly privileged access review
    return documented("A.8.2", [connector_evidence("A.5.15", *AWS_IAM),
                                record_due("Privileged access review", "Privileged access review", 31, first_due_days=35)])


def check_privileged_utilities():
    # POL-003 4.4: privileged utility programs; use checked in the monthly privileged access review (PRC-002)
    return documented("A.8.18", [record_due("Privileged access review", "Privileged access review", 31, first_due_days=35)])


def check_information_access():
    return documented("A.8.3", [connector_evidence("A.5.15", *AWS_IAM)])


def check_source_code_access():
    return documented("A.8.4", [connector_evidence("A.8.4", "Access to source code", "GitHub branch protection evidence"),
                                other_check("code_review", "Code review")])


def check_capacity():
    return documented("A.8.6", [other_check("monitoring", "Monitoring")])


def check_information_deletion():
    return documented("A.8.10")


def check_data_masking():
    return documented("A.8.11")


def check_backup():
    return documented("A.8.13", [RESTORE])


def check_redundancy():
    # Decision 18 Nov 2026: head-office systems are not business-critical; recovery by restore from backup is accepted
    return documented("A.8.14", [accepted_risk("Risk acceptance"), RESTORE])


def check_clock_sync():
    return documented("A.8.17", [record_due("Clock synchronisation", "Clock synchronisation check", 365)])


def office_network_names():
    """UniFi network names that are the office (site profile key office_networks)."""
    return tuple(site_profile.get("office_networks") or ())


SECURITY_CATEGORIES = ("MALWARE", "PHISHING")


def web_filtering_signal(ref, docs):
    """UniFi gateway settings from the latest UniFi connector run: the office network has intrusion prevention in blocking
    mode and an enabled content-filtering profile that blocks malware and phishing."""
    from orasec.posture.models import ConnectorRun  # noqa: PLC0415
    since = timezone.now() - datetime.timedelta(days=2)
    run = (ConnectorRun.objects.filter(connector__kind="unifi", connector__enabled=True, status__in=("ok", "warning"),
                                       finished_at__gte=since).order_by("-finished_at").first())
    wf = (run.stats or {}).get("web_filtering") if run else None
    if not wf:
        return "UniFi gateway filtering", "fail", "UniFi gateway filtering settings not collected in the last 2 days"
    problems, ok = [], []
    for net in office_network_names():
        ips = [w for w in wf if net in w.get("ips_networks", []) and w.get("ips_mode") == "ips"]
        # UniFi 'Basic' filtering is the FAMILY preset (blocks malware, phishing and adult content, no subscription);
        # 'Enhanced' custom categories need CyberSecure and must include malware and phishing.
        cf = [p for w in wf for p in w.get("content_filtering", [])
              if p.get("enabled") and net in p.get("networks", [])
              and ("FAMILY" in p.get("categories", []) or all(c in p.get("categories", []) for c in SECURITY_CATEGORIES))]
        if not ips:
            problems.append(f"intrusion prevention not blocking on {net}")
        if not cf:
            problems.append(f"no enabled content filter blocking malware and phishing on {net}")
        if ips and cf:
            mode = "Basic: malware, phishing, adult" if "FAMILY" in cf[0]["categories"] else f"{len(cf[0]['categories'])} categories"
            ok.append(f"{net}: intrusion prevention blocking, content filter '{cf[0]['name']}' ({mode})")
    if problems:
        return "UniFi gateway filtering", "fail", "UniFi gateway: " + "; ".join(problems)
    return "UniFi gateway filtering", "pass", "; ".join(ok) + f" (read {timezone.localtime(run.finished_at):%d %b %H:%M})"


def check_web_filtering():
    return documented("A.8.23", [web_filtering_signal])


def check_data_leakage():
    # POL-006 s5.7 / POL-010: layered controls -- UniFi gateway filtering, Wazuh file-integrity monitoring on servers
    return documented("A.8.12", [web_filtering_signal, other_check("agent_coverage", "Wazuh agents (file-integrity monitoring)")])


def check_application_security():
    return documented("A.8.26")


def check_secure_architecture():
    return documented("A.8.27")


def check_outsourced_development():
    return documented("A.8.30")


def check_environment_separation():
    # POL-013 / POL-010: UAT environments on the head-office servers with their own
    # database, secrets and encryption keys; checked and recorded at least once a year
    return documented("A.8.31", [record_due("Environment separation check", "Environment separation check", 366)])


def check_test_information():
    # POL-010: test environments hold synthetic or masked data only; checked and recorded at least once a year
    return documented("A.8.33", [record_due("Test data check", "Test data check", 366)])


def check_independent_review():
    # FWK-001 v2.4 s11.3: every in-house tool pen tested each year by a team member not responsible for it;
    # first test 29 Nov 2026
    return documented("A.5.35", [record_due("Internal pen test", "Internal pen test", 366, first_due=datetime.date(2026, 11, 29))])


def check_audit_testing():
    return documented("A.8.34")


READINESS_CHECKS = {
    "A.5.14": "info_transfer", "A.5.15": "access_control", "A.5.16": "identity_management",
    "A.5.17": "authentication_information", "A.5.18": "access_review", "A.5.21": "ict_supply_chain",
    "A.5.23": "cloud_services", "A.5.24": "incident_planning", "A.5.25": "incident_assessment",
    "A.5.26": "incident_response", "A.5.27": "incident_learning", "A.5.28": "evidence_collection",
    "A.5.29": "disruption", "A.5.30": "ict_continuity", "A.5.31": "legal_requirements",
    "A.5.32": "intellectual_property", "A.5.35": "independent_review", "A.5.33": "records_protection", "A.5.34": "privacy",
    "A.6.1": "screening", "A.6.2": "employment_terms", "A.6.4": "disciplinary", "A.6.5": "after_termination",
    "A.6.6": "confidentiality_agreements", "A.6.7": "remote_working", "A.6.8": "event_reporting",
    "A.7.1": "physical_perimeter", "A.7.2": "physical_entry", "A.7.3": "secure_offices",
    "A.7.4": "physical_monitoring", "A.7.5": "environmental_threats", "A.7.6": "secure_areas",
    "A.7.7": "clear_desk", "A.7.8": "equipment_siting", "A.7.9": "offsite_assets",
    "A.7.11": "supporting_utilities", "A.7.12": "cabling", "A.7.13": "equipment_maintenance",
    "A.7.14": "secure_disposal", "A.8.2": "privileged_access", "A.8.3": "information_access",
    "A.8.4": "source_code_access", "A.8.6": "capacity", "A.8.10": "information_deletion",
    "A.8.11": "data_masking", "A.8.12": "data_leakage", "A.8.13": "backup", "A.8.14": "redundancy", "A.8.17": "clock_sync", "A.8.18": "privileged_utilities", "A.8.23": "web_filtering", "A.8.26": "application_security",
    "A.8.27": "secure_architecture", "A.8.30": "outsourced_development", "A.8.31": "environment_separation", "A.8.33": "test_information",
    "A.8.34": "audit_testing",
}


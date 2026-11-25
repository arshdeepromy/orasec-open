"""ISO/IEC 27001:2022 catalogue (clauses 4-10 and Annex A), seeding and automated control checks."""
import datetime

from django.utils import timezone

from orasec.posture.models import (
    ComplianceControl,
    ComplianceFramework,
    Connector,
    ControlCheckResult,
    ControlImplementation,
    FindingPriority,
    IntelFeed,
    InventoryAsset,
    PostureSnapshot,
)

CODE = "iso27001-2022"

CLAUSES = [
    ("4.1", "Understanding the organization and its context", "Identify internal and external issues that affect the ISMS outcomes."),
    ("4.2", "Understanding the needs and expectations of interested parties", "Identify interested parties and their security requirements."),
    ("4.3", "Determining the scope of the ISMS", "Define and document the ISMS boundaries and applicability."),
    ("4.4", "Information security management system", "Establish, implement, maintain and continually improve the ISMS."),
    ("5.1", "Leadership and commitment", "Top management demonstrates leadership of the ISMS."),
    ("5.2", "Policy", "Top management establishes an information security policy."),
    ("5.3", "Organizational roles, responsibilities and authorities", "Security roles are assigned and communicated."),
    ("6.1.1", "Actions to address risks and opportunities — general", "Plan actions that address ISMS risks and opportunities."),
    ("6.1.2", "Information security risk assessment", "Define and apply a repeatable risk assessment process."),
    ("6.1.3", "Information security risk treatment", "Select treatment options and controls; produce the Statement of Applicability."),
    ("6.2", "Information security objectives and planning to achieve them", "Set measurable security objectives and plans."),
    ("6.3", "Planning of changes", "Plan changes to the ISMS in a controlled way."),
    ("7.1", "Resources", "Provide the resources the ISMS needs."),
    ("7.2", "Competence", "Ensure people doing security work are competent."),
    ("7.3", "Awareness", "People are aware of the policy and their contribution."),
    ("7.4", "Communication", "Determine internal and external ISMS communication."),
    ("7.5", "Documented information", "Create, control and retain ISMS documented information."),
    ("8.1", "Operational planning and control", "Plan and control the processes that meet security requirements."),
    ("8.2", "Information security risk assessment", "Perform risk assessments at planned intervals or on significant change."),
    ("8.3", "Information security risk treatment", "Implement the risk treatment plan."),
    ("9.1", "Monitoring, measurement, analysis and evaluation", "Evaluate security performance and ISMS effectiveness."),
    ("9.2", "Internal audit", "Run internal audits at planned intervals."),
    ("9.3", "Management review", "Top management reviews the ISMS at planned intervals."),
    ("10.1", "Continual improvement", "Continually improve the suitability and effectiveness of the ISMS."),
    ("10.2", "Nonconformity and corrective action", "React to nonconformities and take corrective action."),
]

ANNEX_A = {
    "Organizational": [
        ("5.1", "Policies for information security", "Approved, published and reviewed security policies and topic-specific policies."),
        ("5.2", "Information security roles and responsibilities", "Security roles are defined and allocated."),
        ("5.3", "Segregation of duties", "Conflicting duties and responsibilities are separated."),
        ("5.4", "Management responsibilities", "Management requires staff to apply security in line with policy."),
        ("5.5", "Contact with authorities", "Contact with relevant authorities is maintained."),
        ("5.6", "Contact with special interest groups", "Contact with security forums and professional groups is maintained."),
        ("5.7", "Threat intelligence", "Information about threats is collected and analysed to produce intelligence."),
        ("5.8", "Information security in project management", "Security is integrated into project management."),
        ("5.9", "Inventory of information and other associated assets", "An inventory of information and assets, with owners, is maintained."),
        ("5.10", "Acceptable use of information and other associated assets", "Rules for acceptable use are identified, documented and implemented."),
        ("5.11", "Return of assets", "Assets are returned on change or termination of employment or agreement."),
        ("5.12", "Classification of information", "Information is classified by its security needs."),
        ("5.13", "Labelling of information", "Labelling procedures follow the classification scheme."),
        ("5.14", "Information transfer", "Rules and agreements protect information in transfer."),
        ("5.15", "Access control", "Rules control physical and logical access based on business and security requirements."),
        ("5.16", "Identity management", "The full life cycle of identities is managed."),
        ("5.17", "Authentication information", "Allocation and management of authentication information is controlled."),
        ("5.18", "Access rights", "Access rights are provisioned, reviewed, modified and removed per policy."),
        ("5.19", "Information security in supplier relationships", "Risks from suppliers' products and services are managed."),
        ("5.20", "Addressing information security within supplier agreements", "Security requirements are agreed with each supplier."),
        ("5.21", "Managing information security in the ICT supply chain", "ICT supply-chain risks are managed."),
        ("5.22", "Monitoring, review and change management of supplier services", "Supplier security practice and service delivery are monitored."),
        ("5.23", "Information security for use of cloud services", "Acquisition, use, management and exit of cloud services is governed."),
        ("5.24", "Information security incident management planning and preparation", "Incident management processes, roles and responsibilities are defined."),
        ("5.25", "Assessment and decision on information security events", "Events are assessed and categorised as incidents where appropriate."),
        ("5.26", "Response to information security incidents", "Incidents are responded to per documented procedures."),
        ("5.27", "Learning from information security incidents", "Knowledge from incidents strengthens controls."),
        ("5.28", "Collection of evidence", "Evidence related to security events is identified, collected and preserved."),
        ("5.29", "Information security during disruption", "Security is maintained during disruption."),
        ("5.30", "ICT readiness for business continuity", "ICT readiness is planned, implemented, maintained and tested."),
        ("5.31", "Legal, statutory, regulatory and contractual requirements", "Applicable requirements are identified and kept up to date."),
        ("5.32", "Intellectual property rights", "Procedures protect intellectual property rights."),
        ("5.33", "Protection of records", "Records are protected from loss, destruction, falsification and unauthorised access."),
        ("5.34", "Privacy and protection of PII", "Privacy and PII protection requirements are met."),
        ("5.35", "Independent review of information security", "The approach to security is independently reviewed."),
        ("5.36", "Compliance with policies, rules and standards for information security", "Compliance with policy and standards is reviewed regularly."),
        ("5.37", "Documented operating procedures", "Operating procedures are documented and available."),
    ],
    "People": [
        ("6.1", "Screening", "Background checks on candidates before joining and on an ongoing basis."),
        ("6.2", "Terms and conditions of employment", "Employment agreements state security responsibilities."),
        ("6.3", "Information security awareness, education and training", "Personnel receive appropriate awareness and training."),
        ("6.4", "Disciplinary process", "A disciplinary process exists for policy violations."),
        ("6.5", "Responsibilities after termination or change of employment", "Duties that remain valid after leaving are defined and enforced."),
        ("6.6", "Confidentiality or non-disclosure agreements", "NDAs reflect protection needs and are reviewed."),
        ("6.7", "Remote working", "Security measures protect information accessed or processed remotely."),
        ("6.8", "Information security event reporting", "Personnel can report observed or suspected events promptly."),
    ],
    "Physical": [
        ("7.1", "Physical security perimeters", "Perimeters protect areas containing information and assets."),
        ("7.2", "Physical entry", "Secure areas are protected by entry controls."),
        ("7.3", "Securing offices, rooms and facilities", "Physical security for offices and facilities is designed and implemented."),
        ("7.4", "Physical security monitoring", "Premises are monitored for unauthorised access."),
        ("7.5", "Protecting against physical and environmental threats", "Protection against natural disasters and other threats."),
        ("7.6", "Working in secure areas", "Measures for working in secure areas."),
        ("7.7", "Clear desk and clear screen", "Clear desk and clear screen rules are enforced."),
        ("7.8", "Equipment siting and protection", "Equipment is sited securely and protected."),
        ("7.9", "Security of assets off-premises", "Off-site assets are protected."),
        ("7.10", "Storage media", "Storage media are managed through their life cycle."),
        ("7.11", "Supporting utilities", "Facilities are protected from power and other utility failures."),
        ("7.12", "Cabling security", "Power and data cables are protected."),
        ("7.13", "Equipment maintenance", "Equipment is maintained correctly."),
        ("7.14", "Secure disposal or re-use of equipment", "Sensitive data and software are removed before disposal or re-use."),
    ],
    "Technological": [
        ("8.1", "User endpoint devices", "Information on user endpoint devices is protected."),
        ("8.2", "Privileged access rights", "Privileged access is restricted and managed."),
        ("8.3", "Information access restriction", "Access to information is restricted per access-control policy."),
        ("8.4", "Access to source code", "Access to source code and development tools is managed."),
        ("8.5", "Secure authentication", "Secure authentication technologies and procedures are implemented."),
        ("8.6", "Capacity management", "Resource use is monitored and adjusted."),
        ("8.7", "Protection against malware", "Malware protection is implemented and supported by awareness."),
        ("8.8", "Management of technical vulnerabilities", "Vulnerabilities are identified, evaluated and remediated in time."),
        ("8.9", "Configuration management", "Secure configurations are established, documented, monitored and reviewed."),
        ("8.10", "Information deletion", "Information is deleted when no longer required."),
        ("8.11", "Data masking", "Data masking is used per access-control policy."),
        ("8.12", "Data leakage prevention", "Data leakage prevention measures are applied."),
        ("8.13", "Information backup", "Backups are maintained and regularly tested."),
        ("8.14", "Redundancy of information processing facilities", "Facilities have sufficient redundancy."),
        ("8.15", "Logging", "Logs of activities, exceptions and events are produced, stored, protected and analysed."),
        ("8.16", "Monitoring activities", "Networks, systems and applications are monitored for anomalous behaviour."),
        ("8.17", "Clock synchronization", "System clocks are synchronised to approved sources."),
        ("8.18", "Use of privileged utility programs", "Utilities that can override controls are restricted."),
        ("8.19", "Installation of software on operational systems", "Software installation on operational systems is controlled."),
        ("8.20", "Networks security", "Networks and network devices are secured, managed and controlled."),
        ("8.21", "Security of network services", "Security mechanisms and service levels of network services are defined and monitored."),
        ("8.22", "Segregation of networks", "Groups of services, users and systems are segregated."),
        ("8.23", "Web filtering", "Access to external websites is managed."),
        ("8.24", "Use of cryptography", "Rules for effective use of cryptography and key management are defined and implemented."),
        ("8.25", "Secure development life cycle", "Rules for secure development of software and systems are applied."),
        ("8.26", "Application security requirements", "Security requirements are identified when developing or acquiring applications."),
        ("8.27", "Secure system architecture and engineering principles", "Secure engineering principles are documented and applied."),
        ("8.28", "Secure coding", "Secure coding principles are applied."),
        ("8.29", "Security testing in development and acceptance", "Security testing is defined and carried out in the development life cycle."),
        ("8.30", "Outsourced development", "Outsourced development is directed, monitored and reviewed."),
        ("8.31", "Separation of development, test and production environments", "Environments are separated and secured."),
        ("8.32", "Change management", "Changes to facilities and systems follow change management."),
        ("8.33", "Test information", "Test information is selected, protected and managed."),
        ("8.34", "Protection of information systems during audit testing", "Audit testing is planned and agreed to limit operational impact."),
    ],
}

AUTO_CHECKS = {
    "A.5.7": "threat_intel", "A.5.9": "asset_inventory", "A.5.10": "policy_acknowledgement", "A.5.11": "return_of_assets", "A.5.12": "classification", "A.5.13": "labelling", "A.8.1": "agent_coverage", "A.8.5": "secure_auth",
    "A.8.7": "agent_coverage", "A.8.8": "vuln_sla", "A.8.9": "config_baseline", "A.8.15": "logging",
    "A.8.16": "monitoring", "A.8.19": "patching", "A.8.20": "network_security", "A.8.22": "segregation",
    "A.8.24": "cryptography", "A.8.28": "secure_coding", "A.8.29": "security_testing", "C9.1": "measurement",
    "C6.1.2": "risk_register", "C4.4": "isms_operation", "C5.1": "documented_information", "C5.2": "policy_acknowledgement", "C5.3": "roles_assigned", "C7.5": "documented_information",
    "C6.1.1": "risks_and_opportunities", "C6.1.3": "risk_treatment", "C8.2": "risk_assessment", "C8.3": "risk_treatment",
    "A.5.19": "supplier_register", "A.5.20": "supplier_agreements", "A.5.22": "supplier_register", "A.5.36": "exceptions_current", "C6.2": "objectives",
    "C6.3": "isms_changes", "A.8.32": "change_management", "C7.1": "resources", "C7.2": "competence", "C7.3": "awareness", "A.6.3": "awareness", "C7.4": "communication", "C8.1": "operation", "C9.2": "internal_audit", "C9.3": "management_review", "C10.1": "improvement", "C10.2": "nonconformity", "A.5.1": "policies", "A.5.2": "roles_assigned", "A.5.3": "change_management", "A.5.4": "policy_acknowledgement", "A.5.5": "authority_contacts", "A.5.6": "interest_groups", "A.5.8": "isms_changes", "A.8.25": "code_review", "A.5.37": "isms_sync",
}


def _sort_key(ref):
    pre, _, num = ref.partition(".") if ref.startswith("A.") else ("C", "", ref.lstrip("C"))
    parts = num.split(".") if pre == "A" else ref.lstrip("C").split(".")
    return ("1" if pre == "A" else "0") + "".join(f"{int(p):03d}" for p in parts)


def seed():
    fw, _ = ComplianceFramework.objects.get_or_create(code=CODE, defaults={
        "name": "ISO/IEC 27001:2022", "version": "2022",
        "description": "Information security, cybersecurity and privacy protection — ISMS requirements (clauses 4-10) and Annex A controls."})
    rows = [(f"C{r}", t, "Clause", s) for r, t, s in CLAUSES]
    for cat, items in ANNEX_A.items():
        rows += [(f"A.{r}", t, cat, s) for r, t, s in items]
    for ref, title, cat, summary in rows:
        c, _ = ComplianceControl.objects.update_or_create(framework=fw, ref=ref, defaults={
            "title": title, "category": cat, "summary": summary, "sort_key": _sort_key(ref), "auto_check": AUTO_CHECKS.get(ref, "")})
        ControlImplementation.objects.get_or_create(control=c, defaults={"auto_status": "unknown" if c.auto_check else "na"})
    return fw


# ---------------------------------------------------------------------------
# Automated checks: each returns (result, detail, metrics). result: pass | warn | fail
# ---------------------------------------------------------------------------
def _connector(kind):
    return Connector.objects.filter(kind=kind, enabled=True).order_by("-last_success_at").first()


def _last_stats(kind):
    c = _connector(kind)
    run = c.runs.filter(status__in=["ok", "warning"]).first() if c else None
    return c, (run.stats if run else {})


def _open_tagged(tags):
    from orasec.models import Finding  # noqa: PLC0415
    return Finding.objects.filter(active=True, duplicate=False, tags__name__in=tags).distinct().count()


def check_threat_intel():
    feeds = {f.name: f for f in IntelFeed.objects.all()}
    fresh = [n for n in ("kev", "epss") if n in feeds and feeds[n].status == "ok" and feeds[n].last_refreshed
             and timezone.now() - feeds[n].last_refreshed < datetime.timedelta(hours=48)]
    m = {n: {"status": f.status, "records": f.records, "refreshed": f.last_refreshed.isoformat() if f.last_refreshed else None} for n, f in feeds.items()}
    if len(fresh) == 2:
        return "pass", f"CISA KEV ({feeds['kev'].records} entries) and EPSS ({feeds['epss'].records} CVEs) refreshed in the last 48 h and applied to findings.", m
    return ("warn" if fresh else "fail"), f"Fresh feeds: {', '.join(fresh) or 'none'} — expected KEV and EPSS within 48 h.", m


def check_asset_inventory():
    """A.5.9: every in-scope asset has an owner and the automatic sources keep the list current."""
    from orasec.posture import asset_inventory as ai  # noqa: PLC0415
    rs = ai.rows(InventoryAsset.objects.filter(retired=False))
    total = len(rs)
    kinds = set(Connector.objects.filter(enabled=True).values_list("kind", flat=True))
    unowned = [r["name"] for r in rs if not r["owners"]]
    stale = [r["name"] for r in rs if r["stale"]]
    auto = [r for r in rs if r["sources"] != "manual"]
    cats = sorted({r["category_label"] for r in rs})
    m = {"assets": total, "auto_synced": len(auto), "manual": total - len(auto), "unowned": unowned[:20],
         "stale": stale[:20], "categories": cats, "sources": sorted(kinds), "page": "/orasec/assets/"}
    if total == 0:
        return "fail", "No assets in the inventory; connect at least one inventory source.", m
    if unowned:
        return "fail", f"{len(unowned)} of {total} assets have no owner (e.g. {', '.join(unowned[:3])}).", m
    if stale:
        return "warn", f"All {total} assets have an owner, but {len(stale)} automatically synced asset(s) were not seen for over {ai.STALE_DAYS} days.", m
    if len(kinds) < 2:
        return "warn", f"All {total} assets have an owner; only {len(kinds)} automatic source is connected.", m
    return "pass", (f"{total} assets ({len(auto)} kept current by {len(kinds)} automatic sources, {total - len(auto)} recorded by hand), "
                    f"all with an owner, none stale. Groups: {', '.join(cats)}."), m


def check_return_of_assets():
    """A.5.11: every leaver or mover has a record (LVR-); devices, access and asset ownership are handed back within
    the due date and signed off by someone other than the leaver."""
    from django.contrib.auth import get_user_model  # noqa: PLC0415

    from orasec.posture.grc_models import LeaverRecord  # noqa: PLC0415
    recs = list(LeaverRecord.objects.select_related("person"))
    open_ = [r for r in recs if r.status == "open"]
    overdue = [r.ref for r in open_ if r.overdue]
    covered = {r.person_id for r in recs}
    inactive = list(get_user_model().objects.filter(is_active=False, is_superuser=False)
                    .exclude(id__in=covered).filter(last_login__isnull=False).values_list("username", flat=True)[:20])
    flagged = InventoryAsset.objects.filter(retired=False, attributes__has_key="needs_new_owner").count()
    m = {"records": len(recs), "open": [r.ref for r in open_], "overdue": overdue,
         "deactivated_without_record": inactive, "assets_needing_owner": flagged, "page": "/orasec/leavers/"}
    if overdue:
        return "fail", f"Leaver checklist overdue: {', '.join(overdue)}.", m
    if inactive:
        return "warn", f"{len(inactive)} deactivated account(s) have no leaver record: {', '.join(inactive[:5])}.", m
    if open_:
        return "warn", f"{len(open_)} leaver record(s) in progress ({', '.join(r.ref for r in open_)}); {flagged} asset(s) need a new owner.", m
    if not recs:
        return "pass", "Leaver process in place (PRC-001 / FRM-002); deactivating an account opens a leaver record automatically. No leavers yet.", m
    return "pass", f"{len(recs)} leaver record(s), all signed off by someone other than the leaver; no asset left without an owner.", m


def check_classification():
    """A.5.12: every in-scope asset carries a classification level from POL-010, and every Restricted or
    Confidential asset has an owner."""
    from orasec.posture import asset_inventory as ai  # noqa: PLC0415
    rs = ai.rows(InventoryAsset.objects.filter(retired=False))
    from collections import Counter  # noqa: PLC0415
    by = Counter(r["classification"] for r in rs)
    manual = sum(1 for r in rs if r["classification_set"])
    high_unowned = [r["name"] for r in rs if r["classification_key"] in ("restricted", "confidential") and not r["owners"]]
    m = {"assets": len(rs), "by_level": dict(by), "set_by_hand": manual, "restricted_or_confidential_unowned": high_unowned[:20],
         "page": "/orasec/assets/list/"}
    if not rs:
        return "fail", "No assets to classify.", m
    if high_unowned:
        return "fail", f"{len(high_unowned)} Restricted/Confidential asset(s) have no owner: {', '.join(high_unowned[:3])}.", m
    return "pass", (f"All {len(rs)} assets classified under POL-010 (" + ", ".join(f"{k} {v}" for k, v in by.items())
                    + f"); {manual} set by hand, the rest by default rule; every Restricted/Confidential asset has an owner."), m


def check_labelling():
    """A.5.13: classification is marked by the three means in POL-010 s4.2 -- policy-library documents carry a
    classification in their header, OraSec evidence items carry a classification label, and uploaded Restricted or
    Confidential evidence files carry the level in the file name."""
    import os  # noqa: PLC0415

    from orasec.posture.models import ControlEvidence  # noqa: PLC0415
    ev = list(ControlEvidence.objects.all().only("id", "title", "classification", "file"))
    by = {}
    for e in ev:
        by[e.classification] = by.get(e.classification, 0) + 1
    bad_files = [e.title for e in ev if e.file and e.classification in ("restricted", "confidential")
                 and e.classification.upper() not in os.path.basename(e.file.name).upper()]
    docs = None
    try:
        from orasec.posture import isms_docs  # noqa: PLC0415
        fms = isms_docs.read_documents() if hasattr(isms_docs, "read_documents") else None
        if fms is not None:
            docs = {"total": len(fms), "unlabelled": [f.get("document_id") for f in fms if not f.get("classification")][:10]}
    except Exception:  # noqa: BLE001 -- policy tool unreachable: judge the OraSec side only
        docs = None
    m = {"evidence": len(ev), "by_level": by, "file_names_missing_level": bad_files[:20], "documents": docs,
         "policy": "POL-010 s4.2"}
    if docs and docs["unlabelled"]:
        return "fail", f"Policy documents without a classification header: {', '.join(map(str, docs['unlabelled'][:5]))}.", m
    if bad_files:
        return "warn", f"{len(bad_files)} Restricted/Confidential evidence file(s) lack the level in the file name (e.g. {bad_files[0]}).", m
    return "pass", (f"All {len(ev)} evidence items carry a classification label (" + ", ".join(f"{k} {v}" for k, v in sorted(by.items()))
                    + ")" + (f"; all {docs['total']} policy documents carry a classification header" if docs else "") + "."), m


def check_agent_coverage():
    _, st = _last_stats("wazuh")
    if not st:
        return "fail", "Wazuh connector has not completed a run.", {}
    total, active = st.get("agents_total", 0), st.get("agents_active", 0)
    servers = InventoryAsset.objects.filter(retired=False, asset_type="server").count()
    m = {"agents_total": total, "agents_active": active, "inventory_servers": servers}
    if total and active == total and active >= servers:
        return "pass", f"All {active} Wazuh agents active (endpoint protection, FIM and malware/rootcheck).", m
    return ("warn" if active else "fail"), f"{active}/{total} Wazuh agents active; {servers} servers in inventory.", m


def check_secure_auth():
    _, st = _last_stats("opnsense")
    no_otp = st.get("users_without_otp")
    if no_otp is None:
        return "warn", "OPNsense account data not available yet.", {}
    m = {"opnsense_users_without_otp": no_otp}
    return ("pass", "All enabled firewall accounts have TOTP.", m) if not no_otp else ("fail", f"Firewall accounts without MFA: {', '.join(no_otp)}.", m)


def check_vuln_sla():
    today = timezone.now().date()
    base = FindingPriority.objects.filter(finding__active=True, finding__duplicate=False)
    overdue = base.filter(due_date__lt=today)
    urgent_over = overdue.filter(band__in=["Urgent", "Needs Action"]).count()
    kev_over = overdue.filter(finding__known_exploited=True).count()
    total = base.count()
    m = {"active_prioritised": total, "overdue": overdue.count(), "overdue_urgent_or_needs_action": urgent_over, "kev_overdue": kev_over}
    if total == 0:
        return "warn", "No prioritised findings yet.", m
    if kev_over == 0 and urgent_over == 0:
        return "pass", f"No Urgent/Needs-Action or KEV findings past their SLA ({total} active findings tracked).", m
    if kev_over == 0 and urgent_over <= max(5, total * 0.02):
        return "warn", f"{urgent_over} Urgent/Needs-Action findings past SLA.", m
    return "fail", f"{urgent_over} Urgent/Needs-Action findings and {kev_over} known-exploited findings past SLA.", m


def check_config_baseline():
    _, st = _last_stats("wazuh")
    sca = st.get("sca") or {}
    scores = [v.get("score") for v in sca.values() if v.get("score") is not None]
    if not scores:
        return "warn", "No Wazuh SCA results yet.", {}
    avg = sum(scores) / len(scores)
    m = {"policies": len(scores), "average_score": round(avg, 1), "failed_checks": st.get("sca_failed")}
    if avg >= 80:
        return "pass", f"Average CIS/SCA hardening score {avg:.0f}% across {len(scores)} policies.", m
    return ("warn" if avg >= 60 else "fail"), f"Average CIS/SCA hardening score {avg:.0f}% ({st.get('sca_failed')} failed checks).", m


def check_logging():
    c, st = _last_stats("wazuh")
    if not st:
        return "fail", "Wazuh connector has not completed a run.", {}
    disc = st.get("agents_disconnected", 0) + st.get("agents_never_connected", 0)
    m = {"agents_active": st.get("agents_active"), "agents_not_reporting": disc}
    return ("pass", f"{st.get('agents_active')} agents shipping logs to the SIEM; none disconnected.", m) if disc == 0 else \
           ("warn", f"{disc} agent(s) not reporting logs.", m)


def check_monitoring():
    c, st = _last_stats("wazuh")
    if not c or not c.last_success_at:
        return "fail", "SIEM connector has never succeeded.", {}
    age = timezone.now() - c.last_success_at
    m = {"alerts_24h": st.get("alerts_24h"), "alerts_24h_high": st.get("alerts_24h_high"), "last_success": c.last_success_at.isoformat()}
    if age < datetime.timedelta(hours=26) and (st.get("alerts_24h") or 0) > 0:
        return "pass", f"SIEM processed {st.get('alerts_24h')} alerts in 24 h ({st.get('alerts_24h_high')} high).", m
    return "warn", "SIEM data is stale or no alerts were received in 24 h.", m


def check_patching():
    _, st = _last_stats("patchmon")
    if not st:
        return "warn", "PatchMon connector has not completed a run.", {}
    m = {k: st.get(k) for k in ("hosts", "security_updates", "updates", "stale", "needs_reboot")}
    if not st.get("security_updates") and not st.get("stale"):
        return "pass", f"{st.get('hosts')} hosts reporting; no outstanding security updates.", m
    return ("warn" if st.get("security_updates", 0) < 20 else "fail"), \
        f"{st.get('security_updates')} outstanding security updates; {st.get('stale')} host(s) not reporting.", m


def check_network_security():
    n = _open_tagged(["network-security", "firewall"])
    fw = _open_tagged(["firmware"])
    m = {"open_firewall_policy_findings": n, "open_firmware_findings": fw,
         "network_connectors": list(Connector.objects.filter(kind__in=["opnsense", "unifi"], enabled=True).values_list("name", flat=True))}
    if not m["network_connectors"]:
        return "warn", "No firewall/network connector configured.", m
    if n == 0 and fw == 0:
        return "pass", "No permissive firewall policies and network-device firmware is current.", m
    return ("fail" if n else "warn"), f"{n} permissive firewall finding(s); {fw} firmware update(s) outstanding.", m


def check_segregation():
    _, st = _last_stats("unifi")
    nets = [n for n in (st.get("networks") or []) if n.get("enabled", True)]
    m = {"networks": [(n.get("name"), n.get("vlanId")) for n in nets]}
    if not st:
        return "warn", "UniFi connector has not completed a run.", m
    return ("pass", f"{len(nets)} segregated networks/VLANs configured.", m) if len(nets) >= 2 else ("warn", "Only one network configured.", m)


def check_cryptography():
    n = _open_tagged(["crypto", "certificate"])
    m = {"open_crypto_findings": n}
    return ("pass", "No expiring certificates or weak Wi-Fi encryption found.", m) if n == 0 else ("warn", f"{n} cryptography finding(s) open.", m)


def _scan_age(type_names):
    from orasec.models import Test  # noqa: PLC0415
    t = Test.objects.filter(test_type__name__in=type_names).order_by("-updated").first()
    return (timezone.now() - t.updated).days if t and t.updated else None


def check_secure_coding():
    from orasec.models import Finding  # noqa: PLC0415
    secrets = Finding.objects.filter(active=True, duplicate=False, test__test_type__name="Gitleaks Scan").count()
    high = Finding.objects.filter(active=True, duplicate=False, severity__in=["Critical", "High"],
                                  test__test_type__name__in=["Semgrep JSON Report", "Trivy Scan"]).count()
    m = {"open_secrets": secrets, "open_sast_sca_critical_high": high, "sast_age_days": _scan_age(["Semgrep JSON Report"])}
    if m["sast_age_days"] is None:
        return "fail", "No SAST results imported.", m
    if secrets == 0 and high == 0:
        return "pass", "No leaked secrets or Critical/High SAST/SCA findings open.", m
    return ("fail" if secrets else "warn"), f"{secrets} leaked secret(s); {high} Critical/High SAST/dependency findings open.", m


def check_security_testing():
    ages = {"SAST": _scan_age(["Semgrep JSON Report"]), "DAST": _scan_age(["ZAP Scan"]), "SCA": _scan_age(["Trivy Scan"]),
            "Secrets": _scan_age(["Gitleaks Scan"])}
    stale = [k for k, v in ages.items() if v is None or v > 14]
    m = {"days_since_last": ages}
    return ("pass", "SAST, DAST, dependency and secret scans all ran within 14 days.", m) if not stale else \
           (("warn" if len(stale) < 3 else "fail"), f"Stale or missing: {', '.join(stale)}.", m)


def check_measurement():
    n = PostureSnapshot.objects.filter(date__gte=timezone.now().date() - datetime.timedelta(days=7)).count()
    return ("pass", f"Posture measured on {n} of the last 7 days.", {"snapshots_7d": n}) if n >= 5 else \
           ("warn", f"Posture measured on {n} of the last 7 days.", {"snapshots_7d": n})


def check_risk_register():
    from orasec.posture.models import RiskRegisterEntry  # noqa: PLC0415
    qs = RiskRegisterEntry.objects.exclude(status="closed")
    overdue = qs.filter(review_date__lt=timezone.now().date()).count()
    m = {"open_risks": qs.count(), "review_overdue": overdue, "without_owner": qs.filter(owner=None).count()}
    if not qs.exists():
        return "fail", "The risk register is empty.", m
    return ("pass", f"{m['open_risks']} risks registered with owners and current reviews.", m) if overdue == 0 and m["without_owner"] == 0 else \
           ("warn", f"{overdue} risk review(s) overdue; {m['without_owner']} without an owner.", m)


def check_isms_operation():
    """ISMS is operating: posture measured daily and the SGC monthly check recorded within 35 days."""
    from orasec.posture.models import ControlEvidence  # noqa: PLC0415
    today = timezone.now().date()
    snap = PostureSnapshot.objects.filter(date__gte=today - datetime.timedelta(days=2)).exists()
    last = ControlEvidence.objects.filter(title__istartswith="SGC monthly check").order_by("-collected_at").first()
    sgc_ok = bool(last and last.collected_at.date() >= today - datetime.timedelta(days=35))
    m = {"posture_measured_last_2_days": snap, "last_sgc_monthly_check": last.collected_at.date().isoformat() if last else None}
    if snap and sgc_ok:
        return "pass", f"Posture measured daily; SGC monthly check recorded on {m['last_sgc_monthly_check']}.", m
    missing = ([] if snap else ["daily posture measurement"]) + ([] if sgc_ok else ["SGC monthly check in the last 35 days"])
    return ("warn" if snap or sgc_ok else "fail"), "Missing: " + ", ".join(missing) + ".", m


def check_documented_information():
    """Approved policy documents attached as evidence are within their review date."""
    from orasec.posture.models import ControlEvidence  # noqa: PLC0415
    today = timezone.now().date()
    pol = ControlEvidence.objects.filter(title__istartswith="Policy:").exclude(valid_until=None)
    titles = {}
    for e in pol:
        titles.setdefault(e.title, e.valid_until)
    expired = sorted(t for t, d in titles.items() if d < today)
    soon = sorted(t for t, d in titles.items() if today <= d < today + datetime.timedelta(days=30))
    m = {"policies": len(titles), "past_review": expired, "review_within_30_days": soon}
    if not titles:
        return "warn", "No policy documents attached as evidence yet.", m
    if expired:
        return "fail", f"{len(expired)} of {len(titles)} policy documents are past their review date.", m
    if soon:
        return "warn", f"{len(soon)} policy document(s) due for review within 30 days.", m
    return "pass", f"All {len(titles)} policy documents are within their review date.", m


# Team roles that must sign FRM-015 Policy Acknowledgement every 12 months.
ACK_ROLES = ["CTO", "Cloud Infrastructure Engineer", "Compliance Officer"]


def check_policy_acknowledgement():
    """Every team role has a signed FRM-015 Policy Acknowledgement from the last 12 months.
    Evidence title format: 'Policy acknowledgement: <role> - <policy version> (<date>)'."""
    from orasec.posture.models import ControlEvidence  # noqa: PLC0415
    today = timezone.now().date()
    year_ago, soon = today - datetime.timedelta(days=365), today + datetime.timedelta(days=30)
    latest = {}
    for role in ACK_ROLES:
        e = (ControlEvidence.objects.filter(title__istartswith=f"Policy acknowledgement: {role}")
             .order_by("-collected_at").first())
        latest[role] = e.collected_at.date() if e else None
    missing = [r for r, d in latest.items() if not d or d < year_ago]
    expiring = [r for r, d in latest.items() if d and d >= year_ago and d + datetime.timedelta(days=365) <= soon]
    m = {"roles": len(ACK_ROLES), "signed": {r: (d.isoformat() if d else None) for r, d in latest.items()}}
    if not missing and not expiring:
        return "pass", f"All {len(ACK_ROLES)} team roles have signed the policy acknowledgement in the last 12 months.", m
    if len(missing) == len(ACK_ROLES):
        return "fail", "No signed policy acknowledgement in the last 12 months for: " + ", ".join(missing) + ".", m
    parts = ([f"missing or older than 12 months: {', '.join(missing)}"] if missing else []) + \
            ([f"due for renewal within 30 days: {', '.join(expiring)}"] if expiring else [])
    return "warn", "Policy acknowledgement " + "; ".join(parts) + ".", m


# Accounts that run automation, not people. They must never own a control.
SERVICE_ACCOUNTS = {"orasec-automation"}


def check_roles_assigned():
    """Every applicable control has an active, personal owner and a review date that has not passed."""
    today = timezone.now().date()
    qs = ControlImplementation.objects.select_related("control", "owner").filter(applicable=True).exclude(status="not_applicable")
    total = qs.count()
    no_owner = [i.control.ref for i in qs if not i.owner_id or not i.owner.is_active or i.owner.username in SERVICE_ACCOUNTS]
    no_review = [i.control.ref for i in qs if not i.review_due]
    overdue = [i.control.ref for i in qs if i.review_due and i.review_due < today]
    owners = {}
    for i in qs:
        if i.owner_id:
            owners[i.owner.get_full_name() or i.owner.username] = owners.get(i.owner.get_full_name() or i.owner.username, 0) + 1
    m = {"controls": total, "without_personal_owner": len(no_owner), "without_review_date": len(no_review),
         "review_overdue": len(overdue), "owners": owners}
    if no_owner:
        return "fail", f"{len(no_owner)} of {total} controls have no personal owner (e.g. {', '.join(no_owner[:5])}).", m
    if no_review or overdue:
        parts = ([f"{len(no_review)} without a review date"] if no_review else []) + ([f"{len(overdue)} past their review date"] if overdue else [])
        return "warn", f"All {total} controls have a personal owner; " + " and ".join(parts) + ".", m
    return "pass", f"All {total} controls have a personal owner and a current review date.", m


# ---------------------------------------------------------------------------
# GRC checks: risk assessment, treatment, opportunities, suppliers, exceptions
# ---------------------------------------------------------------------------
def check_risk_assessment():
    """An approved risk assessment of the organisation's own risks within the last 12 months (ISO 27001 8.2)."""
    from orasec.posture.grc_models import RiskAssessment  # noqa: PLC0415
    today = timezone.now().date()
    last = RiskAssessment.objects.filter(status="approved").order_by("-assessed_on").first()
    pending = RiskAssessment.objects.filter(status="submitted").count()
    m = {"last_approved": last.assessed_on.isoformat() if last else None, "awaiting_approval": pending}
    if not last:
        return ("warn" if pending else "fail"), ("Risk assessment awaiting Director approval." if pending else "No approved risk assessment."), m
    if last.assessed_on < today - datetime.timedelta(days=365):
        return "fail", f"Last approved risk assessment {last.ref} is older than 12 months ({last.assessed_on:%d %b %Y}).", m
    if last.next_assessment and last.next_assessment <= today + datetime.timedelta(days=30):
        return "warn", f"{last.ref} approved; next assessment due {last.next_assessment:%d %b %Y}.", m
    return "pass", f"{last.ref} approved {last.decided_at:%d %b %Y} with {last.risks.count()} risks; next due {last.next_assessment:%d %b %Y}.", m


def check_risk_treatment():
    """Every open risk has an owner, a treatment plan and a current review date; Critical risks are under treatment."""
    from orasec.posture.models import RiskRegisterEntry  # noqa: PLC0415
    today = timezone.now().date()
    qs = list(RiskRegisterEntry.objects.exclude(status="closed"))
    gaps = [r.ref for r in qs if not r.owner_id or not r.treatment_plan or not r.review_date]
    overdue = [r.ref for r in qs if r.review_date and r.review_date < today]
    crit_open = [r.ref for r in qs if r.inherent_score >= 20 and r.status == "open"]
    m = {"open_risks": len(qs), "incomplete": len(gaps), "review_overdue": len(overdue), "critical_not_in_treatment": len(crit_open)}
    if not qs:
        return "fail", "The risk register has no open or treated risks.", m
    if crit_open:
        return "fail", "Critical risk(s) not under treatment: " + ", ".join(crit_open) + ".", m
    if gaps or overdue:
        parts = ([f"{len(gaps)} without owner, plan or review date"] if gaps else []) + ([f"{len(overdue)} review(s) overdue"] if overdue else [])
        return "warn", "Risk treatment: " + "; ".join(parts) + ".", m
    return "pass", f"All {len(qs)} open risks have an owner, a treatment plan and a current review date.", m


def check_risks_and_opportunities():
    """Risks and opportunities are both determined and recorded (ISO 27001 6.1.1)."""
    from orasec.posture.grc_models import Opportunity  # noqa: PLC0415
    from orasec.posture.models import RiskRegisterEntry  # noqa: PLC0415
    risks = RiskRegisterEntry.objects.exclude(status="closed").count()
    opps = Opportunity.objects.exclude(status="dropped").count()
    m = {"open_risks": risks, "opportunities": opps}
    if risks and opps:
        return "pass", f"{risks} risks and {opps} opportunities recorded.", m
    missing = ([] if risks else ["risks"]) + ([] if opps else ["opportunities"])
    return ("warn" if risks or opps else "fail"), "Not recorded: " + " and ".join(missing) + ".", m


def check_supplier_register():
    """Every current supplier has an approved assessment and an annual review that is not overdue (A.5.19, A.5.22)."""
    from orasec.posture.grc_models import Supplier  # noqa: PLC0415
    today = timezone.now().date()
    sup = list(Supplier.objects.exclude(status="exited"))
    unassessed = [s.name for s in sup if not s.approved_assessment]
    overdue = [s.name for s in sup if s.approved_assessment and (not s.next_review or s.next_review < today)]
    m = {"suppliers": len(sup), "without_approved_assessment": len(unassessed), "review_overdue": len(overdue),
         "critical": sum(1 for s in sup if s.tier == "critical")}
    if not sup:
        return "fail", "The supplier register is empty.", m
    if unassessed or overdue:
        parts = ([f"{len(unassessed)} of {len(sup)} without an approved assessment"] if unassessed else []) + \
                ([f"{len(overdue)} annual review(s) overdue"] if overdue else [])
        crit = [s.name for s in sup if s.tier == "critical" and not s.approved_assessment]
        return ("fail" if crit else "warn"), "Suppliers: " + "; ".join(parts) + (f" (Critical: {', '.join(crit[:4])})" if crit else "") + ".", m
    return "pass", f"All {len(sup)} suppliers have an approved assessment and a current review.", m


def check_supplier_agreements():
    """Critical and High suppliers have contract terms recorded and breach notification confirmed (A.5.20)."""
    from orasec.posture.grc_models import Supplier  # noqa: PLC0415
    sup = list(Supplier.objects.exclude(status="exited").filter(tier__in=["critical", "high"]))
    gaps = [s.name for s in sup if not s.contract.strip() or not s.breach_notification]
    m = {"critical_high": len(sup), "missing_terms": len(gaps)}
    if not sup:
        return "fail", "No Critical or High suppliers recorded.", m
    if gaps:
        return ("fail" if len(gaps) == len(sup) else "warn"), \
            f"{len(gaps)} of {len(sup)} Critical/High suppliers lack recorded terms or confirmed breach notification.", m
    return "pass", f"All {len(sup)} Critical/High suppliers have terms and breach notification recorded.", m


def check_exceptions_current():
    """No expired exception is still relied on, and none waits more than 10 days for a decision (A.5.36)."""
    from orasec.posture.grc_models import GovernanceException  # noqa: PLC0415
    today = timezone.now().date()
    qs = GovernanceException.objects.all()
    expired = qs.filter(status__in=["approved", "expired"], expiry__lt=today).count()
    stale = qs.filter(status="requested", requested_at__date__lt=today - datetime.timedelta(days=10)).count()
    active = qs.filter(status="approved", expiry__gte=today).count()
    m = {"active": active, "expired_not_closed": expired, "pending_over_10_days": stale}
    if expired or stale:
        return "warn", f"{expired} expired exception(s) not closed; {stale} request(s) waiting over 10 days.", m
    return "pass", f"{active} active exception(s), all within their expiry; no overdue requests.", m



def check_objectives():
    """Each security objective has an owner, a plan and a due date, and is measured (ISO 27001 6.2). Measures them first."""
    from orasec.posture.objectives import measure_all  # noqa: PLC0415
    objs = measure_all()
    if not objs:
        return "fail", "No security objectives recorded.", {}
    live = [o for o in objs if o.applicable]
    gaps = [o.ref for o in live if not o.owner_id or not o.plan.strip() or not o.due_date]
    counts = {s: sum(1 for o in objs if o.status == s) for s, _ in objs[0].STATUS}
    m = {"objectives": len(objs), **counts, "missing_owner_plan_or_date": gaps}
    summary = (f"{counts['met']} met, {counts['on_track']} on track, {counts['off_track']} off track"
               + (f", {counts['not_applicable']} not applicable yet" if counts["not_applicable"] else ""))
    if gaps:
        return "warn", f"{len(objs)} objectives ({summary}); missing owner, plan or due date: {', '.join(gaps)}.", m
    return "pass", f"{len(objs)} objectives with owners, plans and due dates, measured today: {summary}.", m


def _change_check(category=None):
    """Shared rules for the change register: approved by someone else, approval in time for emergencies and
    after-the-fact records, reviewed within 14 days of being done, no request left waiting over 10 days."""
    from orasec.posture.grc_models import ChangeRequest  # noqa: PLC0415
    now = timezone.now()
    qs = ChangeRequest.objects.exclude(status="cancelled")
    if category:
        qs = qs.filter(category=category)
    items = list(qs.select_related("requested_by", "approved_by"))
    year = [c for c in items if c.requested_at >= now - datetime.timedelta(days=365)]
    late_approval = [c.ref for c in items if c.approval_overdue]
    pending_approval = [c.ref for c in items if c.status == "implemented" and not c.approved_by_id and not c.approval_overdue]
    review_overdue = [c.ref for c in items if c.review_overdue]
    stale = [c.ref for c in items if c.status == "submitted" and c.requested_at < now - datetime.timedelta(days=10)]
    self_approved = [c.ref for c in items if c.approved_by_id and c.approved_by_id == c.requested_by_id and not c.imported]
    m = {"changes_12_months": len(year), "closed": sum(1 for c in items if c.status == "closed"),
         "open": sum(1 for c in items if c.status in ("submitted", "approved", "implemented")),
         "approval_overdue": late_approval, "awaiting_approval_after_change": pending_approval,
         "review_overdue": review_overdue, "waiting_over_10_days": stale, "approved_by_requester": self_approved,
         "imported_history": sum(1 for c in items if c.imported)}
    return items, year, m


def check_change_management():
    """Every IT and ISMS change is raised, approved by someone other than the requester, and reviewed (A.8.32)."""
    items, year, m = _change_check()
    if not items:
        return "warn", "No changes recorded in the Change Register yet.", m
    if m["approval_overdue"] or m["approved_by_requester"]:
        return "fail", (f"Changes made without approval in time: {', '.join(m['approval_overdue']) or 'none'}; "
                        f"approved by the requester: {', '.join(m['approved_by_requester']) or 'none'}."), m
    late = m["review_overdue"] + m["waiting_over_10_days"] + m["awaiting_approval_after_change"]
    if late:
        return "warn", (f"{len(year)} change(s) in 12 months. Needs attention: {', '.join(late)} "
                        "(approval after the change, review overdue, or waiting over 10 days)."), m
    return "pass", f"{len(year)} change(s) in 12 months, {m['closed']} reviewed and closed; all approved by someone other than the requester.", m


def check_isms_changes():
    """Changes to the ISMS are planned: why, consequences, resources and owner recorded, approved, reviewed (6.3)."""
    items, year, m = _change_check("isms")
    if not items:
        return "warn", "No ISMS changes recorded. Record changes to scope, policies, roles, risk method or objectives in the Change Register.", m
    unplanned = [c.ref for c in items if not (c.reason.strip() and c.impact.strip() and c.resources.strip() and c.owner_id)]
    m["missing_why_consequences_resources_or_owner"] = unplanned
    if m["approval_overdue"] or m["approved_by_requester"]:
        return "fail", (f"ISMS changes made without approval in time: {', '.join(m['approval_overdue']) or 'none'}; "
                        f"approved by the person who raised them: {', '.join(m['approved_by_requester']) or 'none'}."), m
    late = unplanned + m["review_overdue"] + m["waiting_over_10_days"] + m["awaiting_approval_after_change"]
    if late:
        return "warn", f"{len(year)} ISMS change(s) in 12 months. Needs attention: {', '.join(dict.fromkeys(late))}.", m
    return "pass", (f"{len(year)} ISMS change(s) in 12 months, each planned (reason, consequences, resources, owner) and approved "
                    f"before or on time; {m['closed']} reviewed and closed, {m['open']} in progress."), m


def check_resources():
    """Resources for the ISMS (7.1): the three roles are filled, ISMS changes record the resources they need,
    and a resources review is recorded on C7.1 at least every 13 months.
    Evidence title format: 'Resources review - <month year>'."""
    from django.contrib.auth import get_user_model  # noqa: PLC0415
    from orasec.posture.models import ControlEvidence  # noqa: PLC0415
    from orasec.posture.grc_models import ChangeRequest  # noqa: PLC0415
    users = get_user_model().objects.filter(is_active=True).exclude(username__in=SERVICE_ACCOUNTS)
    roles = {
        "Director": users.filter(groups__name="Director").exists(),
        "Cloud Infrastructure Engineer": users.filter(is_superuser=True).exclude(groups__name="Director").exists(),
        "Compliance Officer": users.filter(groups__name="Compliance Officer").exists(),
    }
    since = timezone.now() - datetime.timedelta(days=365)
    no_resources = [c.ref for c in ChangeRequest.objects.filter(category="isms", requested_at__gte=since, imported=False)
                    .exclude(status="cancelled") if not c.resources.strip()]
    review = (ControlEvidence.objects.filter(title__istartswith="Resources review", collected_at__gte=timezone.now()
              - datetime.timedelta(days=396)).order_by("-collected_at").first())
    empty = [r for r, ok in roles.items() if not ok]
    m = {"roles_filled": roles, "isms_changes_without_resources": no_resources,
         "last_resources_review": review.collected_at.date().isoformat() if review else None}
    if empty:
        return "fail", "Role(s) with no active person: " + ", ".join(empty) + ".", m
    gaps = ([f"ISMS changes with no resources recorded: {', '.join(no_resources)}"] if no_resources else []) + \
           ([] if review else ["no resources review recorded in the last 13 months (add evidence titled 'Resources review - <month year>')"])
    if gaps:
        return "warn", "All three roles are filled; " + "; ".join(gaps) + ".", m
    return "pass", (f"All three roles are filled, every ISMS change records its resources, and the last resources review "
                    f"was on {m['last_resources_review']}."), m


COMPETENCE_ROLES = ["Director/CTO", "Cloud Infrastructure Engineer", "Compliance Officer"]


def check_competence():
    """Competence (7.2): each security role has a competence record (role requirements met or gaps with training
    actions) from the last 13 months. Evidence title format: 'Competence record: <role> - <name> (<date>)'."""
    from orasec.posture.models import ControlEvidence  # noqa: PLC0415
    cutoff = timezone.now() - datetime.timedelta(days=396)
    latest = {}
    for role in COMPETENCE_ROLES:
        e = (ControlEvidence.objects.filter(title__istartswith=f"Competence record: {role}")
             .order_by("-collected_at").first())
        latest[role] = e.collected_at if e else None
    missing = [r for r, d in latest.items() if not d or d < cutoff]
    m = {"roles": len(COMPETENCE_ROLES), "last_record": {r: (d.date().isoformat() if d else None) for r, d in latest.items()}}
    if not missing:
        return "pass", f"All {len(COMPETENCE_ROLES)} security roles have a competence record from the last 13 months.", m
    if len(missing) == len(COMPETENCE_ROLES):
        return "fail", "No competence record in the last 13 months for: " + ", ".join(missing) + ".", m
    return "warn", "Competence record missing or older than 13 months for: " + ", ".join(missing) + ".", m

def check_awareness():
    """Awareness (7.3) and training (A.6.3): the annual security awareness session was held in the last 13 months
    and every team role has signed the policy acknowledgement (FRM-015) in the last 12 months.
    Evidence title format: 'Awareness session - <month year>'."""
    from orasec.posture.models import ControlEvidence  # noqa: PLC0415
    s = (ControlEvidence.objects.filter(title__istartswith="Awareness session",
                                        collected_at__gte=timezone.now() - datetime.timedelta(days=396))
         .order_by("-collected_at").first())
    ack, ack_detail, ack_m = check_policy_acknowledgement()
    m = {"last_session": s.collected_at.date().isoformat() if s else None, "acknowledgements": ack_m.get("signed", {})}
    if not s:
        return "fail", ("No awareness session recorded in the last 13 months (add evidence titled "
                        "'Awareness session - <month year>' with the agenda and attendance)."), m
    if ack != "pass":
        return "warn", f"Awareness session held on {m['last_session']}; {ack_detail}", m
    return "pass", (f"Awareness session held on {m['last_session']} and every team role has signed the policy "
                    "acknowledgement in the last 12 months."), m



def _fetch_security_txt(url):
    import urllib.request  # noqa: PLC0415
    req = urllib.request.Request(url, headers={"User-Agent": "OraSec-compliance-check"})
    with urllib.request.urlopen(req, timeout=15) as r:  # noqa: S310 (fixed https URL)
        return r.status, r.read(20000).decode("utf-8", "replace")


def check_communication():
    """Communication (7.4): the public security contact (security.txt, RFC 9116) is published, has a Contact,
    and its Expires date has not passed (renewed yearly by the Compliance Officer, FWK-001 section 5.6)."""
    from django.conf import settings  # noqa: PLC0415
    from orasec import site as site_profile  # noqa: PLC0415
    url = getattr(settings, "ORASEC_SECURITY_TXT_URL", "") or site_profile.get("security_txt_url") or ""
    m = {"url": url}
    if not url:
        return "warn", "No security.txt address is set (site profile key security_txt_url); the public security contact cannot be checked.", m
    try:
        status, body = _fetch_security_txt(url)
    except Exception as e:  # noqa: BLE001
        m["error"] = f"{e.__class__.__name__}: {e}"
        return "fail", f"security.txt could not be fetched from {url} ({m['error']}).", m
    fields = {}
    for line in body.splitlines():
        k, sep, v = line.partition(":")
        if sep and not line.lstrip().startswith("#"):
            fields.setdefault(k.strip().lower(), v.strip())
    m.update({"status": status, "contact": fields.get("contact"), "expires": fields.get("expires")})
    if status != 200 or not fields.get("contact"):
        return "fail", f"security.txt at {url} has no Contact field (HTTP {status}).", m
    try:
        exp = datetime.datetime.fromisoformat(fields.get("expires", "").replace("Z", "+00:00"))
    except ValueError:
        return "warn", "security.txt is published with a Contact, but its Expires date is missing or not valid.", m
    days = (exp - timezone.now()).days
    m["days_to_expiry"] = days
    if days < 0:
        return "fail", f"security.txt expired on {exp.date().isoformat()}; renew the Expires date.", m
    if days < 30:
        return "warn", f"security.txt expires in {days} days ({exp.date().isoformat()}); renew it.", m
    return "pass", f"security.txt is published with Contact {fields['contact']} and expires on {exp.date().isoformat()}.", m

# Operational processes whose own checks show that planned work is being carried out (8.1).
# The schedule of recurring work is FWK-001 section 5.2; each process keeps its own check.
OPERATION_CONTROLS = {
    "C4.4": "SGC monthly check", "C6.1.3": "Risk treatment", "A.8.8": "Vulnerability remediation within SLA",
    "A.8.19": "Patching", "A.8.32": "Change management", "C6.2": "Security objectives", "A.5.36": "Exceptions",
}


def check_operation():
    """Operational planning and control (8.1): summary of the checks of the processes that run on the schedule in
    FWK-001 section 5.2 (SGC check, risk treatment, vulnerabilities, patching, changes, objectives, exceptions)."""
    rows = {i.control.ref: i for i in ControlImplementation.objects.select_related("control")
            .filter(control__framework__code=CODE, control__ref__in=list(OPERATION_CONTROLS))}
    res = {ref: (rows[ref].auto_status if ref in rows else "unknown") for ref in OPERATION_CONTROLS}
    m = {"processes": {f"{ref} {name}": res[ref] for ref, name in OPERATION_CONTROLS.items()}}
    bad = [f"{OPERATION_CONTROLS[r]} ({r})" for r, v in res.items() if v == "fail"]
    warn = [f"{OPERATION_CONTROLS[r]} ({r})" for r, v in res.items() if v in ("warn", "unknown", "na")]
    if bad:
        return "fail", "Planned work not on track: " + ", ".join(bad) + (("; needs attention: " + ", ".join(warn)) if warn else "") + ".", m
    if warn:
        return "warn", "Needs attention: " + ", ".join(warn) + ".", m
    return "pass", f"All {len(OPERATION_CONTROLS)} operational processes are on track.", m

def _last_record(prefixes, ref):
    from orasec.posture.models import ControlEvidence  # noqa: PLC0415
    q = ControlEvidence.objects.filter(control__ref=ref, control__framework__code=CODE,
                                       collected_at__gte=timezone.now() - datetime.timedelta(days=396))
    hits = [e for e in q.order_by("-collected_at") if any(e.title.lower().startswith(x) for x in prefixes)]
    return hits[0] if hits else None


def check_internal_audit():
    """Internal audit (9.2): an internal audit or review is recorded on C9.2 within the last 13 months.
    Evidence title format: 'Internal audit <month year>: ...' (or 'Internal review ...')."""
    e = _last_record(("internal audit", "internal review"), "C9.2")
    m = {"last_internal_audit": e.collected_at.date().isoformat() if e else None, "title": e.title if e else None}
    if not e:
        return "fail", "No internal audit recorded in the last 13 months (add evidence on C9.2 titled 'Internal audit <month year>: ...').", m
    return "pass", f"Last internal audit or review recorded on {m['last_internal_audit']}.", m


def check_management_review():
    """Management review (9.3): top management reviews the ISMS at least every 13 months (FWK-001 5.2).
    Evidence title format on C9.3: 'Management review - <month year>'."""
    e = _last_record(("management review",), "C9.3")
    m = {"last_management_review": e.collected_at.date().isoformat() if e else None}
    if not e:
        return "fail", "No management review recorded in the last 13 months (add evidence on C9.3 titled 'Management review - <month year>').", m
    return "pass", f"Last management review recorded on {m['last_management_review']}.", m

def check_improvement():
    """Continual improvement (10.1): improvements are tracked in the OraSec opportunity register (OPP-) with an owner,
    an action and a review date, none overdue, and at least one improvement is progressed or closed every 13 months."""
    from orasec.posture.grc_models import Opportunity  # noqa: PLC0415
    today = timezone.localdate()
    opps = list(Opportunity.objects.all())
    live = [o for o in opps if o.status not in ("realised", "dropped")]
    incomplete = [o.ref for o in live if not (o.owner_id and o.action.strip() and o.review_date)]
    overdue = [o.ref for o in live if o.review_date and o.review_date < today]
    recent = [o.ref for o in opps if o.updated >= timezone.now() - datetime.timedelta(days=396)]
    m = {"opportunities": len(opps), "open": len(live), "incomplete": incomplete, "overdue": overdue, "updated_13m": recent}
    if not opps:
        return "fail", "No improvements recorded in the opportunity register.", m
    gaps = ([f"missing owner, action or review date: {', '.join(incomplete)}"] if incomplete else []) + \
           ([f"review date passed: {', '.join(overdue)}"] if overdue else []) + \
           ([] if recent else ["no improvement progressed in the last 13 months"])
    if gaps:
        return "warn", "Improvement register: " + "; ".join(gaps) + ".", m
    return "pass", f"{len(opps)} improvements tracked ({len(live)} open), all owned and on schedule.", m


def check_nonconformity():
    """Nonconformity and corrective action (10.2): every nonconformity in the OraSec register (NC-) has an owner and a
    due date, none is overdue, and closed ones record the cause, corrective action and an independent effectiveness check."""
    from orasec.posture.grc_models import Nonconformity  # noqa: PLC0415
    today = timezone.localdate()
    items = list(Nonconformity.objects.all())
    live = [n for n in items if n.status not in ("closed", "dropped")]
    no_owner = [n.ref for n in live if not (n.owner_id and n.due_date)]
    overdue = [n.ref for n in live if n.due_date and n.due_date < today]
    weak = [n.ref for n in items if n.status == "closed" and not (n.cause.strip() and n.corrective_action.strip()
            and n.effectiveness.strip() and n.verified_by_id and n.verified_by_id != n.owner_id)]
    m = {"total": len(items), "open": len(live), "no_owner_or_due": no_owner, "overdue": overdue, "closed_incomplete": weak}
    if overdue or weak:
        return "fail", "; ".join(([f"overdue: {', '.join(overdue)}"] if overdue else []) +
                                 ([f"closed without cause, action or independent check: {', '.join(weak)}"] if weak else [])) + ".", m
    if no_owner:
        return "warn", f"Missing owner or due date: {', '.join(no_owner)}.", m
    if not items:
        return "pass", "Nonconformity register in place; none recorded yet.", m
    return "pass", f"{len(items)} nonconformities recorded ({len(live)} open), all owned and on time.", m

def check_policies():
    """Policies for information security (A.5.1): the approved policy library (Document Register or a policy file)
    is recorded as evidence on A.5.1 within the last 13 months, and every role has signed the policy acknowledgement.
    Evidence title format on A.5.1: 'Policy: <ID> <title> <version> (<date>)' or 'Document Register ...'."""
    e = _last_record(("policy:", "document register"), "A.5.1")
    ack_status, ack_detail, _ = check_policy_acknowledgement()
    m = {"last_policy_review": e.collected_at.date().isoformat() if e else None, "acknowledgement": ack_status}
    if not e:
        return "fail", "No approved policy library recorded on A.5.1 in the last 13 months.", m
    if ack_status != "pass":
        return "warn", f"Policy library approved on {m['last_policy_review']}; acknowledgement: {ack_detail}", m
    return "pass", f"Policy library approved on {m['last_policy_review']} and acknowledged by every role.", m

def _contact_list(ref, prefix, what):
    e = _last_record((prefix.lower(),), ref)
    m = {"last_reviewed": e.collected_at.date().isoformat() if e else None}
    if not e:
        return "fail", f"No {what} list recorded on {ref} in the last 13 months (add evidence titled '{prefix} - <month year>').", m
    return "pass", f"{what.capitalize()} list reviewed on {m['last_reviewed']}.", m


def check_authority_contacts():
    """Contact with authorities (A.5.5): a list of authorities (who, when to contact, how) reviewed within 13 months.
    Evidence title format on A.5.5: 'Authority contacts - <month year>'."""
    return _contact_list("A.5.5", "Authority contacts", "authority contacts")


def check_interest_groups():
    """Contact with special interest groups (A.5.6): the security groups and advisory feeds followed, reviewed within 13 months.
    Evidence title format on A.5.6: 'Special interest groups - <month year>'."""
    return _contact_list("A.5.6", "Special interest groups", "special interest groups")

CODE_REVIEW_START = datetime.date(2026, 11, 18)  # rule in force from this date (FWK-001 5.3)


def _second_person(reviewers, author):
    return [r for r in reviewers if r != author and r.split(" <")[0] != author]


def check_code_review():
    """Second-person code review (A.8.25, FWK-001 5.3): every commit on the default branch of the reviewed repos
    in the last 30 days carries a 'Reviewed-by: <name>' line naming someone other than the author.
    A commit that reached the branch without the line can be reviewed afterwards: a later reviewed commit lists it on a
    'Reviewed-commit: <sha>' line. Such commits count as reviewed and are reported as reviewed after they were pushed.
    Repos: GitHub connector option 'review_repos', else the site profile key review_repos."""
    import re  # noqa: PLC0415

    from orasec.posture.connectors.base import get_connector_class  # noqa: PLC0415
    from orasec.posture.models import Connector  # noqa: PLC0415
    gh = Connector.objects.filter(kind="github").first()
    if not gh:
        return "warn", "No GitHub connector configured; code review cannot be checked.", {}
    from orasec import site as site_profile  # noqa: PLC0415
    repos = (gh.options or {}).get("review_repos") or site_profile.get("review_repos") or []
    if not repos:
        return "warn", "No repository is set for the code review check (GitHub connector option review_repos).", {}
    since = max(CODE_REVIEW_START, timezone.localdate() - datetime.timedelta(days=30))
    conn = get_connector_class("github")(gh)
    missing, late, total = [], [], 0
    for repo in repos:
        try:
            commits = conn._paged(f"https://api.github.com/repos/{repo}/commits", since=f"{since.isoformat()}T00:00:00+13:00")
        except Exception as exc:  # noqa: BLE001
            return "warn", f"GitHub could not be read for {repo}: {exc}", {"repos": repos}
        if isinstance(commits, dict):
            return "warn", f"GitHub returned an error for {repo}: {commits.get('message', '')}", {"repos": repos}
        rows, records = [], []  # records: (sha prefixes reviewed afterwards, who reviewed them)
        for c in commits:
            if len(c.get("parents") or []) > 1:
                continue  # merge commits
            msg = (c.get("commit") or {}).get("message", "")
            author = ((c.get("commit") or {}).get("author") or {}).get("name", "").strip().lower()
            lines = msg.splitlines()
            rev = [ln.split(":", 1)[1].strip().lower() for ln in lines if ln.lower().startswith("reviewed-by:")]
            rows.append((c.get("sha", ""), author, rev))
            listed = [t for ln in lines if ln.lower().startswith("reviewed-commit:")
                      for t in re.findall(r"\b[0-9a-f]{7,40}\b", ln.split(":", 1)[1].lower())]
            if listed and _second_person(rev, author):
                records.append((listed, rev))
        for sha, author, rev in rows:
            total += 1
            if _second_person(rev, author):
                continue
            if any(_second_person(reviewers, author) for listed, reviewers in records if any(sha.startswith(t) for t in listed)):
                late.append(f"{repo}@{sha[:7]}")
            else:
                missing.append(f"{repo}@{sha[:7]}")
    m = {"repos": repos, "since": since.isoformat(), "commits": total, "without_review": missing, "reviewed_late": late}
    if missing:
        return "fail", f"{len(missing)} of {total} commits since {since} have no 'Reviewed-by:' line from a second person: " + ", ".join(missing[:10]) + ".", m
    if late:
        return "pass", (f"All {total} commits since {since} were reviewed by a second person; {len(late)} of them after they were "
                        "pushed (late review recorded): " + ", ".join(late[:10]) + "."), m
    return "pass", f"All {total} commits since {since} were reviewed by a second person.", m


def check_isms_sync():
    """Documented operating procedures kept in step (A.5.37): the policy tool and OraSec are in sync. Pass when the last full
    reconciliation is under 26 h old, no sync run has been failing for over an hour and no conflict is older than 7 days."""
    from orasec.posture.models import Connector, IsmsConflict, IsmsSyncRun  # noqa: PLC0415
    if not Connector.objects.filter(kind="isms", enabled=True).exists():
        return "na", "Policy tool sync is not configured.", {}
    now = timezone.now()
    last = IsmsSyncRun.objects.filter(kind="full", ok=True).first()
    last_any = IsmsSyncRun.objects.filter(finished__isnull=False).first()
    failing = bool(last_any and not last_any.ok and last_any.finished < now - datetime.timedelta(hours=1))
    old = IsmsConflict.objects.filter(resolved=False, created__lt=now - datetime.timedelta(days=7)).count()
    m = {"last_full": last.finished.isoformat() if last else None, "failing": failing, "old_conflicts": old}
    if not last or last.finished < now - datetime.timedelta(hours=26):
        return "fail", "No successful full sync with the policy tool in the last 26 hours.", m
    if failing or old:
        return "warn", ("Sync failing for over an hour. " if failing else "") + (f"{old} conflict(s) open over 7 days." if old else ""), m
    return "pass", f"Policy tool in sync (last full sync {timezone.localtime(last.finished):%d %b %H:%M}).", m


# Readiness checks for controls run mainly through approved procedures.
from orasec.posture import readiness_checks as _rc  # noqa: E402

globals().update({k: v for k, v in vars(_rc).items() if k.startswith("check_")})
AUTO_CHECKS.update(_rc.READINESS_CHECKS)

CHECKS = {k: v for k, v in globals().items() if k.startswith("check_")}


def evaluate_all():
    out = {}
    impls = ControlImplementation.objects.select_related("control").exclude(control__auto_check="")
    for impl in sorted(impls, key=lambda i: i.control.auto_check == "operation"):  # summary check runs last
        fn = CHECKS.get("check_" + impl.control.auto_check)
        if not fn:
            continue
        try:
            result, detail, metrics = fn()
        except Exception as e:  # keep evaluating the rest
            result, detail, metrics = "warn", f"Check error: {e.__class__.__name__}: {e}", {}
        impl.auto_status, impl.auto_detail, impl.auto_evaluated_at = result, detail, timezone.now()
        impl.save(update_fields=["auto_status", "auto_detail", "auto_evaluated_at", "updated"])
        ControlCheckResult.objects.create(control=impl.control, result=result, detail=detail, metrics=metrics)
        out[impl.control.ref] = result
    return out


def control_value(impl):
    if not impl.applicable or impl.status == "not_applicable":
        return None
    v = {"implemented": 1.0, "in_progress": 0.5, "not_started": 0.0}.get(impl.status, 0.0)
    cap = {"fail": 0.4, "warn": 0.75}.get(impl.auto_status)
    if impl.auto_status == "pass" and v < 0.75:
        v = 0.75  # automated evidence of operation counts towards implementation
    return min(v, cap) if cap is not None else v


def compliance_score():
    vals = [control_value(i) for i in ControlImplementation.objects.filter(control__framework__code=CODE)]
    vals = [v for v in vals if v is not None]
    return int(round(1000 * sum(vals) / len(vals))) if vals else 0


def summary():
    qs = ControlImplementation.objects.filter(control__framework__code=CODE).select_related("control")
    agg = {"total": 0, "applicable": 0, "implemented": 0, "in_progress": 0, "not_started": 0, "not_applicable": 0,
           "auto_pass": 0, "auto_warn": 0, "auto_fail": 0, "evidence": 0}
    for i in qs:
        agg["total"] += 1
        agg["applicable"] += 1 if i.applicable and i.status != "not_applicable" else 0
        agg[i.status] = agg.get(i.status, 0) + 1
        if i.auto_status in ("pass", "warn", "fail"):
            agg["auto_" + i.auto_status] += 1
    from orasec.posture.models import ControlEvidence  # noqa: PLC0415
    agg["evidence"] = ControlEvidence.objects.filter(control__framework__code=CODE).count()
    agg["score"] = compliance_score()
    return agg



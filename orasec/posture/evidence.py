"""
Automatic ISO/IEC 27001:2022 evidence.

Every successful connector run, intel refresh and patch deployment is recorded as evidence of operation against the
Annex A controls it demonstrates. One automated record is kept per control, source and day (re-runs on the same day
update it), each valid for 35 days and linking back to the run that produced it.
"""
import datetime
import logging

from django.utils import timezone

logger = logging.getLogger(__name__)

# connector kind -> [(control ref, what the run demonstrates)]
CONNECTOR_CONTROLS = {
    "wazuh": [("A.8.16", "Security monitoring: SIEM agents and alerts collected"), ("A.8.15", "Logging: host and security logs centralised in Wazuh"),
              ("A.8.8", "Technical vulnerability management: vulnerability detection on hosts"), ("A.8.9", "Configuration management: CIS/SCA policy checks"),
              ("A.8.7", "Protection against malware: endpoint agent coverage")],
    "patchmon": [("A.8.8", "Technical vulnerability management: pending security updates inventoried"),
                 ("A.8.19", "Installation of software on operational systems: package inventory per host")],
    "semaphore": [("A.8.8", "Patch automation inventory (Ansible)"), ("A.8.32", "Change management: patching runs through controlled templates")],
    "opnsense": [("A.8.20", "Network security: firewall rules and state reviewed"), ("A.8.22", "Segregation of networks: interfaces and VPN selectors"),
                 ("A.8.24", "Use of cryptography: IPsec and TLS certificate state"), ("A.8.8", "Firewall firmware and package vulnerability audit")],
    "unifi": [("A.8.20", "Network security: gateway firewall policies and devices"), ("A.8.21", "Security of network services: Wi-Fi and WAN configuration"),
              ("A.8.22", "Segregation of networks: VLANs and zones")],
    "aws": [("A.5.23", "Information security for use of cloud services: AWS CSPM assessment"), ("A.8.20", "Network security: VPC and security groups"),
            ("A.8.15", "Logging: CloudTrail and VPC flow logs"), ("A.8.16", "Monitoring: GuardDuty / Security Hub"),
            ("A.8.24", "Use of cryptography: storage encryption"), ("A.5.15", "Access control: IAM users, MFA and keys")],
    "cloudflare": [("A.5.23", "Information security for use of cloud services: Cloudflare edge configuration"),
                   ("A.8.20", "Network security: WAF, proxying and tunnels"), ("A.8.24", "Use of cryptography: TLS mode, minimum TLS, HSTS, DNSSEC"),
                   ("A.8.16", "Monitoring: edge threat analytics")],
    "github": [("A.8.25", "Secure development life cycle: repository security features"), ("A.8.28", "Secure coding: code and dependency scanning"),
               ("A.8.4", "Access to source code: branch protection"), ("A.8.29", "Security testing in development and acceptance")],
}
VALID_DAYS = 35


def _record(ref, title, description, url, when=None):
    from orasec.posture.models import ComplianceControl, ControlEvidence  # noqa: PLC0415
    from orasec.posture import compliance  # noqa: PLC0415
    ctrl = ComplianceControl.objects.filter(framework__code=compliance.CODE, ref=ref).first()
    if not ctrl:
        return None
    when = when or timezone.now()
    day = timezone.localdate(when)
    ev = ControlEvidence.objects.filter(control=ctrl, source="auto", title=title, collected_at__date=day).first()
    if ev:
        ev.description, ev.url, ev.collected_at = description, url, when
        ev.valid_until = day + datetime.timedelta(days=VALID_DAYS)
        ev.save(update_fields=["description", "url", "collected_at", "valid_until"])
        return ev
    return ControlEvidence.objects.create(control=ctrl, title=title, description=description, url=url, source="auto", collected_at=when,
                                          valid_until=day + datetime.timedelta(days=VALID_DAYS))


def _summary(run):
    st = run.stats or {}
    keys = ("assets_created", "assets_updated", "findings_new", "findings_closed", "product_version", "repos", "rules_total", "attack_alerts_24h",
            "threats_72h", "vulnerable_packages", "devices", "clients", "iam_users", "findings_by_check")
    parts = [f"{k.replace('_', ' ')}: {st[k]}" for k in keys if st.get(k) not in (None, "", [])]
    imports = st.get("imports") or []
    if imports:
        parts.append("tests: " + "; ".join(f"{i.get('title', '')} ({i.get('count', i.get('new', 0))})" for i in imports[:6]))
    return "\n".join(parts)


def from_connector_run(run):
    """Record evidence for a finished connector run (ok or warning). Never raises."""
    try:
        if run.status not in ("ok", "warning"):
            return 0
        c = run.connector
        when = run.finished_at or timezone.now()
        n = 0
        for ref, what in CONNECTOR_CONTROLS.get(c.kind, []):
            title = f"{what} — {c.name}"
            desc = f"Automated collection by OraSec connector '{c.name}' ({c.get_kind_display()}) on {timezone.localtime(when):%d %b %Y %H:%M}.\n{_summary(run)}"
            if _record(ref, title[:300], desc, f"/orasec/runs/{run.id}/", when):
                n += 1
        return n
    except Exception:
        logger.exception("evidence collection failed for run %s", getattr(run, "id", "?"))
        return 0


def from_intel_refresh(feeds):
    try:
        recs = ", ".join(f"{f.name.upper()} {f.records} records" for f in feeds)
        return bool(_record("A.5.7", "Threat intelligence: CISA KEV and FIRST EPSS feeds refreshed",
                            f"Threat intelligence feeds refreshed and applied to findings: {recs}.", "/orasec/diagnostics/"))
    except Exception:
        logger.exception("intel evidence failed")
        return False


def from_patch_deployment(dep):
    try:
        if dep.status != "success":
            return False
        title = f"Patch deployment #{dep.id} on {dep.inventory_host} ({dep.get_mode_display()})"
        desc = (f"Semaphore task {dep.task_id}, template {dep.template_id}, requested by {dep.requested_by or 'system'}"
                f"{', change ' + dep.change_ref if dep.change_ref else ''}.\n{dep.summary}")
        url = f"/orasec/patching/runs/{dep.id}/"
        _record("A.8.8", title, desc, url)
        if dep.mode == "apply":
            _record("A.8.32", title, desc, url)
        return True
    except Exception:
        logger.exception("patch evidence failed")
        return False


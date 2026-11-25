"""
Parser for OraSec connector output (OPNsense, UniFi, PatchMon, Wazuh SCA).

Input: {"findings": [{"title", "severity", "description", "mitigation", "impact", "references",
         "component_name", "component_version", "fix_version", "host", "unique_id", "cve" | "cves",
         "cvss_score", "date", "tags", "category"}]}
Deduplication is by ``unique_id`` (unique_id_from_tool), so reimports close findings that the source
no longer reports.
"""
import json

from django.utils import timezone

from orasec.location.feature import locations_enabled
from orasec.models import Endpoint, Finding
from orasec.tools.locations import LocationData

SCAN_TYPES = {
    "OraSec OPNsense": "OPNsense firewall: package vulnerability audit, firmware, certificates, accounts and rule hygiene.",
    "OraSec UniFi": "UniFi Network: device firmware, Wi-Fi security, firewall policy and inventory hygiene.",
    "OraSec PatchMon": "PatchMon: hosts with outstanding security and package updates.",
    "OraSec Wazuh SCA": "Wazuh Security Configuration Assessment: failed CIS/hardening checks.",
    "OraSec AWS": "AWS: security groups, IAM, S3, RDS, EC2, CloudTrail and GuardDuty/Security Hub/Inspector findings.",
    "OraSec Cloudflare": "Cloudflare: TLS/HSTS settings, WAF, DNS exposure, SPF/DMARC and DNSSEC.",
    "OraSec GitHub": "GitHub: Dependabot, code scanning and secret scanning alerts, repository security settings.",
    "OraSec Plerion": "Plerion: failed cloud security posture checks across the connected cloud accounts.",
    "OraSec Tenable": "Tenable Vulnerability Management: open vulnerabilities from the bulk export.",
    "OraSec Check Point": "Check Point: what the firewall policy lets the internet reach, and broad rules.",
}
SEVERITIES = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info", "informational": "Info"}


class OraSecConnectorsParser:

    def get_scan_types(self):
        return list(SCAN_TYPES)

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return SCAN_TYPES.get(scan_type, scan_type) + " Produced by OraSec connectors (JSON)."

    def get_findings(self, file, test):
        raw = file.read()
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        data = json.loads(raw or "{}")
        out = {}
        for item in data.get("findings", []):
            uid = item.get("unique_id") or f"{item.get('host', '')}:{item.get('title', '')}"
            if uid in out:
                continue
            sev = SEVERITIES.get(str(item.get("severity", "info")).lower(), "Info")
            f = Finding(
                title=str(item.get("title", "Untitled"))[:511],
                test=test,
                severity=sev,
                description=item.get("description") or item.get("title") or "",
                mitigation=item.get("mitigation") or None,
                impact=item.get("impact") or None,
                references=item.get("references") or None,
                component_name=(item.get("component_name") or None) and str(item["component_name"])[:200],
                component_version=(item.get("component_version") or None) and str(item["component_version"])[:100],
                fix_version=(item.get("fix_version") or None) and str(item["fix_version"])[:100],
                fix_available=bool(item.get("fix_version")) or item.get("fix_available"),
                unique_id_from_tool=uid[:500],
                vuln_id_from_tool=(item.get("rule_id") or None),
                static_finding=True,
                dynamic_finding=False,
                date=(item.get("date") or timezone.now().date().isoformat())[:10],
            )
            if item.get("cvss_score") is not None:
                try:
                    f.cvssv3_score = float(item["cvss_score"])
                except (TypeError, ValueError):
                    pass
            cves = item.get("cves") or ([item["cve"]] if item.get("cve") else [])
            if cves:
                f.unsaved_vulnerability_ids = [str(c) for c in cves]
            if item.get("host"):
                if locations_enabled():
                    f.unsaved_locations = [LocationData.url(host=item["host"])]
                else:
                    f.unsaved_endpoints = [Endpoint(host=item["host"])]
            if item.get("tags"):
                f.unsaved_tags = [str(t)[:100] for t in item["tags"]]
            out[uid] = f
        return list(out.values())


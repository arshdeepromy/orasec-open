"""
PatchMon connector (PatchMon Integration API, scoped credentials).

Auth: HTTP Basic, token key (patchmon_ae_...) as user, token secret as password. Scope host:get (read only).
  GET /api/v1/api/hosts?include=stats           hosts with update counts, reboot flag, reporting state
  GET /api/v1/api/hosts/:id/system              kernel, reboot reason
  GET /api/v1/api/hosts/:id/packages?updates_only=true   outstanding updates (security first)

One finding per outstanding *security* update per host (High), plus one per host for
outstanding non-security updates (Low, aggregated) and a stale-reporting finding when the agent
has stopped reporting. Findings close automatically when PatchMon stops reporting them.

Secrets: {"token_secret": "..."}; username = token key.
Options: {"stale_hours": 48, "non_security": true}
"""
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from orasec.posture.connectors.base import CONNECTOR_SCAN_TYPES, AssetRecord, BaseConnector, CollectResult, ConnectorError, TestBatch, register

API = "/api/v1/api"


@register
class PatchMonConnector(BaseConnector):
    kind = "patchmon"
    secret_fields = ("token_secret",)

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.http.session.auth = (self.connector.username, self.secrets.get("token_secret", ""))

    def test(self):
        data = self.http.get(f"{API}/hosts")
        return f"PatchMon — {data.get('total', len(data.get('hosts', [])))} hosts visible to this credential"

    def collect(self):
        res = CollectResult()
        hosts = self.http.get(f"{API}/hosts", params={"include": "stats"}).get("hosts", [])
        stale_hours = int(self.options.get("stale_hours", 48))
        findings = []
        totals = {"hosts": len(hosts), "security_updates": 0, "updates": 0, "needs_reboot": 0, "stale": 0}
        for h in hosts:
            name = h.get("friendly_name") or h.get("hostname") or h["id"]
            rec = AssetRecord(key=f"host:{h['id']}", name=name, hostname=h.get("hostname") or "", ip_address=h.get("ip") or "",
                              os_name=h.get("os_type") or "", os_version=h.get("os_version") or "", asset_type="server",
                              attributes={"patchmon_id": h["id"], "updates": h.get("updates_count"),
                                          "security_updates": h.get("security_updates_count"), "needs_reboot": h.get("needs_reboot"),
                                          "last_update": h.get("last_update"), "status": h.get("status"), "groups": h.get("host_groups")})
            res.assets.append(rec)
            totals["needs_reboot"] += 1 if h.get("needs_reboot") else 0
            last = parse_datetime(h["last_update"]) if h.get("last_update") else None
            if last is None or (timezone.now() - last).total_seconds() > stale_hours * 3600:
                totals["stale"] += 1
                findings.append({
                    "title": f"Patch agent not reporting: {name}",
                    "severity": "Medium",
                    "description": f"PatchMon has not received a report from **{name}** since {h.get('last_update') or 'enrolment'}. "
                                   "Patch status for this host is unknown.",
                    "mitigation": "Check the PatchMon agent service on the host and its connectivity to PatchMon.",
                    "host": name, "unique_id": f"patchmon:{h['id']}:stale", "tags": ["patching", "agent-health"],
                    "component_name": "patchmon-agent",
                })
            try:
                pk = self.http.get(f"{API}/hosts/{h['id']}/packages", params={"updates_only": "true"}).get("packages", [])
            except ConnectorError as e:
                res.warnings.append(f"{name}: packages unavailable ({e})")
                continue
            sec = [p for p in pk if p.get("is_security_update")]
            other = [p for p in pk if p.get("needs_update") and not p.get("is_security_update")]
            totals["security_updates"] += len(sec)
            totals["updates"] += len(pk)
            for p in sec:
                findings.append({
                    "title": f"Security update outstanding: {p['name']} on {name}",
                    "severity": "High",
                    "description": f"A security update is available for **{p['name']}** on **{name}**.\n\n"
                                   f"Installed: `{p.get('current_version')}`  \nAvailable: `{p.get('available_version')}`\n\n"
                                   f"{p.get('description') or ''}",
                    "mitigation": f"Apply the {p['name']} update (Semaphore patch run or the host's package manager).",
                    "component_name": p["name"], "component_version": p.get("current_version"),
                    "fix_version": p.get("available_version"), "host": name,
                    "unique_id": f"patchmon:{h['id']}:sec:{p['name']}", "tags": ["patching", "security-update"],
                })
            if other and self.options.get("non_security", True):
                listing = "\n".join(f"- `{p['name']}` {p.get('current_version')} → {p.get('available_version')}" for p in other[:200])
                findings.append({
                    "title": f"{len(other) if len(other) < 2 else 'Multiple'} non-security update(s) outstanding on {name}",
                    "severity": "Low",
                    "description": f"{len(other)} non-security package update(s) are outstanding on **{name}**:\n\n{listing}",
                    "mitigation": "Include these in the next scheduled patch window.",
                    "host": name, "unique_id": f"patchmon:{h['id']}:non-security", "tags": ["patching"],
                    "component_name": "os-packages",
                })
            if h.get("needs_reboot"):
                findings.append({
                    "title": f"Reboot required to complete patching: {name}",
                    "severity": "Low",
                    "description": f"**{name}** reports that a reboot is required (e.g. a new kernel is installed but not running).",
                    "mitigation": "Schedule a reboot in the next maintenance window.",
                    "host": name, "unique_id": f"patchmon:{h['id']}:reboot", "tags": ["patching", "reboot"],
                    "component_name": "kernel",
                })
        res.batches.append(TestBatch(title="PatchMon patch status", scan_type=CONNECTOR_SCAN_TYPES["patchmon"],
                                     payload={"findings": findings}, count=len(findings),
                                     product_name=self.options.get("product_name")))
        res.stats.update(totals)
        return res


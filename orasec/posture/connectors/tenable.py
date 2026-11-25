"""
Tenable Vulnerability Management connector: assets and open vulnerabilities through the bulk export API.

Base URL: https://cloud.tenable.com (or your regional or FedRAMP host).
Username: API access key. Secrets: {"secret_key": "..."}. Use the keys of a user with the Basic role and "Can view"
on all assets; this connector only reads and exports.
Options: {"days": 90, "severities": ["critical", "high", "medium", "low"], "plugin_output": false,
          "chunk_assets": 1000, "num_assets": 500, "timeout_minutes": 30, "product_name": "Infrastructure hosts"}

  GET  /session                                    who the keys belong to (connection test); /users as a fallback
  POST /assets/export, /vulns/export               queue an export, returns export_uuid
  GET  /{kind}/export/{uuid}/status                QUEUED | PROCESSING | FINISHED | ERROR | CANCELLED, chunks_available
  GET  /{kind}/export/{uuid}/chunks/{n}            one chunk, a JSON list of records

What is imported
- Assets assessed in the last ``days`` days (licensed, not deleted, not terminated).
- Vulnerabilities in state OPEN or REOPENED found in the last ``days`` days, at the listed severities. Fixed ones are
  left out on purpose: each finding is keyed on asset + plugin + port, so one that Tenable no longer reports open is
  closed here by the next run.

A truncated read is indistinguishable from a shrunken estate, and here it would close real findings. So an export
that fails, is cancelled, times out or loses a chunk fails the whole run and nothing is imported.
"""
import time

from orasec.posture.connectors.base import (
    AssetRecord,
    BaseConnector,
    CollectResult,
    ConnectorError,
    TestBatch,
    register,
)

SEVERITIES = ("critical", "high", "medium", "low", "info")
SERVER_HINTS = ("windows server", "linux", "ubuntu", "red hat", "rhel", "centos", "debian", "suse", "esxi", "solaris", "aix", "freebsd")
WORKSTATION_HINTS = ("windows 10", "windows 11", "windows 7", "windows 8", "mac os", "macos")
POLL_SECONDS = 5


def _strings(value):
    if isinstance(value, str):
        return [value] if value else []
    return [str(v) for v in (value or []) if v]


def classify(record):
    """Asset type from what Tenable knows: cloud ids first, then device type, then the operating system."""
    if record.get("aws_ec2_instance_id") or record.get("azure_vm_id") or record.get("gcp_instance_id"):
        return "cloud_instance"
    kinds = " ".join(_strings(record.get("system_types"))).lower()
    os_name = " ".join(_strings(record.get("operating_systems"))).lower()
    for word, kind in (("firewall", "firewall"), ("switch", "switch"), ("wireless-access-point", "access_point"), ("router", "network_device")):
        if word in kinds:
            return kind
    if any(h in os_name for h in SERVER_HINTS):
        return "server"
    if any(h in os_name for h in WORKSTATION_HINTS):
        return "workstation"
    if "embedded" in kinds or "printer" in kinds:
        return "network_device"
    return "other"


@register
class TenableConnector(BaseConnector):
    kind = "tenable"
    secret_fields = ("secret_key",)

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        # The key material only ever lives in this header: never in a query string, never in the run log.
        self.http.session.headers.update({
            "X-ApiKeys": f"accessKey={(self.connector.username or '').strip()};secretKey={(self.secrets.get('secret_key') or '').strip()};",
            "Accept": "application/json", "Content-Type": "application/json", "User-Agent": "OraSec-Tenable/1.0"})

    # --- export ---------------------------------------------------------------
    def _export(self, kind, body):
        """Run one export to the end and return every record. Raises unless every chunk was read."""
        uuid = (self.http.post(f"/{kind}/export", json=body) or {}).get("export_uuid")
        if not uuid:
            msg = f"Tenable accepted the {kind} export but returned no export_uuid"
            raise ConnectorError(msg)
        deadline = time.monotonic() + 60 * int(self.options.get("timeout_minutes", 30))
        records, done = [], set()
        while True:
            st = self.http.get(f"/{kind}/export/{uuid}/status") or {}
            status = str(st.get("status") or "").upper()
            for chunk_id in st.get("chunks_available") or []:
                if chunk_id in done:
                    continue
                rows = self.http.get(f"/{kind}/export/{uuid}/chunks/{chunk_id}", timeout=120)
                if not isinstance(rows, list):
                    msg = f"Tenable {kind} export chunk {chunk_id} is not a list; nothing was imported"
                    raise ConnectorError(msg)
                records.extend(r for r in rows if isinstance(r, dict))
                done.add(chunk_id)
            if status == "FINISHED":
                failed = st.get("chunks_failed") or []
                if failed:
                    msg = f"Tenable {kind} export lost chunk(s) {failed}; nothing was imported"
                    raise ConnectorError(msg)
                if set(st.get("chunks_available") or []) - done:
                    continue  # chunks listed by the final status are fetched on the next pass
                self.log.append(f"{kind} export {uuid}: {len(records)} records in {len(done)} chunk(s)")
                return records
            if status in {"ERROR", "CANCELLED"}:
                msg = f"Tenable {kind} export ended as {status}; nothing was imported"
                raise ConnectorError(msg)
            if time.monotonic() > deadline:
                msg = f"Tenable {kind} export did not finish in {self.options.get('timeout_minutes', 30)} minutes; nothing was imported"
                raise ConnectorError(msg)
            time.sleep(POLL_SECONDS)

    # --- connector ------------------------------------------------------------
    def test(self):
        try:
            me = self.http.get("/session")
        except ConnectorError:
            users = self.http.get("/users")  # keys of an administrator without a session endpoint
            return f"Tenable keys accepted ({len(users.get('users') or [])} users visible)"
        who = me.get("username") or me.get("name") or me.get("email") or "API user"
        return f"Tenable keys accepted for {who}"

    def collect(self):
        res = CollectResult()
        days = int(self.options.get("days", 90))
        since = int(time.time()) - days * 86400

        # --- assets ---
        names = {}
        for rec in self._export("assets", {
                "chunk_size": int(self.options.get("chunk_assets", 1000)),
                "filters": {"last_assessed": since, "is_licensed": True, "is_deleted": False, "is_terminated": False}}):
            uuid = str(rec.get("id") or rec.get("uuid") or "")
            if not uuid:
                continue
            hostnames, fqdns = _strings(rec.get("hostnames")), _strings(rec.get("fqdns"))
            ipv4s, macs, oses = _strings(rec.get("ipv4s")), _strings(rec.get("mac_addresses")), _strings(rec.get("operating_systems"))
            host = (hostnames[0] if hostnames else "") or (fqdns[0].split(".")[0] if fqdns else "") or str(rec.get("netbios_name") or "")
            name = host or (ipv4s[0] if ipv4s else uuid)
            names[uuid] = name
            res.assets.append(AssetRecord(
                key=uuid, name=name, hostname=host, asset_type=classify(rec), ip_address=ipv4s[0] if ipv4s else "",
                mac_address=macs[0] if macs else "", os_name=(oses[0] if oses else "")[:200], scanned=True,
                attributes={"uuid": uuid, "fqdn": fqdns[0] if fqdns else "", "ipv4s": ipv4s[:20], "has_agent": bool(rec.get("has_agent")),
                            "system_types": _strings(rec.get("system_types")), "acr_score": rec.get("acr_score"),
                            "exposure_score": rec.get("exposure_score"), "network": rec.get("network_name"),
                            "last_seen": rec.get("last_seen") or rec.get("updated_at"),
                            "aws_ec2_instance_id": rec.get("aws_ec2_instance_id"), "azure_vm_id": rec.get("azure_vm_id")}))
        res.stats["assets"] = len(res.assets)

        # --- vulnerabilities ---
        wanted = [s for s in (str(x).lower() for x in self.options.get("severities") or SEVERITIES[:4]) if s in SEVERITIES]
        with_output = bool(self.options.get("plugin_output", False))
        findings, by_sev = {}, dict.fromkeys(SEVERITIES, 0)
        for rec in self._export("vulns", {
                "num_assets": int(self.options.get("num_assets", 500)), "include_unlicensed": False,
                "filters": {"severity": wanted, "state": ["OPEN", "REOPENED"], "since": since}}):
            asset, plugin, port = rec.get("asset") or {}, rec.get("plugin") or {}, rec.get("port") or {}
            uuid, pid = str(asset.get("uuid") or asset.get("id") or ""), str(plugin.get("id") or "")
            if not uuid or not pid or str(rec.get("state") or "OPEN").upper() == "FIXED":
                continue
            sev = str(rec.get("severity") or "info").lower()
            sev = sev if sev in SEVERITIES else "info"
            pnum, proto = int(port.get("port") or 0), str(port.get("protocol") or "").lower()
            uid = f"tenable:{uuid}:{pid}:{pnum}/{proto}"
            if uid in findings:
                continue
            host = names.get(uuid) or asset.get("hostname") or asset.get("fqdn") or asset.get("ipv4") or uuid
            vpr = (plugin.get("vpr") or {}).get("score")
            desc = [str(plugin.get("synopsis") or ""), "", str(plugin.get("description") or "")]
            if pnum:
                desc += ["", f"Found on {proto or 'tcp'}/{pnum}" + (f" ({port.get('service')})" if port.get("service") else "") + "."]
            if with_output and rec.get("output"):
                desc += ["", "Plugin output:", "```", str(rec["output"])[:4000], "```"]
            tags = ["tenable", *(["exploit-available"] if plugin.get("exploit_available") else [])]
            findings[uid] = {
                "title": f"{plugin.get('name') or 'Tenable plugin ' + pid}"[:500], "severity": sev,
                "description": "\n".join(desc).strip() or str(plugin.get("name") or pid),
                "mitigation": str(plugin.get("solution") or ""), "references": "\n".join(_strings(plugin.get("see_also"))[:10]),
                "impact": f"Tenable VPR {vpr}" if vpr is not None else "", "host": str(host)[:250],
                "component_name": str(plugin.get("family") or "")[:200], "rule_id": pid, "unique_id": uid,
                "cves": _strings(plugin.get("cve"))[:50], "cvss_score": plugin.get("cvss3_base_score") or plugin.get("cvss_base_score"),
                "fix_available": bool(plugin.get("has_patch")) or None, "date": str(rec.get("first_found") or "")[:10] or None, "tags": tags}
            by_sev[sev] += 1
        res.stats["findings"] = len(findings)
        res.stats["by_severity"] = by_sev
        res.batches.append(TestBatch(title="Tenable vulnerabilities", scan_type="OraSec Tenable", payload={"findings": list(findings.values())},
                                     count=len(findings), product_name=self.options.get("product_name")))
        return res


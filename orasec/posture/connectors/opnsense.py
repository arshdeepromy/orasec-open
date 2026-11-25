"""
OPNsense connector (verified against OPNsense 26.7; key/secret over HTTP Basic, JSON).

  GET  /api/core/firmware/info                     product version, packages, plugins
  POST /api/core/firmware/status                   pending updates (last check)
  POST /api/core/firmware/audit                    starts `pkg audit` (FreeBSD VuXML)
  GET  /api/core/firmware/upgradestatus            audit progress + log
  GET  /api/core/system/status                     system notices
  GET  /api/interfaces/overview/interfaces_info    interfaces and addresses
  GET  /api/ipsec/sessions/search_phase1           site-to-site tunnels and traffic
  GET  /api/firewall/filter/search_rule            filter rules (topology + rule hygiene)
  GET  /api/diagnostics/firewall/log               recent filter log (blocked inbound -> attack map)
The GUI certificate is checked over TLS, so the API user needs no access to the certificate
manager (which can export private keys).

API user privileges: page-system-status, page-status-interfaces, page-status-ipsec,
page-diagnostics-logs-firewall-general, page-firewall-rules, page-system-firmware-manualupdate.
The connector never calls update/upgrade/reboot endpoints.

Secrets: {"api_secret": "..."}; username = API key.
Options: {"asset_name": "cloud-fw", "audit": true, "cert_warn_days": 30, "tls_hosts": ["10.20.0.11:443"],
          "site": "Cloud", "attack_events": true}
"""
import datetime
import re
import socket
import ssl
import time
from urllib.parse import urlparse

from django.utils import timezone

from orasec.posture.connectors.base import CONNECTOR_SCAN_TYPES, AssetRecord, BaseConnector, CollectResult, ConnectorError, TestBatch, register

AUDIT_RE = re.compile(r"^(?P<pkg>\S+)-(?P<ver>[0-9][^\s]*) is vulnerable:\s*$")
SENSITIVE_PORTS = {"22": "SSH", "23": "Telnet", "3389": "RDP", "3306": "MySQL", "5432": "PostgreSQL", "1433": "MSSQL",
                   "6379": "Redis", "27017": "MongoDB", "445": "SMB", "5900": "VNC", "9200": "Elasticsearch/OpenSearch"}


def tls_expiry(host, port=443, timeout=10):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as s, ctx.wrap_socket(s, server_hostname=host) as ss:
        der = ss.getpeercert(binary_form=True)
    from cryptography import x509  # noqa: PLC0415
    cert = x509.load_der_x509_certificate(der)
    return cert.not_valid_after_utc, cert.subject.rfc4514_string()


@register
class OPNsenseConnector(BaseConnector):
    kind = "opnsense"
    secret_fields = ("api_secret",)

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.http.session.auth = (self.connector.username, self.secrets.get("api_secret", ""))

    def test(self):
        info = self.http.get("/api/core/firmware/info")
        return f"OPNsense {self._version(info)} — {len(info.get('package', []))} packages known"

    @staticmethod
    def _version(info):
        return info.get("product_version") or (info.get("product") or {}).get("product_version", "?")

    def _audit(self):
        start = self.http.post("/api/core/firmware/audit", json={})
        if start.get("status") not in ("ok", None):
            msg = f"audit did not start: {start}"
            raise ConnectorError(msg)
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            time.sleep(3)
            st = self.http.get("/api/core/firmware/upgradestatus")
            if st.get("status") == "done":
                return st.get("log", "")
            if st.get("status") == "error":
                msg = "audit reported an error"
                raise ConnectorError(msg)
        msg = "audit did not finish within 5 minutes"
        raise ConnectorError(msg)

    @staticmethod
    def parse_audit(log):
        out, cur = [], None
        for line in log.splitlines():
            s = line.strip()
            m = AUDIT_RE.match(s)
            if m:
                cur = {"pkg": m["pkg"], "version": m["ver"], "entries": []}
                out.append(cur)
                continue
            if cur is None or not s:
                continue
            if s.startswith("CVE:"):
                if cur["entries"]:
                    cur["entries"][-1]["cves"].append(s[4:].strip())
            elif s.startswith("WWW:"):
                if cur["entries"]:
                    cur["entries"][-1]["url"] = s[4:].strip()
            elif re.search(r"problem\(s\) in \d+ (installed )?package", s, re.IGNORECASE) or s.startswith("***"):
                cur = None
            else:
                cur["entries"].append({"title": s, "cves": [], "url": ""})
        return out

    def collect(self):  # noqa: C901, PLR0912, PLR0915 (one pass over the appliance's APIs)
        res = CollectResult()
        findings = []
        name = self.options.get("asset_name", "OPNsense")
        info = self.http.get("/api/core/firmware/info")
        version = self._version(info)
        plugins = [p.get("name") for p in info.get("plugin", []) if str(p.get("installed")) == "1"]
        rec = AssetRecord(key="appliance", name=name, hostname=name, asset_type="firewall", vendor="Deciso / OPNsense",
                          model="OPNsense", firmware=version, os_name="OPNsense", os_version=version,
                          internet_exposed=True, online=True, attributes={"plugins": plugins, "site": self.options.get("site", "")})
        res.stats["product_version"] = version
        base = {"host": name}

        # pending firmware updates
        try:
            st = self.http.post("/api/core/firmware/status", json={})
            res.stats["firmware_status"] = st.get("status")
            pending = st.get("all_packages") or st.get("upgrade_packages") or []
            if st.get("status") in ("update", "upgrade") or (isinstance(pending, list) and pending):
                latest = st.get("product_latest") or (st.get("product") or {}).get("product_latest") or "newer"
                findings.append({**base,
                    "title": f"OPNsense firmware update available ({version} → {latest})",
                    "severity": "High" if st.get("status") == "upgrade" else "Medium",
                    "description": f"The firewall reports pending updates. {st.get('status_msg', '')}\n\nInstalled: `{version}`",
                    "mitigation": "Review the changelog and update in a maintenance window (System → Firmware → Updates).",
                    "component_name": "opnsense", "component_version": version, "fix_version": str(latest)[:100],
                    "unique_id": "opnsense:firmware:update", "tags": ["firmware", "patching"]})
        except ConnectorError as e:
            res.warnings.append(f"firmware status unavailable ({e})")

        # package vulnerability audit
        if self.options.get("audit", True):
            try:
                vulns = self.parse_audit(self._audit())
                res.stats["vulnerable_packages"] = len(vulns)
                for v in vulns:
                    for e in v["entries"] or [{"title": "vulnerable package", "cves": [], "url": ""}]:
                        cves = sorted(set(e["cves"]))
                        vid = e["url"].rstrip("/").split("/")[-1].removesuffix(".html") if e["url"] else (cves[0] if cves else e["title"][:60])
                        findings.append({**base,
                            "title": f"{v['pkg']} {v['version']}: {e['title']}"[:500],
                            "severity": "High" if cves else "Medium",
                            "description": f"`pkg audit` on the firewall reports **{v['pkg']} {v['version']}** as vulnerable.\n\n{e['title']}\n\n"
                                           f"CVE(s): {', '.join(cves) or 'none listed'}",
                            "mitigation": "Update the package (System → Firmware). If no fix is published yet, assess exposure of the affected service.",
                            "references": e["url"], "cves": cves, "component_name": v["pkg"], "component_version": v["version"],
                            "unique_id": f"opnsense:audit:{v['pkg']}:{vid}", "tags": ["package-audit"]})
            except ConnectorError as e:
                res.warnings.append(f"package audit unavailable ({e})")

        # GUI/TLS certificates (checked over TLS, no cert-manager access needed)
        warn_days = int(self.options.get("cert_warn_days", 30))
        u = urlparse(self.connector.base_url)
        tls_hosts = self.options.get("tls_hosts") or [f"{u.hostname}:{u.port or 443}"]
        res.stats["certificates"] = []
        for hp in tls_hosts:
            host, _, port = hp.partition(":")
            try:
                exp, subject = tls_expiry(host, int(port or 443))
                days = (exp - datetime.datetime.now(datetime.UTC)).days
                res.stats["certificates"].append({"endpoint": hp, "subject": subject, "expires": exp.isoformat(), "days": days})
                if days <= warn_days:
                    findings.append({**base,
                        "title": f"TLS certificate {'expired' if days < 0 else 'expiring'} on {hp}",
                        "severity": "High" if days < 7 else "Medium",
                        "description": f"The certificate served on **{hp}** ({subject}) {'expired' if days < 0 else 'expires'} on {exp.date()} ({abs(days)} days).",
                        "mitigation": "Renew the certificate (System → Trust → Certificates) and assign it to the GUI/service.",
                        "unique_id": f"opnsense:tls:{hp}", "tags": ["certificate", "crypto"], "component_name": "certificate"})
            except (OSError, ValueError) as e:
                res.warnings.append(f"TLS check {hp} failed ({e.__class__.__name__})")

        # optional: accounts (requires the User Manager privilege, which can also edit users)
        if self.options.get("users"):
            try:
                users = self.http.get("/api/auth/user/search").get("rows", [])
                no_otp = [x.get("name") for x in users if str(x.get("disabled", "0")) in ("0", "") and not x.get("otp_seed")]
                res.stats["users_without_otp"] = no_otp
                for n in no_otp:
                    findings.append({**base, "title": f"Firewall account without MFA: {n}", "severity": "Medium",
                                     "description": f"Local OPNsense account **{n}** is enabled without a TOTP seed.",
                                     "mitigation": "Configure TOTP and require a TOTP authentication server for GUI logins.",
                                     "unique_id": f"opnsense:user-no-otp:{n}", "tags": ["access-control", "mfa"], "component_name": "user-manager"})
            except ConnectorError as e:
                res.warnings.append(f"user accounts unavailable ({e})")

        # system notices
        try:
            status = self.http.get("/api/core/system/status")
            subs = (status.get("metadata") or status).get("subsystems") or []
            res.stats["system_notices"] = subs if isinstance(subs, list) else list(subs)
        except ConnectorError as e:
            res.warnings.append(f"system status unavailable ({e})")

        # interfaces
        try:
            ifs = self.http.get("/api/interfaces/overview/interfaces_info").get("rows", [])
            res.stats["interfaces"] = [{"id": i.get("identifier"), "name": i.get("description"), "device": i.get("device"),
                                        "status": i.get("status"), "addr4": i.get("addr4"), "addr6": i.get("addr6"),
                                        "vlan": i.get("vlan_tag")} for i in ifs if i.get("identifier")]
            rec.attributes["interfaces"] = res.stats["interfaces"]
            wan = [i for i in ifs if (i.get("identifier") or "").lower() == "wan" and i.get("addr4")]
            if wan:
                rec.ip_address = wan[0]["addr4"].split("/")[0]
        except ConnectorError as e:
            res.warnings.append(f"interfaces unavailable ({e})")

        # IPsec site-to-site tunnels
        try:
            tunnels = self.http.get("/api/ipsec/sessions/search_phase1").get("rows", [])
            res.stats["ipsec"] = [{"name": t.get("phase1desc") or t.get("name"), "local_id": t.get("local-id"), "remote": t.get("remote-addrs"),
                                   "remote_id": t.get("remote-id"), "version": t.get("version"), "connected": bool(t.get("connected")),
                                   "bytes_in": t.get("bytes-in"), "bytes_out": t.get("bytes-out"), "uptime_s": t.get("install-time")} for t in tunnels]
            for t in res.stats["ipsec"]:
                if not t["connected"]:
                    findings.append({**base, "title": f"Site-to-site VPN down: {t['name']}", "severity": "Medium",
                                     "description": f"IPsec tunnel **{t['name']}** to {t['remote']} is not connected.",
                                     "mitigation": "Check phase 1/2 status and peer reachability (VPN → IPsec → Status).",
                                     "unique_id": f"opnsense:ipsec:{t['name']}:down", "tags": ["vpn", "availability"], "component_name": "ipsec"})
        except ConnectorError as e:
            res.warnings.append(f"IPsec status unavailable ({e})")

        # filter rules: topology input + hygiene findings
        try:
            rows = self.http.get("/api/firewall/filter/search_rule", params={"rowCount": -1}).get("rows", [])
            rules = []
            for r in rows:
                rule = {"uuid": r.get("uuid"), "enabled": str(r.get("enabled")) == "1", "action": (r.get("action") or "").lower(),
                        "direction": r.get("direction"), "interface": r.get("interface") or r.get("%interface") or "",
                        "protocol": r.get("protocol") or "any", "source": r.get("source_net") or "any", "source_port": r.get("source_port") or "any",
                        "destination": r.get("destination_net") or "any", "destination_port": r.get("destination_port") or "any",
                        "description": r.get("description") or "", "automatic": bool(r.get("is_automatic")), "log": bool(r.get("log"))}
                rules.append(rule)
                if rule["enabled"] and rule["action"] == "pass" and not rule["automatic"] and rule["direction"] in ("in", None) \
                        and "wan" in str(rule["interface"]).lower() and rule["source"] in ("any", ""):
                    port = str(rule["destination_port"])
                    if rule["destination"] in ("any", "") and port in ("any", ""):
                        sev, why = "High", "allows **any** traffic from the internet"
                    elif port in SENSITIVE_PORTS:
                        sev, why = "High", f"exposes **{SENSITIVE_PORTS[port]} ({port})** to the whole internet"
                    else:
                        continue
                    findings.append({**base, "title": f"Permissive WAN rule: {rule['description'] or rule['uuid']}", "severity": sev,
                                     "description": f"Enabled inbound rule on {rule['interface']} {why} (destination {rule['destination']}, port {port}).",
                                     "mitigation": "Restrict the source to known addresses (alias) or remove the rule; prefer VPN access.",
                                     "unique_id": f"opnsense:rule:{rule['uuid']}:permissive", "tags": ["firewall", "network-security"],
                                     "component_name": "firewall-rule"})
            res.stats["rules"] = rules
            res.stats["rules_total"] = len(rules)
        except ConnectorError as e:
            res.warnings.append(f"filter rules unavailable ({e})")

        # firewall log: blocked inbound from public sources -> attack map
        if self.options.get("attack_events", True):
            try:
                from orasec.posture import geo  # noqa: PLC0415
                log = self.http.get("/api/diagnostics/firewall/log", params={"limit": 2000})
                events, blocked = [], 0
                for e in log if isinstance(log, list) else []:
                    if e.get("action") != "block" or e.get("dir") != "in":
                        continue
                    blocked += 1
                    ts = e.get("__timestamp__")
                    try:
                        when = timezone.make_aware(datetime.datetime.fromisoformat(ts)) if ts and "+" not in ts else datetime.datetime.fromisoformat(ts)
                    except (TypeError, ValueError):
                        when = timezone.now()
                    events.append({"event_id": e.get("__digest__") or f"{ts}-{e.get('src')}-{e.get('dstport')}", "occurred_at": when,
                                   "src_ip": e.get("src", ""), "dst_ip": e.get("dst", ""), "dst_port": int(e["dstport"]) if str(e.get("dstport", "")).isdigit() else None,
                                   "protocol": e.get("protoname", ""), "target": name, "rule": f"rule {e.get('rulenr')} ({e.get('reason')})",
                                   "detail": f"{e.get('interface')} {e.get('tcpflags', '')}".strip()})
                res.stats["blocked_inbound_in_log"] = blocked
                res.stats["attack_events_new"] = geo.store_events("opnsense", events)
            except ConnectorError as e:
                res.warnings.append(f"firewall log unavailable ({e})")

        rec.scanned = True
        res.assets.append(rec)
        res.batches.append(TestBatch(title=f"OPNsense: {name}", scan_type=CONNECTOR_SCAN_TYPES["opnsense"],
                                     payload={"findings": findings}, count=len(findings), product_name=self.options.get("product_name")))
        return res


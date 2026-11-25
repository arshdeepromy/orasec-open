"""
UniFi Network connector (official UniFi Network Integration API v1, local console).

Base URL: https://<console>  — paths under /proxy/network/integration (+ /v1/...), header X-API-KEY. Verified on Network 11.0.99.
List endpoints take offset/limit (max 200) and return {offset, limit, count, totalCount, data}.
  GET /v1/info                                   application version
  GET /v1/sites                                  sites
  GET /v1/sites/{s}/devices                      adopted devices: model, firmwareVersion, firmwareUpdatable, state, supported
  GET /v1/sites/{s}/clients                      connected clients (type WIRED/WIRELESS/VPN/TELEPORT)
  GET /v1/sites/{s}/wifi/broadcasts              SSIDs incl. securityConfiguration
  GET /v1/sites/{s}/firewall/zones|policies      zone-based firewall
  GET /v1/sites/{s}/networks, /wans, /vpn/servers   inventory context
Attack map (UniFi internal v2 API, same X-API-KEY, verified on Network 11.0.99):
  POST /proxy/network/v2/api/site/{ref}/traffic-flows   {"action":["blocked"],"timestampFrom","timestampTo","pageSize","pageNumber"}
       blocked incoming flows: source ip/region, destination ip/port, blocking policy (Region Blocking, firewall, ...)
  POST /proxy/network/v2/api/site/{ref}/system-log/all   {"categories":["SECURITY"], ...}
       IPS events THREAT_BLOCKED (SRC_IP, DST_IP, severity)
Read-only: the connector only issues GET requests.

Secrets: {"api_key": "..."}.
Options: {"site": "default" (name or id; blank = all), "clients": true}
"""
import ipaddress
import datetime

from django.utils import timezone

from orasec import site as site_profile
from orasec.posture.connectors.base import CONNECTOR_SCAN_TYPES, AssetRecord, BaseConnector, CollectResult, ConnectorError, TestBatch, register

API = "/proxy/network/integration"
DEVICE_TYPE = {"gateway": "firewall", "switching": "switch", "accessPoint": "access_point"}
WEAK_WIFI = {"OPEN": ("High", "an open (unencrypted) network"), "WEP": ("High", "WEP, which is broken"),
             "WPA_PERSONAL": ("Medium", "WPA (TKIP), which is deprecated"), "WPA1": ("Medium", "WPA1, which is deprecated")}


def in_subnets(ip, subnets):
    try:
        addr = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return False
    return any(addr in n for n in subnets)


@register
class UniFiConnector(BaseConnector):
    kind = "unifi"
    secret_fields = ("api_key",)

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.http.session.headers.update({"X-API-KEY": self.secrets.get("api_key", ""), "Accept": "application/json"})

    def _paged(self, path, **params):
        offset = 0
        while True:
            page = self.http.get(f"{API}{path}", params={**params, "offset": offset, "limit": 200})
            data = page.get("data", [])
            yield from data
            offset += len(data)
            if not data or offset >= page.get("totalCount", 0):
                return

    def test(self):
        info = self.http.get(f"{API}/v1/info")
        sites = list(self._paged("/v1/sites"))
        return f"UniFi Network {info.get('applicationVersion', '?')} — {len(sites)} site(s)"

    def _v2_pages(self, ref, path, body, max_pages):
        out = []
        for page in range(max_pages):
            r = self.http.post(f"/proxy/network/v2/api/site/{ref}{path}", json={**body, "pageSize": 500, "pageNumber": page})
            data = r.get("data", []) if isinstance(r, dict) else (r or [])
            out.extend(data)
            if not (isinstance(r, dict) and r.get("has_next")) or not data:
                break
        return out

    def _attacks(self, site, res):
        """Blocked inbound flows and IPS threat events -> AttackEvent rows (attack map)."""
        from orasec.posture import geo  # noqa: PLC0415
        ref = site.get("internalReference") or "default"
        hours = int(self.options.get("attack_window_hours", 24))
        now = timezone.now()
        body = {"timestampFrom": int((now - datetime.timedelta(hours=hours)).timestamp() * 1000), "timestampTo": int(now.timestamp() * 1000)}
        ms = lambda v: datetime.datetime.fromtimestamp(int(v) / 1000, tz=datetime.UTC)  # noqa: E731
        events = []
        try:
            for f in self._v2_pages(ref, "/traffic-flows", {**body, "action": ["blocked"]}, int(self.options.get("attack_max_pages", 20))):
                src, dst = f.get("source") or {}, f.get("destination") or {}
                if f.get("direction") not in (None, "incoming") or not src.get("ip"):
                    continue
                events.append({"event_id": f"flow:{f.get('id')}", "occurred_at": ms(f.get("time") or f.get("flow_start_time")), "src_ip": src["ip"],
                               "country": src.get("region") if len(src.get("region") or "") == 2 else "", "dst_ip": dst.get("ip", ""),
                               "dst_port": dst.get("port"), "protocol": f.get("protocol", ""),
                               "target": dst.get("device_name") or dst.get("ip", ""), "action": "block", "hits": int(f.get("count") or 1),
                               "rule": ", ".join(p.get("name", "") for p in f.get("policies") or []) or "UniFi firewall",
                               "detail": f"{f.get('service', '')} {dst.get('zone_name', '')} risk {f.get('risk', '')}".strip()})
            res.stats["blocked_flows"] = len(events)
        except ConnectorError as e:
            res.warnings.append(f"traffic flows unavailable ({str(e)[:120]})")
        n_flows = len(events)
        try:
            for ev in self._v2_pages(ref, "/system-log/all", {**body, "categories": ["SECURITY"]}, int(self.options.get("attack_max_pages", 20))):
                p = ev.get("parameters") or {}
                if ev.get("event") != "THREAT_BLOCKED" or "SRC_IP" not in p:
                    continue  # SRC_CLIENT variants are outbound blocks from our own devices
                events.append({"event_id": f"ips:{ev.get('id')}", "occurred_at": ms(ev["timestamp"]), "src_ip": p["SRC_IP"].get("id", ""),
                               "dst_ip": (p.get("DST_IP") or {}).get("id", ""), "target": (p.get("DST_IP") or {}).get("name", ""),
                               "action": "block", "rule": f"UniFi IPS: {ev.get('title_raw', 'Threat Detected and Blocked')}",
                               "detail": f"{ev.get('severity', '')} {ev.get('subcategory', '')}".strip()})
            res.stats["ips_blocked"] = len(events) - n_flows
        except ConnectorError as e:
            res.warnings.append(f"IPS events unavailable ({str(e)[:120]})")
        res.stats["attack_events_new"] = res.stats.get("attack_events_new", 0) + geo.store_events("unifi", events)

    def _client_subnets(self, site):
        """Subnets of the networks whose clients are company assets (option client_networks, default the site profile's office_networks).
        None means no filter (option set to "*"). Raises ConnectorError if the networks cannot be read, so no
        out-of-scope device is imported by mistake."""
        wanted = self.options.get("client_networks") or list(site_profile.get("office_networks") or [])
        if wanted == "*" or wanted == ["*"]:
            return None
        ref = site.get("internalReference") or "default"
        nets = self.http.get(f"/proxy/network/api/s/{ref}/rest/networkconf").get("data") or []
        out = []
        for n in nets:
            if n.get("name") in wanted and n.get("ip_subnet"):
                try:
                    out.append(ipaddress.ip_interface(n["ip_subnet"]).network)
                except ValueError:
                    continue
        if not out:
            raise ConnectorError(f"none of the in-scope networks {wanted} found")
        return out

    def _web_filtering(self, site):
        """Filtering in force per network, by name. Only names, modes and categories are kept (no tokens)."""
        ref = site.get("internalReference") or "default"
        nets = {n.get("_id"): n.get("name") for n in
                (self.http.get(f"/proxy/network/api/s/{ref}/rest/networkconf").get("data") or [])}
        ips = next((s for s in (self.http.get(f"/proxy/network/api/s/{ref}/get/setting").get("data") or [])
                    if s.get("key") == "ips"), {})
        profiles = self.http.get(f"/proxy/network/v2/api/site/{ref}/content-filtering") or []
        return {
            "site": site.get("name") or ref,
            "ips_mode": ips.get("ips_mode", ""),
            "ips_networks": sorted(nets.get(i, i) for i in ips.get("enabled_networks") or []),
            "ips_categories": len(ips.get("enabled_categories") or []),
            "ad_blocking_networks": sorted(nets.get(c.get("network_id"), c.get("network_id"))
                                           for c in ips.get("ad_blocking_configurations") or [] if c.get("network_id")),
            "content_filtering": [{"name": p.get("name"), "enabled": bool(p.get("enabled")),
                                   "categories": sorted(p.get("categories") or []),
                                   "networks": sorted(nets.get(i, i) for i in p.get("network_ids") or [])}
                                  for p in profiles if isinstance(p, dict)],
        }

    def collect(self):
        res = CollectResult()
        info = self.http.get(f"{API}/v1/info")
        res.stats["application_version"] = info.get("applicationVersion")
        want = (self.options.get("site") or "").strip().lower()
        sites = [s for s in self._paged("/v1/sites") if not want or want in (s.get("id", "").lower(), (s.get("name") or "").lower(), (s.get("internalReference") or "").lower())]
        findings = []
        stats = {"devices": 0, "devices_updatable": 0, "devices_offline": 0, "clients": 0, "ssids": 0, "firewall_policies": 0}
        for site in sites:
            sid, sname = site["id"], site.get("name") or site["id"]
            gateway_key = None
            # ---- devices
            for d in self._paged(f"/v1/sites/{sid}/devices"):
                stats["devices"] += 1
                feats = d.get("features") or []
                feats = list(feats) if isinstance(feats, list) else list(feats.keys())
                atype = next((DEVICE_TYPE[f] for f in ("gateway", "switching", "accessPoint") if f in feats), "network_device")
                label = d.get("name") or d.get("model") or d.get("macAddress")
                key = f"device:{d.get('macAddress') or d['id']}"
                if atype == "firewall":
                    gateway_key = key
                res.assets.append(AssetRecord(
                    key=key, name=label, asset_type=atype, ip_address=d.get("ipAddress") or "", mac_address=(d.get("macAddress") or "").lower(),
                    vendor="Ubiquiti", model=d.get("model") or "", firmware=d.get("firmwareVersion") or "",
                    online=d.get("state") == "ONLINE", internet_exposed=atype == "firewall", scanned=True,
                    attributes={"site": sname, "state": d.get("state"), "features": feats, "firmware_updatable": d.get("firmwareUpdatable"),
                                "supported": d.get("supported")}))
                base = {"host": label, "component_name": d.get("model") or "unifi-device", "component_version": d.get("firmwareVersion")}
                if d.get("firmwareUpdatable"):
                    stats["devices_updatable"] += 1
                    findings.append({**base,
                        "title": f"UniFi firmware update available: {label}",
                        "severity": "High" if atype == "firewall" else "Medium",
                        "description": f"**{label}** ({d.get('model')}) on site *{sname}* runs firmware `{d.get('firmwareVersion')}` and "
                                       "the controller reports a newer firmware is available. Network-device firmware updates routinely fix "
                                       "remotely exploitable vulnerabilities.",
                        "mitigation": "Review the release notes and update the device firmware (UniFi Devices → Update).",
                        "unique_id": f"unifi:{key}:firmware", "tags": ["firmware", "network"]})
                if d.get("state") == "OFFLINE":
                    stats["devices_offline"] += 1
                    findings.append({**base,
                        "title": f"UniFi device offline: {label}",
                        "severity": "Low",
                        "description": f"**{label}** on site *{sname}* is adopted but offline, so it is neither monitored nor patched.",
                        "mitigation": "Restore the device or remove it from the controller if it has been decommissioned.",
                        "unique_id": f"unifi:{key}:offline", "tags": ["inventory", "network"]})
                if d.get("supported") is False:
                    findings.append({**base,
                        "title": f"Unsupported UniFi device: {label}",
                        "severity": "Medium",
                        "description": f"The controller marks **{label}** ({d.get('model')}) as not supported; it may no longer receive security updates.",
                        "mitigation": "Plan replacement with a supported model (ISO 27001 A.8.8 / end-of-life management).",
                        "unique_id": f"unifi:{key}:unsupported", "tags": ["end-of-life", "network"]})

            # ---- clients (inventory)
            if self.options.get("clients", True):
                try:
                    subnets = self._client_subnets(site)
                    for c in self._paged(f"/v1/sites/{sid}/clients"):
                        # only clients on the in-scope networks are company assets (default: the office networks)
                        if subnets is not None and not in_subnets(c.get("ipAddress"), subnets):
                            stats["clients_out_of_scope"] = stats.get("clients_out_of_scope", 0) + 1
                            continue
                        stats["clients"] += 1
                        mac = (c.get("macAddress") or "").lower()
                        res.assets.append(AssetRecord(
                            key=f"client:{mac or c['id']}", name=c.get("name") or mac or c["id"], asset_type="client",
                            ip_address=c.get("ipAddress") or "", mac_address=mac, online=True,
                            attributes={"site": sname, "connection": c.get("type"), "connected_at": c.get("connectedAt"),
                                        "access": (c.get("access") or {}).get("type")},
                            parent_key=gateway_key))
                except ConnectorError as e:
                    res.warnings.append(f"{sname}: clients unavailable ({e})")

            # ---- Wi-Fi security
            try:
                for w in self._paged(f"/v1/sites/{sid}/wifi/broadcasts"):
                    stats["ssids"] += 1
                    sec = w.get("securityConfiguration") or {}
                    stype = str(sec.get("type") or sec.get("mode") or "").upper()
                    hotspot = bool(w.get("hotspotConfiguration"))
                    weak = next((v for k, v in WEAK_WIFI.items() if stype == k or stype.startswith(k + "_")), None)
                    if w.get("enabled") and weak and not (stype == "OPEN" and hotspot):
                        findings.append({
                            "title": f"Weak Wi-Fi security on SSID '{w.get('name')}'",
                            "severity": weak[0],
                            "description": f"SSID **{w.get('name')}** on site *{sname}* uses {weak[1]} (`{stype}`).",
                            "mitigation": "Use WPA3 (or WPA2/WPA3 transitional) with a strong passphrase, or 802.1X for staff networks.",
                            "host": w.get("name"), "component_name": "wifi", "unique_id": f"unifi:{sid}:ssid:{w.get('id')}:security",
                            "tags": ["wifi", "crypto"]})
                    elif w.get("enabled") and stype and "WPA3" not in stype and stype not in ("OPEN",):
                        findings.append({
                            "title": f"Wi-Fi SSID '{w.get('name')}' does not use WPA3",
                            "severity": "Info",
                            "description": f"SSID **{w.get('name')}** uses `{stype}`. WPA2 is acceptable, but WPA3 resists offline passphrase cracking.",
                            "mitigation": "Enable WPA3 or WPA2/WPA3 transitional mode where all clients support it.",
                            "host": w.get("name"), "component_name": "wifi", "unique_id": f"unifi:{sid}:ssid:{w.get('id')}:wpa3",
                            "tags": ["wifi", "hardening"]})
            except ConnectorError as e:
                res.warnings.append(f"{sname}: Wi-Fi broadcasts unavailable ({e})")

            # ---- firewall: inbound allow-any from the internet
            try:
                zones = {z["id"]: z.get("name", "") for z in self._paged(f"/v1/sites/{sid}/firewall/zones")}
                for p in self._paged(f"/v1/sites/{sid}/firewall/policies"):
                    stats["firewall_policies"] += 1
                    src = (p.get("source") or {})
                    dst = (p.get("destination") or {})
                    sz, dz = zones.get(src.get("zoneId"), ""), zones.get(dst.get("zoneId"), "")
                    # SYSTEM_DEFINED policies are UniFi's built-ins: stateful "Allow Return Traffic" (established/related only),
                    # IPv6 neighbour discovery and the IKE/ESP rules the site-to-site VPN needs. Only user rules are judged here.
                    user_rule = (p.get("metadata") or {}).get("origin", "USER_DEFINED") != "SYSTEM_DEFINED"
                    if (user_rule and p.get("enabled") and p.get("action", {}).get("type", p.get("action")) == "ALLOW"
                            and sz.lower() in ("external", "internet", "wan") and dz.lower() not in ("external", "internet", "wan")
                            and not dst.get("trafficFilter") and not src.get("trafficFilter")):
                        findings.append({
                            "title": f"UniFi firewall allows any traffic from {sz} to {dz}: '{p.get('name')}'",
                            "severity": "High",
                            "description": f"Enabled policy **{p.get('name')}** on site *{sname}* allows traffic from zone *{sz}* to *{dz}* "
                                           "with no port, address or application filter.",
                            "mitigation": "Restrict the policy to the specific destination hosts and ports that need to be reachable.",
                            "host": sname, "component_name": "firewall-policy", "unique_id": f"unifi:{sid}:policy:{p.get('id')}:any",
                            "tags": ["firewall", "network-security"]})
            except ConnectorError as e:
                res.warnings.append(f"{sname}: firewall policies unavailable ({e})")

            # ---- attack map: blocked inbound flows and IPS detections
            if self.options.get("attack_events", True):
                self._attacks(site, res)

            # ---- web filtering (A.8.23): intrusion prevention, DNS content filtering, ad blocking (internal API, same key)
            try:
                res.stats.setdefault("web_filtering", []).append(self._web_filtering(site))
            except ConnectorError as e:
                res.warnings.append(f"{sname}: web filtering settings unavailable ({e})")

            # ---- context
            for path, keyname in (("/networks", "networks"), ("/wans", "wans"), ("/vpn/servers", "vpn_servers")):
                try:
                    res.stats.setdefault(keyname, []).extend(
                        {k: v for k, v in item.items() if k in ("name", "vlanId", "enabled", "type", "management", "id")}
                        for item in self._paged(f"/v1/sites/{sid}{path}"))
                except ConnectorError as e:
                    res.warnings.append(f"{sname}: {keyname} unavailable ({e})")
        res.stats.update(stats)
        res.batches.append(TestBatch(title="UniFi Network", scan_type=CONNECTOR_SCAN_TYPES["unifi"], payload={"findings": findings},
                                     count=len(findings), product_name=self.options.get("product_name")))
        return res


"""
Cloudflare connector: zones, DNS, TLS/HSTS settings, WAF, email-auth records, tunnels, Access apps and
threat analytics (verified against Free-plan zones).

API token (read-only): Zone: Zone, DNS, Zone Settings, SSL and Certificates, Firewall Services, Analytics, Zone WAF;
Account: Access: Apps and Policies, Account Settings, Cloudflare Tunnel (optional).
  GET  /zones                                            zones
  GET  /zones/{z}/settings                               ssl, min_tls_version, always_use_https, security_header, ...
  GET  /zones/{z}/dns_records                            records (proxied flag, origin exposure)
  GET  /zones/{z}/dnssec                                 DNSSEC status
  GET  /zones/{z}/rulesets/phases/http_request_firewall_managed/entrypoint   managed WAF deployment
  POST /graphql  httpRequests1hGroups                   requests/threats per country per hour (Free plan, 3-day window)
  GET  /accounts/{a}/cfd_tunnel, /accounts/{a}/access/apps   tunnels and Zero Trust apps (topology)

Secrets: {"api_token": "..."}. Options: {"zones": ["example.com", ...] (blank = all), "account_id": "...", "product_name": "..."}
"""
import datetime
import ipaddress

from django.utils import timezone

from orasec.posture.connectors.base import AssetRecord, BaseConnector, CollectResult, ConnectorError, TestBatch, register

GQL = """query($zone: String!, $since: Time!) { viewer { zones(filter: {zoneTag: $zone}) {
  httpRequests1hGroups(limit: 72, filter: {datetime_geq: $since}, orderBy: [datetime_DESC]) {
    dimensions { datetime } sum { requests threats countryMap { clientCountryName requests threats } } } } } }"""
MAIL_HINTS = ("mail", "smtp", "mx", "imap", "pop", "autodiscover", "_domainkey", "_dmarc")


def _public(ip):
    try:
        a = ipaddress.ip_address(ip)
        return not (a.is_private or a.is_loopback or a.is_reserved)
    except ValueError:
        return False


@register
class CloudflareConnector(BaseConnector):
    kind = "cloudflare"
    secret_fields = ("api_token",)

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.http.session.headers.update({"Authorization": f"Bearer {self.secrets.get('api_token', '')}", "Content-Type": "application/json"})

    def _get(self, path, **params):
        r = self.http.get(path, params=params or None)
        if not r.get("success", True):
            msg = f"{path}: {r.get('errors')}"
            raise ConnectorError(msg)
        return r

    def _all(self, path, **params):
        out, page = [], 1
        while True:
            r = self._get(path, page=page, per_page=100, **params)
            out.extend(r.get("result") or [])
            info = r.get("result_info") or {}
            if page >= info.get("total_pages", 1):
                return out
            page += 1

    def test(self):
        v = self._get("/client/v4/user/tokens/verify")
        zones = self._all("/client/v4/zones")
        return f"Cloudflare token {v.get('result', {}).get('status')} — {len(zones)} zones visible"

    def collect(self):  # noqa: C901, PLR0912, PLR0915
        from orasec.posture import geo  # noqa: PLC0415
        res = CollectResult()
        f = []
        want = {z.lower() for z in self.options.get("zones", [])}
        zones = [z for z in self._all("/client/v4/zones") if not want or z["name"].lower() in want]
        topo = {"zones": [], "tunnels": [], "access_apps": []}
        events = []
        since = (timezone.now() - datetime.timedelta(hours=71)).strftime("%Y-%m-%dT%H:00:00Z")

        for z in zones:
            zid, zn = z["id"], z["name"]
            base = {"host": zn, "component_name": "cloudflare-zone"}

            def add(title, sev, desc, key, mit, tags=(), _zn=zn, _base=base):
                f.append({**_base, "title": f"{title} ({_zn})", "severity": sev, "description": desc, "mitigation": mit,
                          "unique_id": f"cloudflare:{_zn}:{key}", "tags": ["cloudflare", *tags]})

            zt = {"name": zn, "id": zid, "plan": (z.get("plan") or {}).get("name"), "status": z.get("status"), "records": []}
            # settings
            try:
                st = {s["id"]: s["value"] for s in self._get(f"/client/v4/zones/{zid}/settings").get("result", [])}
                zt["settings"] = {k: st.get(k) for k in ("ssl", "min_tls_version", "always_use_https", "tls_1_3", "security_level", "browser_check")}
                if st.get("ssl") in ("off", "flexible"):
                    add(f"Cloudflare SSL mode is '{st.get('ssl')}'", "High",
                        f"Traffic between Cloudflare and the origin is **not encrypted** (SSL mode `{st.get('ssl')}`).", "ssl-mode",
                        "Install an origin certificate and set SSL mode to Full (strict).", ["crypto", "tls"])
                elif st.get("ssl") == "full":
                    add("Cloudflare SSL mode is 'full' (not strict)", "Medium", "The origin certificate is not validated.", "ssl-mode",
                        "Use a valid or Cloudflare Origin CA certificate and switch to Full (strict).", ["crypto", "tls"])
                if st.get("min_tls_version") in ("1.0", "1.1"):
                    add(f"Minimum TLS version is {st.get('min_tls_version')}", "Medium", "Clients can negotiate deprecated TLS 1.0/1.1.", "min-tls",
                        "Set Minimum TLS Version to 1.2.", ["crypto", "tls"])
                if st.get("always_use_https") != "on":
                    add("Always Use HTTPS is off", "Medium", "Plain HTTP requests are not redirected to HTTPS.", "always-https",
                        "Enable Always Use HTTPS.", ["crypto", "tls"])
                hsts = ((st.get("security_header") or {}).get("strict_transport_security") or {})
                if not hsts.get("enabled"):
                    add("HSTS is not enabled", "Low", "Browsers are not told to require HTTPS (HTTP Strict Transport Security).", "hsts",
                        "Enable HSTS (max-age ≥ 6 months, include subdomains) once all subdomains serve HTTPS.", ["crypto", "tls"])
                if st.get("security_level") in ("off", "essentially_off"):
                    add("Security level is off", "Medium", "Cloudflare's IP reputation challenge is disabled.", "security-level",
                        "Set Security Level to Medium or higher.", ["waf"])
            except ConnectorError as e:
                res.warnings.append(f"{zn}: settings unavailable ({e})")
            # managed WAF
            try:
                ep = self.http.request("GET", f"/client/v4/zones/{zid}/rulesets/phases/http_request_firewall_managed/entrypoint", expect_json=False)
                ok = ep.status_code == 200 and (ep.json().get("result") or {}).get("rules")
                zt["managed_waf"] = bool(ok)
                if not ok:
                    add("Managed WAF rules not deployed", "Medium", "No Cloudflare Managed Ruleset is deployed on the zone.", "waf",
                        "Deploy the Cloudflare (Free) Managed Ruleset in Security → WAF → Managed rules.", ["waf"])
            except ConnectorError:
                zt["managed_waf"] = None
            # DNSSEC
            try:
                ds = self._get(f"/client/v4/zones/{zid}/dnssec").get("result", {})
                zt["dnssec"] = ds.get("status")
                if ds.get("status") != "active":
                    add("DNSSEC is not active", "Low", f"DNSSEC status: {ds.get('status')}.", "dnssec",
                        "Enable DNSSEC and add the DS record at the registrar.", ["dns"])
            except ConnectorError as e:
                res.warnings.append(f"{zn}: DNSSEC unavailable ({e})")
            # DNS records
            try:
                recs = self._all(f"/client/v4/zones/{zid}/dns_records")
                txt = [r for r in recs if r["type"] == "TXT"]
                dmarc = [r["content"] for r in txt if r["name"].lower() == f"_dmarc.{zn}".lower()]
                spf = [r["content"] for r in txt if r["name"].lower() == zn.lower() and "v=spf1" in r["content"]]
                has_mx = any(r["type"] == "MX" for r in recs)
                if has_mx and not spf:
                    add("No SPF record", "Medium", "The domain receives mail but publishes no SPF policy.", "spf", "Publish an SPF record ending in -all or ~all.", ["email"])
                if has_mx or spf:
                    if not dmarc:
                        add("No DMARC record", "Medium", "Spoofed mail from this domain is not rejected.", "dmarc", "Publish a DMARC record; move to p=quarantine/reject.", ["email"])
                    elif "p=none" in dmarc[0].replace(" ", ""):
                        add("DMARC policy is p=none", "Medium", f"DMARC only monitors (`{dmarc[0][:120]}`); spoofed mail is still delivered.", "dmarc",
                            "After reviewing aggregate reports, move to p=quarantine, then p=reject.", ["email"])
                for r in recs:
                    zt["records"].append({"type": r["type"], "name": r["name"], "content": r["content"][:120], "proxied": r.get("proxied")})
                    if r["type"] in ("A", "AAAA", "CNAME"):
                        res.assets.append(AssetRecord(key=f"dns:{r['name']}", name=r["name"], hostname=r["name"], asset_type="application",
                                                      vendor="Cloudflare", model=f"DNS {r['type']}", internet_exposed=True,
                                                      attributes={"zone": zn, "content": r["content"], "proxied": r.get("proxied"), "type": r["type"]}))
                    if r["type"] in ("A", "AAAA") and not r.get("proxied") and _public(r["content"]) and not any(h in r["name"].lower() for h in MAIL_HINTS):
                        add(f"Unproxied record exposes origin IP: {r['name']}", "Medium",
                            f"`{r['name']}` resolves directly to **{r['content']}**, bypassing Cloudflare's WAF/DDoS protection and revealing the origin.",
                            f"dns:{r['name']}:unproxied", "Proxy the record (orange cloud) or use a Cloudflare Tunnel; restrict the origin to Cloudflare IPs.",
                            ["dns", "exposure"])
                    if r["type"] in ("A", "AAAA") and not _public(r["content"]):
                        add(f"Public DNS points to a private IP: {r['name']}", "Low", f"`{r['name']}` resolves to internal address {r['content']}.",
                            f"dns:{r['name']}:private", "Remove internal records from public DNS (use split-horizon DNS).", ["dns", "information-disclosure"])
            except ConnectorError as e:
                res.warnings.append(f"{zn}: DNS unavailable ({e})")
            # threat analytics (country level on the Free plan)
            try:
                g = self.http.post("/client/v4/graphql", json={"query": GQL, "variables": {"zone": zid, "since": since}})
                rows = (((g.get("data") or {}).get("viewer") or {}).get("zones") or [{}])[0].get("httpRequests1hGroups") or []
                zt["requests_72h"] = sum(x["sum"]["requests"] for x in rows)
                zt["threats_72h"] = sum(x["sum"]["threats"] for x in rows)
                for x in rows:
                    hour = x["dimensions"]["datetime"]
                    for c in x["sum"].get("countryMap") or []:
                        if c.get("threats"):
                            events.append({"event_id": f"{zn}:{hour}:{c['clientCountryName']}", "occurred_at": datetime.datetime.fromisoformat(hour.replace("Z", "+00:00")),
                                           "country": c["clientCountryName"], "src_ip": None, "target": zn, "hits": c["threats"], "action": "block",
                                           "rule": "Cloudflare threat (aggregated, Free plan)", "protocol": "https"})
            except ConnectorError as e:
                res.warnings.append(f"{zn}: analytics unavailable ({e})")
            topo["zones"].append(zt)

        acct = self.options.get("account_id") or (zones[0].get("account") or {}).get("id") if zones else None
        if acct:
            for path, key in ((f"/client/v4/accounts/{acct}/cfd_tunnel", "tunnels"), (f"/client/v4/accounts/{acct}/access/apps", "access_apps")):
                try:
                    items = self._all(path, **({"is_deleted": "false"} if key == "tunnels" else {}))
                    topo[key] = [{"id": i.get("id"), "name": i.get("name"), "status": i.get("status"), "domain": i.get("domain"),
                                  "connections": len(i.get("connections") or []), "type": i.get("type")} for i in items]
                except ConnectorError as e:
                    res.warnings.append(f"{key} unavailable ({e})")
        res.stats["topology"] = topo
        res.stats["attack_events_new"] = geo.store_events("cloudflare", events)
        res.stats["threats_72h"] = sum(z.get("threats_72h", 0) for z in topo["zones"])
        res.batches.append(TestBatch(title="Cloudflare edge", scan_type="OraSec Cloudflare", payload={"findings": f}, count=len(f),
                                     product_name=self.options.get("product_name")))
        return res


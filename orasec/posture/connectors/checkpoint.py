"""
Check Point connector: reads the firewall policy from Check Point management (a Smart-1 Cloud tenant or an on-prem
Security Management or Multi-Domain server) and works out which machines the internet can reach through the
firewall, on which ports, and which rule opens each one.

Read-only, three ways
1. On the Check Point side the administrator has a Read Only permission profile with "Management API Login".
2. Every session is opened with ``login {"read-only": true}``. If the server reports a session that is not
   read-only, the connector logs out and stops.
3. The client sends only ``login``, ``logout``, ``keepalive`` and ``show-*``. Every Web API command is a POST, so
   the verb says nothing about writing; the command name does, and anything else is refused before a request is
   built. It talks to the management API only, never to a gateway.

TLS is always verified for this connector, whatever the "verify TLS" box says: an on-prem server with a private
certificate needs a certificate this server trusts.

Two ways to reach management (option ``auth_mode``)
- "direct" (default): Base URL = the Management API URL, https://<server>/web_api or
  https://<tenant>.maas.checkpoint.com/<context>/web_api ("/web_api" is added when missing).
- "portal": Base URL = the Authentication URL from the Check Point Portal API Keys page (service Smart-1 Cloud).
  Options ``client_id``; secret ``portal_secret``. The Management API URL is built from the Smart-1 Cloud service
  details unless option ``management_url`` is set. The portal token alone is not a management login: the rule base
  still needs the administrator below.
Management login (both modes): secret ``api_key`` (a read-only administrator's API key), or Username + secret
``password``.

Options: {"auth_mode": "direct", "client_id": "", "management_url": "", "domain": "", "packages": ["Standard"],
          "product_name": "Network perimeter"}

Reads: show-gateways-and-servers, show-packages, the object inventory (hosts, networks, address ranges, groups,
groups with exclusion, TCP and UDP services, service groups), then for each package the first access layer and
every inline layer its rules apply, and the NAT rule base. A short page or a total that moves while reading fails
the whole run; nothing is imported from a partial read.

Findings (closed again by the next run once the policy no longer allows it)
- High: an administration or database port (SSH, RDP, SMB, SQL, ...) of a known asset open to anyone on the internet.
- Info: the other internet-facing ports of each asset, as one finding per asset.
- High / Medium / Low: broad rules that accept traffic from outside to Any destination.
Assets: the gateways and management servers. Assets the internet can reach are marked internet exposed.
"""
import contextlib
import re
from urllib.parse import urlparse

from orasec.posture.connectors import checkpoint_policy as cp
from orasec.posture.connectors.aws import ADMIN_PORTS
from orasec.posture.connectors.base import (
    AssetRecord,
    BaseConnector,
    CollectResult,
    ConnectorError,
    TestBatch,
    register,
)

INVENTORY = ("show-hosts", "show-networks", "show-address-ranges", "show-groups", "show-groups-with-exclusion",
             "show-services-tcp", "show-services-udp", "show-service-groups")
SESSION_COMMANDS = {"login", "logout", "keepalive"}
PORTAL_READS = {"mgmt-service", "gateways"}


def allowed(command):
    return command in SESSION_COMMANDS or re.fullmatch(r"show-[a-z0-9-]+", command) is not None


def _web_api(url):
    url = (url or "").strip().rstrip("/")
    return url if not url or url.endswith("/web_api") else url + "/web_api"


@register
class CheckPointConnector(BaseConnector):
    kind = "checkpoint"
    secret_fields = ("api_key", "password", "portal_secret")

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.http.verify = True  # never skipped for a firewall manager
        self.portal = self.options.get("auth_mode") == "portal"
        self.base = _web_api(self.options.get("management_url") if self.portal else self.connector.base_url)
        self.sid = ""
        self.bearer = ""

    # --- portal (Smart-1 Cloud service API) -----------------------------------
    def _portal_token(self):
        if self.bearer:
            return self.bearer
        url = (self.connector.base_url or "").strip()
        if not url.lower().startswith("https://"):
            msg = "The Check Point Portal Authentication URL must start with https://"
            raise ConnectorError(msg)
        r = self.http.post(url, json={"clientId": (self.options.get("client_id") or "").strip(), "accessKey": self.secrets.get("portal_secret", "")})
        token = ((r.get("data") or {}).get("token") if isinstance(r.get("data"), dict) else None) or r.get("token")
        if not token:
            msg = "The Check Point Portal accepted the request but returned no token"
            raise ConnectorError(msg)
        self.bearer = token
        return token

    def _portal_get(self, what):
        if what not in PORTAL_READS:
            msg = "Refusing that Smart-1 Cloud service call: this connector only reads the service details and the gateway list"
            raise ConnectorError(msg)
        url = f"https://{urlparse(self.connector.base_url).netloc}/app/maas/api/v1/{what}"
        for attempt in (1, 2):
            try:
                r = self.http.get(url, headers={"Authorization": f"Bearer {self._portal_token()}", "Accept": "application/json"})
                break
            except ConnectorError as e:
                if attempt == 1 and "HTTP 401" in str(e):
                    self.bearer = ""  # the token lasts 30 minutes: fetch a new one once
                    continue
                raise
        if not r.get("success"):
            msg = f"Smart-1 Cloud {what} failed: {str(r.get('message') or '')[:200]}"
            raise ConnectorError(msg)
        return r.get("data") or {}

    def _prepare_portal(self):
        svc = self._portal_get("mgmt-service")
        if not self.base and svc.get("name") and svc.get("sharedSecret"):
            self.base = f"https://{svc['name']}.maas.checkpoint.com/{svc['sharedSecret']}/web_api"
        return svc

    # --- management API -------------------------------------------------------
    def call(self, command, payload=None):
        if not allowed(command):
            msg = f'Refusing to send Check Point command "{command}": this connector only reads'
            raise ConnectorError(msg)
        if not self.base:
            msg = "No Management API URL is known yet"
            raise ConnectorError(msg)
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if command != "login":
            if not self.sid:
                msg = "No Check Point session is open"
                raise ConnectorError(msg)
            headers["X-chkp-sid"] = self.sid
        for attempt in (1, 2):
            if self.portal:
                headers["Authorization"] = f"Bearer {self._portal_token()}"
            try:
                # the URL carries the Smart-1 Cloud context: log the command, not the URL
                return self.http.request("POST", f"{self.base}/{command}", json=payload or {}, headers=headers, timeout=120, log_as=f"web_api/{command}")
            except ConnectorError as e:
                if self.portal and attempt == 1 and "HTTP 401" in str(e):
                    self.bearer = ""
                    continue
                raise
        return {}

    def login(self):
        key, user, password = self.secrets.get("api_key", ""), (self.connector.username or "").strip(), self.secrets.get("password", "")
        payload = {"read-only": True, "session-timeout": 900}
        if key:
            payload["api-key"] = key
        elif user and password:
            payload.update({"user": user, "password": password})
        elif not self.portal:
            msg = "No credentials to log in with: set the management API key, or the user name and password"
            raise ConnectorError(msg)
        if self.options.get("domain"):
            payload["domain"] = str(self.options["domain"]).strip()
        reply = self.call("login", payload)
        sid = str(reply.get("sid") or "")
        if not sid:
            msg = "Check Point accepted the login but returned no session id"
            raise ConnectorError(msg)
        self.sid = sid
        if reply.get("read-only") is False:
            self.logout()
            msg = "Check Point opened a session that is not read-only. Refusing to continue."
            raise ConnectorError(msg)
        return reply

    def logout(self):
        if not self.sid:
            return
        with contextlib.suppress(ConnectorError):  # the session times out on its own
            self.call("logout")
        self.sid = ""

    def each(self, command, payload, key="objects", limit=500):
        """Every row of a paged list. A truncated read raises: it must never look like a smaller estate."""
        out, offset, total = [], 0, None
        while True:
            page = self.call(command, {**payload, "limit": limit, "offset": offset})
            rows = page.get(key) or []
            t = int(page.get("total", len(rows)))
            if total is None:
                total = t
            elif t != total:
                msg = f"Check Point {command} changed size while it was being read ({total}, then {t}). Nothing was imported."
                raise ConnectorError(msg)
            out.extend(r for r in rows if isinstance(r, dict))
            if not rows and len(out) < total:
                msg = f"Check Point {command} stopped at {len(out)} of {total}. Nothing was imported."
                raise ConnectorError(msg)
            offset += limit
            if len(out) >= total or offset >= 1000000:
                return out

    def rulebase(self, command, payload):
        rules, dictionary, offset, total, limit = [], {}, 0, None, 100

        def flatten(items, section):
            for item in items or []:
                kind = str(item.get("type") or "")
                if kind.endswith("-section"):
                    flatten(item.get("rulebase"), str(item.get("name") or ""))
                elif kind.endswith("-rule"):
                    rules.append({**item, "_section": section})

        while True:
            page = self.call(command, {**payload, "limit": limit, "offset": offset, "details-level": "standard", "use-object-dictionary": True})
            t = int(page.get("total") or 0)
            if total is None:
                total = t
            elif t != total:
                msg = f"Check Point {command} changed while it was being read. Nothing was imported."
                raise ConnectorError(msg)
            for o in page.get("objects-dictionary") or []:
                if isinstance(o, dict) and o.get("uid"):
                    dictionary[str(o["uid"])] = o
            before = len(rules)
            flatten(page.get("rulebase"), "")
            if len(rules) == before and len(rules) < total:
                msg = f"Check Point {command} stopped at {len(rules)} of {total} rules. Nothing was imported."
                raise ConnectorError(msg)
            offset += limit
            if len(rules) >= total or offset >= 200000:
                return rules, dictionary

    def read(self):
        """One complete, consistent read of the policy. Logs out whatever happens."""
        wanted = {str(p).strip() for p in self.options.get("packages") or [] if str(p).strip()}
        self.login()
        try:
            gateways = self.each("show-gateways-and-servers", {"details-level": "full"})
            packages = [p for p in self.each("show-packages", {"details-level": "full"}, key="packages")
                        if not wanted or str(p.get("name") or "") in wanted]
            objects = {}
            for cmd in INVENTORY:
                rows = self.each(cmd, {"details-level": "full"})
                objects.update({str(o["uid"]): o for o in rows if o.get("uid")})
                self.log.append(f"{cmd}: {len(rows)}")
            for g in gateways:
                if g.get("uid"):
                    objects.setdefault(str(g["uid"]), g)
            top, inline, nat = {}, {}, []
            for p in packages:
                pkg, layers = str(p.get("name") or ""), p.get("access-layers") or []
                if not layers:
                    self.log.append(f"Package {pkg} has no access layer; skipped.")
                    continue
                queue, done = [(str(layers[0].get("uid") or ""), False)], set()
                while queue:
                    luid, is_inline = queue.pop(0)
                    if not luid or luid in done:
                        continue
                    done.add(luid)
                    rules, dictionary = self.rulebase("show-access-rulebase", {"uid": luid})
                    for uid, o in dictionary.items():
                        objects.setdefault(uid, o)
                    (inline.setdefault(luid, []) if is_inline else top.setdefault(pkg, [])).extend(rules)
                    queue.extend((str(r["inline-layer"]), True) for r in rules if r.get("inline-layer"))
                    self.log.append(f"Package {pkg}, layer {luid}: {len(rules)} rule(s).")
                rules, dictionary = self.rulebase("show-nat-rulebase", {"package": pkg})
                for uid, o in dictionary.items():
                    objects.setdefault(uid, o)
                nat.extend(rules)
        finally:
            self.logout()
        return {"gateways": gateways, "packages": [str(p.get("name") or "") for p in packages], "objects": objects,
                "top": top, "inline": inline, "nat": nat}

    # --- connector ------------------------------------------------------------
    def test(self):
        lines = []
        if self.portal:
            svc = self._prepare_portal()
            gw = self._portal_get("gateways")
            lines.append(f"Portal key accepted: Smart-1 Cloud service {svc.get('name', '?')} (version {svc.get('version', '?')}), "
                         f"{int(gw.get('total') or len(gw.get('objects') or []))} gateway(s) registered.")
        try:
            login = self.login()
            gws = self.call("show-gateways-and-servers", {"limit": 1, "details-level": "uid"})
            pkgs = self.call("show-packages", {"limit": 1, "details-level": "uid"})
        except ConnectorError as e:
            if lines:  # the portal half works: say so, and what the rule base still needs
                return (lines[0] + f" Reading the rule base needs a management login, and it was not accepted: {str(e)[:200]} "
                        "Add a read-only management administrator (API key, or user name and password).")
            raise
        finally:
            self.logout()
        lines.append(f"Management login accepted (read-only session, API {login.get('api-server-version', '?')}): "
                     f"{int(gws.get('total') or 0)} gateway(s) and server(s), {int(pkgs.get('total') or 0)} policy package(s) visible.")
        return " ".join(lines)

    @staticmethod
    def _targets():
        """Every known machine address: {"ip": int, "ref": asset id}."""
        from orasec.posture.models import InventoryAsset  # noqa: PLC0415
        out, names = [], {}
        for a in InventoryAsset.objects.filter(retired=False).exclude(asset_type="client").only("id", "name", "ip_address", "attributes"):
            ips = {a.ip_address} if a.ip_address else set()
            for src in (a.attributes or {}).values():
                if isinstance(src, dict):
                    ips.update(str(x) for x in src.get("ipv4s") or [])
            names[a.id] = a.name
            out.extend({"ip": n, "ref": a.id} for n in {cp.ip2int(i) for i in ips} if n is not None)
        return out, names

    def collect(self):
        res = CollectResult()
        service_gateways = []
        if self.portal:
            self._prepare_portal()
            service_gateways = (self._portal_get("gateways").get("objects") or [])
            self.log.append(f"Smart-1 Cloud service: {len(service_gateways)} registered gateway(s).")
        try:
            snap = self.read()
        except ConnectorError as e:
            if not self.portal:
                raise
            # the gateways are known, the rule base is not: keep the last findings, say why
            res.warnings.append(f"The rule base was not read: the management server did not accept the login ({str(e)[:200]})")
            for g in service_gateways:
                name = str(g.get("name") or "")
                if name:
                    res.assets.append(AssetRecord(key=f"gw:{name}", name=name, hostname=name, asset_type="firewall", vendor="Check Point",
                                                  attributes={"status": g.get("status"), "source": "smart-1 cloud service"}))
            res.stats["gateways"] = len(res.assets)
            return res

        for g in snap["gateways"]:
            name = str(g.get("name") or "")
            if not name:
                continue
            kind = str(g.get("type") or "")
            policy = g.get("policy") or {}
            res.assets.append(AssetRecord(
                key=f"gw:{g.get('uid') or name}", name=name, hostname=name, vendor="Check Point", model=kind[:120],
                asset_type="firewall" if "gateway" in kind.lower() or "cluster" in kind.lower() else "server",
                ip_address=str(g.get("ipv4-address") or ""), firmware=str(g.get("version") or "")[:120],
                attributes={"type": kind, "policy": policy.get("access-policy-name"), "policy_installed": policy.get("access-policy-installed")}))

        policy = cp.Policy(snap["objects"])
        effective = {pkg: policy.effective(rules, snap["inline"]) for pkg, rules in snap["top"].items()}
        targets, names = self._targets()
        out = cp.exposure(targets, policy.nat_forwards(snap["nat"]), effective)
        live = [p for p in out["paths"] if not p["latent"]]

        mgmt = urlparse(self.base).netloc or "checkpoint"
        findings, per_asset = [], {}
        for p in live:
            if p["reach"] != "anyone":
                continue
            per_asset.setdefault(p["ref"], []).append(p)
        for ref, paths in per_asset.items():
            name = names.get(ref, paths[0]["ip"])
            other = {"tcp": [], "udp": []}
            for p in paths:
                admin = sorted(port for port in ADMIN_PORTS if p["protocol"] == "tcp" and p["port_from"] <= port <= p["port_to"])
                whole = (p["port_from"], p["port_to"]) == (1, cp.PORT_MAX)
                how = f"through static NAT on {p['front']}" if p["via"] == "nat" else f"directly on {p['front']}"
                findings.extend({
                    "title": f"Internet can reach {name} on tcp/{port} ({ADMIN_PORTS[port]})", "severity": "High", "host": name,
                    "description": f"The firewall policy lets **anyone on the internet** reach **{name}** ({p['ip']}) on tcp/{port} "
                                   f"({ADMIN_PORTS[port]}), {how}.\n\n- Rule: `{p['rule']}`",
                    "mitigation": "Limit the rule's source to the addresses that need it, or put the service behind a VPN or a zero-trust gateway.",
                    "component_name": "checkpoint-policy", "unique_id": f"checkpoint:{mgmt}:{p['ip']}:tcp:{port}",
                    "tags": ["checkpoint", "exposure", "admin-port"]} for port in (admin if not whole else []))
                if whole:
                    findings.append({
                        "title": f"Internet can reach {name} on every {p['protocol']} port", "severity": "High", "host": name,
                        "description": f"The firewall policy lets **anyone on the internet** reach **{name}** ({p['ip']}) on every "
                                       f"{p['protocol']} port, {how}.\n\n- Rule: `{p['rule']}`",
                        "mitigation": "Replace the Any service with the ports the machine really serves.",
                        "component_name": "checkpoint-policy", "unique_id": f"checkpoint:{mgmt}:{p['ip']}:{p['protocol']}:all",
                        "tags": ["checkpoint", "exposure"]})
                else:
                    other[p["protocol"]].append((p["port_from"], p["port_to"]))
            ports = cp.describe_ports({k: cp.merge(v) for k, v in other.items()})
            if ports:
                rules = sorted({p["rule"] for p in paths})
                findings.append({
                    "title": f"Internet-facing ports on {name}", "severity": "Info", "host": name,
                    "description": f"The firewall policy lets anyone on the internet reach **{name}** on: {ports}.\n\n"
                                   + "\n".join(f"- Rule: `{r}`" for r in rules[:20]),
                    "mitigation": "Confirm each port is meant to be public and that the service behind it is patched.",
                    "component_name": "checkpoint-policy", "unique_id": f"checkpoint:{mgmt}:asset:{ref}:ports", "tags": ["checkpoint", "exposure"]})
        for b in out["broad"]:
            any_port = "any" in b["ports"]
            sev = "Low" if b["reach"] != "anyone" else ("High" if any_port else "Medium")
            who = "anyone on the internet" if b["reach"] == "anyone" else f"{b['sources']} outside source(s)"
            findings.append({
                "title": f"Broad firewall rule: {b['rule']}", "severity": sev,
                "description": f"Rule `{b['rule']}` accepts **{b['ports']}** from {who} to **Any destination**. "
                               "It is not mapped onto single machines here, because that would call every machine exposed.",
                "mitigation": "Name the destinations the rule is for, or remove it if the cleanup rule already covers the intent.",
                "component_name": "checkpoint-policy", "unique_id": f"checkpoint:{mgmt}:broad:{b['rule_uid'] or b['rule']}",
                "tags": ["checkpoint", "broad-rule"]})

        reachable = {p["ref"] for p in live if p["reach"] == "anyone"}
        if reachable:
            from orasec.posture.models import InventoryAsset  # noqa: PLC0415
            InventoryAsset.objects.filter(id__in=reachable, internet_exposed=False).update(internet_exposed=True)

        n_rules = sum(len(r) for r in snap["top"].values()) + sum(len(r) for r in snap["inline"].values())
        res.stats.update({
            "gateways": len(snap["gateways"]), "packages": snap["packages"], "objects": len(snap["objects"]), "rules": n_rules,
            "nat_rules": len(snap["nat"]), "machines_checked": len({t["ref"] for t in targets}),
            "machines_reachable": len({p["ref"] for p in live}), "ways_in": len(live),
            "latent": len([p for p in out["paths"] if p["latent"]]), "broad_rules": len(out["broad"]),
            "exposure": [{**p, "asset": names.get(p["ref"], "")} for p in out["paths"][:500]], "broad": out["broad"][:100]})
        res.batches.append(TestBatch(title="Check Point firewall policy", scan_type="OraSec Check Point", payload={"findings": findings},
                                     count=len(findings), product_name=self.options.get("product_name")))
        return res


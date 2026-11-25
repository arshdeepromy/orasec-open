"""
Wazuh connector (built against the Wazuh 4.14 server API spec and the 4.8+ indexer state indices).

Server API (base_url, e.g. https://wazuh.example.internal:55000):
  POST /security/user/authenticate      basic auth -> JWT (expires after auth_token_exp_timeout, default 900 s)
  GET  /agents                          inventory, paged with offset/limit (<= 500 recommended)
  GET  /syscollector/{id}/os|hardware   OS and hardware inventory
  GET  /sca/{id}                        SCA policies per agent
  GET  /sca/{id}/checks/{policy}?result=failed   failed configuration checks
Indexer (options.indexer_url, e.g. https://wazuh.indexer:9200):
  wazuh-states-vulnerabilities-*        current vulnerability state per agent (scroll API for > 10k)
  wazuh-alerts-*                        alert volume for monitoring metrics, and the security alerts people are told about

Secrets: {"password": "<server API password>", "indexer_username": "...", "indexer_password": "..."}
Options: {"indexer_url": "...", "vuln_product": "Infrastructure hosts", "sca": true, "alerts_level": 12}

Security alerts (collect_security_alerts, read every 5 minutes by orasec.posture.security_alerts, and sent at once by the
Wazuh integration to posture.wazuh_webhook) are only: a break-in attempt, a break-in, or ransomware. Vulnerabilities,
configuration checks, health problems and firewall blocks are never among them. Options, all optional:
  alert_kinds           [[name, [rule groups], lowest level], ...]  default ALERT_KINDS
  alert_watch_paths     file-integrity changes to files that give access (SSH keys, sudo rights, sshd settings, scheduled jobs)
  alert_ignore_paths    ["*.dpkg-*"]  package manager work files
  alert_exclude_groups  ["vulnerability-detector", "sca", "service_availability", "low_diskspace"]
"""
import datetime
import fnmatch

from django.utils import timezone

from orasec.posture.connectors.base import (
    CONNECTOR_SCAN_TYPES,
    AssetRecord,
    BaseConnector,
    CollectResult,
    ConnectorError,
    Http,
    TestBatch,
    register,
)

PAGE = 500

# -- security alerts: only a break-in attempt, a break-in, or ransomware ------------------------------
# Each kind: (name, rule groups, lowest level). An alert counts when it has one of the groups at that level or above.
# Never: vulnerabilities, CIS checks, health (out of memory, disk full), firewall blocks, ordinary maintenance.
ALERT_KINDS = (
    ("Break-in attempt", ("authentication_failures", "authentication_failed", "brute_force", "invalid_login",
                          "attack", "exploit_attempt", "sql_injection", "web_attack"), 10),  # repeated failures, attacks
    ("Break-in", ("authentication_success",), 10),  # a login that succeeded after many failures (Wazuh 40112, level 12)
    ("Break-in", ("rootcheck",), 10),               # rootkit (level 11); the level 7 "anomaly" checks are not
    ("Break-in", ("adduser", "orasec_access_change"), 8),  # new account or group; a change to a file that gives access
    ("Ransomware", ("ransomware",), 0),             # OraSec rules on the Wazuh manager (ransom note, canary file)
)
ALERT_EXCLUDE_GROUPS = ("vulnerability-detector", "sca", "service_availability", "low_diskspace")
# A changed file that gives access, also when the Wazuh rule that raises its level (orasec_access_change) is missing
ALERT_WATCH_PATHS = ("*/.ssh/authorized_keys*", "/etc/sudoers", "/etc/sudoers.d/*", "/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/*",
                     "/etc/crontab", "/etc/cron.d/*")
ALERT_IGNORE_PATHS = ("*.dpkg-*",)
ALERT_FIELDS = ["id", "timestamp", "data.srcip", "data.dstport", "data.protocol", "data.title", "agent.id", "agent.name", "predecoder.hostname",
                "rule.description", "rule.level", "rule.groups", "rule.id", "syscheck.path", "syscheck.event"]


def _alert_rules(options):
    o = options or {}
    kinds = [(str(k[0]), list(k[1]), int(k[2])) for k in o.get("alert_kinds", ALERT_KINDS)]
    return {"kinds": kinds,
            "exclude": list(o.get("alert_exclude_groups", ALERT_EXCLUDE_GROUPS)),
            "watch": list(o.get("alert_watch_paths", ALERT_WATCH_PATHS)),
            "ignore": list(o.get("alert_ignore_paths", ALERT_IGNORE_PATHS))}


def security_alert_query(options, since):
    """Indexer query for the alerts people are told about, from ``since`` (an aware datetime) until now."""
    r = _alert_rules(options)
    wanted = [{"bool": {"filter": [{"terms": {"rule.groups": groups}}, {"range": {"rule.level": {"gte": level}}}]}}
              for _name, groups, level in r["kinds"] if groups]
    if r["watch"]:
        wanted.append({"bool": {"filter": [{"term": {"rule.groups": "syscheck"}},
                                           {"bool": {"should": [{"wildcard": {"syscheck.path": p}} for p in r["watch"]], "minimum_should_match": 1}}],
                                "must_not": [{"wildcard": {"syscheck.path": p}} for p in r["ignore"]]}})
    start = since.astimezone(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    query = {"bool": {"filter": [{"range": {"timestamp": {"gte": start}}}, {"bool": {"should": wanted, "minimum_should_match": 1}}]}}
    if r["exclude"]:
        query["bool"]["must_not"] = [{"terms": {"rule.groups": r["exclude"]}}]
    return query


def alert_kind(options, level, groups, path=""):
    """The same rule as security_alert_query, for one alert already in hand: its kind, or None when people are not told."""
    r = _alert_rules(options)
    groups = set(groups or [])
    if groups & set(r["exclude"]):
        return None
    level = int(level or 0)
    for name, kind_groups, lowest in r["kinds"]:
        if groups & set(kind_groups) and level >= lowest:
            return name
    if (path and "syscheck" in groups and any(fnmatch.fnmatchcase(path, p) for p in r["watch"])
            and not any(fnmatch.fnmatchcase(path, p) for p in r["ignore"])):
        return "Break-in"
    return None


def is_security_alert(options, level, groups, path=""):
    return alert_kind(options, level, groups, path) is not None


def _alert_time(source):
    try:
        return datetime.datetime.fromisoformat(source["timestamp"].replace("Z", "+00:00").replace("+0000", "+00:00"))
    except (KeyError, ValueError):
        return timezone.now()


def alert_detail(options, rule, path=""):
    """Text kept with an attack-map event: the level, the security-alert mark when people are told about it, the rule groups."""
    from orasec.posture import geo  # noqa: PLC0415
    groups = rule.get("groups") or []
    kind = alert_kind(options, rule.get("level"), groups, path)
    mark = f"{geo.SECURITY_ALERT} " if kind else ""
    return f"level {rule.get('level')} {mark}" + ",".join(groups[:4])


def security_alert_event(hit, options=None):
    """One indexer hit -> one attack-map event. The machine that raised it is the target; an attacker address is optional."""
    src = hit.get("_source", {})
    rule, data, fim = src.get("rule") or {}, src.get("data") or {}, src.get("syscheck") or {}
    path = fim.get("path") or ""
    what = rule.get("description") or "Wazuh alert"
    more = path or data.get("title") or ""
    if more and more not in what:
        what = f"{what}: {more}"
    kind = alert_kind(options, rule.get("level"), rule.get("groups"), path)
    if kind:
        what = f"{kind}: {what}"
    port = data.get("dstport")
    agent = src.get("agent") or {}
    target = agent.get("name", "")
    if agent.get("id") == "000":  # sent to the manager by syslog (a firewall): name the sender, not the manager
        target = (src.get("predecoder") or {}).get("hostname") or target
    # Wazuh's own alert id, so the alert sent by the webhook and the one read from the indexer are stored once
    return {"event_id": src.get("id") or hit.get("_id"), "occurred_at": _alert_time(src), "src_ip": data.get("srcip") or "", "host_alert": True,
            "target": target, "dst_port": int(port) if str(port or "").isdigit() else None,
            "protocol": data.get("protocol", ""), "rule": what, "action": "alert", "detail": alert_detail(options, rule, path)}


@register
class WazuhConnector(BaseConnector):
    kind = "wazuh"
    secret_fields = ("password", "indexer_username", "indexer_password", "webhook_token")

    def _login(self):
        user = self.connector.username or "wazuh-wui"
        data = self.http.post("/security/user/authenticate", auth=(user, self.secrets.get("password", "")))
        token = (data.get("data") or {}).get("token")
        if not token:
            msg = "Wazuh API login returned no token"
            raise ConnectorError(msg)
        self.http.session.headers["Authorization"] = f"Bearer {token}"

    def _paged(self, path, params=None):
        params = dict(params or {})
        offset = 0
        while True:
            params.update({"offset": offset, "limit": PAGE})
            data = self.http.get(path, params=params).get("data", {})
            items = data.get("affected_items", [])
            yield from items
            offset += len(items)
            if not items or offset >= data.get("total_affected_items", 0):
                return

    def test(self):
        self._login()
        info = self.http.get("/").get("data", {})
        n = self.http.get("/agents/summary/status").get("data", {}).get("connection", {})
        return f"Wazuh {info.get('api_version', '?')} — {n.get('active', 0)} active / {n.get('total', 0)} agents"

    # -- indexer -------------------------------------------------------------
    def _indexer(self):
        url = self.options.get("indexer_url")
        if not url:
            return None
        ix = Http(url, verify=self.connector.verify_tls, log=self.log, timeout=120)
        ix.session.auth = (self.secrets.get("indexer_username", "admin"), self.secrets.get("indexer_password", ""))
        return ix

    def _scroll(self, ix, index, query, size=2000):
        body = {"size": size, "query": query}
        data = ix.post(f"/{index}/_search?scroll=2m", json=body)
        sid = data.get("_scroll_id")
        hits = data.get("hits", {}).get("hits", [])
        out = list(hits)
        try:
            while hits:
                data = ix.post("/_search/scroll", json={"scroll": "2m", "scroll_id": sid})
                sid = data.get("_scroll_id", sid)
                hits = data.get("hits", {}).get("hits", [])
                out.extend(hits)
        finally:
            if sid:
                try:
                    ix.request("DELETE", "/_search/scroll", json={"scroll_id": sid})
                except ConnectorError:
                    pass
        return out

    # -- security alerts -----------------------------------------------------
    def collect_security_alerts(self, since, limit=500):
        """
        Alerts that point to a suspected hack or unauthorised action since ``since``, newest first, as attack-map events.

        One indexer search with the read-only account; the server API is not used.
        """
        ix = self._indexer()
        if ix is None:
            msg = "No indexer address on this connector (option indexer_url)"
            raise ConnectorError(msg)
        ix.timeout = 30
        body = {"size": limit, "sort": [{"timestamp": "desc"}], "_source": ALERT_FIELDS, "query": security_alert_query(self.options, since)}
        hits = ix.post("/wazuh-alerts-*/_search", json=body).get("hits", {}).get("hits", [])
        return [security_alert_event(h, self.options) for h in hits]

    # -- collection ----------------------------------------------------------
    def collect(self):
        res = CollectResult()
        self._login()
        agents = list(self._paged("/agents", {"select": "id,name,ip,status,os.name,os.version,os.platform,version,lastKeepAlive,group,manager"}))
        active = [a for a in agents if a.get("status") == "active"]
        res.stats.update({"agents_total": len(agents), "agents_active": len(active),
                          "agents_disconnected": sum(1 for a in agents if a.get("status") == "disconnected"),
                          "agents_never_connected": sum(1 for a in agents if a.get("status") == "never_connected")})
        res.stats["agents"] = [{"id": a["id"], "name": a.get("name"), "status": a.get("status"),
                                "last_keepalive": a.get("lastKeepAlive"), "version": a.get("version")} for a in agents]

        ix = self._indexer()
        vuln_product = self.options.get("vuln_product", "Infrastructure hosts")
        sca_total = sca_failed = 0
        for a in agents:
            aid, name = a["id"], a.get("name") or a["id"]
            os_ = a.get("os") or {}
            rec = AssetRecord(key=f"agent:{aid}", name=name, hostname=name, ip_address=a.get("ip", "") if a.get("ip") not in ("any", "127.0.0.1") else "",
                              os_name=os_.get("name", ""), os_version=os_.get("version", ""),
                              asset_type="server", online=a.get("status") == "active",
                              attributes={"agent_id": aid, "status": a.get("status"), "agent_version": a.get("version"),
                                          "last_keepalive": a.get("lastKeepAlive"), "groups": a.get("group", [])})
            if a.get("status") != "active":
                res.assets.append(rec)
                continue
            try:
                osinfo = self.http.get(f"/syscollector/{aid}/os").get("data", {}).get("affected_items", [])
                if osinfo and osinfo[0].get("hostname"):
                    rec.hostname = osinfo[0]["hostname"]   # the machine's own hostname; the agent name stays as an alias
            except ConnectorError as e:
                res.warnings.append(f"{name}: OS inventory unavailable ({e})")
            watch = self.options.get("watch_processes", ["cloudflared"])
            if watch:
                found = set()
                for proc in watch:
                    try:
                        items = self.http.get(f"/syscollector/{aid}/processes", params={"search": proc, "select": "name", "limit": 5}).get("data", {}).get("affected_items", [])
                        if any(proc in (i.get("name") or "") for i in items):
                            found.add(proc)
                    except ConnectorError:
                        break
                rec.attributes["services"] = sorted(found)
            try:
                hw = self.http.get(f"/syscollector/{aid}/hardware").get("data", {}).get("affected_items", [])
                if hw:
                    rec.attributes["cpu"] = (hw[0].get("cpu") or {}).get("name")
                    rec.attributes["ram_mb"] = int(((hw[0].get("ram") or {}).get("total") or 0) / 1024)
            except ConnectorError as e:
                res.warnings.append(f"{name}: hardware inventory unavailable ({e})")

            # vulnerability state (one test per agent, same titles as the previous cron import)
            if ix is not None and aid != "000":
                try:
                    hits = self._scroll(ix, "wazuh-states-vulnerabilities-*", {"term": {"agent.id": aid}})
                    res.batches.append(TestBatch(title=f"Wazuh vulnerabilities: {name}", scan_type="Wazuh",
                                                 payload={"hits": {"hits": hits}}, product_name=vuln_product, count=len(hits)))
                    rec.scanned = True
                    res.stats.setdefault("vulnerability_states", {})[name] = len(hits)
                except ConnectorError as e:
                    res.warnings.append(f"{name}: vulnerability state unavailable ({e})")

            # Security Configuration Assessment: failed checks become findings
            if self.options.get("sca", True):
                findings = []
                try:
                    for pol in self._paged(f"/sca/{aid}"):
                        sca_total += (pol.get("pass", 0) or 0) + (pol.get("fail", 0) or 0)
                        res.stats.setdefault("sca", {})[f"{name}/{pol.get('policy_id')}"] = {
                            "score": pol.get("score"), "pass": pol.get("pass"), "fail": pol.get("fail"),
                            "invalid": pol.get("invalid"), "name": pol.get("name")}
                        for chk in self._paged(f"/sca/{aid}/checks/{pol['policy_id']}", {"result": "failed"}):
                            sca_failed += 1
                            findings.append(self._sca_finding(name, pol, chk))
                except ConnectorError as e:
                    res.warnings.append(f"{name}: SCA unavailable ({e})")
                if findings or aid != "000":
                    res.batches.append(TestBatch(title=f"Wazuh SCA: {name}", scan_type=CONNECTOR_SCAN_TYPES["wazuh_sca"],
                                                 payload={"findings": findings}, product_name=vuln_product, count=len(findings)))
            if aid == "000" and not self.options.get("manager_asset", False):
                continue  # the manager itself; the machine it runs on has its own agent
            res.assets.append(rec)
        res.stats["sca_checks"], res.stats["sca_failed"] = sca_total, sca_failed

        # alert volume (monitoring evidence for the Command Center and ISO A.8.15 / A.8.16)
        if ix is not None:
            level = int(self.options.get("alerts_level", 12))
            try:
                body = {"size": 0, "track_total_hits": True, "query": {"range": {"timestamp": {"gte": "now-24h"}}},
                        "aggs": {"high": {"filter": {"range": {"rule.level": {"gte": level}}}},
                                 "by_agent": {"terms": {"field": "agent.name", "size": 50}}}}
                data = ix.post("/wazuh-alerts-*/_search", json=body)
                res.stats["alerts_24h"] = data.get("hits", {}).get("total", {}).get("value", 0)
                res.stats["alerts_24h_high"] = data.get("aggregations", {}).get("high", {}).get("doc_count", 0)
                res.stats["alerts_by_agent"] = {b["key"]: b["doc_count"] for b in data.get("aggregations", {}).get("by_agent", {}).get("buckets", [])}
            except ConnectorError as e:
                res.warnings.append(f"alert metrics unavailable ({e})")
        # attacker IPs from alerts (auth failures, web attacks, scans, firewall drops) -> attack map
        if ix is not None and self.options.get("attack_events", True):
            try:
                from orasec.posture import geo  # noqa: PLC0415
                groups = self.options.get("attack_groups", ["authentication_failed", "authentication_failures", "invalid_login", "attack", "web",
                                                            "recon", "firewall_drop", "attacks", "accesslog", "exploit_attempt"])
                body = {"size": 2000, "sort": [{"timestamp": "desc"}], "_source": ["timestamp", "data.srcip", "agent.name", "rule.description",
                        "rule.level", "rule.groups", "data.dstport", "data.protocol", "id"],
                        "query": {"bool": {"filter": [{"range": {"timestamp": {"gte": "now-24h"}}}, {"exists": {"field": "data.srcip"}},
                                                      {"terms": {"rule.groups": groups}}]}}}
                hits = ix.post("/wazuh-alerts-*/_search", json=body).get("hits", {}).get("hits", [])
                events = []
                for h in hits:
                    s_ = h.get("_source", {})
                    ip = (s_.get("data") or {}).get("srcip", "")
                    port = (s_.get("data") or {}).get("dstport")
                    events.append({"event_id": h.get("_id"), "occurred_at": _alert_time(s_), "src_ip": ip, "target": (s_.get("agent") or {}).get("name", ""),
                                   "dst_port": int(port) if str(port or "").isdigit() else None, "protocol": (s_.get("data") or {}).get("protocol", ""),
                                   "rule": (s_.get("rule") or {}).get("description", ""), "action": "alert",
                                   "detail": alert_detail(self.options, s_.get("rule") or {})})
                res.stats["attack_alerts_24h"] = len(events)
                res.stats["attack_events_new"] = geo.store_events("wazuh", events)
            except ConnectorError as e:
                res.warnings.append(f"attack alerts unavailable ({e})")
        res.stats["collected_at"] = timezone.now().isoformat()
        return res

    @staticmethod
    def _sca_finding(agent_name, pol, chk):
        compliance = {}
        for c in chk.get("compliance", []) or []:
            compliance.setdefault(c.get("key"), []).append(c.get("value"))
        refs = chk.get("references") or ""
        desc = (chk.get("description") or "") + "\n\n**Rationale:** " + (chk.get("rationale") or "-")
        if chk.get("reason"):
            desc += f"\n\n**Reason:** {chk['reason']}"
        if compliance:
            desc += "\n\n**Compliance mapping:** " + "; ".join(f"{k}: {', '.join(v)}" for k, v in compliance.items())
        return {
            "title": f"SCA: {chk.get('title', 'check ' + str(chk.get('id')))}",
            "severity": "Medium",
            "description": desc,
            "mitigation": chk.get("remediation") or "",
            "references": refs if isinstance(refs, str) else ", ".join(refs),
            "component_name": pol.get("name", pol.get("policy_id")),
            "host": agent_name,
            "unique_id": f"wazuh-sca:{agent_name}:{pol.get('policy_id')}:{chk.get('id')}",
            "tags": ["sca", "configuration", str(pol.get("policy_id"))],
            "category": "configuration",
        }


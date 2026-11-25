"""
Beszel connector: host health hub (agent on every server, workstation and Pi).

Beszel is a PocketBase application. A hub user with the *readonly* role is enough.
  POST /api/collections/users/auth-with-password   -> token (sent as the Authorization header)
  GET  /api/collections/systems/records            name, host, status, info {cpu, mp, dp, dt, bb, la, u, v}
  GET  /api/collections/system_details/records     hostname, os_name, kernel, cpu, cores, threads, memory, arch
  GET  /api/collections/containers/records         containers per system (name, image, status, cpu, memory)
  GET  /api/collections/system_stats/records       1-minute history (used by orasec.posture.health)

The scheduled run feeds the asset inventory: one asset per monitored machine, so a new machine with an agent
appears on the live topology by itself. Live numbers (CPU, memory, disk, network, temperature) are read on
demand by orasec.posture.health and cached for a few seconds; they are not stored in the database.

Username: hub user e-mail. Secret: {"password": "..."}. Options: none required.
"""
import ipaddress

from django.core.cache import cache

from orasec.posture.connectors.base import AssetRecord, BaseConnector, CollectResult, ConnectorError, Http, register

OS_NAMES = {0: "Linux", 1: "macOS", 2: "Windows", 3: "FreeBSD"}
TUNNEL_HINTS = ("cloudflared",)


def _is_ip(v):
    try:
        ipaddress.ip_address(v)
    except ValueError:
        return False
    return True


class BeszelClient:

    """Small authenticated client; the login token is cached so page views don't log in every time."""

    def __init__(self, connector, log=None, timeout=15):
        self.connector = connector
        self.http = Http(connector.base_url, verify=connector.verify_tls, timeout=timeout, log=log)
        self._token = None

    def _cache_key(self):
        stamp = int(self.connector.updated.timestamp()) if getattr(self.connector, "updated", None) else 0
        return f"orasec-beszel-token:{self.connector.pk}:{stamp}"

    def login(self, *, force=False):
        tok = None if force else cache.get(self._cache_key())
        if not tok:
            data = self.http.post("/api/collections/users/auth-with-password",
                                  json={"identity": self.connector.username, "password": self.connector.get_secrets().get("password", "")})
            tok = data.get("token")
            if not tok:
                msg = "Beszel login returned no token"
                raise ConnectorError(msg)
            cache.set(self._cache_key(), tok, 1800)
        self._token = tok
        self.http.session.headers["Authorization"] = tok

    def get(self, path, **params):
        if not self._token:
            self.login()
        try:
            return self.http.get(path, params=params or None)
        except ConnectorError as e:
            if "HTTP 401" not in str(e) and "HTTP 403" not in str(e):
                raise
            self.login(force=True)
            return self.http.get(path, params=params or None)

    def records(self, collection, per_page=200, max_pages=25, **params):
        out = []
        for page in range(1, max_pages + 1):
            items = self.get(f"/api/collections/{collection}/records", page=page, perPage=per_page, skipTotal=1, **params).get("items", [])
            out.extend(items)
            if len(items) < per_page:
                break
        return out


@register
class BeszelConnector(BaseConnector):
    kind = "beszel"
    secret_fields = ("password",)

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.client = BeszelClient(self.connector, log=self.log, timeout=30)

    def test(self):
        systems = self.client.records("systems")
        up = sum(1 for s in systems if s.get("status") == "up")
        return f"Beszel — {up} of {len(systems)} systems up"

    def collect(self):
        res = CollectResult()
        systems = self.client.records("systems", sort="name")
        try:
            details = {d.get("system") or d.get("id"): d for d in self.client.records("system_details")}
        except ConnectorError as e:
            details = {}
            res.warnings.append(f"system details unavailable ({e})")
        try:
            containers = self.client.records("containers", per_page=500, fields="system,name,image,status,health")
        except ConnectorError as e:
            containers = []
            res.warnings.append(f"container list unavailable ({e})")
        by_sys = {}
        for c in containers:
            by_sys.setdefault(c.get("system"), []).append(c)

        stats = {"systems": len(systems), "containers": len(containers), "systems_list": []}
        for s in systems:
            sid, st = s["id"], s.get("status") or "unknown"
            stats[st] = stats.get(st, 0) + 1
            d = details.get(sid, {})
            info = s.get("info") or {}
            cons = by_sys.get(sid, [])
            os_code = d.get("os")
            host = s.get("host") or ""
            names = sorted({c.get("name") or "" for c in cons} - {""})
            tunnel = any(h in (c.get("image") or "").lower() or h in (c.get("name") or "").lower() for c in cons for h in TUNNEL_HINTS)
            mem = d.get("memory") or 0
            res.assets.append(AssetRecord(
                key=f"system:{sid}", name=s.get("name") or d.get("hostname") or sid,
                asset_type="workstation" if os_code in {1, 2} else "server",
                hostname=d.get("hostname") or "", ip_address=host if _is_ip(host) else "",
                online=st == "up",
                attributes={"system_id": sid, "status": st, "agent_version": info.get("v"), "os": d.get("os_name") or OS_NAMES.get(os_code, ""),
                            "platform": OS_NAMES.get(os_code, ""), "kernel": d.get("kernel"), "arch": d.get("arch"), "cpu_model": d.get("cpu"),
                            "cores": d.get("cores"), "threads": d.get("threads"), "memory_gb": round(mem / 1024 ** 3, 1) if mem else None,
                            "containers": len(cons), "container_names": names[:40], "services": ["cloudflared"] if tunnel else []},
            ))
            stats["systems_list"].append({"id": sid, "name": s.get("name"), "status": st, "cpu": info.get("cpu"), "mem": info.get("mp"),
                                          "disk": info.get("dp"), "agent": info.get("v")})
        res.stats = stats
        return res

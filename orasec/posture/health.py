"""
Live host health for the topology (CPU, memory, disk, network, temperature, load, uptime, containers).

Source: the Beszel hub configured as an OraSec connector (kind "beszel"). Numbers are read on demand and cached in
Valkey for a few seconds, so many open topology pages cost one hub call. Nothing here is stored in the database.
"""
import logging

from django.core.cache import cache
from django.utils import timezone

from orasec.posture.connectors.base import ConnectorError

logger = logging.getLogger(__name__)

SNAPSHOT_TTL = 10
DETAIL_TTL = 10
# (warn, critical) thresholds; a Raspberry Pi starts throttling at about 80 °C
THRESHOLDS = {"cpu": (75, 90), "mem": (80, 92), "disk": (85, 95), "temp": (70, 80)}
RANK = {"ok": 0, "unknown": 0, "warn": 1, "crit": 2}


def connector():
    from orasec.posture.models import Connector  # noqa: PLC0415
    return Connector.objects.filter(kind="beszel", enabled=True).first()


def _client(conn):
    from orasec.posture.connectors.beszel import BeszelClient  # noqa: PLC0415
    return BeszelClient(conn, timeout=8)


def level(metric, value):
    if value is None:
        return "unknown"
    warn, crit = THRESHOLDS[metric]
    return "crit" if value >= crit else "warn" if value >= warn else "ok"


def _num(v):
    try:
        return round(float(v), 1)
    except (TypeError, ValueError):
        return None


def summarize(system):
    """One Beszel system record -> the compact health block the topology draws on a node."""
    info = system.get("info") or {}
    status = system.get("status") or "unknown"
    m = {"cpu": _num(info.get("cpu")), "mem": _num(info.get("mp")), "disk": _num(info.get("dp")), "temp": _num(info.get("dt")) or None}
    levels = {k: level(k, v) for k, v in m.items()}
    if status != "up":
        overall = "down" if status == "down" else "unknown"
    else:
        worst = max((RANK[v] for v in levels.values()), default=0)
        overall = {0: "ok", 1: "warn", 2: "crit"}[worst]
    la = info.get("la") or []
    return {"system_id": system["id"], "name": system.get("name"), "status": status, "health": overall, **m, "levels": levels,
            "net_bps": info.get("bb"), "load": la[:3] if isinstance(la, list) else [], "uptime_s": info.get("u"),
            "agent_version": info.get("v"), "updated": system.get("updated")}


def snapshot():
    """{"systems": {system_id: summary}, "fetched": iso, "error": str|None, "configured": bool}."""
    key = "orasec-health:snapshot"
    data = cache.get(key)
    if data is not None:
        return data
    conn = connector()
    if not conn:
        data = {"systems": {}, "fetched": timezone.now().isoformat(), "error": None, "configured": False}
    else:
        try:
            systems = _client(conn).records("systems")
            data = {"systems": {s["id"]: summarize(s) for s in systems}, "fetched": timezone.now().isoformat(), "error": None, "configured": True}
        except ConnectorError as e:
            logger.warning("health snapshot failed: %s", e)
            data = {"systems": {}, "fetched": timezone.now().isoformat(), "error": "Health hub unreachable", "configured": True}
    cache.set(key, data, SNAPSHOT_TTL)
    return data


def _history_point(rec):
    s = rec.get("stats") or {}
    temps = [v for v in (s.get("t") or {}).values() if isinstance(v, (int, float))]
    b = s.get("b") or [None, None]
    return {"t": rec.get("created"), "cpu": _num(s.get("cpu")), "mem": _num(s.get("mp")), "disk": _num(s.get("dp")),
            "temp": _num(max(temps)) if temps else None, "tx": b[0] if len(b) > 0 else None, "rx": b[1] if len(b) > 1 else None,
            "load": (s.get("la") or [None])[0]}


def detail(system_id, points=60):
    """Last hour (1-minute points), hardware details and containers for one system."""
    key = f"orasec-health:detail:{system_id}"
    data = cache.get(key)
    if data is not None:
        return data
    conn = connector()
    if not conn:
        return {"error": "Health monitoring is not configured."}
    sid = "".join(ch for ch in str(system_id) if ch.isalnum())
    cl = _client(conn)
    try:
        system = cl.get(f"/api/collections/systems/records/{sid}")
        hist = cl.get("/api/collections/system_stats/records", filter=f"system='{sid}' && type='1m'", sort="-created", perPage=points, skipTotal=1)
        det = cl.get("/api/collections/system_details/records", filter=f"system='{sid}'", perPage=1, skipTotal=1).get("items", [])
        cons = cl.get("/api/collections/containers/records", filter=f"system='{sid}'", perPage=200, skipTotal=1).get("items", [])
    except ConnectorError as e:
        logger.warning("health detail failed: %s", e)
        return {"error": "Health hub unreachable"}
    d = det[0] if det else {}
    mem = d.get("memory") or 0
    data = {
        "summary": summarize(system),
        "history": [_history_point(r) for r in reversed(hist.get("items", []))],
        "details": {"hostname": d.get("hostname"), "os": d.get("os_name"), "kernel": d.get("kernel"), "cpu": d.get("cpu"), "cores": d.get("cores"),
                    "threads": d.get("threads"), "arch": d.get("arch"), "memory_gb": round(mem / 1024 ** 3, 1) if mem else None},
        "containers": sorted(({"name": c.get("name"), "image": c.get("image"), "status": c.get("status"), "cpu": _num(c.get("cpu")),
                               "memory_mb": _num(c.get("memory")), "health": c.get("health")} for c in cons),
                             key=lambda c: -(c["cpu"] or 0))[:40],
        "fetched": timezone.now().isoformat(),
    }
    cache.set(key, data, DETAIL_TTL)
    return data

"""
Live network topology.

Machines (servers, workstations, Pis, cloud instances) are NOT listed here: they come from the asset inventory, which
the connectors keep current (Wazuh, PatchMon, Beszel, UniFi, AWS). A renamed, added or removed machine shows up on the
next page refresh, and the layout grows to fit. The *site model* below only holds the network fabric that no API
describes on its own (zones, internet, CDN edge, office gateway, cloud firewall, documented links). It is not in the code:
it comes from the site profile (orasec.site, key "topology"); without one a neutral example is drawn. `build()` overlays live data:
  opnsense   IPsec tunnel state/bytes, interfaces, filter rules (non-automatic), firmware
  aws        VPCs, subnets, instances and security-group ingress/egress (replaces the documented SG rules)
  cloudflare tunnels (status/connections) and proxied zones
  unifi      networks / VLAN IDs, WANs, VPN servers
  wazuh / patchmon / semaphore   per-host agent status from the asset inventory
  beszel     live host health (CPU, memory, disk, network, temperature) via orasec.posture.health
Each element records which source supplied it, so the UI can show "live" versus "documented".
"""
import copy
import datetime
import ipaddress
import logging

from django.core.cache import cache
from django.utils import timezone

from orasec import site as site_profile
from orasec.posture.models import Connector, InventoryAsset

logger = logging.getLogger(__name__)

def site_model():
    """The documented network fabric: site profile key "topology" (see orasec.site for the shape and the example)."""
    return site_profile.get("topology") or {}


def _cfg(key, default=None):
    return site_model().get(key, default)


def _fabric_ips():
    """Addresses the site model draws itself (the cloud firewall and any fixed instance), so they are not drawn twice."""
    t = site_model()
    return {ip for ip in [t.get("firewall_ip"), *[n.get("instance_ip") for n in t.get("nodes", [])]] if ip}


def _cloud_networks():
    cidrs = _cfg("cloud_cidr") or []
    out = []
    for c in [cidrs] if isinstance(cidrs, str) else cidrs:
        try:
            out.append(ipaddress.ip_network(c))
        except ValueError:
            logger.warning("site profile: bad cloud_cidr %r", c)
    return out


HOST_TYPES = ("server", "workstation", "cloud_instance")
STALE_DAYS = 14
FIRST_Y, GAP = 215, 140                    # host cards are 120 px tall
ONPREM_X, AWS_X = 118, 1085


def _latest(kind):
    c = Connector.objects.filter(kind=kind, enabled=True).first()
    if not c:
        return None, {}
    run = c.runs.filter(status__in=["ok", "warning"]).first()
    return c, (run.stats if run else {}) or {}


def _asset_status(a):
    if not a:
        return None
    attrs = a.attributes or {}
    agents = []
    for k in ("wazuh", "patchmon", "beszel", "semaphore"):
        v = attrs.get(k)
        if v:
            st = v.get("status") or v.get("agent_status") or ("in inventory" if k == "semaphore" else "")
            agents.append(f"{'health' if k == 'beszel' else k}: {st}".strip(": "))
    return {"asset_id": a.id, "agents": agents, "ip": a.ip_address or "", "os": f"{a.os_name} {a.os_version}".strip() or attrs.get("beszel", {}).get("os", ""),
            "online": a.online, "last_seen": a.last_seen.isoformat() if a.last_seen else ""}


def _sg_lines(sg, direction):
    out = []
    for r in sg.get(direction, []):
        ports = "all ports" if r["ports"] == "all" else r["ports"]
        proto = "all protocols" if r["proto"] == "all" else r["proto"].upper()
        out.append(f"{proto} {ports} {'from' if direction == 'ingress' else 'to'} {r['peer']}" + (f" ({r['description']})" if r.get("description") else ""))
    return out


def _zone_of(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if any(addr in net for net in _cloud_networks()):
        return "aws"
    if addr.is_private:
        return "onprem"
    return None


def _is_manager_pseudo(a):
    """The Wazuh manager reports itself as agent 000 with no IP; it is not a machine of its own."""
    src = a.sources or {}
    return not a.ip_address and set(src) == {"wazuh"} and (a.attributes or {}).get("wazuh", {}).get("agent_id") == "000"


def host_assets():
    """Machines to draw: typed hosts seen recently, one per IP, most-sourced record wins."""
    since = timezone.now() - datetime.timedelta(days=STALE_DAYS)
    qs = list(InventoryAsset.objects.filter(retired=False, asset_type__in=HOST_TYPES, last_seen__gte=since))
    qs.sort(key=lambda a: (-len(a.sources or {}), a.name.lower()))
    seen, out, fabric = set(), [], _fabric_ips()
    for a in qs:
        topo = (a.attributes or {}).get("topology") or {}
        if topo.get("hidden") or _is_manager_pseudo(a):
            continue
        ip = a.ip_address or ""
        if ip in fabric or not _zone_of(ip):
            continue
        if ip in seen:
            continue
        seen.add(ip)
        out.append(a)
    out.sort(key=lambda a: (_zone_of(a.ip_address), 0 if a.asset_type == "server" else 1, a.name.lower()))
    return out


def _services(a):
    attrs = a.attributes or {}
    svc = set()
    for k in ("wazuh", "beszel"):
        svc.update((attrs.get(k) or {}).get("services") or [])
    return svc


def _role(a):
    attrs = a.attributes or {}
    topo = attrs.get("topology") or {}
    if topo.get("role"):
        return topo["role"]
    b = attrs.get("beszel") or {}
    w = attrs.get("wazuh") or {}
    hw = " · ".join(x for x in [b.get("os") or f"{a.os_name} {a.os_version}".strip(),
                                 f"{b['cores']} cores" if b.get("cores") else (w.get("cpu") or ""),
                                 f"{b['memory_gb']} GB RAM" if b.get("memory_gb") else (f"{round(w['ram_mb'] / 1024)} GB RAM" if w.get("ram_mb") else "")] if x)
    names = [n for n in b.get("container_names") or [] if not n.startswith("beszel")]
    runs = f" Runs {len(names)} containers: {', '.join(names[:8])}{'…' if len(names) > 8 else ''}." if names else ""
    return (hw + "." if hw else "") + runs


def _vlan_for(g, ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for v in g["lan"]["vlans"]:
        if addr in ipaddress.ip_network(v["cidr"]):
            return v
    return None


def _maybe_sync_inventory(health_snap, linked_ids):
    """A machine with a new health agent appears without waiting for the next scheduled connector run."""
    unknown = set(health_snap.get("systems", {})) - linked_ids
    if not unknown or not cache.add("orasec-topology:beszel-sync", 1, 120):
        return
    c = Connector.objects.filter(kind="beszel", enabled=True).first()
    if c and c.last_status != "running":
        from orasec.posture.tasks import run_connector_task  # noqa: PLC0415
        try:
            run_connector_task.delay(c.id, "topology")
        except Exception:  # broker down: the schedule will pick it up
            logger.warning("could not queue beszel sync", exc_info=True)


def _layout(g, nodes, hosts):
    """Stack hosts in their zone's column, grow the zones and the canvas to fit, centre the fabric."""
    per_zone = {"onprem": [], "aws": []}
    for n in hosts:
        per_zone[n["zone"]].append(n)
    aws_fixed = [n for n in nodes.values() if n.get("fixed") and n.get("zone") == "aws"]
    rows = max(len(per_zone["onprem"]), len(per_zone["aws"]) + len(aws_fixed), 4)
    height = max(560, (FIRST_Y - 120) + rows * GAP)
    for z in g["zones"]:
        z["h"] = height
    for i, n in enumerate(per_zone["onprem"]):
        n["x"], n["y"] = ONPREM_X, FIRST_Y + i * GAP
    for i, n in enumerate(per_zone["aws"] + aws_fixed):
        n["x"], n["y"] = AWS_X, FIRST_Y + i * GAP
    mid = 120 + height / 2
    for nid in ("gateway", "internet", "firewall"):
        if nid in nodes:
            nodes[nid]["y"] = mid
    g["view"] = {"w": 1200, "h": 120 + height + 40}


def build():  # noqa: C901, PLR0912, PLR0915
    from orasec.posture import health  # noqa: PLC0415
    model = site_model()
    g = copy.deepcopy({k: model.get(k) or ([] if k != "lan" else {}) for k in ("zones", "nodes", "links", "lan")})
    g["lan"].setdefault("vlans", [])
    g["lan"].setdefault("lan_link", {"restrictions": [], "inbound": [], "outbound": []})
    g["lan"].setdefault("admin_link", {"restrictions": [], "inbound": [], "outbound": []})
    fw_ip, fw_name, fabric = model.get("firewall_ip") or "", model.get("firewall_name") or "the cloud firewall", _fabric_ips()
    subnet_labels = model.get("subnet_labels") or {}
    nodes = {n["id"]: n for n in g["nodes"]}
    links = {link["id"]: link for link in g["links"]}
    sources = {}

    # ---- machines from the live inventory
    snap = health.snapshot()
    hosts, by_ip, linked = [], {}, set()
    for a in host_assets():
        zone = _zone_of(a.ip_address)
        attrs = a.attributes or {}
        sid = (attrs.get("beszel") or {}).get("system_id")
        hn = (a.hostname or "").strip()
        n = {"id": f"a{a.id}", "kind": "workstation" if a.asset_type == "workstation" else "server", "label": a.name,
             "sub": " · ".join(x for x in [a.ip_address, hn if hn and hn.lower() != a.name.lower() else ""] if x),
             "zone": zone, "asset_id": a.id, "detail": _role(a), "agents": _asset_status(a), "editable": True}
        if sid:
            linked.add(sid)
            n["health_id"] = sid
            if sid in snap["systems"]:
                n["health"] = snap["systems"][sid]
        b = attrs.get("beszel") or {}
        if b.get("container_names"):
            n["live"] = {"containers": [x for x in b["container_names"] if not x.startswith("beszel")][:30]}
        hosts.append(n)
        nodes[n["id"]] = n
        by_ip[a.ip_address] = n
        if zone == "onprem":
            v = _vlan_for(g, a.ip_address)
            base = g["lan"]["lan_link"] if not v or v["vlan"] == 1 else g["lan"]["admin_link"]
            label = (f"VLAN {v['vlan']}" if v and v["vlan"] else v["name"]) if v else "LAN"
            links[f"gateway-{n['id']}"] = {"id": f"gateway-{n['id']}", "a": "gateway", "b": n["id"], "kind": "vlan", "label": label,
                                       "sub": v["cidr"] if v else a.ip_address, "what": f"{a.name} on {v['name'] if v else 'the LAN'}.", **copy.deepcopy(base)}
            if v is not None:
                v["hosts"].append(n["id"])
        else:
            subnet = ".".join(a.ip_address.split(".")[:3]) + ".0/24"
            links[f"firewall-{n['id']}"] = {"id": f"firewall-{n['id']}", "a": "firewall", "b": n["id"], "kind": "lan", "label": subnet_labels.get(subnet, "Subnet"),
                                            "sub": subnet, "what": f"Routed subnet {subnet}; egress from {a.name} goes through {fw_name} (NAT + firewall).",
                                            "restrictions": [f"No public IP on the instance (all egress via {fw_name})"], "inbound": [], "outbound": [f"All via {fw_name} NAT"]}
        if "cloudflared" in _services(a):
            links[f"cf-{n['id']}"] = {"id": f"cf-{n['id']}", "a": "cloudflare", "b": n["id"], "kind": "tunnel", "label": "Cloudflare Tunnel",
                                      "sub": "outbound only · 7844", "curve": -60 if zone == "onprem" else 60,
                                      "what": f"cloudflared on {a.name} keeps an outbound connection to Cloudflare and serves the published hostnames.",
                                      "restrictions": ["Outbound-initiated: no inbound ports opened on the firewall"],
                                      "inbound": ["None (requests arrive over the established tunnel)"],
                                      "outbound": ["TCP/UDP 7844 (QUIC/HTTP2) to Cloudflare edge", "HTTPS 443 to api.cloudflare.com"]}
    _layout(g, nodes, hosts)
    if snap.get("configured"):
        sources["health"] = snap.get("error") or f"{len(snap['systems'])} agents"
        _maybe_sync_inventory(snap, linked)

    # ---- OPNsense live
    c, st = _latest("opnsense")
    if st and "firewall" in nodes:
        sources["opnsense"] = st.get("product_version", "live")
        n = nodes["firewall"]
        n["live"] = {"version": st.get("product_version"), "firmware": st.get("firmware_status"), "vulnerable_packages": st.get("vulnerable_packages"),
                     "rules": st.get("rules_total"), "interfaces": [f"{i.get('name')} {i.get('addr4')} ({i.get('status')})" for i in st.get("interfaces", []) if i.get("addr4")]}
        n["status"] = "up"
        tun = next(iter(st.get("ipsec") or []), None)
        if tun and "vpn" in links:
            lk = links["vpn"]
            lk["status"] = "up" if tun.get("connected") else "down"
            lk["live"] = {"tunnel": tun.get("name"), "connected": tun.get("connected"), "version": tun.get("version"),
                          "uptime_s": tun.get("uptime_s"), "bytes_in": tun.get("bytes_in"), "bytes_out": tun.get("bytes_out"),
                          "local": tun.get("local_id"), "remote": tun.get("remote")}
            lk["source"] = "opnsense (live)"
        custom = [r for r in st.get("rules", []) if not r.get("automatic") and r.get("enabled")]
        if custom:
            lines = [f"{r['action'].upper()} {r.get('protocol', 'any')} {r.get('source', 'any')} → {r.get('destination', 'any')}:{r.get('destination_port', 'any')}"
                     f" [{r.get('interface') or 'floating'}] {r.get('description', '')}".strip() for r in custom[:25]]
            for lid in ("inet-firewall", "vpn"):
                if lid in links:
                    links[lid]["firewall_rules"] = lines

    # ---- AWS live (security groups per instance, instance state)
    c, st = _latest("aws")
    topo = st.get("topology") if st else None
    if topo:
        sources["aws"] = topo.get("account")
        for region, rt in (topo.get("regions") or {}).items():
            sgs = {s["id"]: s for s in rt.get("security_groups", [])}
            inst_by_ip = {i.get("private_ip"): i for i in rt.get("instances", []) if i.get("private_ip")}
            targets = ([("firewall", "inet-firewall", fw_ip)] if fw_ip and "firewall" in nodes else []) + [
                (n["id"], f"firewall-{n['id']}", ip) for ip, n in by_ip.items() if n["zone"] == "aws"]
            for nid, lid, ip in targets:
                inst = inst_by_ip.get(ip)
                if not inst:
                    continue
                nodes[nid]["status"] = "up" if inst["state"] == "running" else "down"
                nodes[nid].setdefault("live", {}).update({"instance": inst["id"], "state": inst["state"], "type": inst.get("type"), "region": region})
                ins, outs = [], []
                for sid in inst.get("sgs", []):
                    sg = sgs.get(sid if isinstance(sid, str) else sid.get("id"))
                    if sg:
                        ins += [f"[{sg['name']}] {x}" for x in _sg_lines(sg, "ingress")]
                        outs += [f"[{sg['name']}] {x}" for x in _sg_lines(sg, "egress")]
                if (ins or outs) and lid in links:
                    links[lid]["inbound"], links[lid]["outbound"], links[lid]["source"] = ins, outs, "aws (live security groups)"
            for fixed in [n for n in nodes.values() if n.get("instance_ip")]:    # documented instances outside the inventory
                inst = inst_by_ip.get(fixed["instance_ip"])
                if inst:
                    fixed["status"] = "up" if inst["state"] == "running" else "down"
                    fixed["sub"] = f"{fixed['instance_ip']} · {inst['state']}"
            others = [i for i in rt.get("instances", []) if i.get("private_ip") not in fabric and i.get("private_ip") not in by_ip and i["state"] != "terminated"]
            if others and "private" in nodes:
                nodes["private"]["live"] = {"other_instances": [f"{i['name']} {i.get('private_ip')} ({i['state']})" for i in others]}
            zone = next((z for z in g["zones"] if z.get("id") == "aws"), None)
            if zone is None:
                continue
            zone["live"] = {"vpcs": [f"{v['name']} {v['cidr']}{' (default)' if v.get('default') else ''}" for v in rt.get("vpcs", [])],
                            "subnets": [f"{s['name']} {s['cidr']}" for s in rt.get("subnets", [])]}

    # ---- Cloudflare live
    c, st = _latest("cloudflare")
    topo = st.get("topology") if st else None
    if topo and "cloudflare" in nodes:
        sources["cloudflare"] = f"{len(topo.get('zones', []))} zones"
        nodes["cloudflare"]["live"] = {"zones": [z.get("name") for z in topo.get("zones", [])],
                                       "tunnels": [f"{t['name']} ({t.get('status')}, {t.get('connections')} conns)" for t in topo.get("tunnels", [])],
                                       "access_apps": [a.get("domain") or a.get("name") for a in topo.get("access_apps", [])],
                                       "threats_72h": st.get("threats_72h")}
        healthy = any(t.get("status") == "healthy" for t in topo.get("tunnels", []))
        for lk in links.values():
            if lk["kind"] == "tunnel":
                lk["status"] = "up" if healthy else "degraded"
                lk["source"] = "cloudflare (live tunnel status) + host process/container"

    # ---- UniFi live
    c, st = _latest("unifi")
    if st and "gateway" in nodes:
        sources["unifi"] = st.get("application_version", "live")
        nodes["gateway"]["live"] = {"networks": [f"{n.get('name')} (VLAN {n.get('vlanId')})" for n in st.get("networks", [])],
                                "wans": [w.get("name") for w in st.get("wans", [])], "vpn_servers": [v.get("name") for v in st.get("vpn_servers", [])],
                                "devices": st.get("devices"), "offline": st.get("devices_offline"), "clients": st.get("clients")}
        nodes["gateway"]["status"] = "up"

    # ---- node status: health agent first, then inventory agents
    for n in hosts:
        h = n.get("health")
        if h and h["status"] in ("up", "down"):
            n["status"] = h["status"]
        elif n.get("agents"):
            n.setdefault("status", {True: "up", False: "down"}.get(n["agents"]["online"], "up" if n["agents"]["agents"] else "unknown"))
    fw_asset = model.get("firewall_asset")
    fw = InventoryAsset.objects.filter(name__iexact=fw_asset).first() if fw_asset and "firewall" in nodes else None
    if fw:
        nodes["firewall"]["agents"] = _asset_status(fw)
        nodes["firewall"].setdefault("status", "up" if fw.online else "unknown")

    if "internet" in nodes:
        nodes["internet"]["status"] = "up"
    if "gateway" in nodes and (links.get("vpn", {}).get("status") == "up" or nodes["gateway"].get("live")):
        nodes["gateway"]["status"] = "up"  # the office gateway is the far end of a connected tunnel
    if "cloudflare" in nodes and any(lk.get("status") == "up" for lk in links.values() if lk.get("kind") == "tunnel"):
        nodes["cloudflare"]["status"] = "up"
    g["nodes"] = list(nodes.values())
    g["links"] = [lk for lk in links.values() if lk.get("a") in nodes and lk.get("b") in nodes]   # a link to a node the site left out is not drawn
    for lk in g["links"]:
        lk.setdefault("status", "up" if nodes[lk["a"]].get("status") != "down" and nodes[lk["b"]].get("status") != "down" else "down")
        lk.setdefault("source", "documented" if not lk["id"].startswith(("gateway-a", "firewall-a", "cf-a")) else "inventory (live)")
    for n in g["nodes"]:
        n.setdefault("status", "unknown")
    g["sources"] = sources
    g["fallback_cloud_rows"] = model.get("fallback_cloud_rows") or []
    g["health_error"] = snap.get("error")
    g["generated"] = timezone.now().isoformat()
    return g


def health_only():
    """Cheap poll for the page: per-node health and status, no layout."""
    from orasec.posture import health  # noqa: PLC0415
    snap = health.snapshot()
    out = {}
    for a in host_assets():
        sid = ((a.attributes or {}).get("beszel") or {}).get("system_id")
        if sid and sid in snap["systems"]:
            out[f"a{a.id}"] = snap["systems"][sid]
    return {"nodes": out, "error": snap.get("error"), "fetched": snap.get("fetched")}

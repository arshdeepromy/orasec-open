"""
Check Point policy reader: which machines the internet can reach through the firewall, on which ports, and which
rule opens each one. Pure logic, no I/O: it works on the objects, rules and NAT rules the connector has read.

Addresses are integers, address sets and port sets are sorted lists of inclusive ``(low, high)`` ranges.

How exposure is worked out
- Sources. ``Any``, the ``Internet`` object and security zones named as external mean *anyone*. Public addresses
  mean *listed*. Private-only sources are internal traffic and are ignored. A negated source covers the internet
  unless the column already did. Objects that cannot be resolved (dynamic, updatable, domain objects, access
  roles) make a source *listed*, never *anyone*.
- Destinations. Hosts, networks, ranges, groups (nested), groups with exclusion, gateways. A rule to ``Any`` (or
  with a negated destination) is not mapped onto machines, which would call the whole estate exposed; it is
  reported as a broad rule instead.
- Services. TCP and UDP ports and ranges, service groups, ``Any``, negation. ICMP and other protocols open
  nothing that listens and are left out.
- First match. Rules are walked in order for each machine address. An Accept opens the ports not already decided;
  a Drop or Reject whose source is *anyone* closes them for every rule below. Disabled rules are skipped.
- Inline layers. The parent rule narrows the inner rules.
- Static NAT and port forwards. Automatic static NAT on a host forwards every port, for anyone. A manual rule from
  one public address to one private address forwards only its original service, for its original source.
- A private machine that policy allows but that has no public address and no NAT is *latent*: the policy would let
  the traffic through if a route appeared.

Known limits: only the first ordered layer of each package is read (a later layer can still block a port shown open
here, it cannot open one shown closed); which gateway a machine sits behind is not known, so every package is read
against every machine; time objects, install-on, VPN columns and access roles are ignored.
"""
import hashlib
import ipaddress
import json
import re

PORT_MAX = 65535
ALL_PORTS = [(1, PORT_MAX)]
PRIVATE = [(int(n.network_address), int(n.broadcast_address)) for n in map(ipaddress.ip_network, (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16"))]


# --- addresses and ranges ---------------------------------------------------
def ip2int(ip):
    try:
        return int(ipaddress.IPv4Address(str(ip).strip()))
    except (ipaddress.AddressValueError, ValueError):
        return None


def int2ip(n):
    return str(ipaddress.IPv4Address(n))


def is_private(n):
    return any(lo <= n <= hi for lo, hi in PRIVATE)


def cidr(net, length):
    base = ip2int(net) or 0
    size = 2 ** (32 - max(0, min(32, int(length))))
    lo = base - (base % size)
    return (lo, lo + size - 1)


def merge(ranges):
    out = []
    for lo, hi in sorted(ranges):
        if out and lo <= out[-1][1] + 1:
            out[-1] = (out[-1][0], max(out[-1][1], hi))
        else:
            out.append((int(lo), int(hi)))
    return out


def subtract(a, b):
    out = []
    b = merge(b)
    for part in merge(a):
        parts = [part]
        for xlo, xhi in b:
            nxt = []
            for lo, hi in parts:
                if xhi < lo or xlo > hi:
                    nxt.append((lo, hi))
                    continue
                if xlo > lo:
                    nxt.append((lo, xlo - 1))
                if xhi < hi:
                    nxt.append((xhi + 1, hi))
            parts = nxt
        out.extend(parts)
    return out


def intersect(a, b):
    out = []
    for xlo, xhi in merge(a):
        for ylo, yhi in merge(b):
            lo, hi = max(xlo, ylo), min(xhi, yhi)
            if lo <= hi:
                out.append((lo, hi))
    return merge(out)


def covers(ranges, n):
    return any(lo <= n <= hi for lo, hi in ranges)


def port_range(spec):
    spec = str(spec or "").strip()
    if m := re.fullmatch(r"(\d+)", spec):
        return (int(m[1]), int(m[1]))
    if m := re.fullmatch(r"(\d+)\s*-\s*(\d+)", spec):
        return (min(int(m[1]), int(m[2])), max(int(m[1]), int(m[2])))
    if m := re.fullmatch(r">\s*(\d+)", spec):
        return (int(m[1]) + 1, PORT_MAX)
    if m := re.fullmatch(r"<\s*(\d+)", spec):
        return (1, max(1, int(m[1]) - 1))
    return None


def describe_ports(svc):
    parts = []
    for proto in ("tcp", "udp"):
        items = [str(lo) if lo == hi else ("any" if (lo, hi) == (1, PORT_MAX) else f"{lo}-{hi}") for lo, hi in svc.get(proto) or []]
        if items:
            parts.append(f"{proto} " + ", ".join(items[:12]) + (", …" if len(items) > 12 else ""))
    return "; ".join(parts)


def _uids(col):
    """A rule column is one uid, a list of uids, or a list of objects that carry a uid."""
    if not col:
        return []
    if not isinstance(col, (list, tuple)):
        col = [col]
    uids = [str((v.get("uid") or "") if isinstance(v, dict) else v) for v in col]
    return [u for u in uids if u]


def _empty():
    return {"any": False, "internet": False, "unknown": 0, "ranges": []}


def _union(a, b):
    return {"any": a["any"] or b["any"], "internet": a["internet"] or b["internet"], "unknown": a["unknown"] + b["unknown"],
            "ranges": a["ranges"] + b["ranges"]}


def _is_any(obj):
    return str(obj.get("type") or "").lower() == "cpmianyobject" or (not obj.get("type") and str(obj.get("name") or "").lower() == "any")


class Policy:

    def __init__(self, objects):
        self.objs = objects  # uid -> object
        self._addr = {}
        self._svc = {}

    def obj(self, uid):
        return self.objs.get(uid) or {}

    def name(self, uid):
        return str(self.obj(uid).get("name") or uid)

    # --- address columns ----------------------------------------------------
    def addresses(self, uid, depth=0):
        if uid in self._addr:
            return self._addr[uid]
        res = _empty()
        if depth > 20:
            return res
        o = self.obj(uid)
        kind, name = str(o.get("type") or "").lower(), str(o.get("name") or "").lower()
        if _is_any(o):
            res["any"] = True
        elif "internet" in kind or name == "internet":
            res["internet"] = True
        elif kind == "security-zone":
            if "external" in name:
                res["internet"] = True
            else:
                res["unknown"] += 1
        elif kind == "network":
            if ip2int(o.get("subnet4")) is not None:
                res["ranges"].append(cidr(o.get("subnet4"), o.get("mask-length4", 32)))
            else:
                res["unknown"] += 1
        elif kind == "address-range":
            a, b = ip2int(o.get("ipv4-address-first")), ip2int(o.get("ipv4-address-last"))
            if a is not None and b is not None:
                res["ranges"].append((min(a, b), max(a, b)))
            else:
                res["unknown"] += 1
        elif kind == "group":
            for m in _uids(o.get("members")):
                res = _union(res, self.addresses(m, depth + 1))
        elif kind == "group-with-exclusion":
            inc = self.addresses((_uids(o.get("include")) or [""])[0], depth + 1)
            exc = self.addresses((_uids(o.get("except")) or [""])[0], depth + 1)
            res = dict(inc)
            res["ranges"] = subtract(inc["ranges"], exc["ranges"])
        else:
            ip = ip2int(o.get("ipv4-address"))
            if ip is not None:
                res["ranges"].append((ip, ip))
            else:
                res["unknown"] += 1
        res["ranges"] = merge(res["ranges"])
        self._addr[uid] = res
        return res

    def column(self, col):
        res = _empty()
        for u in _uids(col):
            res = _union(res, self.addresses(u))
        res["ranges"] = merge(res["ranges"])
        return res

    def column_is_any(self, col):
        uids = _uids(col)
        return not uids or any(_is_any(self.obj(u)) or str(self.obj(u).get("name") or "").lower() == "any" for u in uids)

    # --- services -----------------------------------------------------------
    def services(self, uid, depth=0):
        if uid in self._svc:
            return self._svc[uid]
        out = {"tcp": [], "udp": []}
        if depth > 20:
            return out
        o = self.obj(uid)
        kind = str(o.get("type") or "").lower()
        if _is_any(o):
            out = {"tcp": list(ALL_PORTS), "udp": list(ALL_PORTS)}
        elif kind in {"service-tcp", "service-udp"}:
            r = port_range(o.get("port"))
            if r:
                out["tcp" if kind == "service-tcp" else "udp"].append(r)
        elif kind == "service-group":
            for m in _uids(o.get("members")):
                s = self.services(m, depth + 1)
                out["tcp"] += s["tcp"]
                out["udp"] += s["udp"]
        out = {"tcp": merge(out["tcp"]), "udp": merge(out["udp"])}
        self._svc[uid] = out
        return out

    def rule_services(self, rule):
        out = {"tcp": [], "udp": []}
        for u in _uids(rule.get("service")):
            s = self.services(u)
            out["tcp"] += s["tcp"]
            out["udp"] += s["udp"]
        out = {"tcp": merge(out["tcp"]), "udp": merge(out["udp"])}
        if rule.get("service-negate"):
            out = {"tcp": subtract(ALL_PORTS, out["tcp"]), "udp": subtract(ALL_PORTS, out["udp"])}
        return out

    # --- one rule -----------------------------------------------------------
    def source_reach(self, rule):
        col = self.column(rule.get("source"))
        outside = col["any"] or col["internet"]
        if rule.get("source-negate"):
            return {"reach": "none" if outside else "anyone", "sources": 0}
        if outside:
            return {"reach": "anyone", "sources": 0}
        public = sum(1 for lo, hi in col["ranges"] if not is_private(lo) or not is_private(hi))
        if public or col["unknown"]:
            return {"reach": "listed", "sources": public + col["unknown"]}
        return {"reach": "none", "sources": 0}

    def rule_destinations(self, rule):
        """Address ranges, or None for "anywhere" (Any, the internet, or a negated column)."""
        if rule.get("destination-negate"):
            return None
        col = self.column(rule.get("destination"))
        return None if col["any"] or col["internet"] else col["ranges"]

    def action(self, rule):
        if rule.get("inline-layer"):
            return "layer"
        a = rule.get("action") or ""
        name = str(a.get("name") or "" if isinstance(a, dict) else self.name(str(a))).lower()
        if name in {"accept", "ask", "inform", "allow"}:
            return "allow"
        if name in {"drop", "reject"}:
            return "deny"
        return "layer" if "layer" in name else "other"

    def effective(self, rules, layers, parent=None, depth=0):
        """Rules that matter for traffic from outside, inline layers expanded in place and narrowed by their parent."""
        out = []
        for rule in rules:
            if rule.get("enabled") is False:
                continue
            src = self.source_reach(rule)
            if src["reach"] == "none":
                continue
            dst, svc, act = self.rule_destinations(rule), self.rule_services(rule), self.action(rule)
            if parent:
                if parent["reach"] == "listed" and src["reach"] == "anyone":
                    src = {"reach": "listed", "sources": parent["sources"]}
                if dst is None:
                    dst = parent["dst"]
                elif parent["dst"] is not None:
                    dst = intersect(dst, parent["dst"])
                svc = {"tcp": intersect(svc["tcp"], parent["svc"]["tcp"]), "udp": intersect(svc["udp"], parent["svc"]["udp"])}
            row = {"rule": rule, "reach": src["reach"], "sources": src["sources"], "dst": dst, "svc": svc, "action": act}
            if act == "layer":
                inner = str(rule.get("inline-layer") or "")
                if inner in layers and depth < 5:
                    out.extend(self.effective(layers[inner], layers, row, depth + 1))
                continue
            out.append(row)
        return out

    # --- NAT ----------------------------------------------------------------
    def nat_forwards(self, nat_rules):
        """Forwards by private address: {address: [{"pub", "svc" (None = every port), "reach"}]}."""
        out = {}
        for o in self.objs.values():
            ns = o.get("nat-settings") or {}
            if not ns.get("auto-rule") or str(ns.get("method") or "").lower() != "static":
                continue
            priv, pub = ip2int(o.get("ipv4-address")), ip2int(ns.get("ipv4-address"))
            if priv is not None and pub is not None and priv != pub:
                out.setdefault(priv, {})[f"{pub}|*"] = {"pub": pub, "svc": None, "reach": "anyone"}
        for r in nat_rules:
            if r.get("enabled") is False:
                continue
            od, td = self.column(r.get("original-destination")), self.column(r.get("translated-destination"))
            if len(od["ranges"]) != 1 or len(td["ranges"]) != 1:
                continue
            (a, b), (c, d) = od["ranges"][0], td["ranges"][0]
            if a != b or c != d or a == c:
                continue
            src = self.source_reach({"source": r.get("original-source")})
            if src["reach"] == "none":
                continue
            svc = None if self.column_is_any(r.get("original-service")) else self.rule_services({"service": r.get("original-service")})
            if svc is not None and not svc["tcp"] and not svc["udp"]:
                continue  # ICMP and the like: no port to reach
            key = f"{a}|{hashlib.sha256(json.dumps(svc).encode()).hexdigest()[:12]}|{src['reach']}"
            out.setdefault(c, {})[key] = {"pub": a, "svc": svc, "reach": src["reach"]}
        return {priv: list(fwd.values()) for priv, fwd in out.items()}


def rule_label(rule, package):
    name = str(rule.get("name") or "").strip()
    return f"{package} #{rule.get('rule-number', '?')}" + (f" {name}" if name else "")


def exposure(targets, nat, effective):
    """
    targets: [{"ip": int, "ref": anything}]; nat: Policy.nat_forwards(); effective: {package: Policy.effective()}.
    Returns {"paths": [...], "broad": [...]}. A path: ref, ip, protocol, port_from, port_to, reach (anyone | listed),
    sources, via (direct | nat), front (public address), latent, package, rule, rule_uid.
    """
    paths, broad = [], []
    for package, rules in effective.items():
        broad.extend({"package": package, "rule": rule_label(r["rule"], package), "rule_uid": str(r["rule"].get("uid") or ""),
                      "reach": r["reach"], "sources": r["sources"], "ports": describe_ports(r["svc"])}
                     for r in rules if r["dst"] is None and r["action"] == "allow" and (r["svc"]["tcp"] or r["svc"]["udp"]))
        for t in targets:
            ip = int(t["ip"])
            public = not is_private(ip)
            fronts = ([{"pub": ip, "svc": None, "reach": "anyone"}] if public
                      else [f for f in nat.get(ip, []) if not is_private(int(f["pub"]))])
            decided = {"tcp": [], "udp": []}
            for r in rules:
                if r["dst"] is None or r["action"] == "other":
                    continue
                on_ip = covers(r["dst"], ip)
                via = [f for f in fronts if on_ip or covers(r["dst"], int(f["pub"]))]
                if not on_ip and not via:
                    continue
                for proto in ("tcp", "udp"):
                    open_ports = subtract(r["svc"][proto], decided[proto])
                    if not open_ports:
                        continue
                    if r["action"] == "allow":
                        base = {"ref": t.get("ref"), "ip": int2ip(ip), "protocol": proto, "sources": int(r["sources"]), "package": package,
                                "rule": rule_label(r["rule"], package), "rule_uid": str(r["rule"].get("uid") or "")}
                        if fronts:
                            for f in via:
                                ports = open_ports if f["svc"] is None else intersect(open_ports, f["svc"].get(proto) or [])
                                reach = "anyone" if r["reach"] == "anyone" and f["reach"] == "anyone" else "listed"
                                paths.extend({**base, "port_from": lo, "port_to": hi, "reach": reach, "via": "direct" if public else "nat",
                                              "front": int2ip(int(f["pub"])), "latent": False} for lo, hi in ports)
                        else:
                            paths.extend({**base, "port_from": lo, "port_to": hi, "reach": r["reach"], "via": "direct", "front": "",
                                          "latent": True} for lo, hi in open_ports)
                    if r["reach"] == "anyone":
                        decided[proto] = merge(decided[proto] + open_ports)
    return {"paths": paths, "broad": broad}


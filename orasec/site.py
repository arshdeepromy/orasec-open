"""
Site profile: the facts about *your* organisation and network that the code must never hard-code.

OraSec reads one optional JSON file (setting ``ORASEC_SITE_FILE``, environment variable of the same name). Every key is
optional; anything you leave out falls back to the neutral defaults below, so a fresh install works with no file at
all. Keep the file outside version control: it describes your own network and people.

    {
      "org_name": "Example Ltd",
      "security_contact": "security@example.com",
      "office_cidrs": ["192.168.10.0/24"],
      "topology": {"cloud_cidr": "10.20.0.0/16", "firewall_ip": "10.20.0.11", "nodes": [...], "links": [...]}
    }

See ``readme-docs/SITE-PROFILE.md`` for every key.
"""
import contextlib
import copy
import json
import logging
import threading

from django.conf import settings

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------------------------------------------------
# neutral example network (documentation address ranges only): one office behind a gateway, one cloud VPC behind a
# firewall, a site-to-site VPN between them, public sites behind a CDN edge.  viewBox 1200 x 720
# ---------------------------------------------------------------------------------------------------------------------
EXAMPLE_TOPOLOGY = {
    "cloud_cidr": "10.20.0.0/16",          # addresses inside it are drawn in the cloud zone
    "firewall_ip": "10.20.0.11",           # private address of the cloud firewall (drawn by the site model)
    "firewall_asset": "cloud-fw",          # its name in the asset inventory
    "firewall_name": "the cloud firewall",  # how link descriptions refer to it
    "subnet_labels": {"10.20.2.0/24": "App subnet"},
    "fallback_cloud_rows": ["VPC 10.20.0.0/16", "Public 10.20.0.0/24", "Private 10.20.1.0/24"],
    "zones": [
        {"id": "onprem", "kind": "onprem", "label": "On-prem · Head office", "sub": "Office gateway",
         "x": 24, "y": 120, "w": 400, "h": 560},
        {"id": "aws", "kind": "cloud", "label": "Cloud", "sub": "VPC 10.20.0.0/16",
         "x": 776, "y": 120, "w": 400, "h": 560},
    ],
    "nodes": [
        {"id": "internet", "kind": "internet", "label": "Internet", "x": 600, "y": 400},
        {"id": "cloudflare", "kind": "edge", "label": "Cloudflare edge", "sub": "example.com", "x": 600, "y": 150},
        {"id": "gateway", "kind": "gateway", "label": "Office gateway", "sub": "WAN 198.51.100.20", "zone": "onprem", "x": 365, "y": 400,
         "detail": "Head-office gateway: firewall, intrusion prevention and IPsec peer."},
        {"id": "firewall", "kind": "firewall", "label": "Cloud firewall", "sub": "10.20.0.11 · 203.0.113.10", "zone": "aws", "x": 850, "y": 400,
         "detail": "Public subnet 10.20.0.0/24. NAT, stateful firewall, IPsec responder."},
        {"id": "private", "kind": "subnet", "label": "Private subnet", "sub": "10.20.1.0/24", "zone": "aws", "x": 1085, "y": 430, "fixed": True,
         "detail": "Private subnet routed through the cloud firewall."},
    ],
    "links": [
        {"id": "gateway-inet", "a": "gateway", "b": "internet", "kind": "wan", "label": "WAN", "sub": "198.51.100.20",
         "what": "Head-office internet uplink through the office gateway.",
         "restrictions": ["Default-deny inbound; intrusion prevention enabled", "Public services are published through a tunnel, not port forwards"],
         "inbound": ["UDP 500, 4500 from 203.0.113.10 (IPsec IKE / NAT-T)"], "outbound": ["Any (NAT)"]},
        {"id": "inet-firewall", "a": "internet", "b": "firewall", "kind": "wan", "label": "Public IP", "sub": "203.0.113.10",
         "what": "Cloud internet gateway to the firewall's public interface.",
         "restrictions": ["Security group: UDP 500/4500 from 198.51.100.20/32 only", "No management ports exposed to the internet"],
         "inbound": ["UDP 500 from 198.51.100.20/32", "UDP 4500 from 198.51.100.20/32"], "outbound": ["All"]},
        {"id": "vpn", "a": "gateway", "b": "firewall", "kind": "vpn", "label": "Site-to-site VPN", "sub": "192.168.10.0/24 ⇄ 10.20.0.0/16", "curve": 170,
         "what": "IPsec site-to-site tunnel between head office and the cloud VPC.",
         "restrictions": ["IKEv2 · AES-256 / SHA-256 / DH14 + PFS", "Peers pinned: 198.51.100.20 ⇄ 203.0.113.10"],
         "inbound": ["SSH 22 (patching)", "Monitoring agents to the on-prem collectors"],
         "outbound": ["HTTPS to the firewall's management interface (from the office LAN)"]},
        {"id": "firewall-private", "a": "firewall", "b": "private", "kind": "lan", "label": "Private subnet", "sub": "10.20.1.0/24",
         "what": "Private subnet routed through the cloud firewall.", "restrictions": [], "inbound": [], "outbound": ["All via the firewall"]},
        {"id": "inet-cf", "a": "internet", "b": "cloudflare", "kind": "edge", "label": "Proxied HTTPS", "sub": "443 / 80",
         "what": "Public visitors reach your sites through the CDN proxy (WAF, DDoS protection, TLS).",
         "restrictions": ["Only proxied records are protected", "Unproxied records point straight at the origin"],
         "inbound": ["TCP 443, 80 from anywhere → edge"], "outbound": ["Origin pulls through the tunnel (no inbound origin ports)"]},
    ],
    "lan": {
        "vlans": [{"name": "LAN (default)", "cidr": "192.168.10.0/24", "vlan": 1, "hosts": []},
                  {"name": "Admin VLAN", "cidr": "192.168.20.0/24", "vlan": None, "hosts": []}],
        "lan_link": {"restrictions": ["Same broadcast domain; the gateway inspects routed traffic"],
                     "inbound": ["Services published by each host (see the host's containers and agents)"],
                     "outbound": ["Any via gateway NAT"]},
        "admin_link": {"restrictions": ["Inter-VLAN routed by the gateway; zone policy governs access to the LAN"],
                       "inbound": [], "outbound": ["HTTPS/HTTP to LAN services", "SSH to LAN hosts"]},
    },
}

DEFAULTS = {
    "org_name": "Your organisation",            # shown in page headers, reports and file names
    "security_contact": "",                     # e-mail address shown in the footer and on the support page
    "issues_url": "",                           # where bugs and feature requests go (support page)
    "security_txt_url": "",                     # compliance check A.5.5/A.5.6 fetches it when set
    "review_repos": [],                         # "owner/repo" list for the second-person code review check
    "asset_owners": [],                         # default joint owners for inventory assets, e.g. ["Alex Lee - CTO"]
    "office_cidrs": ["192.168.10.0/24"],        # addresses inside them are "head office"
    "office_networks": ["Office"],              # UniFi network names whose clients are company assets
    "locations": {"cloud": "Cloud", "onprem": "On-premises", "office": "Head office", "information": "Company systems"},
    "attack_map_target": {"name": "Head office", "lat": 0.0, "lon": 0.0, "country": ""},   # country: your ISO code, e.g. "AU"
    "policy_tool": {"name": "the policy tool", "organization": ""},
    "default_product_type": "Infrastructure",
    "notify_emails": [],                        # pre-filled in new automation rules
    "classification_words": {"restricted": [], "confidential": []},   # extra name hints for default classification
    "org_aliases": [],                          # names an impostor may claim to speak for (assistant guardrails)
    "topology": EXAMPLE_TOPOLOGY,
}

_lock = threading.Lock()
_cache = None


def _merge(base, extra):
    out = copy.deepcopy(base)
    for k, v in (extra or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict) and k != "topology":
            out[k] = _merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def _load():
    path = getattr(settings, "ORASEC_SITE_FILE", "") or ""
    data = {}
    if path:
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
            if not isinstance(data, dict):
                raise TypeError("the site file must hold one JSON object")
        except (OSError, ValueError, TypeError):
            logger.exception("site profile %s could not be read; using the built-in defaults", path)
            data = {}
    prof = _merge(DEFAULTS, data)
    if isinstance(data.get("topology"), dict):
        # a site that describes its own network replaces the example drawing, but may leave the simple keys out
        prof["topology"] = {**{k: v for k, v in EXAMPLE_TOPOLOGY.items() if k not in ("zones", "nodes", "links", "lan")},
                            **copy.deepcopy(data["topology"])}
        for k in ("zones", "nodes", "links", "lan"):
            prof["topology"].setdefault(k, copy.deepcopy(EXAMPLE_TOPOLOGY[k]))
    return prof


def profile():
    """The merged site profile (read once per process; call ``reset()`` after changing the file)."""
    global _cache  # noqa: PLW0603
    if _cache is None:
        with _lock:
            if _cache is None:
                _cache = _load()
    return _cache


def get(key, default=None):
    """``get("org_name")`` or dotted ``get("locations.cloud")``."""
    cur = profile()
    for part in key.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


def reset():
    global _cache  # noqa: PLW0603
    _cache = None


@contextlib.contextmanager
def override(**values):
    """For tests: ``with site.override(org_name="Acme"): ...``"""
    global _cache  # noqa: PLW0603
    before = _cache
    _cache = _merge(profile(), values)
    if "topology" in values:
        _cache["topology"] = copy.deepcopy(values["topology"])
    try:
        yield _cache
    finally:
        _cache = before


def org_name():
    return get("org_name") or DEFAULTS["org_name"]


def file_prefix():
    """Safe prefix for downloaded report file names."""
    import re  # noqa: PLC0415
    return re.sub(r"[^A-Za-z0-9]+", "-", org_name()).strip("-") or "OraSec"


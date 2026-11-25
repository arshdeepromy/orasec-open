"""Live asset inventory (ISO/IEC 27001 A.5.9).

One place that answers: what do we have, who owns it, where does it sit, is it
current. Devices and cloud resources are kept current by the connectors
(Wazuh, PatchMon, Beszel, UniFi, AWS, GitHub, DNS); cloud services follow the
supplier register; internal tools and information assets are added by hand.
Nothing here deletes an asset -- assets are retired.
"""
from __future__ import annotations

import datetime
import ipaddress
import logging
from collections import Counter
from typing import Any

from django.core.cache import cache
from django.db.models import Q
from django.utils import timezone

from orasec import site as site_profile
from orasec.posture.models import InventoryAsset

logger = logging.getLogger(__name__)

CACHE_KEY = "orasec:asset-inventory:v1"
CACHE_TTL = 60 * 20
STALE_DAYS = 7

CATEGORIES = [
    ("device", "Devices & network"),
    ("cloud", "Cloud resources"),
    ("code", "Code repositories"),
    ("domain", "Domains & websites"),
    ("cloud service", "Cloud services"),
    ("internal tool", "Internal tools"),
    ("information", "Information"),
]
CATEGORY_LABEL = dict(CATEGORIES)
CATEGORY_SLUG = {"devices": "device", "cloud-resources": "cloud", "code": "code", "domains": "domain",
                 "cloud-services": "cloud service", "internal-tools": "internal tool", "information": "information"}
SLUG_FOR = {v: k for k, v in CATEGORY_SLUG.items()}

def joint_owners() -> list[str]:
    """Default joint owners for inventory assets (site profile key asset_owners)."""
    return list(site_profile.get("asset_owners") or [])


def office_networks():
    out = []
    for cidr in site_profile.get("office_cidrs") or []:
        try:
            out.append(ipaddress.ip_network(cidr))
        except ValueError:
            continue
    return out


DEVICE_TYPES = {"server", "workstation", "firewall", "switch", "access_point", "network_device", "client"}


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------
def category(a: InventoryAsset) -> str:
    cat = (a.attributes or {}).get("category")
    if cat in CATEGORY_LABEL:
        return cat
    n = (a.name or "").lower()
    if n.startswith("s3://") or a.asset_type == "cloud_instance":
        return "cloud"
    if "/" in n and not n.startswith("s3://") and a.asset_type in ("application", "other"):
        return "code"
    if a.asset_type in DEVICE_TYPES:
        return "device"
    if "." in n and " " not in n:
        return "domain"
    return "device" if a.asset_type in ("container",) else "internal tool"


def _ip_in_office(ip: str | None) -> bool:
    try:
        return bool(ip) and any(ipaddress.ip_address(ip) in net for net in office_networks())
    except ValueError:
        return False


def location(a: InventoryAsset, suppliers: dict[str, Any] | None = None) -> str:
    """Where the asset sits, in words. No IP addresses."""
    at = a.attributes or {}
    if at.get("location"):
        return str(at["location"])
    cat = category(a)
    if cat == "cloud service":
        s = (suppliers or {}).get(at.get("supplier_ref") or "")
        return f"Supplier cloud ({s.data_location})" if s and s.data_location else "Supplier cloud"
    if cat == "cloud":
        return site_profile.get("locations.cloud")
    if cat == "code":
        return "GitHub"
    if cat == "domain":
        return "Cloudflare (DNS / edge)"
    if cat == "internal tool":
        return site_profile.get("locations.onprem")
    if cat == "information":
        return str(at.get("held_in") or site_profile.get("locations.information"))
    srcs = set((a.sources or {}).keys())
    if "aws" in srcs or a.asset_type == "cloud_instance":
        return site_profile.get("locations.cloud")
    if _ip_in_office(a.ip_address) or {"unifi", "beszel", "wazuh", "patchmon"} & srcs:
        return site_profile.get("locations.office")
    return "Unknown"


CLASSIFICATIONS = [("public", "Public"), ("internal", "Internal"), ("confidential", "Confidential"), ("restricted", "Restricted")]
CLASS_LABEL = dict(CLASSIFICATIONS)
_RESTRICTED_WORDS = ("customer", "vault", "vaultwarden", "password", "credential", "backup", "uploads", "database")
_CONFIDENTIAL_WORDS = ("isms", "source code", "policy tool", "orasec", "wazuh", "patchmon", "nas")


def _words(level: str, base: tuple) -> tuple:
    """Built-in name hints plus the site's own (site profile key classification_words)."""
    return (*base, *[str(w).lower() for w in (site_profile.get(f"classification_words.{level}") or [])])


def default_classification(a: InventoryAsset) -> str:
    """Default level under POL-010; an explicit attributes["classification"] always wins."""
    n = (a.name or "").lower()
    cat = category(a)
    if any(w in n for w in _words("restricted", _RESTRICTED_WORDS)):
        return "restricted"
    if cat == "information":
        return "confidential"
    if cat == "code" or any(w in n for w in _words("confidential", _CONFIDENTIAL_WORDS)):
        return "confidential"
    if cat in ("cloud",) or a.asset_type in ("server", "firewall", "cloud_instance"):
        return "confidential"
    if cat == "cloud service":
        return "confidential" if (a.attributes or {}).get("business_critical") else "internal"
    if cat == "domain":
        return "public"
    return "internal"


def classification(a: InventoryAsset) -> tuple[str, bool]:
    """(level, set_by_hand)."""
    v = (a.attributes or {}).get("classification")
    if v in CLASS_LABEL:
        return v, True
    return default_classification(a), False


def owners(a: InventoryAsset) -> list[str]:
    joint = list((a.attributes or {}).get("joint_owners") or [])
    if joint:
        return joint
    if a.owner_id:
        u = a.owner
        return [u.get_full_name() or u.username]
    return []


def auto_synced(a: InventoryAsset) -> bool:
    return not (a.attributes or {}).get("manual") and bool(a.sources)


def row(a: InventoryAsset, suppliers=None, open_vulns: int = 0, network: bool = False) -> dict[str, Any]:
    now = timezone.now()
    stale = auto_synced(a) and (not a.last_seen or now - a.last_seen > datetime.timedelta(days=STALE_DAYS))
    r = {"id": a.id, "name": a.name, "category": category(a), "category_label": CATEGORY_LABEL[category(a)],
         "type": a.get_asset_type_display(), "location": location(a, suppliers), "owners": owners(a),
         "criticality": a.criticality, "business_critical": bool((a.attributes or {}).get("business_critical")),
         "sources": "manual" if (a.attributes or {}).get("manual") else ", ".join(sorted((a.sources or {}).keys())),
         "online": a.online, "exposed": a.internet_exposed, "last_seen": a.last_seen, "stale": stale,
         "supplier_ref": (a.attributes or {}).get("supplier_ref") or "", "open_vulns": open_vulns,
         "needs_new_owner": ((a.attributes or {}).get("needs_new_owner") or {}).get("leaver", ""),
         "classification": CLASS_LABEL[classification(a)[0]], "classification_key": classification(a)[0],
         "classification_set": classification(a)[1]}
    if network:
        r.update({"hostname": a.hostname, "ip": a.ip_address, "mac": a.mac_address})
    return r


def _suppliers() -> dict[str, Any]:
    from orasec.posture.grc_models import Supplier  # noqa: PLC0415
    return {s.ref: s for s in Supplier.objects.all()}


def _open_vulns() -> dict[str, int]:
    from django.db.models import Count  # noqa: PLC0415

    from orasec.models import Endpoint  # noqa: PLC0415
    return {h.lower(): n for h, n in Endpoint.objects.filter(findings__active=True, findings__duplicate=False)
            .order_by().values_list("host").annotate(n=Count("findings", distinct=True)) if h}


def rows(qs=None, network: bool = False) -> list[dict[str, Any]]:
    qs = qs if qs is not None else InventoryAsset.objects.filter(retired=False)
    sup, fv = _suppliers(), _open_vulns()
    out = []
    for a in qs.select_related("owner"):
        n = fv.get((a.hostname or "").lower(), 0) or fv.get((a.name or "").lower(), 0)
        out.append(row(a, sup, n, network))
    return out


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
def compute() -> dict[str, Any]:
    from orasec.posture.models import Connector  # noqa: PLC0415
    rs = rows()
    by_cat = Counter(r["category"] for r in rs)
    by_loc = Counter(r["location"] for r in rs)
    by_owner = Counter(o for r in rs for o in (r["owners"] or ["No owner"]))
    by_crit = Counter(str(r["criticality"] or "-") for r in rs)
    by_class = Counter(r["classification"] for r in rs)
    attention = []
    for r in rs:
        why = []
        if not r["owners"]:
            why.append("no owner")
        if r["stale"]:
            why.append(f"not seen for over {STALE_DAYS} days")
        if r["category"] == "cloud service" and not r["supplier_ref"]:
            why.append("not linked to a supplier")
        if r["location"] == "Unknown":
            why.append("location unknown")
        if r.get("needs_new_owner"):
            why.append(f"needs a new owner ({r['needs_new_owner']})")
        if why:
            attention.append({"id": r["id"], "name": r["name"], "category": r["category_label"], "why": ", ".join(why)})
    sources = [{"name": c.name, "kind": c.kind, "status": c.last_status or "never run",
                "last_success": c.last_success_at} for c in Connector.objects.filter(enabled=True).order_by("name")]
    data = {
        "generated": timezone.now(), "total": len(rs),
        "categories": [{"key": k, "slug": SLUG_FOR[k], "label": l, "n": by_cat.get(k, 0)} for k, l in CATEGORIES],
        "business_critical": sum(r["business_critical"] for r in rs),
        "no_owner": sum(1 for r in rs if not r["owners"]),
        "stale": sum(r["stale"] for r in rs),
        "offline": sum(1 for r in rs if r["online"] is False),
        "exposed": sum(1 for r in rs if r["exposed"]),
        "with_vulns": sum(1 for r in rs if r["open_vulns"]),
        "auto_synced": sum(1 for r in rs if r["sources"] != "manual"),
        "by_location": by_loc.most_common(), "by_owner": by_owner.most_common(), "by_criticality": sorted(by_crit.items()),
        "by_classification": [(l, by_class.get(l, 0)) for _, l in CLASSIFICATIONS],
        "attention": attention[:50], "sources": sources,
    }
    cache.set(CACHE_KEY, data, CACHE_TTL)
    return data


def dashboard(refresh: bool = False) -> dict[str, Any]:
    if not refresh:
        d = cache.get(CACHE_KEY)
        if d:
            return d
    return compute()


def filtered(params) -> Any:
    qs = InventoryAsset.objects.filter(retired=False) if params.get("retired") != "1" else InventoryAsset.objects.all()
    if params.get("q"):
        q = params["q"]
        qs = qs.filter(Q(name__icontains=q) | Q(hostname__icontains=q))
    if params.get("type"):
        qs = qs.filter(asset_type=params["type"])
    return qs


def apply_row_filters(rs: list[dict], params) -> list[dict]:
    cat = CATEGORY_SLUG.get(params.get("group") or "", params.get("category") or "")
    if cat:
        rs = [r for r in rs if r["category"] == cat]
    if params.get("location"):
        rs = [r for r in rs if r["location"] == params["location"]]
    if params.get("owner"):
        rs = [r for r in rs if params["owner"] in r["owners"] or (params["owner"] == "No owner" and not r["owners"])]
    if params.get("attention") == "1":
        rs = [r for r in rs if not r["owners"] or r["stale"] or r.get("needs_new_owner")]
    if params.get("classification"):
        rs = [r for r in rs if r["classification_key"] == params["classification"]]
    if params.get("critical") == "1":
        rs = [r for r in rs if r["business_critical"]]
    sort = params.get("sort") or "category"
    keyf = {"name": lambda r: r["name"].lower(), "location": lambda r: (r["location"], r["name"].lower()),
            "vulns": lambda r: -r["open_vulns"], "last_seen": lambda r: r["last_seen"] or timezone.now() - datetime.timedelta(days=9999),
            "criticality": lambda r: -(r["criticality"] or 0)}.get(sort, lambda r: ([k for k, _ in CATEGORIES].index(r["category"]), r["name"].lower()))
    return sorted(rs, key=keyf)


# ---------------------------------------------------------------------------
# Supplier register -> cloud service assets
# ---------------------------------------------------------------------------
LIVE_SUPPLIER = ("active", "assessing")


def sync_supplier(s) -> InventoryAsset | None:
    qs = InventoryAsset.objects.filter(attributes__supplier_ref=s.ref) if s.ref else InventoryAsset.objects.none()
    a = qs.first() or InventoryAsset.objects.filter(name=s.name, attributes__category="cloud service").first()
    if s.status not in LIVE_SUPPLIER:
        if a and not a.retired:
            a.retired = True
            a.save(update_fields=["retired"])
        return a
    created = a is None
    if created:
        a = InventoryAsset(name=s.name, asset_type="application")
    at = dict(a.attributes or {})
    at.setdefault("joint_owners", joint_owners())
    at.update({"category": "cloud service", "supplier_ref": s.ref, "manual": True,
               "business_critical": s.tier in ("critical", "high") or at.get("business_critical", False)})
    changed = created or a.retired or a.name != s.name or at != (a.attributes or {})
    a.name, a.attributes, a.retired = s.name, at, False
    if a.owner_id is None and s.owner_id:
        a.owner_id = s.owner_id
    if changed:
        a.save()
    return a


def reconcile() -> dict[str, int]:
    from orasec.posture.grc_models import Supplier  # noqa: PLC0415
    n = 0
    for s in Supplier.objects.all():
        if sync_supplier(s) is not None:
            n += 1
    d = compute()
    return {"suppliers": n, "assets": d["total"]}


# ---------------------------------------------------------------------------
# Data for Ora (no IP addresses, MACs or hostnames)
# ---------------------------------------------------------------------------
def report_data(group: str | None = None) -> dict[str, Any]:
    d = dashboard()
    rs = rows()
    cat = CATEGORY_SLUG.get(group or "", group or "")
    if cat in CATEGORY_LABEL:
        rs = [r for r in rs if r["category"] == cat]
    items = [{"name": r["name"], "category": r["category_label"], "where": r["location"], "owners": r["owners"],
              "criticality": r["criticality"], "classification": r["classification"], "business_critical": r["business_critical"], "source": r["sources"],
              "online": r["online"], "internet_exposed": r["exposed"], "open_vulnerabilities": r["open_vulns"],
              "stale": r["stale"]} for r in rs]
    return {"generated": d["generated"].isoformat(), "total": len(items),
            "by_category": {c["label"]: c["n"] for c in d["categories"]},
            "by_location": dict(d["by_location"]), "by_owner": dict(d["by_owner"]),
            "by_classification": dict(d.get("by_classification") or []),
            "business_critical": d["business_critical"], "no_owner": d["no_owner"], "stale": d["stale"],
            "offline": d["offline"], "internet_exposed": d["exposed"], "with_open_vulnerabilities": d["with_vulns"],
            "needs_attention": d["attention"][:20], "assets": items[:250], "path": "/orasec/assets/"}



def set_classification(a: InventoryAsset, level: str, by=None) -> None:
    if level not in CLASS_LABEL:
        raise ValueError(level)
    at = dict(a.attributes or {})
    old = at.get("classification")
    at["classification"] = level
    at.setdefault("classification_history", []).append({"from": old or "default", "to": level,
        "by": (by.get_full_name() or by.username) if by else "OraSec", "at": timezone.now().isoformat(timespec="minutes")})
    a.attributes = at
    a.save(update_fields=["attributes"])
    cache.delete(CACHE_KEY)

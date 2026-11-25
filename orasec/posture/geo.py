"""Local IP geolocation (DB-IP Lite country + ASN, CC BY 4.0). No external lookups."""
import functools
import ipaddress
import logging
import os

logger = logging.getLogger(__name__)
GEO_DIR = os.environ.get("ORASEC_GEOIP_DIR", "/app/geoip")


@functools.cache
def _reader(name):
    try:
        import maxminddb  # noqa: PLC0415
        path = os.path.join(GEO_DIR, f"dbip-{name}-lite.mmdb")
        return maxminddb.open_database(path) if os.path.exists(path) else None
    except Exception:  # library or database missing: geolocation is optional
        logger.warning("GeoIP database %s unavailable", name)
        return None


def is_public(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_reserved or a.is_unspecified)


@functools.lru_cache(maxsize=50000)
def lookup(ip):
    """Return (country_code, asn, org) for a public IP."""
    if not is_public(ip):
        return "", "", ""
    cc = asn = org = ""
    r = _reader("country")
    if r:
        try:
            rec = r.get(ip) or {}
            cc = (rec.get("country") or {}).get("iso_code", "") or ""
        except Exception:  # noqa: BLE001 corrupt record
            pass
    r = _reader("asn")
    if r:
        try:
            rec = r.get(ip) or {}
            asn = str(rec.get("autonomous_system_number") or "")
            org = (rec.get("autonomous_system_organization") or "")[:200]
        except Exception:  # noqa: BLE001
            pass
    return cc, asn, org


# Mark in AttackEvent.detail of a detection that people are told about: a suspected hack or unauthorised action.
# The phone notifications (orasec.mobile.notify) look for the same words.
SECURITY_ALERT = "security alert"


def flag(cc):
    return "".join(chr(0x1F1E6 + ord(c) - 65) for c in cc.upper()) if len(cc) == 2 and cc.isalpha() else ""


def _is_ip(value):
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def store_events(source, events):
    """
    events: iterable of dicts with event_id, occurred_at, src_ip, ... -> number newly stored.

    Blocked traffic needs a public source address (or a country): the rest is our own network talking.
    A detection on one of our own machines (``host_alert``) is kept without one: a rootkit warning has no
    address at all, and a wrong password can come from inside the network.
    """
    from orasec.posture.models import AttackEvent  # noqa: PLC0415
    objs = []
    for e in events:
        ip = e.get("src_ip") or None
        public = bool(ip) and is_public(ip)
        if e.get("host_alert"):
            if ip and not _is_ip(ip):
                ip = None  # a host name in the address field: keep the alert, drop the value
        elif (ip and not public) or (not ip and not e.get("country")):
            continue
        cc, asn, org = lookup(ip) if public else ("", "", "")
        objs.append(AttackEvent(source=source, event_id=str(e["event_id"])[:120], occurred_at=e["occurred_at"],
                                action=e.get("action", "block")[:20], src_ip=ip, src_country=e.get("country") or cc,
                                src_asn=asn, src_org=org, dst_ip=str(e.get("dst_ip", ""))[:64], dst_port=e.get("dst_port"),
                                protocol=str(e.get("protocol", ""))[:12], target=str(e.get("target", ""))[:200],
                                rule=str(e.get("rule", ""))[:300], detail=str(e.get("detail", ""))[:500], hits=e.get("hits", 1)))
    before = AttackEvent.objects.filter(source=source).count()
    # hourly aggregates (Cloudflare) grow during the hour: refresh the hit count on conflict
    AttackEvent.objects.bulk_create(objs, update_conflicts=True, unique_fields=["source", "event_id"], update_fields=["hits"], batch_size=1000)
    return AttackEvent.objects.filter(source=source).count() - before

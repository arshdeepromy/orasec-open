"""
Security alerts: detections that point to a suspected hack or an unauthorised action.

They are read from Wazuh every 5 minutes (task ``refresh_security_alerts``), kept as attack-map events with the mark
``geo.SECURITY_ALERT`` in the detail, listed first on the Attacks screen and announced by the phone notifications.
Vulnerabilities are findings and never arrive here.

The full Wazuh connector run (assets, vulnerabilities, configuration checks) stays on its own, slower schedule.
"""
import datetime
import logging

from django.conf import settings
from django.core.cache import cache
from django.db.models import Q
from django.utils import timezone

from orasec.posture import geo

logger = logging.getLogger(__name__)

STATE_KEY = "orasec-security-alerts:state"
STATE_TTL = 7 * 24 * 3600
LOOK_BACK = datetime.timedelta(hours=24)   # first read, and the most a later read goes back
OVERLAP = datetime.timedelta(minutes=10)   # alerts reach the indexer a little late; an alert read twice is stored once
STALE = datetime.timedelta(minutes=20)     # a feed without a good read for this long is shown as not working
TOP_LEVEL = 16                             # Wazuh rule levels end at 16


def min_level():
    """Alerts at this level or above are announced, whichever tool they came from (same setting as the phone notifications)."""
    return int(getattr(settings, "ORASEC_PUSH_ALERT_LEVEL", 10))


def announced_q(minimum=None):  # noqa: ARG001  (kept for callers; the level alone no longer decides)
    """Events people are told about: marked security alerts (break-in attempt, break-in, ransomware) and traffic a tool
    flagged but let through. A high level alone is not enough."""
    return Q(action="allow") | Q(action="alert", detail__contains=geo.SECURITY_ALERT)


def _when(value):
    try:
        return datetime.datetime.fromisoformat(value) if value else None
    except ValueError:
        return None


def refresh(now=None):
    """Read new security alerts from every enabled Wazuh connector. Returns the state kept for the Attacks screen."""
    from orasec.posture.connectors.base import get_connector_class  # noqa: PLC0415
    from orasec.posture.models import Connector  # noqa: PLC0415
    now = now or timezone.now()
    before = cache.get(STATE_KEY) or {}
    state = {}
    for c in Connector.objects.filter(enabled=True, kind="wazuh"):
        st = dict(before.get(str(c.id)) or {})
        last_ok = _when(st.get("last_ok"))
        since = max(now - LOOK_BACK, last_ok - OVERLAP) if last_ok else now - LOOK_BACK
        st["last_run"] = now.isoformat()
        try:
            events = get_connector_class(c.kind)(c).collect_security_alerts(since)
            st.update(ok=True, last_ok=now.isoformat(), read=len(events), new=geo.store_events("wazuh", events), error="")
            if st["new"]:  # an alert the webhook did not bring: tell phones now
                from orasec.mobile.tasks import alerts_soon  # noqa: PLC0415
                alerts_soon()
            st.pop("failing_since", None)
        except Exception as e:  # a failed read must be visible on the screen, and the next run tries again
            st.update(ok=False, error=f"{e.__class__.__name__}: {e}"[:300])
            st.setdefault("failing_since", now.isoformat())
            logger.warning("security alerts: connector %s (%s) could not be read: %s", c.id, c.name, st["error"])
        state[str(c.id)] = st
    cache.set(STATE_KEY, state, STATE_TTL)
    return state


def feed_status(now=None):
    """For the Attacks screen: is the 5-minute read working? No error text and no addresses leave here."""
    now = now or timezone.now()
    state = cache.get(STATE_KEY) or {}
    if not state:
        return {"connected": False, "ok": False, "last_ok": None, "failing_since": None}
    good = [t for t in (_when(s.get("last_ok")) for s in state.values()) if t]
    failing = [t for t in (_when(s.get("failing_since")) for s in state.values()) if t]
    last_ok = max(good) if good else None
    ok = not failing and bool(last_ok) and now - last_ok <= STALE
    return {"connected": True, "ok": ok, "last_ok": last_ok.isoformat() if last_ok else None,
            "failing_since": min(failing).isoformat() if failing else None}


def _level(detail):
    for word, nxt in zip((detail or "").split(), (detail or "").split()[1:], strict=False):
        if word == "level" and nxt.isdigit():
            return int(nxt)
    return None


def rows(queryset, limit=40):
    """Newest announced events of this queryset, in the same shape as the live feed of the Attacks screen."""
    return [{"t": e.occurred_at.isoformat(), "ip": e.src_ip, "cc": e.src_country, "flag": geo.flag(e.src_country), "source": e.source,
             "action": e.action, "target": e.target, "port": e.dst_port, "rule": e.rule[:200], "hits": e.hits, "level": _level(e.detail),
             "internal": not (e.src_ip and geo.is_public(e.src_ip))}
            for e in queryset.filter(announced_q()).order_by("-occurred_at")[:limit]]

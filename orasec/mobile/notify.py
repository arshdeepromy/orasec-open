"""
What the OraSec app is told about, and who is told.

Four kinds, each can be switched off per person (MobilePushPrefs):

critical   a critical or known-exploited finding that is new for this person         -> everyone with a linked phone
alerts     a security alert from the monitoring tools in the last 24 hours: a suspected hack or unauthorised action
           (never a vulnerability: those are findings)                               -> everyone with a linked phone
approvals  a change or an exception this person may approve, review or decide now     -> that person only
overdue    an open finding that passed its fix-by date                                -> everyone with a linked phone

Rules:
- One notification per kind and run, with a count. No titles, asset names, CVE numbers or people's names leave OraSec.
- Nothing is announced twice (MobilePushSent). When a person first registers a phone, or switches a kind back on,
  what is already there is marked as known and not announced. Approvals are the exception: they are announced.
- approvals and overdue are sent between 08:00 and 20:00 local time only; critical and alerts at any time.
- Only active people with organisation-wide access and a linked, not revoked phone get anything.
- A phone that was not used for 60 days must be linked again (auth.IDLE_EXPIRY); it gets nothing and its address is removed.

run() is called every five minutes by the scheduled job (orasec.mobile.tasks.mobile_push).
"""
import datetime
import logging
import re
from dataclasses import dataclass

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.db.models import Q
from django.utils import timezone

from orasec.mobile import push
from orasec.mobile.auth import IDLE_EXPIRY, org_wide
from orasec.mobile.models import PUSH_KINDS, MobileDevice, MobilePushPrefs, MobilePushSent

logger = logging.getLogger(__name__)

DAYTIME_ONLY = {"approvals", "overdue"}
DAY_START, DAY_END = 8, 20
ALERT_ACTIONS = ("alert", "allow")  # blocked traffic is never announced
ALERT_WINDOW = datetime.timedelta(hours=24)
PATHS = {"critical": "/vulns", "alerts": "/attacks", "approvals": "/governance", "overdue": "/my-work"}
_LEVEL = re.compile(r"\blevel (\d+)\b")
# The Wazuh connector writes these words into the detail of an alert that points to a suspected hack or unauthorised action,
# also below the level: a new user account, a changed SSH key or sudo right (orasec.posture.geo.SECURITY_ALERT).
SECURITY_ALERT = "security alert"


@dataclass
class Notice:
    kind: str
    refs: set
    title: str
    body: str

    @property
    def data(self):
        return {"kind": self.kind, "path": PATHS[self.kind], "count": len(self.refs)}


def _findings():
    from orasec.models import Finding  # noqa: PLC0415
    return Finding.objects.filter(active=True, duplicate=False)


def critical_refs():
    ids = _findings().filter(Q(severity="Critical") | Q(known_exploited=True)).values_list("id", flat=True)
    return {f"f{i}" for i in ids}


def overdue_refs(today):
    return {f"o{i}" for i in _findings().filter(priority__due_date__lt=today).values_list("id", flat=True)}


def alert_level(detail):
    m = _LEVEL.search(detail or "")
    return int(m.group(1)) if m else 0


def is_announced(action, detail, minimum=None):  # noqa: ARG001  (the level alone no longer decides)
    """An alert people are told about: a marked security alert (break-in attempt, break-in, ransomware) or traffic a tool
    flagged but let through. Not every alert at a high level."""
    return action == "allow" or SECURITY_ALERT in (detail or "")


def alert_refs(now):
    from orasec.posture.models import AttackEvent  # noqa: PLC0415
    minimum = int(getattr(settings, "ORASEC_PUSH_ALERT_LEVEL", 10))
    rows = AttackEvent.objects.filter(action__in=ALERT_ACTIONS, occurred_at__gte=now - ALERT_WINDOW,
                                      occurred_at__lte=now + datetime.timedelta(minutes=5)).values_list("id", "action", "detail")
    return {f"a{i}" for i, action, detail in rows if is_announced(action, detail, minimum)}


def approval_refs(user):
    """Changes and exceptions this person may decide right now, by the same rules as the web pages."""
    from orasec.posture import grc_actions  # noqa: PLC0415
    from orasec.posture.grc_models import ChangeRequest, GovernanceException  # noqa: PLC0415
    refs = set()
    for c in ChangeRequest.objects.filter(status__in=["submitted", "implemented"]):
        perm = grc_actions.change_permissions(user, c)
        if perm["approve"]:
            refs.add(f"c{c.id}:approve")
        if perm["review"]:
            refs.add(f"c{c.id}:review")
    for e in GovernanceException.objects.filter(status="requested"):
        if grc_actions.exception_state(e, user)["may_decide"]:
            refs.add(f"e{e.id}")
    return refs


def _plural(n, one, many):
    """`many` holds one %d for the number."""
    return one if n == 1 else many % n


def build(kind, refs, *, mine=0):
    n = len(refs)
    if kind == "critical":
        return Notice(kind, refs, "New critical findings",
                      _plural(n, "A new critical or known-exploited finding needs attention.",
                              "%d new critical or known-exploited findings need attention."))
    if kind == "alerts":
        return Notice(kind, refs, "Security alert",
                      _plural(n, "A security alert came in: a suspected break-in or ransomware.",
                              "%d security alerts came in: suspected break-ins or ransomware."))
    if kind == "approvals":
        return Notice(kind, refs, "Waiting for you",
                      _plural(n, "1 item is waiting for your approval or review. Open OraSec on the web to decide.",
                              "%d items are waiting for your approval or review. Open OraSec on the web to decide."))
    body = _plural(n, "1 finding passed its fix-by date.", "%d findings passed their fix-by date.")
    if mine and n == 1:
        body += " It is assigned to you."
    elif mine:
        body += _plural(mine, " 1 of them is assigned to you.", " %d of them are assigned to you.")
    return Notice(kind, refs, "Overdue findings", body)


def seen(user, kind):
    return set(MobilePushSent.objects.filter(user=user, kind=kind).values_list("ref", flat=True))


def mark(user, kind, refs, now=None):
    now = now or timezone.now()
    MobilePushSent.objects.bulk_create([MobilePushSent(user=user, kind=kind, ref=r, created=now) for r in refs],
                                       ignore_conflicts=True, batch_size=1000)


def seed(user, kinds, now=None):
    """Mark what is there now as known, so switching notifications on does not announce old things."""
    now = now or timezone.now()
    today = timezone.localdate(now)
    for kind in kinds:
        if kind == "critical":
            mark(user, kind, critical_refs(), now)
        elif kind == "overdue":
            mark(user, kind, overdue_refs(today), now)
        elif kind == "alerts":
            mark(user, kind, alert_refs(now), now)


def daytime(now):
    return DAY_START <= timezone.localtime(now).hour < DAY_END


def notices_for(user, prefs, now, shared, kinds=None):
    """The notifications this person should get now. `shared` holds what is the same for everyone in this run."""
    out = []
    day = daytime(now)
    for kind in PUSH_KINDS:
        if (kinds is not None and kind not in kinds) or not getattr(prefs, kind) or (kind in DAYTIME_ONLY and not day):
            continue
        refs = approval_refs(user) if kind == "approvals" else shared[kind]
        fresh = refs - seen(user, kind)
        if not fresh:
            continue
        mine = 0
        if kind == "overdue":
            ids = [int(r[1:]) for r in fresh]
            mine = _findings().filter(id__in=ids, assignment__assignee=user).count()
        out.append(build(kind, fresh, mine=mine))
    return out


def phones(now=None):
    """Linked phones that take notifications: not revoked, used within the idle limit, with an address."""
    now = now or timezone.now()
    return MobileDevice.objects.filter(revoked_at=None, last_seen__gte=now - IDLE_EXPIRY).exclude(push_token="")


def deliver(user, notice, send=None, now=None):
    """Send one notice to every phone of this person. True when at least one phone took it."""
    send = send or push.send
    took = False
    for device in phones(now).filter(user=user):
        result = send(device.push_kind, device.push_token, notice.title, notice.body, notice.data)
        if result.ok:
            took = True
        elif result.gone:
            MobileDevice.objects.filter(pk=device.pk).update(push_token="", push_updated=timezone.now())
            logger.info("mobile push: device %s no longer takes notifications; address removed", device.pk)
        else:
            logger.warning("mobile push: device %s: %s", device.pk, result.detail)
    return took


def prune(now):
    """Keep the 'already told' list small. Old alert references go; the rest only when long gone."""
    MobilePushSent.objects.filter(kind="alerts", created__lt=now - datetime.timedelta(days=3)).delete()
    MobilePushSent.objects.filter(kind="approvals", created__lt=now - datetime.timedelta(days=180)).delete()
    # a phone past the idle limit has to be linked again: forget where its notifications went
    MobileDevice.objects.filter(last_seen__lt=now - IDLE_EXPIRY).exclude(push_token="").update(push_token="", push_updated=now)


def run(now=None, send=None, kinds=None):
    """One pass over everyone with a linked phone. Returns counts for the log.
    ``kinds``: only these kinds (the instant pass after a new security alert uses ("alerts",)); None for all."""
    stats = {"people": 0, "sent": 0, "skipped": ""}
    if not push.available():
        stats["skipped"] = "not set up"
        return stats
    if not cache.add("orasec:mobile:push:run", 1, 240):
        stats["skipped"] = "another pass is running"
        return stats
    try:
        now = now or timezone.now()
        user_ids = phones(now).values_list("user_id", flat=True).distinct()
        users = [u for u in get_user_model().objects.filter(id__in=list(user_ids), is_active=True) if org_wide(u)]
        if not users:
            prune(now)
            return stats
        today = timezone.localdate(now)
        want = set(PUSH_KINDS if kinds is None else kinds)
        shared = {"critical": critical_refs() if "critical" in want else set(), "alerts": alert_refs(now) if "alerts" in want else set(),
                  "overdue": overdue_refs(today) if "overdue" in want else set()}
        for user in users:
            prefs, created = MobilePushPrefs.objects.get_or_create(user=user)
            if created:
                seed(user, PUSH_KINDS, now)
            stats["people"] += 1
            for notice in notices_for(user, prefs, now, shared, kinds):
                if deliver(user, notice, send, now):
                    mark(user, notice.kind, notice.refs, now)
                    stats["sent"] += 1
        prune(now)
        return stats
    finally:
        cache.delete("orasec:mobile:push:run")

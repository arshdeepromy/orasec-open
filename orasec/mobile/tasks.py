"""Background jobs of the mobile app (the 5-minute pass is scheduled in settings CELERY_BEAT_SCHEDULE)."""
import logging

from django.core.cache import cache

from orasec.celery import app

logger = logging.getLogger(__name__)

SOON_KEY = "orasec:mobile:push:alerts-soon"
SOON_DELAY = 3     # seconds: alerts that arrive together go out as one notification
RETRY_DELAY = 10   # seconds: the 5-minute pass is running, try again shortly


@app.task(ignore_result=True)
def mobile_push(**kwargs):
    """Tell linked phones about new critical findings, alerts, waiting approvals and overdue findings."""
    from orasec.mobile import notify  # noqa: PLC0415
    stats = notify.run()
    if stats["sent"]:
        logger.info("mobile push: %s notification(s) to %s person(s)", stats["sent"], stats["people"])


@app.task(bind=True, ignore_result=True, max_retries=12)
def mobile_push_alerts(self, **kwargs):
    """At once after a new security alert (break-in attempt, break-in, ransomware): tell phones about alerts only."""
    from orasec.mobile import notify  # noqa: PLC0415
    stats = notify.run(kinds=("alerts",))
    if stats["skipped"] == "another pass is running":
        raise self.retry(countdown=RETRY_DELAY)
    if stats["sent"]:
        logger.info("mobile push (instant): %s alert notification(s) to %s person(s)", stats["sent"], stats["people"])


def alerts_soon():
    """Called when a new security alert is stored: send the alert notification within seconds, not at the next 5-minute pass.
    Several alerts within a few seconds start one pass. Never raises: the 5-minute pass is the safety net."""
    try:
        if cache.add(SOON_KEY, 1, SOON_DELAY):
            mobile_push_alerts.apply_async(countdown=SOON_DELAY)
    except Exception as exc:  # noqa: BLE001
        logger.warning("mobile push: instant alert pass could not be queued: %s", exc)

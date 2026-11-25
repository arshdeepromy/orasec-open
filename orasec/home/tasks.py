"""Background refresh of the security dashboard (scheduled in settings CELERY_BEAT_SCHEDULE)."""
import logging

from orasec.celery import app

logger = logging.getLogger(__name__)


@app.task(ignore_result=True)
def refresh_dashboard(**kwargs):
    from orasec.home import metrics  # noqa: PLC0415
    data = metrics.refresh()
    if data:
        logger.info("dashboard metrics refreshed in %s ms", data.get("compute_ms"))

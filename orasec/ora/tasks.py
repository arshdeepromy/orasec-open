"""Ora background jobs (scheduled in settings CELERY_BEAT_SCHEDULE)."""
import logging

from orasec.celery import app

logger = logging.getLogger(__name__)


@app.task(ignore_result=True)
def ora_memory(**kwargs):
    """Short notes of finished chats, so Ora can pick up where a user left off."""
    from orasec.ora import service  # noqa: PLC0415
    n = service.summarise_pending()
    if n:
        logger.info("ora: %s chat notes saved", n)


@app.task(ignore_result=True)
def ora_sweep(**kwargs):
    """Retention: old chats and notes, expired cards, old usage rows."""
    from orasec.ora import service  # noqa: PLC0415
    logger.info("ora: retention sweep %s", service.sweep())

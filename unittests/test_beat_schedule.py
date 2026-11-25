"""Scheduled (beat) tasks must accept the keyword arguments OraSec adds when it sends a task to the queue."""
import importlib

from django.conf import settings
from django.test import SimpleTestCase

from orasec.celery import OraSecAsyncTask, app
from orasec.celery_dispatch import RESERVED_DISPATCH_KWARGS


class TestBeatSchedule(SimpleTestCase):

    """
    OraSecAsyncTask.apply_async adds ``async_user_id`` to every OraSec task it sends, and Celery checks the
    arguments against the task's signature before queueing. A scheduled task without ``**kwargs`` is therefore
    refused by beat on every run and never reaches a worker (refresh_asset_inventory, 17-18 Nov 2026).
    """

    def test_every_scheduled_task_accepts_the_dispatch_kwargs(self):
        self.assertTrue(settings.CELERY_BEAT_SCHEDULE)
        for name, entry in settings.CELERY_BEAT_SCHEDULE.items():
            task_name = entry["task"]
            if task_name.startswith("celery."):
                continue  # Celery's own tasks get no extra kwargs
            with self.subTest(entry=name, task=task_name):
                importlib.import_module(task_name.rsplit(".", 1)[0])
                task = app.tasks[task_name]
                if not isinstance(task, OraSecAsyncTask):
                    continue  # plain Celery base class: nothing is injected
                kwargs = dict(entry.get("kwargs") or {})
                kwargs.update(dict.fromkeys(RESERVED_DISPATCH_KWARGS))
                # Same check Celery runs in Task.apply_async (typing=True); raises TypeError on a mismatch.
                task.__header__(*(entry.get("args") or ()), **kwargs)

    def test_asset_inventory_refresh_is_scheduled_and_accepts_them(self):
        from orasec.posture.tasks import refresh_asset_inventory  # noqa: PLC0415
        self.assertIn(refresh_asset_inventory.name, {e["task"] for e in settings.CELERY_BEAT_SCHEDULE.values()})
        refresh_asset_inventory.__header__(async_user_id=None)

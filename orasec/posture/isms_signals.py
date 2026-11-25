"""Push OraSec changes to the policy tool within seconds (debounced per record)."""
from django.core.cache import cache
from django.db import transaction
from django.db.models.signals import post_delete, post_save

from orasec.posture import isms_sync

DEBOUNCE = 5  # seconds


def _queue(entity, pk):
    if isms_sync.syncing():
        return  # write made by the sync itself: no echo
    if not cache.add(f"isms-push-pending:{entity}:{pk}", 1, DEBOUNCE + 10):
        return
    from orasec.posture.tasks import isms_push  # noqa: PLC0415
    transaction.on_commit(lambda: isms_push.apply_async(args=[entity, pk], countdown=DEBOUNCE))


def connect():
    for spec in isms_sync.SPECS:
        if not spec.signals:
            continue
        model = spec.model

        def _saved(sender, instance, _e=spec.entity, **kw):
            _queue(_e, instance.pk)

        post_save.connect(_saved, sender=model, weak=False, dispatch_uid=f"isms-sync-save-{spec.entity}")
        post_delete.connect(_saved, sender=model, weak=False, dispatch_uid=f"isms-sync-del-{spec.entity}")


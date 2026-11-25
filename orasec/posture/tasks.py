"""Celery tasks for OraSec posture features (scheduled in settings CELERY_BEAT_SCHEDULE)."""
import logging

from django.core.cache import cache

from orasec.celery import app

logger = logging.getLogger(__name__)


def _locked(name, seconds):
    return cache.add(f"orasec-posture-lock:{name}", 1, seconds)


def _unlock(name):
    cache.delete(f"orasec-posture-lock:{name}")


@app.task(ignore_result=True)
def run_due_connectors(**kwargs):
    from orasec.posture.models import Connector  # noqa: PLC0415
    from orasec.plugins import registry as plugins  # noqa: PLC0415
    for c in Connector.objects.filter(enabled=True):
        if not plugins.source_on(c.kind):
            continue
        if c.is_due and c.last_status != "running":
            run_connector_task.delay(c.id, "schedule")


@app.task(ignore_result=True)
def run_connector_task(connector_id, triggered_by="manual", user_id=None, **kwargs):
    from orasec.models import OraSec_User  # noqa: PLC0415
    from orasec.posture.connectors.base import run_connector  # noqa: PLC0415
    from orasec.posture.models import Connector  # noqa: PLC0415
    lock = f"connector-{connector_id}"
    if not _locked(lock, 3600):
        logger.info("connector %s already running", connector_id)
        return
    try:
        c = Connector.objects.get(id=connector_id)
        from orasec.plugins import registry as plugins  # noqa: PLC0415
        if not plugins.source_on(c.kind):
            logger.info("connector %s not run: the %s plugin is off", connector_id, c.kind)
            return
        user = OraSec_User.objects.filter(id=user_id).first() if user_id else None
        run_connector(c, triggered_by=triggered_by, user=user)
        if c.kind != "beszel":  # health inventory has no findings
            refresh_priorities.delay()
    finally:
        _unlock(lock)


@app.task(ignore_result=True)
def refresh_security_alerts(**kwargs):
    """Every 5 minutes: new alerts that point to a suspected hack or unauthorised action (one small search per Wazuh connector)."""
    from orasec.plugins import registry as plugins  # noqa: PLC0415
    if not plugins.source_on("wazuh"):
        return
    if not _locked("security-alerts", 240):
        return
    try:
        from orasec.posture import security_alerts  # noqa: PLC0415
        security_alerts.refresh()
    finally:
        _unlock("security-alerts")


@app.task(ignore_result=True)
def refresh_intel(**kwargs):
    from orasec.posture import intel  # noqa: PLC0415
    from orasec.plugins import registry as plugins  # noqa: PLC0415
    if plugins.is_on("intel.kev"):
        intel.refresh_kev()
    if plugins.is_on("intel.epss"):
        intel.refresh_epss()
    intel.apply_intel()
    from orasec.posture import evidence  # noqa: PLC0415
    from orasec.posture.models import IntelFeed  # noqa: PLC0415
    evidence.from_intel_refresh(IntelFeed.objects.all())
    refresh_priorities.delay()


@app.task(ignore_result=True)
def refresh_priorities(**kwargs):
    from orasec.posture import intel, services  # noqa: PLC0415
    if not _locked("priorities", 900):
        return
    try:
        intel.apply_intel()
        intel.compute_priorities()
        services.auto_cover_new_findings()
        services.run_triage_rules()
    finally:
        _unlock("priorities")


@app.task(ignore_result=True)
def daily_posture(**kwargs):
    from orasec.posture import compliance, services  # noqa: PLC0415
    compliance.seed()
    compliance.evaluate_all()
    services.snapshot()



@app.task(ignore_result=True, bind=True, max_retries=None)
def patch_deployment_task(self, deployment_id, **kwargs):
    """Start a Semaphore patch run, then poll it until it finishes (re-queued every 10 s, up to 2 h)."""
    from django.utils import timezone  # noqa: PLC0415

    from orasec.posture import patching  # noqa: PLC0415
    from orasec.posture.models import Connector, PatchDeployment  # noqa: PLC0415
    dep = PatchDeployment.objects.select_related("connector").get(id=deployment_id)
    try:
        if dep.task_id is None:
            patching.start(dep)
        elif patching.poll(dep):
            if dep.mode == "apply" and dep.status == "success":
                # ask PatchMon for fresh numbers once the agent has reported
                for c in Connector.objects.filter(kind="patchmon", enabled=True):
                    run_connector_task.apply_async((c.id, "after patch run"), countdown=60 * int(dep.connector.options.get("patchmon_refresh_minutes", 5)))
            return
    except Exception as e:
        dep.status, dep.summary, dep.finished_at = "error", f"{e.__class__.__name__}: {str(e)[:400]}", timezone.now()
        dep.save()
        return
    if dep.started_at and (timezone.now() - dep.started_at).total_seconds() > 7200:
        dep.status, dep.summary = "error", "Timed out waiting for Semaphore (2 h)."
        dep.save()
        return
    raise self.retry(countdown=10)


# ---------------------------------------------------------------------------
# Policy tool (ISMS) two-way sync
# ---------------------------------------------------------------------------
@app.task(bind=True, ignore_result=True, max_retries=20)
def isms_push(self, entity, pk, **kwargs):
    from orasec.posture import isms_sync  # noqa: PLC0415
    cache.delete(f"isms-push-pending:{entity}:{pk}")
    from orasec.plugins import registry as plugins  # noqa: PLC0415
    if not plugins.source_on("isms"):
        return
    try:
        run = isms_sync.push_one(entity, pk)
    except isms_sync.Busy:
        raise self.retry(countdown=5)
    if run is not None and not run.ok and run.error:
        raise self.retry(countdown=min(30 * 2 ** self.request.retries, 900))


@app.task(bind=True, ignore_result=True, max_retries=20)
def isms_event_pull(self, **kwargs):
    from orasec.posture import isms_sync  # noqa: PLC0415
    cache.delete("isms-pull-pending")
    from orasec.plugins import registry as plugins  # noqa: PLC0415
    if not plugins.source_on("isms"):
        return
    try:
        run = isms_sync.reconcile("event", wait=True)
    except isms_sync.Busy:
        raise self.retry(countdown=5)
    if run is not None and not run.ok and run.error:
        raise self.retry(countdown=min(30 * 2 ** self.request.retries, 900))


@app.task(bind=True, ignore_result=True, max_retries=10)
def isms_nightly(self, **kwargs):
    from orasec.plugins import registry as plugins  # noqa: PLC0415
    from orasec.posture import isms_sync  # noqa: PLC0415
    if not plugins.source_on("isms"):
        return
    try:
        isms_sync.reconcile("full", wait=True)
    except isms_sync.Busy:
        raise self.retry(countdown=20)


@app.task(ignore_result=True)
def refresh_asset_inventory(**kwargs):
    """Supplier register -> cloud service assets, then rebuild the cached inventory dashboard (A.5.9)."""
    from orasec.posture import asset_inventory  # noqa: PLC0415
    return asset_inventory.reconcile()

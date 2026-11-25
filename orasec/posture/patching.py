"""Patch Center: deploy OS patches to hosts through Semaphore (Ansible) and track the result."""
import logging
import re

from django.utils import timezone

from orasec.posture.connectors.base import ConnectorError, get_connector_class
from orasec.posture.models import Connector, InventoryAsset, PatchDeployment

logger = logging.getLogger(__name__)
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
MSG = re.compile(r"""^"?msg"?:\s*["']?(.*?)["']?,?$""")
RECAP = re.compile(r"^(\S+)\s*:\s*ok=\d+")


def semaphore_connector():
    return Connector.objects.filter(kind="semaphore", enabled=True).first()


def patch_target(asset, connector=None):
    """Return (inventory_host, group, production) for an asset, or None if Semaphore cannot reach it."""
    connector = connector or semaphore_connector()
    if connector is None:
        return None
    info = (asset.attributes or {}).get("semaphore")
    if info and info.get("inventory_host"):
        return info["inventory_host"], info.get("group", ""), bool(info.get("production"))
    return None


def patchable_assets():
    c = semaphore_connector()
    if not c:
        return []
    out = []
    for a in InventoryAsset.objects.filter(retired=False).exclude(attributes__semaphore=None).order_by("name"):
        t = patch_target(a, c)
        if t:
            pm = (a.attributes or {}).get("patchmon") or {}
            a.patch_host, a.patch_group, a.patch_production = t
            a.pm_updates, a.pm_security, a.pm_reboot = pm.get("updates"), pm.get("security_updates"), pm.get("needs_reboot")
            a.last_deploy = a.patch_deployments.first()
            out.append(a)
    return out


def request_deployment(asset, user, mode="apply", change_ref="", reason=""):
    c = semaphore_connector()
    if c is None:
        msg = "No Semaphore connector is configured."
        raise ValueError(msg)
    target = patch_target(asset, c)
    if not target:
        msg = f"{asset.name} is not in the Semaphore inventory."
        raise ValueError(msg)
    host, group, production = target
    if mode == "apply" and production and not change_ref.strip():
        msg = "Production hosts need a change record reference before patching."
        raise ValueError(msg)
    if PatchDeployment.objects.filter(asset=asset, status__in=["requested", "waiting", "running"]).exists():
        msg = f"A patch run for {asset.name} is already in progress."
        raise ValueError(msg)
    tpl = c.options.get("apply_template" if mode == "apply" else "check_template")
    if not tpl:
        msg = f"Semaphore connector option '{mode}_template' is not set."
        raise ValueError(msg)
    return PatchDeployment.objects.create(asset=asset, connector=c, inventory_host=host, inventory_group=group, mode=mode,
                                          template_id=int(tpl), change_ref=change_ref.strip(), reason=reason, requested_by=user)


def start(dep):
    impl = get_connector_class("semaphore")(dep.connector)
    who = dep.requested_by.username if dep.requested_by else "OraSec"
    msg = f"OraSec {dep.get_mode_display().lower()} on {dep.inventory_host} by {who}" + (f" ({dep.change_ref})" if dep.change_ref else "")
    task = impl.launch(dep.template_id, dep.inventory_host, msg)
    dep.task_id, dep.status, dep.started_at = task["id"], task.get("status", "waiting") if task.get("status") in ("waiting", "running") else "waiting", timezone.now()
    dep.save(update_fields=["task_id", "status", "started_at"])
    return dep


def poll(dep):
    """Refresh status and output from Semaphore. Returns True when finished."""
    impl = get_connector_class("semaphore")(dep.connector)
    t = impl.task(dep.task_id)
    st = t.get("status", "running")
    dep.status = {"starting": "running", "waiting": "waiting"}.get(st, st if st in ("running", "success", "error", "stopped") else "running")
    try:
        lines = impl.output(dep.task_id)
        dep.output = ANSI.sub("", "\n".join(line.get("output", "") for line in lines))[-60000:]
    except ConnectorError:
        logger.warning("patch output unavailable for task %s", dep.task_id)
    done = dep.status in ("success", "error", "stopped")
    if done:
        dep.finished_at = timezone.now()
        lines = [ln.strip() for ln in dep.output.splitlines()]
        msgs = [m.group(1) for ln in lines if dep.inventory_host in ln and (m := MSG.match(ln))]
        dep.summary = (msgs[-1] if msgs else dep.get_status_display())[:500]
        # safety net: the run must only have touched the requested host
        hosts = {m.group(1) for ln in lines if (m := RECAP.match(ln))}
        if hosts and hosts != {dep.inventory_host}:
            dep.status = "error"
            dep.summary = f"SAFETY: run touched {sorted(hosts)}, expected only {dep.inventory_host}. Check the Semaphore template."[:500]
    dep.save()
    if done:
        from orasec.posture import evidence  # noqa: PLC0415
        evidence.from_patch_deployment(dep)
    return done


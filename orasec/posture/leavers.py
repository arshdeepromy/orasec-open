"""Leavers and movers (ISO/IEC 27001 A.5.11 return of assets, A.5.18 / A.6.5 access removal).

Deactivating an OraSec account opens a leaver record automatically. Every asset the person owns or jointly owns is
listed on it and flagged "needs a new owner" in the asset inventory. The FRM-002 checklist is ticked step by
step; someone other than the leaver and other than whoever started the record signs it off.
Nothing is deleted.
"""
from __future__ import annotations

import logging

from django.core.cache import cache
from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from orasec.posture.grc_models import LeaverRecord
from orasec.posture.models import InventoryAsset

logger = logging.getLogger(__name__)


def display(u) -> str:
    return (u.get_full_name() or u.username).strip()


def _matches(name: str, u) -> bool:
    n = (name or "").lower()
    keys = {k.lower() for k in (display(u), u.username, u.first_name, u.last_name) if k and len(k) > 2}
    return any(k in n for k in keys)


def owned_assets(u) -> list[InventoryAsset]:
    out = []
    for a in InventoryAsset.objects.filter(retired=False).filter(Q(owner=u) | Q(attributes__has_key="joint_owners")):
        joint = [j for j in (a.attributes or {}).get("joint_owners") or [] if _matches(j, u)]
        if a.owner_id == u.id or joint:
            out.append(a)
    return out


def _flag(rec: LeaverRecord, assets: list[InventoryAsset]) -> list[dict]:
    snap = []
    for a in assets:
        at = dict(a.attributes or {})
        at["needs_new_owner"] = {"leaver": rec.ref, "person": display(rec.person)}
        a.attributes = at
        a.save(update_fields=["attributes"])
        snap.append({"id": a.id, "name": a.name, "owner": a.owner_id == rec.person_id,
                     "joint": [j for j in at.get("joint_owners") or [] if _matches(j, rec.person)]})
    from orasec.posture import asset_inventory  # noqa: PLC0415
    cache.delete(asset_inventory.CACHE_KEY)
    return snap


@transaction.atomic
def start(person, *, by=None, kind="leaver", leaving_date=None, reason="", automatic=False) -> LeaverRecord:
    rec = LeaverRecord.objects.filter(person=person, status="open").first()
    if rec:
        return rec
    rec = LeaverRecord(person=person, kind=kind, started_by=by, started_automatically=automatic, reason=reason or "")
    if leaving_date:
        rec.leaving_date = leaving_date
    rec.save()
    rec.assets = _flag(rec, owned_assets(person))
    if not rec.assets:
        _tick(rec, "assets", by, "No assets owned or jointly owned.")
    rec.save()
    return rec


def _tick(rec: LeaverRecord, key: str, by, note: str = "") -> None:
    for s in rec.steps:
        if s["key"] == key and not s["done"]:
            s.update(done=True, by=display(by) if by else "OraSec", at=timezone.now().isoformat(timespec="minutes"), note=note[:500])


class Refused(Exception):
    pass


def tick(rec: LeaverRecord, key: str, by, note: str = "") -> LeaverRecord:
    if rec.status != "open":
        raise Refused("This record is already closed.")
    if by and by.id == rec.person_id:
        raise Refused("The leaver can't tick their own checklist.")
    if key not in {s["key"] for s in rec.steps}:
        raise Refused("Unknown step.")
    if key == "assets" and pending_assets(rec):
        raise Refused("Some assets still need a new owner. Reassign them first.")
    _tick(rec, key, by, note)
    rec.save(update_fields=["steps", "updated"])
    return rec


def pending_assets(rec: LeaverRecord) -> list[InventoryAsset]:
    return [a for a in InventoryAsset.objects.filter(attributes__needs_new_owner__leaver=rec.ref)]


@transaction.atomic
def reassign(rec: LeaverRecord, new_owner, by, asset_ids: list[int] | None = None) -> int:
    """Move ownership (and joint ownership) of the leaver's assets to new_owner."""
    if rec.status != "open":
        raise Refused("This record is already closed.")
    if new_owner.id == rec.person_id or not new_owner.is_active:
        raise Refused("Pick an active person other than the leaver.")
    from orasec.posture.asset_inventory import joint_owners  # noqa: PLC0415
    label = next((j for j in joint_owners() if _matches(j, new_owner)), display(new_owner))
    n = 0
    for a in pending_assets(rec):
        if asset_ids and a.id not in asset_ids:
            continue
        at = dict(a.attributes or {})
        joint = [j for j in at.get("joint_owners") or [] if not _matches(j, rec.person)]
        if at.get("joint_owners") and label not in joint:
            joint.append(label)
        if at.get("joint_owners") is not None:
            at["joint_owners"] = joint
        at.pop("needs_new_owner", None)
        at.setdefault("owner_history", []).append({"from": display(rec.person), "to": display(new_owner), "leaver": rec.ref,
                                                    "by": display(by), "at": timezone.now().isoformat(timespec="minutes")})
        a.attributes = at
        if a.owner_id == rec.person_id or a.owner_id is None:
            a.owner = new_owner
        a.save()
        n += 1
    if not pending_assets(rec):
        _tick(rec, "assets", by, f"Assets moved to {display(new_owner)}.")
        rec.save(update_fields=["steps", "updated"])
    from orasec.posture import asset_inventory  # noqa: PLC0415
    cache.delete(asset_inventory.CACHE_KEY)
    return n


def sign_off(rec: LeaverRecord, by, note: str = "") -> LeaverRecord:
    if rec.status != "open":
        raise Refused("This record is already closed.")
    if by.id in (rec.person_id, rec.started_by_id):
        raise Refused("Sign-off must be by someone other than the leaver and whoever started the record.")
    if not rec.complete:
        raise Refused(f"{len(rec.steps) - rec.done_count} checklist step(s) are still open.")
    rec.status, rec.signed_off_by, rec.signed_off_at = "signed_off", by, timezone.now()
    if note:
        rec.note = (rec.note + "\n" + note).strip()[:4000]
    rec.save()
    return rec


def summary(rec: LeaverRecord) -> dict:
    return {"ref": rec.ref, "id": rec.id, "person": display(rec.person), "kind": rec.get_kind_display(),
            "status": rec.get_status_display(), "leaving_date": rec.leaving_date.isoformat(),
            "due_date": rec.due_date.isoformat() if rec.due_date else None, "overdue": bool(rec.overdue),
            "started_by": display(rec.started_by) if rec.started_by else "OraSec (account deactivated)",
            "steps": [{"key": s["key"], "label": s["label"], "done": s["done"], "by": s["by"]} for s in rec.steps],
            "done": rec.done_count, "total": len(rec.steps),
            "assets_needing_owner": [a.name for a in pending_assets(rec)],
            "signed_off_by": display(rec.signed_off_by) if rec.signed_off_by else None,
            "path": f"/orasec/leavers/{rec.id}/"}

"""Risk acceptance governance: new/extended acceptances need approval by someone other than the requester."""
import logging
import threading

from crum import get_current_user
from django.conf import settings
from django.db.models.signals import m2m_changed, post_save, pre_save
from django.dispatch import receiver

from orasec.models import Risk_Acceptance

_state = threading.local()


class bypass:

    """Context manager: changes made by the approval workflow itself must not re-trigger it."""

    def __enter__(self):
        _state.bypass = True

    def __exit__(self, *exc):
        _state.bypass = False


def _enabled():
    return getattr(settings, "RISK_ACCEPTANCE_APPROVAL_REQUIRED", True) and not getattr(_state, "bypass", False)


@receiver(m2m_changed, sender=Risk_Acceptance.accepted_findings.through)
def ra_findings_added(sender, instance, action, reverse, pk_set, **kwargs):
    if action != "post_add" or reverse or not _enabled() or not isinstance(instance, Risk_Acceptance):
        return
    from orasec.posture.services import hold_for_approval  # noqa: PLC0415
    with bypass():
        hold_for_approval(instance, get_current_user() or instance.owner)


@receiver(pre_save, sender=Risk_Acceptance)
def ra_remember_expiry(sender, instance, **kwargs):
    if instance.pk:
        instance._orasec_old_expiry = Risk_Acceptance.objects.filter(pk=instance.pk).values_list("expiration_date", flat=True).first()


@receiver(post_save, sender=Risk_Acceptance)
def ra_extended(sender, instance, created, **kwargs):
    """Extending or reinstating an acceptance needs a fresh approval."""
    if created or not _enabled():
        return
    old = getattr(instance, "_orasec_old_expiry", None)
    if old and instance.expiration_date and instance.expiration_date > old:
        from orasec.posture.services import hold_for_approval  # noqa: PLC0415
        with bypass():
            hold_for_approval(instance, get_current_user() or instance.owner)



# --- Asset inventory: supplier register drives the "cloud service" assets (A.5.9) ---
def _supplier_to_asset(sender, instance, **kwargs):
    from django.db import transaction  # noqa: PLC0415

    from orasec.posture import asset_inventory  # noqa: PLC0415

    def run():
        try:
            asset_inventory.sync_supplier(instance)
            from django.core.cache import cache  # noqa: PLC0415
            cache.delete(asset_inventory.CACHE_KEY)
        except Exception:  # noqa: BLE001 -- never break a supplier save
            logging.getLogger(__name__).exception("asset inventory: supplier sync failed")
    transaction.on_commit(run)


def _connect_supplier_assets():
    from django.db.models.signals import post_save  # noqa: PLC0415

    from orasec.posture.grc_models import Supplier  # noqa: PLC0415
    post_save.connect(_supplier_to_asset, sender=Supplier, dispatch_uid="orasec-supplier-asset")


_connect_supplier_assets()


# --- Leavers (A.5.11): deactivating an account opens a leaver record ---
def _user_pre_save(sender, instance, **kwargs):
    if not instance.pk:
        return
    try:
        old = sender.objects.only("is_active").get(pk=instance.pk)
    except sender.DoesNotExist:
        return
    if old.is_active and not instance.is_active:
        from django.db import transaction  # noqa: PLC0415

        by = get_current_user()

        def run():
            try:
                from orasec.posture import leavers  # noqa: PLC0415
                leavers.start(instance, by=by if getattr(by, "pk", None) and by.pk != instance.pk else None,
                              automatic=True, reason="Account deactivated in OraSec.")
            except Exception:  # noqa: BLE001
                logging.getLogger(__name__).exception("leaver record: could not start")
        transaction.on_commit(run)


def _connect_leavers():
    from django.contrib.auth import get_user_model  # noqa: PLC0415
    from django.db.models.signals import pre_save as _ps  # noqa: PLC0415
    _ps.connect(_user_pre_save, sender=get_user_model(), dispatch_uid="orasec-leaver-on-deactivate")


_connect_leavers()

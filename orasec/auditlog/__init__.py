"""
Audit-log package for OraSec.

The public API is exposed lazily via PEP 562 so that importing
``orasec.auditlog`` (and especially ``orasec.auditlog.settings``) at Django
settings-load time does not pull in submodules that depend on
``django.conf.settings`` or other not-yet-built parts of the orasec app.
"""
import importlib

_LAZY_EXPORTS = {  # noqa: RUF067 -- table backs the PEP 562 __getattr__ re-export
    "run_flush_auditlog":               "orasec.auditlog.services",
    "configure_audit_system":           "orasec.auditlog.services",
    "configure_pghistory_triggers":     "orasec.auditlog.services",
    "register_django_pghistory_models": "orasec.auditlog.services",
    "process_events_for_display":       "orasec.auditlog.helpers",
    "TAG_MODEL_MAPPING":                "orasec.auditlog.helpers",
    "get_tracked_models":               "orasec.auditlog.backfill",
    "process_model_backfill":           "orasec.auditlog.backfill",
}


def __getattr__(name):
    module_path = _LAZY_EXPORTS.get(name)
    if module_path is None:
        msg = f"module 'orasec.auditlog' has no attribute {name!r}"
        raise AttributeError(msg)
    return getattr(importlib.import_module(module_path), name)

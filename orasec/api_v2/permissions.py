"""
Backward-compat re-export for callers that still import permission classes
from ``orasec.api_v2.permissions``. The canonical home is
``orasec.authorization.api_permissions`` after the legacy authorization
consolidation; this shim lets sub-package modules consolidated from
upstream (``orasec/notifications/api/views.py``, etc.) keep their old import
path.
"""
from orasec.authorization.api_permissions import *  # noqa: F403

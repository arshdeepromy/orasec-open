path = "risk_acceptance"  # noqa: RUF067

# Backward-compat: the AcceptedRisks/AcceptedFindings mixins + AcceptedRiskSerializer
# were historically importable as `orasec.risk_acceptance.api.<X>` (via the old api.py).
# finding/test/engagement api viewsets consume them as `ra_api.<X>` — keep them resolvable.
from orasec.risk_acceptance.api.mixins import (  # noqa: E402, F401 -- backward compat
    AcceptedFindingsMixin,
    AcceptedRisk,
    AcceptedRiskSerializer,
    AcceptedRisksMixin,
    _accept_risks,
)

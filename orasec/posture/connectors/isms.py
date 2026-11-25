"""Policy tool (ISMS document tool) connector: holds the API token and runs the two-way sync.

Secrets: {"token": "isms_...", "webhook_token": "<random>"}. base_url: e.g. http://policy.example.internal:9095
"""
from orasec.posture.connectors.base import BaseConnector, CollectResult, ConnectorError, register


@register
class IsmsConnector(BaseConnector):
    kind = "isms"
    secret_fields = ("token", "webhook_token")

    def test(self):
        from orasec.posture import isms_sync  # noqa: PLC0415
        try:
            n = len(isms_sync.Client(self.connector).list("/risks"))
        except Exception as e:  # noqa: BLE001
            raise ConnectorError(str(e)) from e
        return f"Policy tool reachable ({n} risks)"

    def collect(self):
        from orasec.posture import isms_sync  # noqa: PLC0415
        run = isms_sync.reconcile("full")
        if run is not None and not run.ok:
            raise ConnectorError(run.error or "sync failed")
        return CollectResult(stats=(run.stats if run else {}))

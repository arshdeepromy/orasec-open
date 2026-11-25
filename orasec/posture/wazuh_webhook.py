"""Wazuh manager integration: one alert at a time, the moment Wazuh raises it (the 5-minute read stays as the safety net).

The Wazuh manager runs ``custom-orasec`` (readme-docs/wazuh-integration) which posts the alert JSON here with
``Authorization: Bearer <webhook_token>``. The token is a secret of the Wazuh connector. The same rule as the
5-minute read decides whether the alert is stored; the alert id is Wazuh's own, so an alert that arrives by both
ways is stored once.
"""
import hmac
import json

from django.core.cache import cache
from django.http import HttpResponse, HttpResponseForbidden, JsonResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from orasec.posture import geo
from orasec.posture.connectors import wazuh
from orasec.posture.models import Connector

MAX_BODY = 64 * 1024
LAST_KEY = "orasec-security-alerts:webhook"
FAILURE_KEY = "orasec-security-alerts:webhook-bad-token"


def _connector(token):
    """The enabled Wazuh connector whose webhook token this is (compared in constant time)."""
    for c in Connector.objects.filter(kind="wazuh", enabled=True):
        expected = c.get_secrets().get("webhook_token", "")
        if expected and hmac.compare_digest(token.encode(), expected.encode()):
            return c
    return None


@csrf_exempt
@require_POST
def alert(request):
    from orasec.plugins import registry as plugins  # noqa: PLC0415
    if not plugins.source_on("wazuh"):
        return HttpResponse(status=404)
    header = request.headers.get("Authorization", "")
    token = header[7:].strip() if header.lower().startswith("bearer ") else ""
    conn = _connector(token) if token else None
    if conn is None:
        cache.set(FAILURE_KEY, timezone.now().isoformat(), 86400)
        return HttpResponseForbidden()
    if len(request.body or b"") > MAX_BODY:
        return HttpResponse(status=413)
    try:
        doc = json.loads(request.body or b"{}")
    except ValueError:
        return JsonResponse({"ok": False, "error": "not JSON"}, status=400)
    if not isinstance(doc, dict) or not isinstance(doc.get("rule"), dict) or not doc.get("id"):
        return JsonResponse({"ok": False, "error": "not a Wazuh alert"}, status=400)
    rule, fim = doc["rule"], doc.get("syscheck") or {}
    if not wazuh.is_security_alert(conn.options, rule.get("level"), rule.get("groups"), fim.get("path") or ""):
        return JsonResponse({"ok": True, "stored": 0, "reason": "not a security alert"})
    event = wazuh.security_alert_event({"_id": doc["id"], "_source": doc}, conn.options)
    stored = geo.store_events("wazuh", [event])
    cache.set(LAST_KEY, timezone.now().isoformat(), 7 * 86400)
    if stored:
        from orasec.mobile.tasks import alerts_soon  # noqa: PLC0415
        alerts_soon()  # phone notification within seconds
    return JsonResponse({"ok": True, "stored": stored})

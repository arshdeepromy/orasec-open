"""Policy tool sync: webhook receiver and the sync status page."""
import hmac
import json

from django.contrib import messages
from django.core.cache import cache
from django.http import HttpResponseForbidden, JsonResponse
from django.shortcuts import get_object_or_404, redirect
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from orasec.posture import isms_sync
from orasec.posture.models import IsmsConflict, IsmsLink, IsmsSyncRun
from orasec.posture.views import render, superuser_required

PULL_DEBOUNCE = 5


@csrf_exempt
@require_POST
def webhook(request, token):
    """Receives the policy tool's (Slack-format) notifications and pulls changes from it."""
    conn = isms_sync.connector()
    expected = (conn.get_secrets().get("webhook_token", "") if conn else "")
    if not expected or not hmac.compare_digest(token, expected):
        return HttpResponseForbidden()
    try:
        payload = json.loads(request.body or b"{}")
    except ValueError:
        payload = {}
    actor, text = isms_sync.parse_event(payload)
    sync_user = (conn.username or (conn.options or {}).get("sync_user") or "").lower()
    if actor and actor == sync_user:
        return JsonResponse({"ok": True, "queued": False, "reason": "own write"})  # caused by the sync: no echo
    cache.set("isms-last-event-in", timezone.now().isoformat(), None)
    if cache.add("isms-pull-pending", 1, PULL_DEBOUNCE + 30):
        from orasec.posture.tasks import isms_event_pull  # noqa: PLC0415
        isms_event_pull.apply_async(countdown=PULL_DEBOUNCE)
    return JsonResponse({"ok": True, "queued": True})


@superuser_required
def sync_page(request):
    if request.method == "POST":
        action = request.POST.get("action")
        if action == "full":
            from orasec.posture.tasks import isms_nightly  # noqa: PLC0415
            isms_nightly.delay()
            messages.success(request, "Full sync started; refresh in a minute.")
        elif action == "retry":
            from orasec.posture.tasks import isms_event_pull  # noqa: PLC0415
            isms_event_pull.delay()
            messages.success(request, "Retry started.")
        return redirect("orasec_isms_sync")
    conn = isms_sync.connector()
    runs = IsmsSyncRun.objects.all()[:25]
    last_full = IsmsSyncRun.objects.filter(kind="full", ok=True).first()
    counts = {s.entity: IsmsLink.objects.filter(entity=s.entity, archived=False).count() for s in isms_sync.SPECS}
    return render(request, "orasec/posture/isms_sync.html", {
        "conn": conn, "runs": runs, "last_full": last_full, "counts": counts,
        "conflicts": IsmsConflict.objects.filter(resolved=False), "resolved": IsmsConflict.objects.filter(resolved=True)[:10],
        "failed": IsmsSyncRun.objects.filter(ok=False, finished__isnull=False)[:10],
        "last_in": cache.get("isms-last-event-in"), "page_title": "Policy tool sync"})


@superuser_required
@require_POST
def resolve(request, cid):
    c = get_object_or_404(IsmsConflict, id=cid, resolved=False)
    choice = request.POST.get("choice", "orasec")
    isms_sync.resolve_conflict(c, "isms" if choice == "isms" else "orasec", request.user)
    messages.success(request, "Conflict resolved.")
    return redirect("orasec_isms_sync")

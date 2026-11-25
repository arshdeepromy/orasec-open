import logging

from django.core.cache import cache
from django.core.serializers.json import DjangoJSONEncoder
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect, JsonResponse
from django.shortcuts import render
from django.urls import reverse

from orasec.home import metrics
from orasec.home.tasks import refresh_dashboard
from orasec.utils import add_breadcrumb

logger = logging.getLogger(__name__)


def home(request: HttpRequest) -> HttpResponse:
    return HttpResponseRedirect(reverse("dashboard"))


def _kick_refresh() -> None:
    """Queue one background refresh per minute at most; never let a broker hiccup break the page."""
    try:
        if cache.add("orasec:dashboard:kick", 1, 60):
            refresh_dashboard.delay()
    except Exception:
        logger.warning("could not queue dashboard refresh", exc_info=True)


def _org_wide(user) -> bool:
    """The dashboard aggregates every product, so it is limited to users with organisation-wide visibility."""
    return bool(user and user.is_authenticated and (user.is_superuser or user.is_staff))


def dashboard(request: HttpRequest) -> HttpResponse:
    """
    Security operations dashboard. Reads the pre-computed metrics document from the cache (see home/metrics.py),
    so the page renders without running aggregation queries; a stale document is refreshed in the background.
    """
    add_breadcrumb(title="Security Operations", top_level=True, request=request)
    if not _org_wide(request.user):
        return render(request, "orasec/dashboard.html", {"data": None, "restricted": True})
    data = metrics.get()
    if data is not None and metrics.is_stale(data):
        _kick_refresh()
    return render(request, "orasec/dashboard.html", {"data": data, "can_refresh": request.user.is_superuser})


def dashboard_data(request: HttpRequest) -> JsonResponse:
    """JSON for the live refresh on the dashboard. ?refresh=1 (superusers) recomputes now."""
    if not _org_wide(request.user):
        return JsonResponse({"detail": "Organisation-wide access required."}, status=403)
    if request.GET.get("refresh") == "1" and request.user.is_superuser:
        data = metrics.refresh() or metrics.get()
    else:
        data = metrics.get()
        if data is not None and metrics.is_stale(data):
            _kick_refresh()
    if data is None:
        return JsonResponse({"pending": True}, status=202)
    return JsonResponse(data, encoder=DjangoJSONEncoder)


def support(request: HttpRequest) -> HttpResponse:
    add_breadcrumb(title="Support", top_level=not len(request.GET), request=request)
    return render(request, "orasec/support.html", {})

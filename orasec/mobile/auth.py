"""Device-token authentication and request guards for the mobile API."""
import datetime
import functools
import logging

from django.core.cache import cache
from django.http import JsonResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt

from orasec.mobile.models import TOKEN_PREFIX, MobileDevice, sha256

logger = logging.getLogger(__name__)
IDLE_EXPIRY = datetime.timedelta(days=60)      # a device unused this long must be linked again
SEEN_EVERY = datetime.timedelta(minutes=5)      # how often last_seen is written


def client_ip(request):
    return (request.headers.get("CF-Connecting-IP") or request.META.get("HTTP_X_FORWARDED_FOR", "").split(",")[0].strip()
            or request.META.get("REMOTE_ADDR") or None)


def error(message, status=400, **extra):
    return JsonResponse({"error": message, **extra}, status=status)


def org_wide(user):
    """The app shows organisation-wide security data, so it needs the same access as the web dashboard."""
    return bool(user and user.is_active and (user.is_superuser or user.is_staff))


def rate_limited(bucket, key, limit, seconds):
    """True when `key` has used up `limit` calls in the window. Fixed window in the shared cache."""
    k = f"orasec:mobile:rl:{bucket}:{key}"
    if cache.add(k, 1, seconds):
        return False
    try:
        n = cache.incr(k)
    except ValueError:
        cache.set(k, 1, seconds)
        n = 1
    return n > limit


def device_from_request(request):
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return None
    token = header[7:].strip()
    if not token.startswith(TOKEN_PREFIX) or len(token) > 120:
        return None
    device = MobileDevice.objects.select_related("user").filter(token_hash=sha256(token), revoked_at=None).first()
    if not device:
        return None
    now = timezone.now()
    if now - device.last_seen > IDLE_EXPIRY:
        device.revoked_at = now
        device.save(update_fields=["revoked_at"])
        return None
    if now - device.last_seen > SEEN_EVERY:
        MobileDevice.objects.filter(pk=device.pk).update(last_seen=now, last_ip=client_ip(request))
    return device


# The app's WebView origins (Android https://localhost, iOS capacitor://localhost). The API uses bearer tokens, never
# cookies, so allowing these origins exposes nothing a browser session could ride on.
APP_ORIGINS = {"https://localhost", "capacitor://localhost", "http://localhost", "ionic://localhost"}


def _cors(request, response):
    origin = request.headers.get("Origin")
    if origin in APP_ORIGINS:
        response["Access-Control-Allow-Origin"] = origin
        response["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
        response["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        response["Access-Control-Max-Age"] = "86400"
        response["Vary"] = "Origin"
    return response


def mobile_api(methods=("GET",), *, auth=True):
    """JSON endpoint for the app: method check, device-token auth, organisation-wide access, no caching."""
    def deco(view):
        @csrf_exempt
        @functools.wraps(view)
        def wrapper(request, *args, **kwargs):
            if request.method == "OPTIONS":
                return _cors(request, JsonResponse({}))
            if request.method not in methods:
                return _cors(request, error("Method not allowed.", 405))
            from orasec.plugins import registry as plugins  # noqa: PLC0415
            if not plugins.is_on("mobile"):
                return _cors(request, error("The mobile app is turned off on this OraSec server. Ask your administrator.", 403, code="plugin_off"))
            if auth:
                if rate_limited("ip", client_ip(request) or "-", 600, 60):
                    return _cors(request, error("Too many requests. Try again in a minute.", 429))
                device = device_from_request(request)
                if device is None:
                    return _cors(request, error("This device is not linked or was signed out. Link it again from OraSec.", 401, code="unlinked"))
                if not org_wide(device.user):
                    return _cors(request, error("Your OraSec account does not have organisation-wide access.", 403, code="no_access"))
                request.user = device.user
                request.mobile_device = device
            response = view(request, *args, **kwargs)
            response["Cache-Control"] = "no-store"
            return _cors(request, response)
        return wrapper
    return deco


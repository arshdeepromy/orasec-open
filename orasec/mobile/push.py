"""
Push delivery for the OraSec app: Firebase Cloud Messaging (Android) and the Apple Push Notification service (iOS).

A notification only says that something is waiting and how many. It never carries a finding title, an asset name,
a CVE number or a person's name: those stay in OraSec and are shown after the app is unlocked.

No extra packages: PyJWT signs the requests, httpx sends them (HTTP/2 for Apple).
Off unless ORASEC_PUSH_ENABLED is set and the key files exist. The key files are never in git.
"""
import contextlib
import json
import logging
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import httpx
import jwt
from django.conf import settings

logger = logging.getLogger(__name__)

GOOGLE_TOKEN_URI = "https://oauth2.googleapis.com/token"  # noqa: S105 - an address, not a secret
FCM_SCOPE = "https://www.googleapis.com/auth/firebase.messaging"
CHANNEL = "orasec"  # Android notification channel, created by the app
_lock = threading.Lock()
_cache = {}


@dataclass
class Result:
    ok: bool
    detail: str = ""
    gone: bool = False  # the device no longer accepts notifications: forget its address


def configured():
    """Which services can be used right now."""
    from orasec.plugins import registry as plugins  # noqa: PLC0415
    on = bool(getattr(settings, "ORASEC_PUSH_ENABLED", False)) and plugins.is_on("push")
    fcm = settings.ORASEC_PUSH_FCM_CREDENTIALS
    apns = settings.ORASEC_PUSH_APNS_KEY_PATH
    return {
        "fcm": bool(on and fcm and Path(fcm).is_file()),
        "apns": bool(on and apns and Path(apns).is_file() and settings.ORASEC_PUSH_APNS_KEY_ID and settings.ORASEC_PUSH_APNS_TEAM_ID),
    }


def available():
    return any(configured().values())


def _cached(name, make):
    with _lock:
        hit = _cache.get(name)
        if hit and hit[1] > time.time() + 60:
            return hit[0]
    value, lifetime = make()
    with _lock:
        _cache[name] = (value, time.time() + lifetime)
    return value


def _fcm_account():
    return json.loads(Path(settings.ORASEC_PUSH_FCM_CREDENTIALS).read_text(encoding="utf-8"))


def _fcm_access_token():
    def make():
        account = _fcm_account()
        issued = int(time.time())
        assertion = jwt.encode({"iss": account["client_email"], "scope": FCM_SCOPE, "aud": GOOGLE_TOKEN_URI,
                                "iat": issued, "exp": issued + 3600}, account["private_key"], algorithm="RS256")
        r = httpx.post(GOOGLE_TOKEN_URI, timeout=10, data={
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": assertion})
        r.raise_for_status()
        body = r.json()
        return (body["access_token"], account["project_id"]), int(body.get("expires_in", 3600))
    return _cached("fcm", make)


def _send_fcm(token, title, body, data, ttl):
    access, project = _fcm_access_token()
    kind = data.get("kind", "orasec")
    message = {"message": {
        "token": token,
        "notification": {"title": title, "body": body},
        "data": data,
        "android": {"priority": "HIGH", "ttl": f"{ttl}s", "collapse_key": kind,
                    "notification": {"channel_id": CHANNEL, "tag": kind, "visibility": "PRIVATE", "default_sound": True}},
    }}
    r = httpx.post(f"https://fcm.googleapis.com/v1/projects/{project}/messages:send", timeout=10,
                   headers={"Authorization": f"Bearer {access}"}, json=message)
    if r.status_code == 200:
        return Result(ok=True, detail="fcm")
    gone = r.status_code == 404 or "UNREGISTERED" in r.text
    return Result(ok=False, detail=f"fcm {r.status_code}", gone=gone)


def _apns_bearer():
    def make():
        key = Path(settings.ORASEC_PUSH_APNS_KEY_PATH).read_text(encoding="utf-8")
        token = jwt.encode({"iss": settings.ORASEC_PUSH_APNS_TEAM_ID, "iat": int(time.time())}, key, algorithm="ES256",
                           headers={"kid": settings.ORASEC_PUSH_APNS_KEY_ID})
        return token, 40 * 60  # Apple accepts a token for up to 60 minutes
    return _cached("apns", make)


def _send_apns(token, title, body, data, ttl, *, sandbox):
    host = "api.sandbox.push.apple.com" if sandbox else "api.push.apple.com"
    kind = data.get("kind", "orasec")
    payload = {"aps": {"alert": {"title": title, "body": body}, "sound": "default", "thread-id": kind}, **data}
    with httpx.Client(http2=True, timeout=10) as client:
        r = client.post(f"https://{host}/3/device/{token}", json=payload, headers={
            "authorization": f"bearer {_apns_bearer()}", "apns-topic": settings.ORASEC_PUSH_APNS_TOPIC,
            "apns-push-type": "alert", "apns-priority": "10", "apns-expiration": str(int(time.time()) + ttl),
            "apns-collapse-id": kind[:64]})
    if r.status_code == 200:
        return Result(ok=True, detail="apns-sandbox" if sandbox else "apns")
    reason = ""
    with contextlib.suppress(ValueError):
        reason = r.json().get("reason", "")
    return Result(ok=False, detail=f"apns {r.status_code} {reason}".strip(),
                  gone=r.status_code == 410 or reason in {"BadDeviceToken", "Unregistered"})


def send(push_kind, token, title, body, data=None, ttl=6 * 3600):
    """Send one notification. Never raises: a delivery problem is logged and reported in the result."""
    data = {k: str(v) for k, v in (data or {}).items()}
    if not token:
        return Result(ok=False, detail="no address for this device")
    ready = configured()
    try:
        if push_kind == "fcm":
            if not ready["fcm"]:
                return Result(ok=False, detail="Android notifications are not set up on the server")
            return _send_fcm(token, title, body, data, ttl)
        if push_kind == "apns":
            if not ready["apns"]:
                return Result(ok=False, detail="iPhone notifications are not set up on the server")
            sandbox = bool(settings.ORASEC_PUSH_APNS_SANDBOX)
            result = _send_apns(token, title, body, data, ttl, sandbox=sandbox)
            if not result.ok and "BadDeviceToken" in result.detail:
                # A development build registers with Apple's test service, a store build with the real one. Try the other.
                other = _send_apns(token, title, body, data, ttl, sandbox=not sandbox)
                return other if other.ok else result
            return result
    except Exception as e:  # delivery problems are logged, never raised
        logger.warning("mobile push: sending failed: %s", e.__class__.__name__)
        return Result(ok=False, detail=f"error: {e.__class__.__name__}")
    return Result(ok=False, detail="this device type has no notifications")

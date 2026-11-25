"""Linked mobile devices for the OraSec app.

A phone is linked with a one-time code that a signed-in user creates in the web app (which itself sits behind
Cloudflare Access). Linking returns a device token; only its SHA-256 is stored. Tokens are revoked from the web
(Mobile app page) or by signing out in the app, and expire after a period without use.
"""
import datetime
import hashlib
import secrets

from django.conf import settings
from django.db import models
from django.utils import timezone

USER = settings.AUTH_USER_MODEL
TOKEN_PREFIX = "osm_"
CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no 0/O, 1/I


def sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def normalise_code(code: str) -> str:
    return "".join(ch for ch in (code or "").upper() if ch.isalnum())


class MobileDevice(models.Model):
    PLATFORMS = [("android", "Android"), ("ios", "iOS"), ("web", "Browser preview")]

    user = models.ForeignKey(USER, related_name="mobile_devices", on_delete=models.CASCADE)
    name = models.CharField(max_length=120)
    platform = models.CharField(max_length=10, choices=PLATFORMS, default="android")
    app_version = models.CharField(max_length=40, blank=True)
    token_hash = models.CharField(max_length=64, unique=True)
    created = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(default=timezone.now)
    last_ip = models.GenericIPAddressField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    # Push notifications: the address Google (Android) or Apple (iOS) gave this install. Empty = no notifications.
    push_token = models.CharField(max_length=512, blank=True)
    push_updated = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-last_seen"]

    def __str__(self):
        return f"{self.name} ({self.get_platform_display()})"

    @property
    def active(self):
        return self.revoked_at is None

    @property
    def push_kind(self):
        """Which service delivers to this device: Firebase Cloud Messaging or the Apple Push Notification service."""
        return {"android": "fcm", "ios": "apns"}.get(self.platform)

    @classmethod
    def issue(cls, *, user, name, platform, app_version="", ip=None):
        token = TOKEN_PREFIX + secrets.token_urlsafe(32)
        device = cls.objects.create(user=user, name=name[:120] or "Phone", platform=platform if platform in dict(cls.PLATFORMS) else "android",
                                    app_version=app_version[:40], token_hash=sha256(token), last_ip=ip)
        return device, token


class MobileLinkCode(models.Model):
    """One-time code shown on the web 'Mobile app' page; valid for a few minutes, single use."""

    user = models.ForeignKey(USER, related_name="mobile_link_codes", on_delete=models.CASCADE)
    code_hash = models.CharField(max_length=64, unique=True)
    created = models.DateTimeField(default=timezone.now)
    expires = models.DateTimeField()
    used_at = models.DateTimeField(null=True, blank=True)
    device = models.ForeignKey(MobileDevice, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")

    class Meta:
        ordering = ["-created"]

    @classmethod
    def create_for(cls, user, minutes=10):
        # one live code per user: creating a new one cancels the previous
        cls.objects.filter(user=user, used_at=None).delete()
        raw = "".join(secrets.choice(CODE_ALPHABET) for _ in range(10))
        obj = cls.objects.create(user=user, code_hash=sha256(raw), expires=timezone.now() + datetime.timedelta(minutes=minutes))
        return obj, f"{raw[:5]}-{raw[5:]}"


PUSH_KINDS = ["critical", "approvals", "alerts", "overdue"]


class MobilePushPrefs(models.Model):

    """Which notifications one person wants on their linked phones. All four are on until they switch one off."""

    user = models.OneToOneField(USER, related_name="mobile_push_prefs", on_delete=models.CASCADE)
    critical = models.BooleanField(default=True)   # a new critical or known-exploited finding
    approvals = models.BooleanField(default=True)  # a change or exception is waiting for this person's decision
    alerts = models.BooleanField(default=True)     # a high-severity alert from the monitoring tools
    overdue = models.BooleanField(default=True)    # a finding passed its fix-by date
    created = models.DateTimeField(default=timezone.now)

    def as_dict(self):
        return {k: getattr(self, k) for k in PUSH_KINDS}


class MobilePushSent(models.Model):

    """
    One thing a person has been told about (or that was already there when they switched a kind on).

    It keeps a notification from being sent twice. It holds no finding text: only the kind and a short reference.
    """

    user = models.ForeignKey(USER, related_name="+", on_delete=models.CASCADE)
    kind = models.CharField(max_length=12)
    ref = models.CharField(max_length=40)
    created = models.DateTimeField(default=timezone.now, db_index=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["user", "kind", "ref"], name="orasec_mobilepush_once")]

"""Records of the connector endpoint: two-step proposals, connected clients and the call log."""
import uuid

from django.conf import settings
from django.db import models
from django.utils import timezone

USER = settings.AUTH_USER_MODEL


class McpProposal(models.Model):

    """A change prepared through the connector. Nothing happens until the same person confirms it, once, in time."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(USER, on_delete=models.CASCADE, related_name="+")
    kind = models.CharField(max_length=30)
    payload = models.JSONField(default=dict)
    card = models.JSONField(default=dict)
    status = models.CharField(max_length=12, default="pending")  # pending|confirmed|failed|expired
    result = models.JSONField(default=dict, blank=True)
    client_name = models.CharField(max_length=120, blank=True)
    created = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField()
    decided_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created"]


class McpClient(models.Model):

    """One assistant client a person has connected. The person (or an admin) can block it."""

    KIND = [("oauth", "Single sign-on"), ("api_token", "API token")]
    user = models.ForeignKey(USER, on_delete=models.CASCADE, related_name="mcp_clients")
    kind = models.CharField(max_length=12, choices=KIND)
    client_id = models.CharField(max_length=200, blank=True)
    client_name = models.CharField(max_length=120, blank=True)
    first_seen = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(default=timezone.now)
    last_ip = models.CharField(max_length=64, blank=True)
    calls = models.PositiveIntegerField(default=0)
    blocked_at = models.DateTimeField(null=True, blank=True)
    blocked_by = models.ForeignKey(USER, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")

    class Meta:
        ordering = ["-last_seen"]
        constraints = [models.UniqueConstraint(fields=["user", "kind", "client_id", "client_name"], name="os_mcpclient_unique")]


class McpAccess(models.Model):

    """Per-person switch: when blocked, no connector call is accepted for this person."""

    user = models.OneToOneField(USER, on_delete=models.CASCADE, related_name="mcp_access")
    blocked_at = models.DateTimeField(null=True, blank=True)
    blocked_by = models.ForeignKey(USER, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")


class McpCall(models.Model):

    """One line for every call to the connector endpoint, also the refused ones."""

    created = models.DateTimeField(default=timezone.now, db_index=True)
    user = models.ForeignKey(USER, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    username = models.CharField(max_length=150, blank=True)
    via = models.CharField(max_length=12, blank=True)           # oauth | api_token
    client_id = models.CharField(max_length=200, blank=True)
    client_name = models.CharField(max_length=120, blank=True)
    ip = models.CharField(max_length=64, blank=True)
    method = models.CharField(max_length=40, blank=True)
    tool = models.CharField(max_length=80, blank=True)
    args = models.CharField(max_length=300, blank=True)
    outcome = models.CharField(max_length=16)                   # ok | tool_error | denied | refused | limited | bad_request
    detail = models.CharField(max_length=300, blank=True)
    write = models.BooleanField(default=False)
    ms = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["-created"]

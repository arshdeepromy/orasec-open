"""Ora, the OraSec assistant: settings, conversations, proposals, memory, usage, knowledge.

Based on the publisher's earlier Ora assistant design. Differences for OraSec: one
organisation (no per-org rows), no support cases (OraSec's users ARE the
security team) and no advisor hand-off.
"""
import uuid

from django.conf import settings
from django.db import models
from django.utils import timezone

PROVIDERS = (
    ("none", "Not set up"),
    ("anthropic", "Anthropic Messages API"),
    ("openai", "OpenAI-compatible (OpenRouter, OpenAI, Azure OpenAI, Ollama)"),
    ("vertex", "Google Vertex AI (service account)"),
    ("scripted", "Scripted test answers (test instances only)"),
)


class OraSettings(models.Model):
    """Singleton (pk=1). Provider secrets are stored encrypted (AES-256-GCM, ``orasec_crypto_encrypt``)."""

    enabled = models.BooleanField(default=True)
    provider = models.CharField(max_length=16, choices=PROVIDERS, default="none")
    model = models.CharField(max_length=100, blank=True)
    base_url = models.CharField(max_length=200, blank=True, default="https://openrouter.ai/api/v1")
    api_key = models.TextField(blank=True, default="")
    vertex_project = models.CharField(max_length=100, blank=True)
    vertex_region = models.CharField(max_length=40, blank=True, default="global")
    vertex_service_account = models.TextField(blank=True, default="")
    rate_limit_per_minute = models.PositiveIntegerField(default=20)
    daily_token_cap = models.PositiveIntegerField(default=600000, help_text="0 = no cap")
    max_output_tokens = models.PositiveIntegerField(default=1400)
    retention_days = models.PositiveIntegerField(default=90)
    memory_enabled = models.BooleanField(default=True)
    updated = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL,
                                   related_name="+")

    class Meta:
        verbose_name = "Ora settings"

    @classmethod
    def load(cls):
        return cls.objects.get_or_create(pk=1)[0]


class OraUserPreference(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, primary_key=True, on_delete=models.CASCADE,
                                related_name="ora_preference")
    hidden = models.BooleanField(default=False)
    notice_ack_at = models.DateTimeField(null=True, blank=True)
    updated = models.DateTimeField(auto_now=True)


class OraConversation(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="ora_conversations")
    title = models.CharField(max_length=120, default="New chat")
    surface = models.CharField(max_length=10, default="web")  # web | mobile
    #: placeholder -> real value ([IP_1] -> 10.0.0.4, [USER_2] -> "Sam") for this chat only.
    vault = models.JSONField(default=dict, blank=True)
    summarised = models.BooleanField(default=False)
    created = models.DateTimeField(default=timezone.now)
    updated = models.DateTimeField(default=timezone.now, db_index=True)

    class Meta:
        indexes = [models.Index(fields=["user", "-updated"])]


class OraMessage(models.Model):
    conversation = models.ForeignKey(OraConversation, on_delete=models.CASCADE, related_name="messages")
    role = models.CharField(max_length=10)  # user | assistant
    text = models.TextField()
    actions = models.JSONField(default=list, blank=True)
    suggestions = models.JSONField(default=list, blank=True)
    mood = models.CharField(max_length=12, default="happy")
    in_scope = models.BooleanField(default=True)
    answered = models.BooleanField(default=True)
    feedback = models.SmallIntegerField(null=True, blank=True)  # 1 / -1
    page_path = models.CharField(max_length=300, blank=True)
    tool = models.CharField(max_length=40, blank=True)
    created = models.DateTimeField(default=timezone.now, db_index=True)

    class Meta:
        ordering = ["created", "id"]


class OraProposal(models.Model):
    """A change Ora prepared. Nothing happens until the user confirms the card."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    conversation = models.ForeignKey(OraConversation, on_delete=models.CASCADE, related_name="proposals")
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="+")
    kind = models.CharField(max_length=30)
    payload = models.JSONField(default=dict)
    card = models.JSONField(default=dict)
    status = models.CharField(max_length=12, default="pending")  # pending|confirmed|cancelled|failed|expired
    result = models.JSONField(default=dict, blank=True)
    created = models.DateTimeField(default=timezone.now)
    decided_at = models.DateTimeField(null=True, blank=True)


class OraMemory(models.Model):
    """A short note about an earlier chat (no secrets, no people's details)."""

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="ora_memories")
    conversation = models.ForeignKey(OraConversation, null=True, blank=True, on_delete=models.SET_NULL,
                                     related_name="+")
    summary = models.CharField(max_length=300)
    topics = models.JSONField(default=list, blank=True)
    outcome = models.CharField(max_length=10, default="info")
    created = models.DateTimeField(default=timezone.now, db_index=True)

    class Meta:
        ordering = ["-created"]


class OraUsage(models.Model):
    """Token counts only -- never content."""

    user = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL,
                             related_name="+")
    feature = models.CharField(max_length=20)  # chat | chat_tool | memory | test
    provider = models.CharField(max_length=16, blank=True)
    model = models.CharField(max_length=100, blank=True)
    input_tokens = models.PositiveIntegerField(default=0)
    output_tokens = models.PositiveIntegerField(default=0)
    latency_ms = models.PositiveIntegerField(default=0)
    ok = models.BooleanField(default=True)
    created = models.DateTimeField(default=timezone.now, db_index=True)


class OraKbArticle(models.Model):
    """Help articles added by superusers (built-in articles live in ``kb_articles.py``)."""

    title = models.CharField(max_length=160)
    path = models.CharField(max_length=200, blank=True)
    keywords = models.JSONField(default=list, blank=True)
    body = models.TextField()
    status = models.CharField(max_length=10, default="draft")  # draft | published | archived
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL,
                                   related_name="+")
    created = models.DateTimeField(default=timezone.now)
    updated = models.DateTimeField(auto_now=True)


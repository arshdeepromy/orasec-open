"""Saved on/off state of the plugins that have no switch of their own (see orasec/plugins/registry.py)."""
from django.conf import settings
from django.db import models


class PluginState(models.Model):

    key = models.CharField(max_length=64, unique=True)
    enabled = models.BooleanField(default=True)
    updated = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")

    class Meta:
        ordering = ["key"]

    def __str__(self):
        return f"{self.key}: {'on' if self.enabled else 'off'}"

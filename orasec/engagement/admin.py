from django.contrib import admin

from orasec.engagement.models import Engagement, Engagement_Presets


@admin.register(Engagement_Presets)
class EngagementPresetsAdmin(admin.ModelAdmin):

    """Admin support for the Engagement_Presets model."""


@admin.register(Engagement)
class EngagementAdmin(admin.ModelAdmin):

    """Admin support for the Engagement model."""

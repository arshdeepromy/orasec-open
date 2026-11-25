from django.contrib import admin

from orasec.url.models import URL


@admin.register(URL)
class URLAdmin(admin.ModelAdmin):

    """Admin support for the URL model."""

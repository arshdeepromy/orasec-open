from django.contrib import admin

from orasec.announcement.models import Announcement, UserAnnouncement

admin.site.register(Announcement)
admin.site.register(UserAnnouncement)

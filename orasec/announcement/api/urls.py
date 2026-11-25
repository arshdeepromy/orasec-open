from orasec.announcement.api import path
from orasec.announcement.api.views import AnnouncementViewSet


def add_announcement_urls(router):
    router.register(path, AnnouncementViewSet, basename="announcement")
    return router

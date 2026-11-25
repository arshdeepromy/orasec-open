from django_filters.rest_framework import DjangoFilterBackend

from orasec.announcement.api.serializer import AnnouncementSerializer
from orasec.announcement.models import Announcement
from orasec.api_v2.views import OraSecModelViewSet
from orasec.authorization import api_permissions as permissions


# Authorization: configuration
class AnnouncementViewSet(
    OraSecModelViewSet,
):
    serializer_class = AnnouncementSerializer
    queryset = Announcement.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = "__all__"
    permission_classes = (permissions.UserHasConfigurationPermissionStaff,)

    def get_queryset(self):
        return Announcement.objects.all().order_by("id")

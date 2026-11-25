from django_filters.rest_framework import DjangoFilterBackend

from orasec.api_v2.views import OraSecModelViewSet
from orasec.authorization import api_permissions as permissions
from orasec.note_type.api.serializer import NoteTypeSerializer
from orasec.note_type.models import Note_Type


# Authorization: configuration
class NoteTypeViewSet(
    OraSecModelViewSet,
):
    serializer_class = NoteTypeSerializer
    queryset = Note_Type.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = [
        "id",
        "name",
        "description",
        "is_single",
        "is_active",
        "is_mandatory",
    ]
    permission_classes = (permissions.UserHasConfigurationPermissionSuperuser,)

    def get_queryset(self):
        return Note_Type.objects.all().order_by("id")

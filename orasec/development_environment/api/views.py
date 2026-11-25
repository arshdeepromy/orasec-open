from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.permissions import IsAuthenticated

from orasec.api_v2.views import OraSecModelViewSet
from orasec.authorization import api_permissions as permissions
from orasec.development_environment.api.serializer import DevelopmentEnvironmentSerializer
from orasec.development_environment.models import Development_Environment


# Authorization: authenticated, configuration
class DevelopmentEnvironmentViewSet(
    OraSecModelViewSet,
):
    serializer_class = DevelopmentEnvironmentSerializer
    queryset = Development_Environment.objects.none()
    filter_backends = (DjangoFilterBackend,)
    permission_classes = (IsAuthenticated, permissions.UserHasDevelopmentEnvironmentPermission)

    def get_queryset(self):
        return Development_Environment.objects.all().order_by("id")

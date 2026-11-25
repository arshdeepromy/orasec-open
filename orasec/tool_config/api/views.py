import logging

from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.utils import extend_schema_view

from orasec.api_v2.views import DeprecationNoticeMixin, PrefetchOraSecModelViewSet, schema_with_prefetch
from orasec.authorization import api_permissions as permissions
from orasec.tool_config.api.serializer import ToolConfigurationSerializer
from orasec.tool_config.models import Tool_Configuration

logger = logging.getLogger(__name__)


# Authorization: configurations
@extend_schema_view(**schema_with_prefetch())
class ToolConfigurationsViewSet(
    DeprecationNoticeMixin,
    PrefetchOraSecModelViewSet,
):
    deprecation = "tool_configuration"
    serializer_class = ToolConfigurationSerializer
    queryset = Tool_Configuration.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = [
        "id",
        "name",
        "tool_type",
        "url",
        "authentication_type",
    ]
    permission_classes = (permissions.UserHasConfigurationPermissionSuperuser,)

    def get_queryset(self):
        return Tool_Configuration.objects.all().order_by("id")

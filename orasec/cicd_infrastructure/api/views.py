from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.permissions import IsAuthenticated

from orasec.api_v2.views import OraSecModelViewSet
from orasec.authorization import api_permissions as permissions
from orasec.cicd_infrastructure.api.serializers import CICDInfrastructureSerializer
from orasec.models import CICDInfrastructure


# Authorization: read open to authenticated users; write requires configuration permission.
class CICDInfrastructureViewSet(
    OraSecModelViewSet,
):
    serializer_class = CICDInfrastructureSerializer
    queryset = CICDInfrastructure.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ["id", "name", "infrastructure_type"]
    permission_classes = (IsAuthenticated, permissions.UserHasCICDInfrastructurePermission)

    def get_queryset(self):
        return CICDInfrastructure.objects.all().order_by("id")

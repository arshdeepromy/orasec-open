from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.utils import extend_schema_view
from rest_framework.permissions import IsAuthenticated

from orasec.api_v2.views import OraSecModelViewSet, PrefetchOraSecModelViewSet, schema_with_prefetch
from orasec.authorization import api_permissions as permissions
from orasec.jira.api.serializers import (
    JIRAInstanceSerializer,
    JIRAIssueSerializer,
    JIRAProjectSerializer,
)
from orasec.jira.queries import (
    get_authorized_jira_issues,
    get_authorized_jira_projects,
)
from orasec.models import (
    JIRA_Instance,
    JIRA_Issue,
    JIRA_Project,
)


class JiraInstanceViewSet(
    OraSecModelViewSet,
):
    serializer_class = JIRAInstanceSerializer
    queryset = JIRA_Instance.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ["id", "url"]
    permission_classes = (permissions.UserHasConfigurationPermissionSuperuser,)

    def get_queryset(self):
        return JIRA_Instance.objects.all().order_by("id")


# Authorization: object-based
# @extend_schema_view(**schema_with_prefetch())
# Nested models with prefetch make the response schema too long for Swagger UI
class JiraIssuesViewSet(
    PrefetchOraSecModelViewSet,
):
    serializer_class = JIRAIssueSerializer
    queryset = JIRA_Issue.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = [
        "id",
        "jira_id",
        "jira_key",
        "finding",
        "engagement",
        "finding_group",
    ]

    permission_classes = (
        IsAuthenticated,
        permissions.UserHasJiraIssuePermission,
    )

    def get_queryset(self):
        return get_authorized_jira_issues("view")


# Authorization: object-based
@extend_schema_view(**schema_with_prefetch())
class JiraProjectViewSet(
    PrefetchOraSecModelViewSet,
):
    serializer_class = JIRAProjectSerializer
    queryset = JIRA_Project.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = [
        "id",
        "jira_instance",
        "product",
        "engagement",
        "enabled",
        "component",
        "project_key",
        "push_all_issues",
        "enable_engagement_epic_mapping",
        "push_notes",
    ]

    permission_classes = (
        IsAuthenticated,
        permissions.UserHasJiraProductPermission,
    )

    def get_queryset(self):
        return get_authorized_jira_projects("view")

from django.urls import path, re_path

from orasec.mcp import views

urlpatterns = [
    # The endpoint. Answers 401 with the metadata pointer itself, so it is exempt from the login redirect.
    re_path(r"^mcp/?$", views.endpoint, name="orasec_mcp"),
    re_path(r"^\.well-known/oauth-protected-resource(?:/mcp/?)?$", views.resource_metadata, name="orasec_mcp_metadata"),
    # Pages (signed-in session)
    path("orasec/mcp/clients/", views.clients_page, name="orasec_mcp_clients"),
    path("orasec/mcp/log/", views.audit_page, name="orasec_mcp_log"),
]

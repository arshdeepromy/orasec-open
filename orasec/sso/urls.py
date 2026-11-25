from django.urls import path, re_path

from orasec.sso import views

urlpatterns = [
    path("sso/login/", views.oidc_login, name="oidc_login"),
    path("sso/callback/", views.oidc_callback, name="oidc_callback"),
    path("sso/backchannel-logout/", views.oidc_backchannel_logout, name="oidc_backchannel_logout"),
    # Microsoft Entra ID and Okta. The generic provider keeps the two addresses above, so nothing registered at an
    # identity provider has to change.
    re_path(r"^sso/(?P<provider>entra|okta)/login/$", views.oidc_login, name="oidc_provider_login"),
    re_path(r"^sso/(?P<provider>entra|okta)/callback/$", views.oidc_callback, name="oidc_provider_callback"),
]


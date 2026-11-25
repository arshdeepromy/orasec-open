from django.urls import path

from orasec.sso import views

urlpatterns = [
    path("sso/login/", views.oidc_login, name="oidc_login"),
    path("sso/callback/", views.oidc_callback, name="oidc_callback"),
    path("sso/backchannel-logout/", views.oidc_backchannel_logout, name="oidc_backchannel_logout"),
]


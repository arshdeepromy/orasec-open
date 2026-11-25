from django.urls import path

from orasec.plugins import views

urlpatterns = [
    path("orasec/plugins/", views.plugins_page, name="orasec_plugins"),
    path("orasec/plugins/<str:key>/toggle/", views.plugin_toggle, name="orasec_plugin_toggle"),
]

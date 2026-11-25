from django.urls import re_path

from orasec.components import views

urlpatterns = [
    re_path(r"^components$", views.components, name="components"),
]

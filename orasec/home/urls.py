from django.urls import re_path

from orasec.home import views

urlpatterns = [
    #  orasec home pages
    re_path(r"^$", views.home, name="home"),
    re_path(r"^dashboard$", views.dashboard, name="dashboard"),
    re_path(r"^dashboard/data$", views.dashboard_data, name="dashboard_data"),
    re_path(r"^support$", views.support, name="support"),
]

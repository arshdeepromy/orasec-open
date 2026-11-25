from django.urls import re_path

from orasec.auditlog.ui.views import action_history
from orasec.utils import get_system_setting

urlpatterns = [
    re_path(
        r"^{}history/(?P<cid>\d+)/(?P<oid>\d+)$".format(get_system_setting("url_prefix")),
        action_history,
        name="action_history",
    ),
]

try:
    from orasec.authorization.query_filters import get_auth_filter
except ImportError:
    def get_auth_filter(key): return None

from orasec.models import Engagement
from orasec.request_cache import cache_for_request_or_task


# Cached: all parameters are hashable, no dynamic queryset filtering
@cache_for_request_or_task
def get_authorized_engagements(permission):
    impl = get_auth_filter("engagement.get_authorized_engagements")
    if impl:
        return impl(permission)
    return Engagement.objects.all().order_by("id")

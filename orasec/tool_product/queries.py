try:
    from orasec.authorization.query_filters import get_auth_filter
except ImportError:
    def get_auth_filter(key): return None

from orasec.request_cache import cache_for_request_or_task
from orasec.tool_product.models import Tool_Product_Settings


# Cached: all parameters are hashable, no dynamic queryset filtering
@cache_for_request_or_task
def get_authorized_tool_product_settings(permission):
    impl = get_auth_filter("tool_product.get_authorized_tool_product_settings")
    if impl:
        return impl(permission)
    return Tool_Product_Settings.objects.all().order_by("id")

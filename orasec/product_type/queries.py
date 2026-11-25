try:
    from orasec.authorization.query_filters import get_auth_filter
except ImportError:
    def get_auth_filter(key): return None

from orasec.models import Product_Type
from orasec.request_cache import cache_for_request_or_task


# Cached: all parameters are hashable, no dynamic queryset filtering
@cache_for_request_or_task
def get_authorized_product_types(permission):
    impl = get_auth_filter("product_type.get_authorized_product_types")
    if impl:
        return impl(permission)
    return Product_Type.objects.all().order_by("name")

try:
    from orasec.authorization.query_filters import get_auth_filter
except ImportError:
    def get_auth_filter(key): return None

from orasec.models import (
    App_Analysis,
    OraSecMeta,
    Engagement_Presets,
    Languages,
    Product,
    Product_API_Scan_Configuration,
)
from orasec.request_cache import cache_for_request_or_task


# Cached: all parameters are hashable, no dynamic queryset filtering
@cache_for_request_or_task
def get_authorized_products(permission, user=None):
    impl = get_auth_filter("product.get_authorized_products")
    if impl:
        return impl(permission, user=user)
    return Product.objects.all().order_by("name")


# Cached: all parameters are hashable, no dynamic queryset filtering
@cache_for_request_or_task
def get_authorized_app_analysis(permission):
    impl = get_auth_filter("product.get_authorized_app_analysis")
    if impl:
        return impl(permission)
    return App_Analysis.objects.all().order_by("id")


# Cached: all parameters are hashable, no dynamic queryset filtering
@cache_for_request_or_task
def get_authorized_orasec_meta(permission):
    impl = get_auth_filter("product.get_authorized_orasec_meta")
    if impl:
        return impl(permission)
    return OraSecMeta.objects.all().order_by("id")


# Cached: all parameters are hashable, no dynamic queryset filtering
@cache_for_request_or_task
def get_authorized_languages(permission):
    impl = get_auth_filter("product.get_authorized_languages")
    if impl:
        return impl(permission)
    return Languages.objects.all().order_by("id")


# Cached: all parameters are hashable, no dynamic queryset filtering
@cache_for_request_or_task
def get_authorized_engagement_presets(permission):
    impl = get_auth_filter("product.get_authorized_engagement_presets")
    if impl:
        return impl(permission)
    return Engagement_Presets.objects.all().order_by("id")


# Cached: all parameters are hashable, no dynamic queryset filtering
@cache_for_request_or_task
def get_authorized_product_api_scan_configurations(permission):
    impl = get_auth_filter("product.get_authorized_product_api_scan_configurations")
    if impl:
        return impl(permission)
    return Product_API_Scan_Configuration.objects.all().order_by("id")

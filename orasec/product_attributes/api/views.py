from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.permissions import IsAuthenticated

from orasec.api_v2.views import OraSecModelViewSet
from orasec.authorization import api_permissions as permissions
from orasec.product_attributes.api.serializer import (
    ProductLifecycleSerializer,
    ProductOriginSerializer,
    ProductPlatformSerializer,
)
from orasec.product_attributes.models import Product_Lifecycle, Product_Origin, Product_Platform


# Authorization: authenticated, configuration
class ProductPlatformViewSet(OraSecModelViewSet):
    serializer_class = ProductPlatformSerializer
    queryset = Product_Platform.objects.none()
    filter_backends = (DjangoFilterBackend,)
    permission_classes = (IsAuthenticated, permissions.UserHasProductPlatformPermission)

    def get_queryset(self):
        return Product_Platform.objects.all().order_by("display_order", "name")


# Authorization: authenticated, configuration
class ProductLifecycleViewSet(OraSecModelViewSet):
    serializer_class = ProductLifecycleSerializer
    queryset = Product_Lifecycle.objects.none()
    filter_backends = (DjangoFilterBackend,)
    permission_classes = (IsAuthenticated, permissions.UserHasProductLifecyclePermission)

    def get_queryset(self):
        return Product_Lifecycle.objects.all().order_by("display_order", "name")


# Authorization: authenticated, configuration
class ProductOriginViewSet(OraSecModelViewSet):
    serializer_class = ProductOriginSerializer
    queryset = Product_Origin.objects.none()
    filter_backends = (DjangoFilterBackend,)
    permission_classes = (IsAuthenticated, permissions.UserHasProductOriginPermission)

    def get_queryset(self):
        return Product_Origin.objects.all().order_by("display_order", "name")

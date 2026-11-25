import logging

from django_filters import CharFilter, OrderingFilter

from orasec.filters import OraSecFilter
from orasec.product_type.models import Product_Type

logger = logging.getLogger(__name__)


class ProductTypeFilter(OraSecFilter):
    name = CharFilter(lookup_expr="icontains")

    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ("name", "name"),
        ),
    )

    class Meta:
        model = Product_Type
        exclude = []
        include = ("name",)

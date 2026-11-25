from rest_framework import serializers

from orasec.authorization.serializer_guards import AuthorizedUsersMemberGuardMixin
from orasec.product_type.models import Product_Type


class ProductTypeSerializer(AuthorizedUsersMemberGuardMixin, serializers.ModelSerializer):
    class Meta:
        model = Product_Type
        fields = "__all__"

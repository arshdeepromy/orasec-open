from django.contrib import admin

from orasec.object.models import Objects_Product, Objects_Review

admin.site.register(Objects_Product)
admin.site.register(Objects_Review)
admin.site.register(Objects_Product.tags.tag_model)

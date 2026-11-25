from django.contrib import admin

from orasec.user.models import Contact, UserContactInfo

admin.site.register(UserContactInfo)
admin.site.register(Contact)

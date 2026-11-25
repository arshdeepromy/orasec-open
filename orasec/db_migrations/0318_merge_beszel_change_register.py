# Joins two migrations that were both made on top of 0316: the Beszel connector and the Change Register.
from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("orasec", "0317_orasec_beszel"),
        ("orasec", "0317_orasec_change_register"),
    ]

    operations = []

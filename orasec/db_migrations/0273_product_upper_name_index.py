from django.contrib.postgres.operations import AddIndexConcurrently
from django.db import migrations, models
from django.db.models.functions import Upper


class Migration(migrations.Migration):
    # CREATE INDEX CONCURRENTLY cannot run inside a transaction block, and avoids
    # an ACCESS EXCLUSIVE lock on the orasec_product table.
    atomic = False

    dependencies = [
        ("orasec", "0272_reencrypt_tool_config_credentials_aes_gcm"),
    ]

    operations = [
        AddIndexConcurrently(
            model_name="product",
            index=models.Index(Upper("name"), name="orasec_product_upper_name_idx"),
        ),
    ]

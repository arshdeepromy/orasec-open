# ISO/IEC 27001 A.5.13: classification label on control evidence (POL-010 s4.2).

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('orasec', '0321_orasec_leaver_record'),
    ]

    operations = [
        migrations.AddField(
            model_name='controlevidence',
            name='classification',
            field=models.CharField(choices=[('public', 'Public'), ('internal', 'Internal'), ('confidential', 'Confidential'), ('restricted', 'Restricted')], default='internal', help_text='POL-010 classification of this evidence (label).', max_length=12),
        ),
    ]

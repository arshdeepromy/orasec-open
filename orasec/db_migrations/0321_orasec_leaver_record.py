# ISO/IEC 27001 A.5.11 / A.5.18 / A.6.5: leaver and mover records (LVR-).

import django.db.models.deletion
import django.utils.timezone
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('orasec', '0320_orasec_isms_sync'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='LeaverRecord',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ref', models.CharField(blank=True, max_length=20, unique=True)),
                ('kind', models.CharField(choices=[('leaver', 'Leaver'), ('mover', 'Mover (role change)')], default='leaver', max_length=10)),
                ('leaving_date', models.DateField(default=django.utils.timezone.localdate)),
                ('due_date', models.DateField(blank=True, help_text='Checklist complete by (default 5 business days)', null=True)),
                ('reason', models.TextField(blank=True)),
                ('started_automatically', models.BooleanField(default=False)),
                ('steps', models.JSONField(blank=True, default=list)),
                ('assets', models.JSONField(blank=True, default=list, help_text='Assets owned or jointly owned when the record started')),
                ('status', models.CharField(choices=[('open', 'Open'), ('signed_off', 'Signed off'), ('cancelled', 'Cancelled')], db_index=True, default='open', max_length=12)),
                ('signed_off_at', models.DateTimeField(blank=True, null=True)),
                ('note', models.TextField(blank=True)),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('updated', models.DateTimeField(auto_now=True)),
                ('person', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='leaver_records', to=settings.AUTH_USER_MODEL)),
                ('started_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='+', to=settings.AUTH_USER_MODEL)),
                ('signed_off_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='+', to=settings.AUTH_USER_MODEL)),
            ],
            options={'ordering': ['-ref']},
        ),
    ]

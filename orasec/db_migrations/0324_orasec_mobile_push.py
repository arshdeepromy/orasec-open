# Mobile app push notifications (orasec.mobile): the address of each linked phone, what each person wants, what was already announced.

import django.db.models.deletion
import django.utils.timezone
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('orasec', '0323_orasec_mcp'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name='mobiledevice',
            name='push_token',
            field=models.CharField(blank=True, max_length=512),
        ),
        migrations.AddField(
            model_name='mobiledevice',
            name='push_updated',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.CreateModel(
            name='MobilePushPrefs',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('critical', models.BooleanField(default=True)),
                ('approvals', models.BooleanField(default=True)),
                ('alerts', models.BooleanField(default=True)),
                ('overdue', models.BooleanField(default=True)),
                ('created', models.DateTimeField(default=django.utils.timezone.now)),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='mobile_push_prefs', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='MobilePushSent',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('kind', models.CharField(max_length=12)),
                ('ref', models.CharField(max_length=40)),
                ('created', models.DateTimeField(db_index=True, default=django.utils.timezone.now)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='+', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'constraints': [models.UniqueConstraint(fields=('user', 'kind', 'ref'), name='orasec_mobilepush_once')],
            },
        ),
    ]

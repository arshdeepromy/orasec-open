# ISO/IEC 27001 10.2: nonconformity and corrective action register (NC-).

import django.db.models.deletion
import django.utils.timezone
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('orasec', '0318_merge_beszel_change_register'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Nonconformity',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ref', models.CharField(blank=True, max_length=20, unique=True)),
                ('title', models.CharField(max_length=300)),
                ('source', models.CharField(choices=[('audit', 'Internal or external audit'), ('incident', 'Security incident'), ('check', 'Failed automatic check'), ('review', 'Management review'), ('other', 'Other')], default='audit', max_length=16)),
                ('control', models.CharField(blank=True, help_text='Clause or control, e.g. A.8.8', max_length=40)),
                ('description', models.TextField(blank=True, help_text='What went wrong')),
                ('correction', models.TextField(blank=True, help_text='Immediate fix')),
                ('cause', models.TextField(blank=True, help_text='Root cause')),
                ('corrective_action', models.TextField(blank=True, help_text='Action so it does not happen again')),
                ('due_date', models.DateField(blank=True, null=True)),
                ('status', models.CharField(choices=[('open', 'Open'), ('action', 'Corrective action in progress'), ('verify', 'Awaiting effectiveness check'), ('closed', 'Closed'), ('dropped', 'Not a nonconformity')], db_index=True, default='open', max_length=16)),
                ('effectiveness', models.TextField(blank=True, help_text='How the fix was checked and the result')),
                ('raised', models.DateField(default=django.utils.timezone.localdate)),
                ('closed_date', models.DateField(blank=True, null=True)),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('updated', models.DateTimeField(auto_now=True)),
                ('owner', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='owned_nonconformities', to=settings.AUTH_USER_MODEL)),
                ('verified_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='verified_nonconformities', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ['-ref'],
            },
        ),
    ]

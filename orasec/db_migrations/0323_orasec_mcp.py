# Connector endpoint (orasec.mcp): two-step proposals, connected clients, per-person switch and the call log.

import django.db.models.deletion
import django.utils.timezone
import uuid
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('orasec', '0322_orasec_evidence_classification'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='McpAccess',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('blocked_at', models.DateTimeField(blank=True, null=True)),
                ('blocked_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='+', to=settings.AUTH_USER_MODEL)),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='mcp_access', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='McpCall',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created', models.DateTimeField(db_index=True, default=django.utils.timezone.now)),
                ('username', models.CharField(blank=True, max_length=150)),
                ('via', models.CharField(blank=True, max_length=12)),
                ('client_id', models.CharField(blank=True, max_length=200)),
                ('client_name', models.CharField(blank=True, max_length=120)),
                ('ip', models.CharField(blank=True, max_length=64)),
                ('method', models.CharField(blank=True, max_length=40)),
                ('tool', models.CharField(blank=True, max_length=80)),
                ('args', models.CharField(blank=True, max_length=300)),
                ('outcome', models.CharField(max_length=16)),
                ('detail', models.CharField(blank=True, max_length=300)),
                ('write', models.BooleanField(default=False)),
                ('ms', models.PositiveIntegerField(default=0)),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='+', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ['-created'],
            },
        ),
        migrations.CreateModel(
            name='McpProposal',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('kind', models.CharField(max_length=30)),
                ('payload', models.JSONField(default=dict)),
                ('card', models.JSONField(default=dict)),
                ('status', models.CharField(default='pending', max_length=12)),
                ('result', models.JSONField(blank=True, default=dict)),
                ('client_name', models.CharField(blank=True, max_length=120)),
                ('created', models.DateTimeField(default=django.utils.timezone.now)),
                ('expires_at', models.DateTimeField()),
                ('decided_at', models.DateTimeField(blank=True, null=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='+', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ['-created'],
            },
        ),
        migrations.CreateModel(
            name='McpClient',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('kind', models.CharField(choices=[('oauth', 'Single sign-on'), ('api_token', 'API token')], max_length=12)),
                ('client_id', models.CharField(blank=True, max_length=200)),
                ('client_name', models.CharField(blank=True, max_length=120)),
                ('first_seen', models.DateTimeField(default=django.utils.timezone.now)),
                ('last_seen', models.DateTimeField(default=django.utils.timezone.now)),
                ('last_ip', models.CharField(blank=True, max_length=64)),
                ('calls', models.PositiveIntegerField(default=0)),
                ('blocked_at', models.DateTimeField(blank=True, null=True)),
                ('blocked_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='+', to=settings.AUTH_USER_MODEL)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='mcp_clients', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ['-last_seen'],
                'constraints': [models.UniqueConstraint(fields=('user', 'kind', 'client_id', 'client_name'), name='os_mcpclient_unique')],
            },
        ),
    ]

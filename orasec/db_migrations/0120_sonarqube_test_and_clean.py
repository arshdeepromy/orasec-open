from django.db import migrations, models
import django.db.models.deletion
import logging

logger = logging.getLogger(__name__)


def sq_clean(apps, schema_editor):
    Sonarqube_Product_model = apps.get_model('orasec', 'Sonarqube_Product')
    Tool_Configuration_model = apps.get_model('orasec', 'Tool_Configuration')
    Tool_Type_model = apps.get_model('orasec', 'Tool_Type')
    tts = Tool_Type_model.objects.filter(name='SonarQube')

    sqtc = Tool_Configuration_model.objects.filter(tool_type__in=tts).first()

    if sqtc:
        for sq in Sonarqube_Product_model.objects.filter(sonarqube_tool_config__isnull=True):
            logger.info('Setting Product SonarQube Configuration for product {} to only existing SonarQube Tool '
                        'Configuration'.format(sq.product.pk))
            sq.sonarqube_tool_config = sqtc
            sq.save()
    else:
        logger.warning('No SonarQube tool configuration found, all invalid SonarQube configurations will be removed.')
        Sonarqube_Product_model.objects.filter(sonarqube_tool_config__isnull=True).delete()


class Migration(migrations.Migration):

    dependencies = [
        ('orasec', '0119_default_group_is_staff'),
    ]

    operations = [
        migrations.RunPython(sq_clean),
        migrations.AddField(
            model_name='test',
            name='sonarqube_config',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='orasec.sonarqube_product', verbose_name='SonarQube Config'),
        ),
        migrations.AlterField(
            model_name='sonarqube_product',
            name='sonarqube_tool_config',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='orasec.tool_configuration',
                                    verbose_name='SonarQube Configuration'),
        ),
    ]

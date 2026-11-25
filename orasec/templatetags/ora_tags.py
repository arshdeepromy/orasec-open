from django import template

register = template.Library()


@register.simple_tag
def ora_asset_version():
    from orasec.ora.views import asset_version  # noqa: PLC0415
    try:
        return asset_version()
    except OSError:
        return "0"

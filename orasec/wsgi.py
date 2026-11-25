"""
WSGI config for orasec project.

This module contains the WSGI application used by Django's development server
and any production WSGI deployments. It should expose a module-level variable
named ``application``. Django's ``runserver`` and ``runfcgi`` commands discover
this application via the ``WSGI_APPLICATION`` setting.

Usually you will have the standard Django WSGI application here, but it also
might make sense to replace the whole Django WSGI application with a custom one
that later delegates to the Django one. For example, you could introduce WSGI
middleware here, or combine a Django application with an application of another
framework.

"""
import logging
import os

from django.core.wsgi import get_wsgi_application

logger = logging.getLogger(__name__)

# We defer to a DJANGO_SETTINGS_MODULE already in the environment. This breaks
# if running multiple sites in the same mod_wsgi process. To fix this, use
# mod_wsgi daemon mode with each site in its own daemon process, or use
# os.environ["DJANGO_SETTINGS_MODULE"] = "orasec.settings"
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "orasec.settings.settings")

# This application object is used by any WSGI server configured to use this
# file. This includes Django's development server, if the WSGI_APPLICATION
# setting points here.
application = get_wsgi_application()


def _warm_up():
    """
    Load the URLconf (and through it every view module) and compile the templates used on every page while the
    uWSGI master loads the app. Workers are forked from the master afterwards, so they start warm instead of paying
    the full import/compile cost (15 s+ on a Raspberry Pi) on their first request.
    """
    from django.core.cache import caches  # noqa: PLC0415
    from django.db import connections  # noqa: PLC0415
    from django.template.loader import get_template  # noqa: PLC0415
    from django.urls import get_resolver  # noqa: PLC0415
    try:
        get_resolver().url_patterns  # noqa: B018
        for name in ("base.html", "orasec/dashboard.html", "orasec/posture/command_center.html"):
            get_template(name)
    except Exception:
        logger.warning("wsgi warm-up failed", exc_info=True)
    finally:
        # never hand a database or cache connection opened here to the forked workers
        connections.close_all()
        for cache in caches.all(initialized_only=True):
            cache.close()


if os.environ.get("ORASEC_WSGI_WARMUP", "1") != "0":
    _warm_up()

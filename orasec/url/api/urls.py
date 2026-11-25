from orasec.url.api import path
from orasec.url.api.views import URLViewSet


def add_url_urls(router):
    router.register(path, URLViewSet, path)
    return router

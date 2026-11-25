from orasec.regulations.api import path
from orasec.regulations.api.views import RegulationsViewSet


def add_regulations_urls(router):
    router.register(path, RegulationsViewSet, basename="regulations")
    return router

# NOTE: do not import query_registrations here. It pulls in orasec.models
# (and orasec.location.models), which can be mid-import when this package
# is loaded transitively (e.g. via `from orasec.authorization.query_filters
# import get_auth_filter`). If that chain raises ImportError, callers
# silently fall back to a stub `get_auth_filter` and the queryset auth
# filters never apply. Registration is now triggered explicitly in
# orasec/apps.py ready() once all models are loaded.

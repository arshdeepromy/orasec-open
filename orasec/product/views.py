# Backward-compat shim: the view logic moved to orasec.product.ui.views during the
# module reorg. External consumers (e.g. orasec-pro) still import from
# orasec.product.views, so re-export the public names from their new location.
from orasec.product.ui.views import *  # noqa: F403 -- backward compat re-export

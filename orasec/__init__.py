

# This will make sure the app is always imported when
# Django starts so that shared_task will use this app.
from .celery import app as celery_app  # noqa: F401

__version__ = "1.0.0"
__url__ = "https://github.com/OraSec/django-OraSec"
__docs__ = "https://github.com/arshdeepromy/orasec-open/tree/main/readme-docs"

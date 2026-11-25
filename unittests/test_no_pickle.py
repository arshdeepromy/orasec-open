"""
Guard tests preventing the reintroduction of pickle into the orasec app.

Pickle deserialization of attacker-controllable bytes is arbitrary code
execution. We removed all uses (form widgets, Celery serializer) and these
tests fail loudly if a future change adds them back.
"""

import re
from pathlib import Path

from django.conf import settings

import orasec
from unittests.orasec_test_case import OraSecTestCase


class TestNoPickle(OraSecTestCase):
    def test_no_pickle_imports_in_orasec(self):
        orasec_root = Path(orasec.__file__).resolve().parent
        offenders = []
        import_re = re.compile(r"^\s*(?:import\s+pickle|from\s+pickle\s+import)\b", re.MULTILINE)
        for path in orasec_root.rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            if import_re.search(text):
                offenders.append(str(path.relative_to(orasec_root.parent)))
        self.assertFalse(
            offenders,
            f"pickle is forbidden in orasec source. Offenders: {offenders}",
        )

    def test_celery_serializer_is_json_only(self):
        self.assertEqual(settings.CELERY_TASK_SERIALIZER, "json")
        self.assertEqual(settings.CELERY_ACCEPT_CONTENT, ["json"])
        self.assertEqual(settings.CELERY_RESULT_SERIALIZER, "json")

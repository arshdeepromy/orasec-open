from datetime import datetime, timedelta
from unittest.mock import patch

from dateutil.relativedelta import relativedelta
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.urls import reverse
from django.utils import timezone

from orasec.home import metrics
from orasec.models import Engagement, Finding, Risk_Acceptance, System_Settings, Test
from unittests.orasec_test_case import OraSecTestCase, versioned_fixtures

User = get_user_model()


def create(when: datetime, product_id: int, titles_and_severities: list[tuple[str, str]]):
    with patch("django.db.models.fields.timezone.now") as mock_now:
        mock_now.return_value = when
        engagement = Engagement.objects.create(product_id=product_id, target_start=when.date(), target_end=when.date())
        test = Test.objects.create(engagement=engagement, test_type_id=120, target_start=when, target_end=when)
        Finding.objects.bulk_create(
            (Finding(title=title, test=test, severity=severity, verified=False)
             for title, severity in titles_and_severities),
        )


def create_with_duplicates(when: datetime, product_id: int, titles_and_severities: list[tuple[str, str]]):
    with patch("django.db.models.fields.timezone.now") as mock_now:
        mock_now.return_value = when
        engagement = Engagement.objects.create(product_id=product_id, target_start=when.date(), target_end=when.date())
        test = Test.objects.create(engagement=engagement, test_type_id=120, target_start=when, target_end=when)
        originals = Finding.objects.filter(test__engagement__product_id=product_id, duplicate=False,
                                           title__in=[title for title, _ in titles_and_severities])
        originals_map = {original.title: original for original in originals}
        Finding.objects.bulk_create(
            (Finding(title=title, test=test, severity=severity, verified=False,
                     duplicate=(title in originals_map), duplicate_finding=originals_map.get(title))
             for title, severity in titles_and_severities),
        )


def mitigate(when: datetime, product_id: int, title: str):
    with patch("django.db.models.fields.timezone.now") as mock_now:
        mock_now.return_value = when
        Finding.objects.filter(test__engagement__product_id=product_id, title=title).update(is_mitigated=True, mitigated=when)


def accept(when: datetime, product_id: int, title: str):
    with patch("django.db.models.fields.timezone.now") as mock_now:
        mock_now.return_value = when
        findings = Finding.objects.filter(test__engagement__product_id=product_id, title=title)
        ra = Risk_Acceptance.objects.create(name="My Risk Acceptance", owner_id=1)
        ra.accepted_findings.add(*findings)
        findings.update(risk_accepted=True)


def verify(when: datetime, product_id: int, title: str):
    with patch("django.db.models.fields.timezone.now") as mock_now:
        mock_now.return_value = when
        Finding.objects.filter(test__engagement__product_id=product_id, title=title).update(verified=True)


@versioned_fixtures
class TestDashboard(OraSecTestCase):
    fixtures = ["orasec_testdata.json"]

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.now = timezone.now()
        cls.week_ago = cls.now - timedelta(weeks=1)
        cls.month_ago = cls.now - relativedelta(months=1)

    @classmethod
    def setUpTestData(cls) -> None:
        System_Settings.objects.update(enable_deduplication=False)  # The default deduplication does not work.
        Engagement.objects.all().delete()

    def setUp(self):
        cache.delete(metrics.CACHE_KEY)
        cache.delete(metrics.LOCK_KEY)

    def _setup_findings(self, product_id: int):
        create(self.week_ago, product_id, [
            ("My Finding 1.1", "Critical"),
            ("My Finding 1.2", "High"),
            ("My Finding 1.3", "Medium"),
            ("My Finding 1.4", "Medium"),
            ("My Finding 1.5", "Low"),
            ("My Finding 1.6", "Info"),
        ])
        mitigate(self.now, product_id, "My Finding 1.4")
        Finding.objects.filter(title="My Finding 1.4").update(active=False)
        accept(self.now, product_id, "My Finding 1.5")
        verify(self.now, product_id, "My Finding 1.3")
        create(self.now, product_id, [("My Finding 2.1", "Critical")])
        create_with_duplicates(self.now, product_id, [("My Finding 2.1", "Critical")])  # duplicate: never counted

    def _get(self, username: str, name: str = "dashboard", **params):
        self.client.force_login(User.objects.get(username=username))
        return self.client.get(reverse(name), params)

    def test_superuser_sees_org_wide_metrics(self):
        self._setup_findings(product_id=2)
        response = self._get("admin")
        self.assertEqual(200, response.status_code)
        data = response.context["data"]
        self.assertIsNotNone(data)
        sev = {s["name"]: s["n"] for s in data["severity"]}
        self.assertEqual(2, sev["Critical"])  # 1.1 and 2.1; the duplicate of 2.1 is excluded
        self.assertEqual(1, sev["High"])
        self.assertEqual(1, sev["Medium"])  # 1.4 is mitigated
        self.assertEqual(data["kpi"]["open"], sum(sev.values()))
        self.assertEqual(1, data["kpi"]["resolved_total"])
        self.assertTrue(data["assets"])
        self.assertContains(response, "Security Operations")

    def test_metrics_are_served_from_cache(self):
        self._setup_findings(product_id=2)
        self._get("admin")
        self.assertIsNotNone(cache.get(metrics.CACHE_KEY))
        with self.assertNumQueries(0, using="default"):
            metrics.get()

    def test_data_endpoint(self):
        self._setup_findings(product_id=2)
        response = self._get("admin", "dashboard_data")
        self.assertEqual(200, response.status_code)
        self.assertIn("severity", response.json())

    def test_regular_user_does_not_see_org_wide_data(self):
        self._setup_findings(product_id=2)
        response = self._get("user1")
        self.assertEqual(200, response.status_code)
        self.assertIsNone(response.context["data"])
        self.assertTrue(response.context["restricted"])
        self.assertEqual(403, self._get("user1", "dashboard_data").status_code)

    def test_resolution_time_after_detection(self):
        self._setup_findings(product_id=2)
        data = metrics.compute()
        medium = next(r for r in data["resolution"] if r["severity"] == "Medium")
        self.assertEqual(1, medium["closed"])
        self.assertEqual(7, medium["median"])  # detected a week ago, mitigated now
        self.assertEqual([1, 0, 0, 0], medium["buckets"])  # 7 days is inside the "<= 7 d" bucket

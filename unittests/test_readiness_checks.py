"""Readiness checks: approved policy-tool documents plus operational signals per control."""
import datetime

from django.utils import timezone

from orasec.posture import compliance
from orasec.posture import readiness_checks as rc
from orasec.posture.models import (ComplianceControl, ComplianceFramework, Connector, ConnectorRun, ControlEvidence,
                                   InventoryAsset)
from unittests.orasec_test_case import OraSecTestCase


class TestReadiness(OraSecTestCase):
    def setUp(self):
        self.fw, _ = ComplianceFramework.objects.get_or_create(code="iso27001-2022", defaults={"name": "ISO"})
        self.c = {}
        for ref in ("A.5.14", "A.5.15", "A.5.18", "A.6.1", "A.7.4", "A.8.13", "A.8.14", "A.8.23", "A.8.31", "A.8.33", "A.5.35"):
            self.c[ref], _ = ComplianceControl.objects.get_or_create(framework=self.fw, ref=ref, defaults={"title": ref, "category": "x"})
        self.today = timezone.localdate()

    def doc(self, ref, doc_id="POL-001", days=365):
        return ControlEvidence.objects.create(control=self.c[ref], source="auto", title=f"Policy tool: {doc_id} Some Policy v2.3",
                                              valid_until=self.today + datetime.timedelta(days=days))

    def test_no_document_fails(self):
        r, d, _m = rc.check_info_transfer()
        self.assertEqual(r, "fail")
        self.assertIn("No approved, in-date document", d)

    def test_document_passes_and_names_it(self):
        self.doc("A.5.14", "STD-003")
        r, d, m = rc.check_info_transfer()
        self.assertEqual(r, "pass", d)
        self.assertIn("STD-003", d)
        self.assertEqual(m["documents"], ["STD-003"])

    def test_expired_document_is_ignored(self):
        self.doc("A.5.14", days=-1)
        self.assertEqual(rc.check_info_transfer()[0], "fail")

    def test_superseded_link_ignored(self):
        self.doc("A.5.14", "STD-003", days=365)
        ControlEvidence.objects.create(control=self.c["A.5.14"], source="auto", title="Policy tool: STD-003 Old v2.3",
                                       valid_until=self.today, description="Approved version 2.3. Superseded on today.")
        r, d, _m = rc.check_info_transfer()
        self.assertEqual(r, "pass", d)

    def test_review_due_soon_warns(self):
        self.doc("A.5.14", days=20)
        self.assertEqual(rc.check_info_transfer()[0], "warn")

    def test_connector_evidence_needed(self):
        self.doc("A.5.15")
        r, d, _m = rc.check_access_control()
        self.assertEqual(r, "fail")
        self.assertIn("AWS IAM evidence", d)
        ControlEvidence.objects.create(control=self.c["A.5.15"], source="auto", title="Access control: IAM users, MFA and keys — AWS",
                                       valid_until=self.today + datetime.timedelta(days=30))
        self.assertEqual(rc.check_access_control()[0], "pass")

    def test_per_role_records(self):
        self.doc("A.6.1", "POL-014")
        r, d, _m = rc.check_screening()
        self.assertEqual(r, "fail")
        self.assertIn("CTO", d)
        for role in rc.ROLES:
            ControlEvidence.objects.create(control=self.c["A.6.1"], title=f"Screening: {role} - identity and references (2026)")
        self.assertEqual(rc.check_screening()[0], "pass")

    def test_first_review_due_from_approval_date(self):
        self.doc("A.5.18", days=365)  # approved today: first quarterly review due in 61 days
        r, d, _m = rc.check_access_review()
        self.assertEqual(r, "pass", d)
        self.assertIn("first user access review due", d)
        ControlEvidence.objects.all().delete()
        self.doc("A.5.18", days=300)  # approved 65 days ago: first review was due 4 days ago
        r, d, _m = rc.check_access_review()
        self.assertEqual(r, "fail", d)
        ControlEvidence.objects.create(control=self.c["A.5.18"], title="Access review: Q4 2026 user access review")
        self.assertEqual(rc.check_access_review()[0], "pass")

    def test_restore_record_counts(self):
        self.doc("A.8.13", "POL-009", days=300)
        old = ControlEvidence.objects.create(control=self.c["A.8.13"], title="Restore test from S3: PASS")
        ControlEvidence.objects.filter(pk=old.pk).update(collected_at=timezone.now() - datetime.timedelta(days=400))
        self.assertEqual(rc.check_backup()[0], "fail")
        ControlEvidence.objects.create(control=self.c["A.8.13"], title="Restore test from S3: PASS (again)")
        r, d, _m = rc.check_backup()
        self.assertEqual(r, "pass", d)
        self.assertIn("next due", d)

    def test_physical_monitoring_uses_inventory(self):
        self.doc("A.7.4", "POL-019")
        self.assertEqual(rc.check_physical_monitoring()[0], "warn")
        now = timezone.now()
        InventoryAsset.objects.create(name="Driveway", asset_type="client", first_seen=now, last_seen=now,
                                      attributes={"device_role": "camera"})
        self.assertEqual(rc.check_physical_monitoring()[0], "pass")

    def test_web_filtering_from_gateway_settings(self):
        self.doc("A.8.23", "POL-006")
        r, d, _m = rc.check_web_filtering()
        self.assertEqual(r, "fail")
        self.assertIn("not collected", d)
        conn = Connector.objects.create(name="UniFi", kind="unifi", base_url="https://unifi.example.internal")
        wf = {"site": "Default", "ips_mode": "ips", "ips_networks": ["Home", "Office"], "ips_categories": 33,
              "ad_blocking_networks": [], "content_filtering": [
                  {"name": "Protected", "enabled": True, "categories": ["FAMILY"], "networks": ["Home"]}]}
        ConnectorRun.objects.create(connector=conn, status="ok", finished_at=timezone.now(), stats={"web_filtering": [wf]})
        r, d, _m = rc.check_web_filtering()
        self.assertEqual(r, "fail")
        self.assertIn("no enabled content filter blocking malware and phishing on Office", d)
        wf["content_filtering"].append({"name": "Company security", "enabled": True,
                                        "categories": ["BOTNETS", "MALWARE", "PHISHING"], "networks": ["Office"]})
        ConnectorRun.objects.create(connector=conn, status="ok", finished_at=timezone.now(), stats={"web_filtering": [wf]})
        r, d, _m = rc.check_web_filtering()
        self.assertEqual(r, "pass", d)
        self.assertIn("Company security", d)
        wf["content_filtering"][-1]["categories"] = ["FAMILY"]
        ConnectorRun.objects.create(connector=conn, status="ok", finished_at=timezone.now(), stats={"web_filtering": [wf]})
        r, d, _m = rc.check_web_filtering()
        self.assertEqual(r, "pass", d)
        self.assertIn("Basic", d)
        wf["ips_mode"] = "ids"
        ConnectorRun.objects.create(connector=conn, status="ok", finished_at=timezone.now(), stats={"web_filtering": [wf]})
        self.assertEqual(rc.check_web_filtering()[0], "fail")

    def test_redundancy_needs_accepted_risk_and_restore_test(self):
        from orasec.posture.grc_models import GovernanceException
        self.doc("A.8.14", "PLN-001")
        ControlEvidence.objects.create(control=self.c["A.8.13"], title="Restore test from S3: PASS")
        r, d, _m = rc.check_redundancy()
        self.assertEqual(r, "fail")
        self.assertIn("no approved risk acceptance", d)
        e = GovernanceException.objects.create(kind="risk_acceptance", title="t", description="t", control=self.c["A.8.14"],
                                               likelihood=2, impact=2, expiry=self.today + datetime.timedelta(days=300),
                                               status="approved")
        r, d, _m = rc.check_redundancy()
        self.assertEqual(r, "pass", d)
        self.assertIn(e.ref, d)
        e.expiry = self.today + datetime.timedelta(days=5)
        e.save()
        self.assertEqual(rc.check_redundancy()[0], "warn")

    def test_environment_separation_and_test_data_records(self):
        self.doc("A.8.31", "POL-013")
        self.doc("A.8.33", "POL-010")
        # documents approved today: first yearly check is not yet due
        self.assertEqual(rc.check_environment_separation()[0], "pass")
        self.assertEqual(rc.check_test_information()[0], "pass")
        old = ControlEvidence.objects.create(control=self.c["A.8.31"], source="manual",
                                             title="Environment separation check: App UAT")
        ControlEvidence.objects.filter(pk=old.pk).update(collected_at=timezone.now() - datetime.timedelta(days=400))
        r, d, _m = rc.check_environment_separation()
        self.assertEqual(r, "fail")
        self.assertIn("overdue", d)
        ControlEvidence.objects.create(control=self.c["A.8.31"], source="manual", title="Environment separation check: App UAT keys")
        r, d, _m = rc.check_environment_separation()
        self.assertEqual(r, "pass", d)
        ControlEvidence.objects.create(control=self.c["A.8.33"], source="manual", title="Test data check: App UAT")
        r, d, _m = rc.check_test_information()
        self.assertEqual(r, "pass", d)
        self.assertIn("last test data check", d)

    def test_independent_review_needs_pen_test_record(self):
        self.doc("A.5.35", "FWK-001")
        r, d, _m = rc.check_independent_review()
        self.assertIn("2026", d)
        expected = "fail" if self.today > datetime.date(2026, 11, 29) else ("warn" if self.today >= datetime.date(2026, 11, 15) else "pass")
        self.assertEqual(r, expected, d)
        ControlEvidence.objects.create(control=self.c["A.5.35"], source="manual", title="Internal pen test: all Ora tools")
        r, d, _m = rc.check_independent_review()
        self.assertEqual(r, "pass", d)
        self.assertIn("last internal pen test", d)

    def test_registered(self):
        for ref, key in rc.READINESS_CHECKS.items():
            self.assertIn("check_" + key, compliance.CHECKS, ref)
            self.assertEqual(compliance.AUTO_CHECKS[ref], key)


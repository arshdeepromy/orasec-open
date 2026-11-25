"""Asset inventory section (ISO/IEC 27001 A.5.9): grouping, owners, supplier sync, exports, access, check."""
import datetime
import io
import json
from unittest import mock

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import Client
from django.utils import timezone

from orasec import site as site_profile
from orasec.posture import asset_inventory as ai
from orasec.posture.compliance import check_asset_inventory
from orasec.posture.grc_models import Supplier
from orasec.posture.models import Connector, InventoryAsset
from unittests.orasec_test_case import OraSecTestCase

User = get_user_model()
OWNERS = ["Alex Lee - Director/CTO", "Dana Smith - Cloud Infrastructure Engineer"]


def _a(name, **kw):
    now = timezone.now()
    kw.setdefault("asset_type", "server")
    kw.setdefault("last_seen", now)
    return InventoryAsset.objects.create(name=name, first_seen=now, **kw)


class Base(OraSecTestCase):
    def setUp(self):
        cache.clear()
        ctx = site_profile.override(asset_owners=OWNERS)
        ctx.__enter__()
        self.addCleanup(ctx.__exit__, None, None, None)
        InventoryAsset.objects.all().delete()
        self.su = User.objects.create_superuser("ai-admin", "a@example.com", "x")
        self.user = User.objects.create_user("ai-user", "u@example.com", "x")


class TestClassification(Base):
    def test_categories_and_locations(self):
        dev = _a("Srv1", ip_address="192.168.10.90", sources={"wazuh": {}}, owner=self.su)
        s3 = _a("s3://bucket-x", asset_type="other", sources={"aws": {}}, owner=self.su)
        repo = _a("acme/repo", asset_type="application", sources={"github": {}}, owner=self.su)
        dom = _a("www.example.com", asset_type="application", sources={"dns": {}}, owner=self.su)
        tool = _a("Policy tool", asset_type="application", attributes={"category": "internal tool", "manual": True,
                                                                         "joint_owners": OWNERS})
        self.assertEqual(["device", "cloud", "code", "domain", "internal tool"], [ai.category(x) for x in (dev, s3, repo, dom, tool)])
        self.assertEqual("Head office", ai.location(dev))
        self.assertEqual("Cloud", ai.location(s3))
        self.assertEqual("GitHub", ai.location(repo))
        self.assertEqual(OWNERS, ai.owners(tool))

    def test_stale_only_for_auto_synced(self):
        old = timezone.now() - datetime.timedelta(days=30)
        a = _a("old box", sources={"wazuh": {}}, last_seen=old, owner=self.su)
        m = _a("manual thing", asset_type="other", last_seen=old, attributes={"manual": True, "category": "information"}, owner=self.su)
        self.assertTrue(ai.row(a)["stale"])
        self.assertFalse(ai.row(m)["stale"])


class TestSupplierSync(Base):
    def _sup(self, **kw):
        kw.setdefault("ref", "SUP-V-901")
        kw.setdefault("name", "Example Mail")
        kw.setdefault("service", "Email")
        kw.setdefault("status", "active")
        kw.setdefault("tier", "critical")
        kw.setdefault("data_location", "Australia")
        with self.captureOnCommitCallbacks(execute=True):
            return Supplier.objects.create(**kw)

    def test_active_supplier_creates_cloud_service_asset(self):
        s = self._sup()
        a = InventoryAsset.objects.get(attributes__supplier_ref=s.ref)
        self.assertEqual("cloud service", a.attributes["category"])
        self.assertEqual(OWNERS, a.attributes["joint_owners"])
        self.assertTrue(a.attributes["business_critical"])
        self.assertEqual("Supplier cloud (Australia)", ai.location(a, {s.ref: s}))

    def test_rename_and_exit_retire_not_delete(self):
        s = self._sup()
        s.name = "Example Mail Pro"
        with self.captureOnCommitCallbacks(execute=True):
            s.save()
        a = InventoryAsset.objects.get(attributes__supplier_ref=s.ref)
        self.assertEqual("Example Mail Pro", a.name)
        s.status = "exited"
        with self.captureOnCommitCallbacks(execute=True):
            s.save()
        a.refresh_from_db()
        self.assertTrue(a.retired)
        self.assertEqual(1, InventoryAsset.objects.filter(attributes__supplier_ref=s.ref).count())

    def test_reconcile_is_idempotent(self):
        self._sup()
        ai.reconcile()
        ai.reconcile()
        self.assertEqual(1, InventoryAsset.objects.filter(attributes__category="cloud service").count())


class TestPagesAndExports(Base):
    def setUp(self):
        super().setUp()
        _a("Srv1", ip_address="192.168.10.90", hostname="srv1", mac_address="aa:bb:cc:dd:ee:ff", sources={"wazuh": {}}, owner=self.su)
        _a("Customer data", asset_type="other", attributes={"category": "information", "manual": True, "joint_owners": OWNERS})
        self.c = Client()

    def test_pages_render_for_org_wide(self):
        self.c.force_login(self.su)
        for u in ("/orasec/assets/", "/orasec/assets/list/", "/orasec/assets/group/information/", "/orasec/assets/list/?view=grouped"):
            self.assertEqual(200, self.c.get(u).status_code, u)

    def test_other_users_get_403(self):
        self.c.force_login(self.user)
        for u in ("/orasec/assets/", "/orasec/assets/list/", "/orasec/assets/export.xlsx", "/orasec/assets/export.pdf"):
            self.assertEqual(403, self.c.get(u).status_code, u)
        self.assertEqual(403, self.c.post("/orasec/assets/ora-report/", {"prompt": "x"}).status_code)

    def test_xlsx_valid_and_no_network_details_by_default(self):
        from openpyxl import load_workbook
        self.c.force_login(self.su)
        r = self.c.get("/orasec/assets/export.xlsx")
        wb = load_workbook(io.BytesIO(r.content))
        text = " ".join(str(c.value) for ws in wb for row in ws.iter_rows() for c in row if c.value is not None)
        self.assertIn("Customer data", text)
        self.assertNotIn("192.168.10.90", text)
        r = self.c.get("/orasec/assets/export.xlsx?network=1")
        wb = load_workbook(io.BytesIO(r.content))
        text = " ".join(str(c.value) for ws in wb for row in ws.iter_rows() for c in row if c.value is not None)
        self.assertIn("192.168.10.90", text)

    def test_pdf_valid(self):
        self.c.force_login(self.su)
        r = self.c.get("/orasec/assets/export.pdf")
        self.assertTrue(r.content.startswith(b"%PDF-1.4"))
        self.assertIn(b"%%EOF", r.content[-10:])
        self.assertNotIn(b"192.168.10.90", r.content)


class TestOra(Base):
    def test_tool_and_report_data_hold_no_ip_or_mac(self):
        from orasec.ora.tools import run_tool
        _a("Srv1", ip_address="192.168.10.90", hostname="srv1-host", mac_address="aa:bb:cc:dd:ee:ff", sources={"wazuh": {}}, owner=self.su)
        out = json.dumps(run_tool("asset_inventory", {}, self.su), default=str)
        self.assertIn("Srv1", out)
        for bad in ("192.168.10.90", "aa:bb:cc", "srv1-host"):
            self.assertNotIn(bad, out)
        self.assertIn("error", json.dumps(run_tool("asset_inventory", {}, self.user)) + "error")

    def test_report_uses_provider_and_cleans_output(self):
        from orasec.ora.providers.base import ProviderResult
        _a("Srv1", sources={"wazuh": {}}, owner=self.su)
        fake = ProviderResult(data={"title": "T", "summary": "S", "sections": [{"heading": "H", "paragraphs": ["p"],
                                     "table": {"columns": ["A"], "rows": [["1"]]}}]})
        c = Client()
        c.force_login(self.su)
        with mock.patch("orasec.ora.providers.router.call_ai", return_value=fake) as m:
            r = c.post("/orasec/assets/ora-report/", {"prompt": "summary"})
            self.assertEqual(200, r.status_code)
            self.assertEqual("T", r.json()["report"]["title"])
            sent = m.call_args[0][0].turns[0].text
            self.assertNotIn("192.168", sent)
            r = c.post("/orasec/assets/ora-report/", {"prompt": "summary", "format": "pdf"})
            self.assertTrue(r.content.startswith(b"%PDF"))


class TestCheck(Base):
    def test_states(self):
        Connector.objects.create(name="w", kind="wazuh", enabled=True)
        Connector.objects.create(name="u", kind="unifi", enabled=True)
        a = _a("box", sources={"wazuh": {}})
        self.assertEqual("fail", check_asset_inventory()[0])
        a.owner = self.su
        a.last_seen = timezone.now() - datetime.timedelta(days=30)
        a.save()
        self.assertEqual("warn", check_asset_inventory()[0])
        a.last_seen = timezone.now()
        a.save()
        self.assertEqual("pass", check_asset_inventory()[0])


class TestClassificationLevels(Base):
    def test_defaults_override_and_check(self):
        from orasec.posture.compliance import check_classification
        cust = _a("Invoicing customer data (database + uploads)", asset_type="other", owner=self.su,
                  attributes={"category": "information", "manual": True})
        dom = _a("www.example.com", asset_type="application", sources={"dns": {}}, owner=self.su)
        dev = _a("Garage WiFi", asset_type="access_point", sources={"unifi": {}}, owner=self.su)
        self.assertEqual(("restricted", False), ai.classification(cust))
        self.assertEqual("public", ai.classification(dom)[0])
        self.assertEqual("internal", ai.classification(dev)[0])
        ai.set_classification(dom, "internal", self.su)
        self.assertEqual(("internal", True), ai.classification(dom))
        self.assertEqual("pass", check_classification()[0])
        cust.owner = None
        cust.save()
        self.assertEqual("fail", check_classification()[0])
        c = Client(); c.force_login(self.su)
        self.assertEqual(302, c.post(f"/orasec/assets/{dev.id}/classification/", {"level": "confidential"}).status_code)
        dev.refresh_from_db()
        self.assertEqual("confidential", dev.attributes["classification"])
        c.force_login(self.user)
        self.assertEqual(403, c.post(f"/orasec/assets/{dev.id}/classification/", {"level": "public"}).status_code)


class TestEvidenceLabelling(Base):
    def test_labels_and_check(self):
        from django.core.files.base import ContentFile
        from orasec.posture.compliance import check_labelling
        from orasec.posture.isms_docs import doc_classification
        from orasec.posture.models import ComplianceControl, ComplianceFramework, ControlEvidence
        ControlEvidence.objects.all().delete()
        self.assertEqual("internal", doc_classification({"classification": "Internal (Confidential when completed)"}))
        self.assertEqual("confidential", doc_classification({"classification": "Confidential when completed"}))
        self.assertEqual("internal", doc_classification({}))
        fw, _ = ComplianceFramework.objects.get_or_create(code="t-fw", defaults={"name": "t"})
        c = ComplianceControl.objects.create(framework=fw, ref="A.99", title="t")
        ControlEvidence.objects.create(control=c, title="plain")
        self.assertEqual("pass", check_labelling()[0])
        e = ControlEvidence.objects.create(control=c, title="secret file", classification="confidential")
        e.file.save("report.pdf", ContentFile(b"x"))
        self.assertEqual("warn", check_labelling()[0])
        e.file.save("report_CONFIDENTIAL.pdf", ContentFile(b"x"))
        self.assertEqual("pass", check_labelling()[0])

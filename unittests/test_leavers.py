"""Leavers and movers (A.5.11): auto start on deactivation, asset flagging, reassignment, sign-off rules, Ora, check."""
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import Client
from django.utils import timezone

from orasec import site as site_profile
from orasec.ora import actions
from orasec.posture import asset_inventory as ai, leavers
from orasec.posture.compliance import check_return_of_assets
from orasec.posture.grc_models import LeaverRecord
from orasec.posture.models import InventoryAsset
from unittests.orasec_test_case import OraSecTestCase

User = get_user_model()
OWNERS = ["Alex Lee - Director/CTO", "Dana Smith - Cloud Infrastructure Engineer"]


class Base(OraSecTestCase):
    def setUp(self):
        cache.clear()
        ctx = site_profile.override(asset_owners=OWNERS)
        ctx.__enter__()
        self.addCleanup(ctx.__exit__, None, None, None)
        InventoryAsset.objects.all().delete()
        self.a = User.objects.create_superuser("lv-admin", "a@example.com", "x", first_name="Alex", last_name="Lee")
        self.b = User.objects.create_superuser("lv-boss", "b@example.com", "x", first_name="Harper", last_name="Brown")
        self.d = User.objects.create_user("lv-dana", "d@example.com", "x", first_name="Dana", last_name="Smith", is_staff=True)
        now = timezone.now()
        self.own = InventoryAsset.objects.create(name="Srv1", asset_type="server", owner=self.d, first_seen=now, last_seen=now)
        self.joint = InventoryAsset.objects.create(name="Mail suite", asset_type="application", first_seen=now, last_seen=now,
                                                   attributes={"category": "cloud service", "manual": True, "joint_owners": OWNERS})


class TestFlow(Base):
    def test_deactivation_starts_record_and_flags_assets(self):
        self.d.is_active = False
        with self.captureOnCommitCallbacks(execute=True):
            self.d.save()
        rec = LeaverRecord.objects.get(person=self.d)
        self.assertTrue(rec.started_automatically)
        self.assertEqual({"Srv1", "Mail suite"}, {x["name"] for x in rec.assets})
        self.assertEqual(2, len(leavers.pending_assets(rec)))
        self.assertTrue(any(r["needs_new_owner"] for r in ai.rows()))

    def test_reassign_tick_and_signoff_rules(self):
        rec = leavers.start(self.d, by=self.a)
        with self.assertRaises(leavers.Refused):
            leavers.tick(rec, "assets", self.a)          # assets still pending
        self.assertEqual(2, leavers.reassign(rec, self.b, self.a))
        self.own.refresh_from_db(); self.joint.refresh_from_db()
        self.assertEqual(self.b, self.own.owner)
        self.assertFalse(any("Dana" in j for j in self.joint.attributes["joint_owners"]))
        self.assertTrue(any("Harper" in j for j in self.joint.attributes["joint_owners"]))
        self.assertNotIn("needs_new_owner", self.joint.attributes)
        for s in rec.steps:
            if not s["done"]:
                leavers.tick(rec, s["key"], self.a)
        with self.assertRaises(leavers.Refused):
            leavers.sign_off(rec, self.a)                 # starter can't sign off
        with self.assertRaises(leavers.Refused):
            leavers.tick(rec, "devices", self.d)          # leaver can't tick
        leavers.sign_off(rec, self.b)
        self.assertEqual("signed_off", rec.status)

    def test_check_states(self):
        self.assertEqual("pass", check_return_of_assets()[0])
        rec = leavers.start(self.d, by=self.a)
        self.assertEqual("warn", check_return_of_assets()[0])
        rec.due_date = timezone.localdate() - timezone.timedelta(days=1)
        rec.save()
        self.assertEqual("fail", check_return_of_assets()[0])


class TestPagesAndOra(Base):
    def test_pages(self):
        rec = leavers.start(self.d, by=self.a)
        c = Client(); c.force_login(self.a)
        self.assertEqual(200, c.get("/orasec/leavers/").status_code)
        self.assertEqual(200, c.get(f"/orasec/leavers/{rec.id}/").status_code)
        c.force_login(User.objects.create_user("lv-x", "x@example.com", "x"))
        self.assertEqual(403, c.get("/orasec/leavers/").status_code)

    def test_ora_cards(self):
        from orasec.ora.tools import run_tool
        self.assertIn("start_leaver", actions.allowed_kinds(self.a))
        self.assertNotIn("start_leaver", actions.allowed_kinds(self.d))
        rec = leavers.start(self.d, by=self.a)
        out = run_tool("leavers", {}, self.a)
        self.assertEqual(rec.ref, out["records"][0]["ref"])
        card, payload = actions.build("leaver_step", {"ref": rec.ref, "step": "devices", "note": "laptop back"}, self.a, None)
        self.assertEqual("devices", payload["step"])
        with self.assertRaises(actions.Clarify):
            actions.build("leaver_signoff", {"ref": rec.ref}, self.a, None)   # starter + incomplete

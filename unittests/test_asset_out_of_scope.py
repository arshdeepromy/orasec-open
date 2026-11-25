"""Assets taken out of scope stay retired when a connector sees them again (A.5.9)."""
from orasec.posture.connectors.base import AssetRecord, _upsert_assets
from orasec.posture.models import Connector, InventoryAsset
from unittests.orasec_test_case import OraSecTestCase


class TestOutOfScope(OraSecTestCase):
    def test_stays_retired(self):
        conn = Connector.objects.create(name="UniFi t", kind="unifi", base_url="https://x")
        rec = AssetRecord(key="aa:bb", name="Washer", mac_address="aa:bb:cc:dd:ee:ff", asset_type="client")
        _upsert_assets(conn, [rec])
        a = InventoryAsset.objects.get(mac_address="aa:bb:cc:dd:ee:ff")
        a.retired = True
        a.attributes = {**a.attributes, "out_of_scope": {"reason": "home device"}}
        a.save()
        _upsert_assets(conn, [rec])
        a.refresh_from_db()
        self.assertTrue(a.retired)
        self.assertIn("out_of_scope", a.attributes)

    def test_plain_retired_comes_back(self):
        conn = Connector.objects.create(name="UniFi t2", kind="unifi", base_url="https://x")
        rec = AssetRecord(key="11:22", name="Pi", mac_address="11:22:33:44:55:66", asset_type="server")
        _upsert_assets(conn, [rec])
        InventoryAsset.objects.filter(mac_address="11:22:33:44:55:66").update(retired=True)
        _upsert_assets(conn, [rec])
        self.assertFalse(InventoryAsset.objects.get(mac_address="11:22:33:44:55:66").retired)

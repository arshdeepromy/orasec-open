"""Live topology, host health (Beszel) and alias-aware asset names."""
import json
from unittest import mock

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.utils import timezone

from orasec.posture import health, topology
from orasec.posture.connectors.base import _upsert_assets  # noqa: PLC2701
from orasec.posture.connectors.beszel import BeszelConnector
from orasec.posture.models import Connector, InventoryAsset
from unittests.orasec_test_case import OraSecTestCase

User = get_user_model()

SYSTEM = {"id": "abc123", "name": "Server 01", "host": "192.168.10.90", "status": "up", "updated": "2026-11-16 09:00:00.000Z",
          "info": {"cpu": 38.4, "mp": 47.3, "dp": 88.0, "dt": 81.2, "bb": 185256, "la": [1.2, 0.9, 0.7], "u": 6529, "v": "0.21.2"}}


def _asset(name, ip, **kw):
    now = timezone.now()
    return InventoryAsset.objects.create(name=name, ip_address=ip, asset_type=kw.pop("asset_type", "server"), last_seen=now, first_seen=now, **kw)


class TestHealthSummary(OraSecTestCase):
    def test_levels_and_overall(self):
        s = health.summarize(SYSTEM)
        self.assertEqual("ok", s["levels"]["cpu"])
        self.assertEqual("warn", s["levels"]["disk"])
        self.assertEqual("crit", s["levels"]["temp"])
        self.assertEqual("crit", s["health"])
        self.assertEqual(185256, s["net_bps"])

    def test_down_system(self):
        s = health.summarize({**SYSTEM, "status": "down"})
        self.assertEqual("down", s["health"])

    def test_missing_values_are_unknown(self):
        s = health.summarize({"id": "x", "status": "up", "info": {}})
        self.assertEqual("unknown", s["levels"]["cpu"])
        self.assertEqual("ok", s["health"])

    def test_snapshot_without_connector(self):
        cache.delete("orasec-health:snapshot")
        snap = health.snapshot()
        self.assertFalse(snap["configured"])
        self.assertEqual({}, snap["systems"])


class TestBeszelConnector(OraSecTestCase):
    def setUp(self):
        self.conn = Connector.objects.create(name="Beszel test", kind="beszel", base_url="http://hub.invalid:8090", username="ro@example.com")

    def _collect(self):
        impl = BeszelConnector(self.conn)
        data = {"systems": [SYSTEM, {"id": "mac1", "name": "Build Mac", "host": "192.168.10.214", "status": "up", "info": {}}],
                "system_details": [{"system": "abc123", "hostname": "server01", "os": 0, "os_name": "Ubuntu 26.04.1 LTS", "cores": 4, "memory": 8 * 1024 ** 3},
                                   {"system": "mac1", "hostname": "app-dev-box", "os": 1, "os_name": "macOS 26.7"}],
                "containers": [{"system": "abc123", "name": "orasec-uwsgi-1", "image": "orasec/orasec-django:1.0.0"},
                               {"system": "abc123", "name": "tunnel", "image": "cloudflare/cloudflared:2026.11.0"}]}
        with mock.patch.object(impl.client, "records", side_effect=lambda coll, **_: data[coll]):
            return impl.collect()

    def test_collect_assets(self):
        res = self._collect()
        by = {a.hostname: a for a in res.assets}
        self.assertEqual("server", by["server01"].asset_type)
        self.assertEqual("workstation", by["app-dev-box"].asset_type)
        self.assertEqual(["cloudflared"], by["server01"].attributes["services"])
        self.assertEqual(8.0, by["server01"].attributes["memory_gb"])
        self.assertEqual(2, res.stats["up"])

    def test_upsert_correlates_by_ip_and_keeps_display_name(self):
        srv1 = _asset("Server 01", "192.168.10.90", hostname="srv-legacy")
        res = self._collect()
        _upsert_assets(self.conn, res.assets)
        srv1.refresh_from_db()
        self.assertEqual("Server 01", srv1.name)          # connectors never overwrite a display name
        self.assertEqual("server01", srv1.hostname)
        self.assertEqual("abc123", srv1.attributes["beszel"]["system_id"])
        self.assertIn("server01", srv1.attributes["aliases"])
        self.assertEqual(2, InventoryAsset.objects.filter(sources__has_key="beszel").count())


class TestAssetAliases(OraSecTestCase):
    def test_find_by_old_name(self):
        a = _asset("srv-01", "192.168.10.90")
        a.name = "Server 01"
        self.assertTrue(a.add_aliases("srv-01", "srv-legacy"))
        a.save()
        self.assertEqual(a.id, InventoryAsset.find("srv-01").id)
        self.assertEqual(a.id, InventoryAsset.find("SRV-Legacy").id)
        self.assertEqual(a.id, InventoryAsset.find("Server 01").id)
        self.assertIsNone(InventoryAsset.find("unknown-host"))
        self.assertFalse(a.add_aliases("srv-01"))             # no change, no save needed


class TestLiveTopology(OraSecTestCase):
    def setUp(self):
        cache.clear()

    def test_hosts_from_inventory(self):
        _asset("Server 01", "192.168.10.90", attributes={"beszel": {"system_id": "abc123", "services": ["cloudflared"]}}, sources={"beszel": {}, "wazuh": {}})
        _asset("Build Mac", "192.168.10.214", asset_type="workstation")
        _asset("app-server", "10.20.2.10")
        _asset("Duplicate weaker record", "192.168.10.90", sources={"unifi": {}})
        _asset("wazuh.manager", "", sources={"wazuh": {}}, attributes={"wazuh": {"agent_id": "000"}})
        _asset("cloud-fw", "10.20.0.11", asset_type="firewall")
        _asset("Phone", "192.168.10.50", asset_type="client")
        _asset("Hidden box", "192.168.10.60", attributes={"topology": {"hidden": True}})
        snap = {"systems": {"abc123": health.summarize(SYSTEM)}, "fetched": timezone.now().isoformat(), "error": None, "configured": True}
        with mock.patch.object(health, "snapshot", return_value=snap):
            g = topology.build()
        hosts = [n for n in g["nodes"] if n.get("asset_id")]
        labels = sorted(n["label"] for n in hosts)
        self.assertEqual(["Build Mac", "Server 01", "app-server"], labels)
        srv1 = next(n for n in hosts if n["label"] == "Server 01")
        self.assertEqual("crit", srv1["health"]["health"])
        self.assertEqual("up", srv1["status"])
        ids = {lk["id"] for lk in g["links"]}
        self.assertIn(f"gateway-{srv1['id']}", ids)
        self.assertIn(f"cf-{srv1['id']}", ids)
        aws = next(n for n in hosts if n["label"] == "app-server")
        self.assertEqual("aws", aws["zone"])
        self.assertIn(f"firewall-{aws['id']}", ids)
        for lk in g["links"]:  # every link points at drawn nodes
            self.assertTrue(any(n["id"] == lk["a"] for n in g["nodes"]) and any(n["id"] == lk["b"] for n in g["nodes"]), lk["id"])

    def test_layout_grows(self):
        for i in range(7):
            _asset(f"host{i}", f"192.168.10.{100 + i}")
        g = topology.build()
        self.assertGreater(g["view"]["h"], 720)
        ys = sorted(n["y"] for n in g["nodes"] if n.get("zone") == "onprem" and n.get("asset_id"))
        self.assertEqual(len(ys), len(set(ys)))


class TestTopologyApi(OraSecTestCase):
    def setUp(self):
        cache.clear()
        self.admin = User.objects.create_superuser("topo-admin", "a@example.com", "x-Very-Long-Pass-123")
        self.user = User.objects.create_user("topo-user", "u@example.com", "x-Very-Long-Pass-123")
        self.asset = _asset("srv-01", "192.168.10.90", attributes={"beszel": {"system_id": "abc123"}})

    def test_regular_user_gets_no_health(self):
        self.client.force_login(self.user)
        snap = {"systems": {"abc123": health.summarize(SYSTEM)}, "fetched": "", "error": None, "configured": True}
        with mock.patch.object(health, "snapshot", return_value=snap):
            g = self.client.get("/orasec/api/topology.json").json()
        self.assertFalse(g["can_health"])
        self.assertTrue(all("health" not in n for n in g["nodes"]))
        self.assertEqual(403, self.client.get(f"/orasec/api/topology/node/{self.asset.id}.json").status_code)
        self.assertEqual(403, self.client.post(f"/orasec/api/topology/node/{self.asset.id}/edit", "{}", content_type="application/json").status_code)

    def test_rename_keeps_alias(self):
        self.client.force_login(self.admin)
        r = self.client.post(f"/orasec/api/topology/node/{self.asset.id}/edit", json.dumps({"name": "  Server   01 ", "role": "OraSec production"}),
                             content_type="application/json")
        self.assertEqual(200, r.status_code)
        self.asset.refresh_from_db()
        self.assertEqual("Server 01", self.asset.name)
        self.assertEqual("OraSec production", self.asset.attributes["topology"]["role"])
        self.assertEqual(self.asset.id, InventoryAsset.find("srv-01").id)
        self.assertEqual(400, self.client.post(f"/orasec/api/topology/node/{self.asset.id}/edit", json.dumps({"name": " "}),
                                               content_type="application/json").status_code)

    def test_node_detail(self):
        self.client.force_login(self.admin)
        with mock.patch.object(health, "detail", return_value={"summary": health.summarize(SYSTEM), "history": [], "containers": [], "details": {}}):
            d = self.client.get(f"/orasec/api/topology/node/{self.asset.id}.json").json()
        self.assertEqual("srv-01", d["name"])
        self.assertEqual("crit", d["health"]["summary"]["health"])

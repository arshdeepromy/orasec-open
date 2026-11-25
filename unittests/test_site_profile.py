"""Site profile (orasec.site): nothing about one organisation's network or people lives in the code."""
import json
import tempfile

from django.test import SimpleTestCase, override_settings
from django.utils import timezone

from orasec import site as site_profile
from orasec.posture import asset_inventory as ai, topology
from orasec.posture.models import InventoryAsset
from unittests.orasec_test_case import OraSecTestCase


class TestProfileFile(SimpleTestCase):
    def setUp(self):
        site_profile.reset()
        self.addCleanup(site_profile.reset)

    def test_defaults_without_a_file(self):
        self.assertEqual("Your organisation", site_profile.org_name())
        self.assertEqual([], site_profile.get("asset_owners"))
        self.assertEqual("10.20.0.0/16", site_profile.get("topology.cloud_cidr"))
        self.assertIsNone(site_profile.get("no.such.key"))
        self.assertEqual("x", site_profile.get("no.such.key", "x"))

    def test_file_overrides_and_keeps_other_defaults(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json") as fh:
            json.dump({"org_name": "Example Ltd", "locations": {"cloud": "AWS Sydney"}, "asset_owners": ["Alex Lee - CTO"],
                       "topology": {"cloud_cidr": "10.99.0.0/16", "nodes": [{"id": "internet", "kind": "internet", "label": "Internet", "x": 1, "y": 1}],
                                    "links": []}}, fh)
            fh.flush()
            with override_settings(ORASEC_SITE_FILE=fh.name):
                site_profile.reset()
                self.assertEqual("Example Ltd", site_profile.org_name())
                self.assertEqual("Example-Ltd", site_profile.file_prefix())
                self.assertEqual("AWS Sydney", site_profile.get("locations.cloud"))
                self.assertEqual("Head office", site_profile.get("locations.office"))        # untouched default
                self.assertEqual(["Alex Lee - CTO"], ai.joint_owners())
                topo = site_profile.get("topology")
                self.assertEqual("10.99.0.0/16", topo["cloud_cidr"])
                self.assertEqual(["internet"], [n["id"] for n in topo["nodes"]])               # the example drawing is replaced, not merged
                self.assertEqual([], topo["links"])
                self.assertIn("vlans", topo["lan"])                                            # parts left out fall back to the example

    def test_unreadable_file_falls_back_to_defaults(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json") as fh:
            fh.write("{not json")
            fh.flush()
            with override_settings(ORASEC_SITE_FILE=fh.name), self.assertLogs("orasec.site", level="ERROR"):
                site_profile.reset()
                self.assertEqual("Your organisation", site_profile.org_name())
        with override_settings(ORASEC_SITE_FILE="/nonexistent/site.json"), self.assertLogs("orasec.site", level="ERROR"):
            site_profile.reset()
            self.assertEqual("Your organisation", site_profile.org_name())

    def test_override_restores(self):
        with site_profile.override(org_name="Acme"):
            self.assertEqual("Acme", site_profile.org_name())
        self.assertEqual("Your organisation", site_profile.org_name())


def _asset(name, ip, **kw):
    now = timezone.now()
    kw.setdefault("asset_type", "server")
    return InventoryAsset.objects.create(name=name, ip_address=ip, first_seen=now, last_seen=now, **kw)


class TestTopologyFollowsTheSite(OraSecTestCase):
    def setUp(self):
        InventoryAsset.objects.all().delete()

    def test_zones_follow_the_cloud_range(self):
        with site_profile.override(topology={**site_profile.EXAMPLE_TOPOLOGY, "cloud_cidr": ["10.99.0.0/16", "172.20.0.0/16"]}):
            self.assertEqual("aws", topology._zone_of("10.99.1.5"))
            self.assertEqual("aws", topology._zone_of("172.20.3.3"))
            self.assertEqual("onprem", topology._zone_of("10.20.0.5"))      # no longer the cloud range
            self.assertIsNone(topology._zone_of("8.8.8.8"))

    def test_a_site_without_gateway_or_firewall_still_draws(self):
        _asset("office-box", "192.168.10.5")
        _asset("cloud-box", "10.20.2.9")
        bare = {"cloud_cidr": "10.20.0.0/16", "zones": site_profile.EXAMPLE_TOPOLOGY["zones"],
                "nodes": [{"id": "internet", "kind": "internet", "label": "Internet", "x": 600, "y": 400}], "links": [], "lan": {}}
        with site_profile.override(topology=bare):
            g = topology.build()
        labels = {n["label"] for n in g["nodes"]}
        self.assertLessEqual({"Internet", "office-box", "cloud-box"}, labels)
        self.assertEqual([], g["links"])                                    # nothing to link to, nothing dangling
        self.assertEqual([], g["fallback_cloud_rows"])

    def test_fixed_instances_are_not_drawn_twice(self):
        _asset("spare-fw", "10.20.0.10")
        model = json.loads(json.dumps(site_profile.EXAMPLE_TOPOLOGY))
        model["nodes"].append({"id": "spare", "kind": "firewall", "label": "Spare firewall", "zone": "aws", "x": 1085, "y": 600, "fixed": True,
                               "instance_ip": "10.20.0.10"})
        with site_profile.override(topology=model):
            self.assertEqual({"10.20.0.11", "10.20.0.10"}, topology._fabric_ips())
            g = topology.build()
        self.assertEqual(1, sum(1 for n in g["nodes"] if "10.20.0.10" in (n.get("sub") or "") or n["label"] in ("spare-fw", "Spare firewall")))

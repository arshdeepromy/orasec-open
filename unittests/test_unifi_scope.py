"""UniFi sync imports only clients on the in-scope networks (default: the Office)."""
import ipaddress

from orasec.posture.connectors.base import ConnectorError
from orasec.posture.connectors.unifi import UniFiConnector, in_subnets
from orasec.posture.models import Connector
from unittests.orasec_test_case import OraSecTestCase

NETS = {"data": [{"name": "Office", "ip_subnet": "192.168.10.1/24"}, {"name": "Home", "ip_subnet": "192.168.2.1/24"}]}


class FakeHttp:
    def __init__(self, data):
        self.data = data

    def get(self, path, **kw):
        return self.data


class TestUnifiScope(OraSecTestCase):
    def conn(self, options=None):
        c = Connector.objects.create(name="UniFi s", kind="unifi", base_url="https://unifi.example.internal", options=options or {})
        u = UniFiConnector(c)
        u.http = FakeHttp(NETS)
        return u

    def test_in_subnets(self):
        nets = [ipaddress.ip_network("192.168.10.0/24")]
        self.assertTrue(in_subnets("192.168.10.27", nets))
        self.assertFalse(in_subnets("192.168.2.42", nets))
        self.assertFalse(in_subnets("", nets))
        self.assertFalse(in_subnets(None, nets))

    def test_default_is_ora_network(self):
        nets = self.conn()._client_subnets({"internalReference": "default"})
        self.assertEqual(nets, [ipaddress.ip_network("192.168.10.0/24")])

    def test_all_networks_option(self):
        self.assertIsNone(self.conn({"client_networks": "*"})._client_subnets({}))

    def test_missing_network_refuses(self):
        u = self.conn({"client_networks": ["Nope"]})
        with self.assertRaises(ConnectorError):
            u._client_subnets({})


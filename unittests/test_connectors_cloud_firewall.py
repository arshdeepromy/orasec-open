"""Tests for the Plerion, Tenable and Check Point connectors. No network: every request is answered by a fake."""
import re
from unittest import mock

from django.contrib.auth import get_user_model
from django.core.cache import cache

from orasec.models import Finding
from orasec.plugins import registry
from orasec.posture.connectors import base, checkpoint, tenable
from orasec.posture.connectors import checkpoint_policy as cp
from orasec.posture.connectors.base import ConnectorError, get_connector_class
from orasec.posture.models import Connector, InventoryAsset
from unittests.orasec_test_case import OraSecTestCase, versioned_fixtures

User = get_user_model()


def fake_http(test, impl, routes):
    """Answer ``impl.http.request`` from ``routes(method, url, kwargs)`` and keep a list of what was asked."""
    calls = []

    def request(method, path, expect_json=True, **kw):
        kw.pop("log_as", None)
        url = path if path.startswith("http") else impl.http.base + path
        calls.append((method, url, kw))
        return routes(method, url, kw)

    p = mock.patch.object(impl.http, "request", side_effect=request)
    p.start()
    test.addCleanup(p.stop)
    return calls


# ---------------------------------------------------------------------------
# Plerion
# ---------------------------------------------------------------------------
PLERION_ASSETS = [
    {"resourceId": "i-0aaa", "resourceName": "i-0aaa", "resourceType": "AWS::EC2::Instance", "provider": "AWS",
     "providerAccountId": "111111111111", "region": "ap-southeast-2", "isPubliclyExposed": True,
     "tags": [{"Key": "Name", "Value": "web-01"}], "operatingSystem": [{"name": "Ubuntu", "version": "24.04"}]},
    {"resourceId": "i-0bbb", "resourceName": "batch-01", "resourceType": "AWS::EC2::Instance", "provider": "AWS",
     "providerAccountId": "222222222222", "region": "us-east-1", "operatingSystem": {"platform": "Amazon Linux"}},
    {"resourceId": "", "resourceName": "no id: skipped"},
    {"resourceId": "i-0ccc", "provider": "AWS", "providerAccountId": "111111111111"},
]
PLERION_FINDINGS = [
    {"id": "prn:findings:1", "detectionId": "PLERION-AWS-1", "severityLevel": "CRITICAL", "status": "FAILED",
     "message": "S3 bucket allows public read", "resourceType": "AWS::S3::Bucket", "resourceName": "reports-bucket",
     "providerAccountId": "111111111111", "region": "ap-southeast-2", "resourceURL": "https://console.example.com/s3/reports-bucket",
     "firstObservedAt": "2026-10-01T02:03:04Z", "slaDueAt": "2026-10-08T00:00:00Z", "provider": "AWS"},
    {"id": "prn:findings:2", "detectionId": "PLERION-AWS-2", "severityLevel": "HIGH", "message": "Security group open to the world",
     "resourceName": "sg-123", "resourceType": "AWS::EC2::SecurityGroup", "providerAccountId": "222222222222", "isExempted": True},
    {"id": "prn:findings:3", "detectionId": "PLERION-AWS-3", "severityLevel": "HIGH", "message": "Root account has no MFA",
     "resourceName": "", "resourceType": "AWS::IAM::Root", "providerAccountId": "222222222222"},
]


def plerion_routes(method, url, kw):
    q = kw.get("params") or {}
    if url.endswith("/v1/tenant"):
        return {"data": {"name": "Example tenant"}}
    if url.endswith("/v1/tenant/assets"):
        if q.get("perPage") == 1:
            return {"data": PLERION_ASSETS[:1], "meta": {"total": 4}}
        page = q.get("page", 1)
        rows = PLERION_ASSETS[:2] if page == 1 else PLERION_ASSETS[2:] if page == 2 else []
        # the live API reports total and hasNextPage on the first page only
        return {"data": rows, "meta": {"total": 4, "hasNextPage": True} if page == 1 else {"total": 0}}
    if url.endswith("/v1/tenant/integrations"):
        if not q.get("cursor"):
            return {"data": [{"provider": "AWS", "awsAccountId": "111111111111", "name": "Production"}], "meta": {"cursor": "c1"}}
        return {"data": [{"provider": "AWS", "providerAccountId": "222222222222", "name": "Sandbox"}], "meta": {"cursor": "c1"}}  # repeated cursor
    if url.endswith("/v1/tenant/findings"):
        if not q.get("cursor"):
            return {"data": PLERION_FINDINGS[:2], "meta": {"total": 3, "cursor": "f1", "hasNextPage": True}}
        if q["cursor"] == "f1":
            return {"data": PLERION_FINDINGS[2:], "meta": {"total": 0, "cursor": "f2"}}
        return {"data": [], "meta": {"total": 0}}
    msg = f"unexpected {method} {url}"
    raise AssertionError(msg)


@versioned_fixtures
class TestPlerion(OraSecTestCase):
    fixtures = ["orasec_testdata.json"]

    def _impl(self, **options):
        c = Connector(name="Plerion", kind="plerion", base_url="https://au.api.plerion.com", options=options)
        c.set_secrets({"api_key": "k" * 20})
        c.save()
        impl = get_connector_class("plerion")(c)
        return impl, fake_http(self, impl, plerion_routes)

    def test_key_is_sent_as_bearer_and_test_reports_the_tenant(self):
        impl, _calls = self._impl()
        self.assertEqual("Bearer " + "k" * 20, impl.http.session.headers["Authorization"])
        self.assertEqual("Plerion tenant Example tenant: 4 assets visible", impl.test())

    def test_assets_are_paged_by_the_first_total_and_named_by_tag(self):
        impl, calls = self._impl(findings=False)
        res = impl.collect()
        self.assertEqual(["web-01", "batch-01", "i-0ccc"], [a.name for a in res.assets])
        web = res.assets[0]
        self.assertEqual(("i-0aaa", "cloud_instance", "Ubuntu", "24.04", True), (web.key, web.asset_type, web.os_name, web.os_version, web.internet_exposed))
        self.assertEqual("Production", web.attributes["account_name"])
        self.assertEqual("Amazon Linux", res.assets[1].os_name)
        self.assertEqual("Sandbox", res.assets[1].attributes["account_name"])
        asset_calls = [c for c in calls if c[1].endswith("/assets")]
        self.assertEqual([1, 2], [c[2]["params"]["page"] for c in asset_calls])  # stopped by the total, not by hasNextPage
        self.assertEqual("AWS::EC2::Instance", asset_calls[0][2]["params"]["resourceTypes"])
        self.assertEqual([], res.batches)
        self.assertEqual(1, res.stats["publicly_exposed"])

    def test_failed_findings_become_findings_and_exempted_ones_do_not(self):
        impl, calls = self._impl(severities="critical, high", providers=["AWS", "Azure"])
        res = impl.collect()
        batch = res.batches[0]
        self.assertEqual(("OraSec Plerion", 2), (batch.scan_type, batch.count))
        f1, f3 = batch.payload["findings"]
        self.assertEqual("S3 bucket allows public read (reports-bucket)", f1["title"])
        self.assertEqual(("critical", "plerion:prn:findings:1", "2026-10-01", "PLERION-AWS-1"), (f1["severity"], f1["unique_id"], f1["date"], f1["rule_id"]))
        self.assertIn("Account: Production (111111111111)", f1["description"])
        self.assertIn("Plerion due date: 2026-10-08", f1["description"])
        self.assertEqual("Root account has no MFA", f3["title"])
        self.assertEqual(1, res.stats["findings_exempted"])
        q = next(c for c in calls if c[1].endswith("/findings"))[2]["params"]
        self.assertEqual(("FAILED", "CRITICAL,HIGH", "AWS,Azure"), (q["statuses"], q["severityLevels"], q["providers"]))

    def test_a_failed_page_fails_the_run_instead_of_importing_part(self):
        impl, _calls = self._impl()

        def broken(method, url, kw):
            if url.endswith("/findings") and (kw.get("params") or {}).get("cursor"):
                msg = "GET /v1/tenant/findings: HTTP 502"
                raise ConnectorError(msg)
            return plerion_routes(method, url, kw)
        with mock.patch.object(impl.http, "request", side_effect=lambda m, p, expect_json=True, **kw: broken(m, impl.http.base + p, kw)), \
                self.assertRaises(ConnectorError):
            impl.collect()

    def test_a_run_imports_findings_and_the_next_run_closes_what_passed(self):
        cache.clear()
        admin = User.objects.get(username="admin")
        c = Connector(name="Plerion run", kind="plerion", base_url="https://au.api.plerion.com", options={"product_name": "Cloud test"})
        c.set_secrets({"api_key": "k"})
        c.save()
        cls = get_connector_class("plerion")
        state = {"findings": PLERION_FINDINGS}

        def routes(method, url, kw):
            if url.endswith("/findings"):
                return {"data": [] if (kw.get("params") or {}).get("cursor") else state["findings"], "meta": {"cursor": "end"}}
            return plerion_routes(method, url, kw)

        def run():
            with mock.patch.object(base.Http, "request", autospec=True,
                                   side_effect=lambda self, m, p, expect_json=True, **kw: routes(m, self.base + p, kw)):
                return base.run_connector(c, "test", admin)
        self.assertIs(cls, get_connector_class(c.kind))
        r = run()
        self.assertEqual("ok", r.status, r.error or r.log)
        open_now = Finding.objects.filter(test__test_type__name="OraSec Plerion", active=True)
        self.assertEqual({"plerion:prn:findings:1", "plerion:prn:findings:3"}, set(open_now.values_list("unique_id_from_tool", flat=True)))
        self.assertEqual("Critical", open_now.get(unique_id_from_tool="plerion:prn:findings:1").severity)
        self.assertTrue(InventoryAsset.objects.filter(name="web-01", asset_type="cloud_instance", internet_exposed=True).exists())
        state["findings"] = PLERION_FINDINGS[2:]  # the bucket is fixed
        r = run()
        self.assertEqual("ok", r.status, r.error or r.log)
        self.assertEqual({"plerion:prn:findings:3"}, set(open_now.values_list("unique_id_from_tool", flat=True)))
        self.assertTrue(Finding.objects.get(unique_id_from_tool="plerion:prn:findings:1").is_mitigated)

    def test_connector_pages_open_for_a_new_kind_and_for_an_existing_connector(self):
        impl, _calls = self._impl()
        self.client.force_login(User.objects.get(username="admin"))
        r = self.client.get("/orasec/connectors/new/")
        self.assertContains(r, "Check Point (firewall policy, internet exposure)")
        r = self.client.get("/orasec/connectors/new/?kind=tenable")
        self.assertContains(r, "https://cloud.tenable.com")
        self.assertContains(r, "Secret key")
        r = self.client.get(f"/orasec/connectors/{impl.connector.id}/edit/")  # no ?kind= in the address
        self.assertEqual(200, r.status_code)
        self.assertContains(r, "read-only</b> tenant API key")
        self.assertNotContains(r, "k" * 20)  # the stored key is never shown again

    def test_new_kinds_are_plugins_with_their_own_text(self):
        rows = {r["key"]: r for r in registry.snapshot()}
        for kind in ("plerion", "tenable", "checkpoint"):
            self.assertIn(f"source.{kind}", rows)
            self.assertNotIn("Scheduled connector that brings", rows[f"source.{kind}"]["summary"])
            self.assertIn(kind, base.CONNECTOR_SCAN_TYPES)


# ---------------------------------------------------------------------------
# Tenable
# ---------------------------------------------------------------------------
T_ASSETS = [
    {"id": "a-1", "hostnames": ["appsrv01"], "fqdns": ["appsrv01.corp.example"], "ipv4s": ["10.1.1.10", "10.1.1.11"],
     "mac_addresses": ["AA:BB:CC:00:00:01"], "operating_systems": ["Microsoft Windows Server 2022 Standard"], "has_agent": True,
     "system_types": ["general-purpose"]},
    {"id": "a-2", "fqdns": ["wkstn042.corp.example"], "ipv4s": ["10.2.0.42"], "operating_systems": ["Microsoft Windows 11 Enterprise"]},
    {"id": "a-3", "ipv4s": ["10.9.9.9"], "aws_ec2_instance_id": "i-0abc", "operating_systems": ["Linux Kernel 6.8"]},
    {"hostnames": ["no id: skipped"]},
]
T_VULNS = [
    {"asset": {"uuid": "a-1", "hostname": "appsrv01"}, "severity": "critical", "state": "OPEN", "first_found": "2026-09-01T10:00:00.000Z",
     "plugin": {"id": 190001, "name": "OpenSSL < 3.0.15 Multiple Vulnerabilities", "family": "Web Servers", "synopsis": "The remote service is out of date.",
                "description": "Long text.", "solution": "Upgrade to 3.0.15.", "see_also": ["https://www.example.com/advisory"], "cve": ["CVE-2026-0001"],
                "cvss3_base_score": 9.8, "exploit_available": True, "vpr": {"score": 9.2}},
     "port": {"port": 443, "protocol": "TCP", "service": "www"}, "output": "Installed version : 3.0.1"},
    {"asset": {"uuid": "a-1"}, "severity": "critical", "state": "OPEN", "plugin": {"id": 190001, "name": "duplicate of the same port"},
     "port": {"port": 443, "protocol": "tcp"}},
    {"asset": {"uuid": "a-2", "fqdn": "wkstn042.corp.example"}, "severity": "medium", "state": "REOPENED",
     "plugin": {"id": 57608, "name": "SMB Signing not required", "cvss_base_score": 5.0}, "port": {"port": 445, "protocol": "TCP"}},
    {"asset": {"uuid": "a-9"}, "severity": "low", "state": "FIXED", "plugin": {"id": 1, "name": "fixed: left out"}},
    {"asset": {}, "plugin": {"id": 2}},
]


def tenable_routes(status_script=None, chunks=None):
    script = {"assets": list((status_script or {}).get("assets") or [{"status": "PROCESSING", "chunks_available": [1]},
                                                                      {"status": "FINISHED", "chunks_available": [1, 2]}]),
              "vulns": list((status_script or {}).get("vulns") or [{"status": "QUEUED"}, {"status": "FINISHED", "chunks_available": [1]}])}
    data = chunks or {("assets", 1): T_ASSETS[:2], ("assets", 2): T_ASSETS[2:], ("vulns", 1): T_VULNS}
    bodies = {}

    def routes(method, url, kw):
        if url.endswith("/session"):
            return {"username": "svc-orasec@example.com"}
        if m := re.search(r"/(assets|vulns)/export$", url):
            bodies[m[1]] = kw["json"]
            return {"export_uuid": f"uuid-{m[1]}"}
        if m := re.search(r"/(assets|vulns)/export/uuid-\1/status$", url):
            steps = script[m[1]]
            return steps.pop(0) if len(steps) > 1 else steps[0]
        if m := re.search(r"/(assets|vulns)/export/uuid-\1/chunks/(\d+)$", url):
            body = data[(m[1], int(m[2]))]
            if isinstance(body, Exception):
                raise body
            return body
        msg = f"unexpected {method} {url}"
        raise AssertionError(msg)
    routes.bodies = bodies
    return routes


@versioned_fixtures
class TestTenable(OraSecTestCase):
    fixtures = ["orasec_testdata.json"]

    def setUp(self):
        p = mock.patch.object(tenable.time, "sleep")
        p.start()
        self.addCleanup(p.stop)

    def _impl(self, routes=None, **options):
        c = Connector(name="Tenable", kind="tenable", base_url="https://cloud.tenable.com", username=" access ", options=options)
        c.set_secrets({"secret_key": "secret"})
        c.save()
        impl = get_connector_class("tenable")(c)
        routes = routes or tenable_routes()
        return impl, fake_http(self, impl, routes), routes

    def test_keys_travel_in_the_header_only(self):
        impl, calls, _ = self._impl()
        self.assertEqual("accessKey=access;secretKey=secret;", impl.http.session.headers["X-ApiKeys"])
        self.assertEqual("Tenable keys accepted for svc-orasec@example.com", impl.test())
        self.assertNotIn("secret", " ".join(c[1] for c in calls))

    def test_assets_come_from_every_chunk_and_are_classified(self):
        impl, _calls, routes = self._impl()
        res = impl.collect()
        self.assertEqual([("appsrv01", "server"), ("wkstn042", "workstation"), ("10.9.9.9", "cloud_instance")],
                         [(a.name, a.asset_type) for a in res.assets])
        srv = res.assets[0]
        self.assertEqual(("a-1", "appsrv01", "10.1.1.10", "AA:BB:CC:00:00:01", True), (srv.key, srv.hostname, srv.ip_address, srv.mac_address, srv.scanned))
        self.assertEqual(["10.1.1.10", "10.1.1.11"], srv.attributes["ipv4s"])
        f = routes.bodies["assets"]["filters"]
        self.assertEqual((True, False, False), (f["is_licensed"], f["is_deleted"], f["is_terminated"]))

    def test_open_vulnerabilities_become_findings_keyed_on_asset_plugin_and_port(self):
        impl, _calls, routes = self._impl(plugin_output=True)
        res = impl.collect()
        batch = res.batches[0]
        self.assertEqual(("OraSec Tenable", 2), (batch.scan_type, batch.count))
        ssl, smb = batch.payload["findings"]
        self.assertEqual("tenable:a-1:190001:443/tcp", ssl["unique_id"])
        self.assertEqual(("critical", "appsrv01", ["CVE-2026-0001"], 9.8, "190001", "2026-09-01"),
                         (ssl["severity"], ssl["host"], ssl["cves"], ssl["cvss_score"], ssl["rule_id"], ssl["date"]))
        self.assertIn("exploit-available", ssl["tags"])
        self.assertIn("Installed version : 3.0.1", ssl["description"])
        self.assertEqual("Tenable VPR 9.2", ssl["impact"])
        self.assertEqual(("tenable:a-2:57608:445/tcp", "wkstn042", 5.0), (smb["unique_id"], smb["host"], smb["cvss_score"]))
        self.assertEqual({"critical": 1, "high": 0, "medium": 1, "low": 0, "info": 0}, res.stats["by_severity"])
        v = routes.bodies["vulns"]["filters"]
        self.assertEqual((["OPEN", "REOPENED"], ["critical", "high", "medium", "low"]), (v["state"], v["severity"]))

    def test_plugin_output_is_left_out_unless_asked_for(self):
        impl, _calls, _ = self._impl()
        self.assertNotIn("Installed version", impl.collect().batches[0].payload["findings"][0]["description"])

    def test_an_export_that_errors_is_cancelled_or_loses_a_chunk_imports_nothing(self):
        for script in ({"vulns": [{"status": "ERROR"}]}, {"vulns": [{"status": "CANCELLED"}]},
                       {"vulns": [{"status": "FINISHED", "chunks_available": [1], "chunks_failed": [2]}]}):
            impl, _calls, _ = self._impl(tenable_routes(script))
            with self.assertRaises(ConnectorError):
                impl.collect()
            impl.connector.delete()
        bad = tenable_routes(chunks={("assets", 1): T_ASSETS[:2], ("assets", 2): ConnectorError("GET chunk: HTTP 500"), ("vulns", 1): T_VULNS})
        impl, _calls, _ = self._impl(bad)
        with self.assertRaises(ConnectorError):
            impl.collect()

    def test_an_export_that_never_finishes_times_out(self):
        impl, _calls, _ = self._impl(tenable_routes({"assets": [{"status": "PROCESSING"}]}), timeout_minutes=0)
        with mock.patch.object(tenable.time, "monotonic", side_effect=[0, 1, 2, 3, 4, 5, 6]), self.assertRaisesRegex(ConnectorError, "did not finish"):
            impl.collect()

    def test_classify(self):
        self.assertEqual("firewall", tenable.classify({"system_types": ["firewall"]}))
        self.assertEqual("server", tenable.classify({"operating_systems": ["Ubuntu 24.04"]}))
        self.assertEqual("workstation", tenable.classify({"operating_systems": "macOS 15"}))
        self.assertEqual("other", tenable.classify({}))


# ---------------------------------------------------------------------------
# Check Point: a sample policy that uses documentation address ranges only
# ---------------------------------------------------------------------------
def _host(uid, name, ip, nat=""):
    o = {"uid": uid, "name": name, "type": "host", "ipv4-address": ip}
    if nat:
        o["nat-settings"] = {"auto-rule": True, "method": "static", "ipv4-address": nat, "install-on": "All"}
    return o


def _tcp(uid, name, port):
    return {"uid": uid, "name": name, "type": "service-tcp", "port": port}


def _rule(uid, n, name, src, dst, svc, act, **extra):
    return {"uid": uid, "type": "access-rule", "rule-number": n, "name": name, "enabled": True, "source": src, "source-negate": False,
            "destination": dst, "destination-negate": False, "service": svc, "service-negate": False, "action": act, **extra}


CP_INVENTORY = {
    "show-gateways-and-servers": [
        {"uid": "gw-1", "name": "edge-gw-01", "type": "simple-gateway", "ipv4-address": "198.51.100.1", "version": "R81.20",
         "policy": {"access-policy-name": "Perimeter", "access-policy-installed": True}},
        {"uid": "gw-2", "name": "cloud-gw-01", "type": "simple-gateway", "ipv4-address": "192.0.2.1", "version": "R81.20"},
        {"uid": "mgmt-1", "name": "mgmt-01", "type": "checkpoint-host", "ipv4-address": "172.31.250.2", "version": "R81.20"}],
    "show-packages": [
        {"uid": "pkg-1", "name": "Perimeter", "access-layers": [{"uid": "layer-1", "name": "Perimeter Network"}]},
        {"uid": "pkg-2", "name": "Cloud", "access-layers": [{"uid": "layer-2", "name": "Cloud Network"}]}],
    "show-hosts": [_host("h-web", "web-01", "172.31.250.10", "198.51.100.10"), _host("h-mail", "mail-01", "172.31.250.20", "198.51.100.20"),
                   _host("h-portal", "portal-01", "198.51.100.30"), _host("h-app", "app-01", "172.31.250.40"),
                   _host("h-app-pub", "app-01-public", "198.51.100.40"), _host("h-db", "db-01", "172.31.250.50")],
    "show-networks": [{"uid": "n-dmz", "name": "dmz-net", "type": "network", "subnet4": "172.31.250.0", "mask-length4": 24},
                      {"uid": "n-partner", "name": "partner-net", "type": "network", "subnet4": "203.0.113.0", "mask-length4": 24}],
    "show-address-ranges": [],
    "show-groups": [{"uid": "g-web", "name": "web-servers", "type": "group", "members": [{"uid": "h-web"}, {"uid": "h-portal"}]}],
    "show-groups-with-exclusion": [],
    "show-services-tcp": [_tcp("s-http", "http", "80"), _tcp("s-https", "https", "443"), _tcp("s-ssh", "ssh", "22"), _tcp("s-smtp", "smtp", "25"),
                          _tcp("s-rdp", "rdp", "3389"), _tcp("s-high", "high-ports", ">1023")],
    "show-services-udp": [{"uid": "s-dns", "name": "domain-udp", "type": "service-udp", "port": "53"}],
    "show-service-groups": [{"uid": "sg-web", "name": "web-services", "type": "service-group", "members": [{"uid": "s-http"}, {"uid": "s-https"}]}],
}
CP_DICTIONARY = [
    {"uid": "any", "name": "Any", "type": "CpmiAnyObject"}, {"uid": "internet", "name": "Internet", "type": "CpmiInternet"},
    {"uid": "a-accept", "name": "Accept", "type": "RulebaseAction"}, {"uid": "a-drop", "name": "Drop", "type": "RulebaseAction"},
    {"uid": "a-layer", "name": "Inner Layer", "type": "RulebaseAction"}, {"uid": "orig", "name": "Original", "type": "Global"}]


def cp_layers(ssh_drop_enabled=True):
    return {
        "layer-1": [
            {"type": "access-section", "name": "Inbound", "rulebase": [
                _rule("r1", 1, "Web in", ["any"], ["g-web"], ["sg-web"], "a-accept"),
                _rule("r2", 2, "Stealth SSH", ["any"], ["n-dmz"], ["s-ssh"], "a-drop", enabled=ssh_drop_enabled),
                _rule("r3", 3, "Admin SSH (shadowed)", ["any"], ["h-web"], ["s-ssh"], "a-accept"),
                _rule("r4", 4, "Partner RDP", ["n-partner"], ["h-app"], ["s-rdp"], "a-accept"),
                _rule("r5", 5, "Mail in", ["any"], ["h-mail"], ["s-smtp"], "a-accept"),
                _rule("r6", 6, "Legacy HTTPS anywhere", ["any"], ["any"], ["s-https"], "a-accept"),
                _rule("r7", 7, "DMZ", ["internet"], ["n-dmz"], ["any"], "a-layer", **{"inline-layer": "layer-3"})]},
            _rule("r8", 8, "Cleanup", ["any"], ["any"], ["any"], "a-drop")],
        "layer-2": [
            _rule("c1", 1, "Portal", ["any"], ["h-portal"], ["s-https"], "a-accept"),
            _rule("c2", 2, "Old DB access", ["any"], ["h-db"], ["s-ssh"], "a-accept", enabled=False),
            _rule("c3", 3, "Cleanup", ["any"], ["any"], ["any"], "a-drop")],
        "layer-3": [
            _rule("i1", 9, "DB high ports", ["any"], ["h-db"], ["s-high"], "a-accept"),
            _rule("i2", 10, "DMZ cleanup", ["any"], ["any"], ["any"], "a-drop")],
    }


CP_NAT = {"Perimeter": [{"type": "nat-section", "name": "Manual Lower Rules", "rulebase": [
    {"uid": "n1", "type": "nat-rule", "rule-number": 1, "enabled": True, "method": "static", "original-source": "any",
     "original-destination": "h-app-pub", "original-service": "any", "translated-source": "orig", "translated-destination": "h-app",
     "translated-service": "orig"}]}], "Cloud": []}


def cp_answer(command, payload, layers=None, read_only=True):
    """What a management server answers. Pages by ``limit`` and ``offset`` like the real one."""
    layers = layers or cp_layers()
    limit, offset = int(payload.get("limit", 500)), int(payload.get("offset", 0))
    if command == "login":
        return {"sid": "sid-1", "read-only": read_only, "api-server-version": "1.9"}
    if command in {"logout", "keepalive"}:
        return {"message": "OK"}
    if command in CP_INVENTORY:
        rows = CP_INVENTORY[command]
        return {"packages" if command == "show-packages" else "objects": rows[offset:offset + limit], "total": len(rows)}
    if command in {"show-access-rulebase", "show-nat-rulebase"}:
        items = CP_NAT.get(payload.get("package"), []) if command == "show-nat-rulebase" else layers.get(payload.get("uid"), [])
        flat = []
        for item in items:
            flat.extend([(item["name"], r) for r in item["rulebase"]] if item["type"].endswith("-section") else [("", item)])
        page = [{"type": r["type"].replace("-rule", "-section"), "name": s, "rulebase": [r]} if s else r for s, r in flat[offset:offset + limit]]
        dictionary = CP_DICTIONARY + [o for cmd, rows in CP_INVENTORY.items() if cmd not in {"show-gateways-and-servers", "show-packages"} for o in rows]
        return {"rulebase": page, "objects-dictionary": dictionary, "total": len(flat)}
    return {"objects": [], "total": 0}


def cp_snapshot(layers=None):
    """Objects, top-level rules, inline layers and NAT rules, the way the connector hands them to the policy reader."""
    layers = layers or cp_layers()
    objects = {o["uid"]: o for o in CP_DICTIONARY}
    for rows in CP_INVENTORY.values():
        objects.update({o["uid"]: o for o in rows})

    def flat(items):
        out = []
        for item in items:
            out.extend(item["rulebase"] if item["type"].endswith("-section") else [item])
        return out
    return objects, {"Perimeter": flat(layers["layer-1"]), "Cloud": flat(layers["layer-2"])}, {"layer-3": flat(layers["layer-3"])}, flat(CP_NAT["Perimeter"])


TARGETS = {"web-01": "172.31.250.10", "mail-01": "172.31.250.20", "portal-01": "198.51.100.30", "app-01": "172.31.250.40", "db-01": "172.31.250.50"}


class TestCheckPointPolicy(OraSecTestCase):

    """The policy reader on its own: no database, no connector."""

    def _exposure(self, layers=None):
        objects, top, inline, nat = cp_snapshot(layers)
        policy = cp.Policy(objects)
        eff = {pkg: policy.effective(rules, inline) for pkg, rules in top.items()}
        out = cp.exposure([{"ip": cp.ip2int(ip), "ref": name} for name, ip in TARGETS.items()], policy.nat_forwards(nat), eff)
        return {(p["ref"], p["package"], p["protocol"], p["port_from"], p["port_to"]): p for p in out["paths"]}, out["broad"]

    def test_ranges(self):
        self.assertEqual([(1, 5), (8, 9)], cp.merge([(8, 9), (1, 3), (4, 5)]))
        self.assertEqual([(1, 2), (6, 10)], cp.subtract([(1, 10)], [(3, 5)]))
        self.assertEqual([(5, 7)], cp.intersect([(1, 7)], [(5, 20)]))
        self.assertEqual((1024, 65535), cp.port_range(">1023"))
        self.assertEqual((1, 1023), cp.port_range("<1024"))
        self.assertEqual((80, 90), cp.port_range("90-80"))
        self.assertIsNone(cp.port_range("icmp"))
        self.assertTrue(cp.is_private(cp.ip2int("172.31.250.10")))
        self.assertFalse(cp.is_private(cp.ip2int("198.51.100.10")))
        self.assertEqual("tcp 80, 443; udp any", cp.describe_ports({"tcp": [(80, 80), (443, 443)], "udp": [(1, 65535)]}))

    def test_web_is_reached_on_80_and_443_through_automatic_nat(self):
        paths, _ = self._exposure()
        for port in (80, 443):
            p = paths[("web-01", "Perimeter", "tcp", port, port)]
            self.assertEqual(("anyone", "nat", "198.51.100.10", False, "Perimeter #1 Web in"), (p["reach"], p["via"], p["front"], p["latent"], p["rule"]))

    def test_an_earlier_drop_closes_ssh_despite_a_later_accept(self):
        paths, _ = self._exposure()
        self.assertFalse([k for k in paths if k[0] == "web-01" and k[3] <= 22 <= k[4]])

    def test_without_the_drop_the_shadowed_rule_opens_ssh(self):
        paths, _ = self._exposure(cp_layers(ssh_drop_enabled=False))
        self.assertEqual("Perimeter #3 Admin SSH (shadowed)", paths[("web-01", "Perimeter", "tcp", 22, 22)]["rule"])

    def test_partner_rdp_is_listed_through_manual_nat(self):
        paths, _ = self._exposure()
        p = paths[("app-01", "Perimeter", "tcp", 3389, 3389)]
        self.assertEqual(("listed", 1, "nat", "198.51.100.40"), (p["reach"], p["sources"], p["via"], p["front"]))

    def test_a_public_machine_is_reached_directly_in_both_packages(self):
        paths, _ = self._exposure()
        self.assertEqual("direct", paths[("portal-01", "Perimeter", "tcp", 443, 443)]["via"])
        self.assertEqual("Cloud #1 Portal", paths[("portal-01", "Cloud", "tcp", 443, 443)]["rule"])

    def test_the_inline_layer_is_narrowed_to_one_host_and_latent_without_nat(self):
        paths, _ = self._exposure()
        p = paths[("db-01", "Perimeter", "tcp", 1024, 65535)]
        self.assertEqual((True, "anyone", "Perimeter #9 DB high ports"), (p["latent"], p["reach"], p["rule"]))
        self.assertFalse([k for k in paths if k[0] in {"web-01", "mail-01"} and k[3] == 1024])  # the inner rule names db-01 only

    def test_the_disabled_rule_is_ignored_and_there_is_one_broad_rule(self):
        paths, broad = self._exposure()
        self.assertFalse([k for k in paths if k[0] == "db-01" and k[1] == "Cloud"])
        self.assertEqual([("Perimeter #6 Legacy HTTPS anywhere", "anyone", "tcp 443")], [(b["rule"], b["reach"], b["ports"]) for b in broad])

    def test_a_manual_forward_of_one_service_opens_only_that_service(self):
        objects, top, inline, _nat = cp_snapshot()
        top["Perimeter"].insert(0, _rule("r0", 0, "App any", ["any"], ["h-app-pub"], ["any"], "a-accept"))
        nat = [{"uid": "n2", "type": "nat-rule", "enabled": True, "original-source": "any", "original-destination": "h-app-pub",
                "original-service": "s-https", "translated-destination": "h-app"}]
        policy = cp.Policy(objects)
        out = cp.exposure([{"ip": cp.ip2int("172.31.250.40"), "ref": "app-01"}], policy.nat_forwards(nat),
                          {"Perimeter": policy.effective(top["Perimeter"], inline)})
        mine = [(p["port_from"], p["port_to"], p["reach"]) for p in out["paths"] if p["rule_uid"] == "r0" and p["protocol"] == "tcp"]
        self.assertEqual([(443, 443, "anyone")], mine)

    def test_negated_and_unresolved_sources(self):
        policy = cp.Policy({"any": CP_DICTIONARY[0], "role": {"uid": "role", "name": "staff", "type": "access-role"},
                         "lan": {"uid": "lan", "type": "network", "subnet4": "10.0.0.0", "mask-length4": 8}})
        self.assertEqual("none", policy.source_reach({"source": ["any"], "source-negate": True})["reach"])
        self.assertEqual("anyone", policy.source_reach({"source": ["lan"], "source-negate": True})["reach"])
        self.assertEqual("none", policy.source_reach({"source": ["lan"]})["reach"])
        self.assertEqual({"reach": "listed", "sources": 1}, policy.source_reach({"source": ["role"]}))  # never "anyone"


@versioned_fixtures
class TestCheckPointConnector(OraSecTestCase):
    fixtures = ["orasec_testdata.json"]

    def setUp(self):
        self.assets = {name: InventoryAsset.objects.create(name=name, hostname=name, ip_address=ip, asset_type="server") for name, ip in TARGETS.items()}

    def _impl(self, answer=cp_answer, secrets=None, username="", base_url="https://mgmt.example.com", name="Check Point", **options):
        c = Connector(name=name, kind="checkpoint", base_url=base_url, username=username, verify_tls=False, options=options)
        c.set_secrets(secrets if secrets is not None else {"api_key": "cp-key"})
        c.save()
        impl = get_connector_class("checkpoint")(c)
        sent = []

        def routes(method, url, kw):
            if "/web_api/" in url:
                command = url.rsplit("/", 1)[1]
                sent.append((command, kw.get("json") or {}, kw.get("headers") or {}))
                return answer(command, kw.get("json") or {})
            if url == "https://portal.example.com/auth/external":
                return {"success": True, "data": {"token": "portal-token"}}
            if url.endswith("/app/maas/api/v1/mgmt-service"):
                return {"success": True, "data": {"name": "tenant1", "sharedSecret": "ctx-123", "version": "R82"}}
            if url.endswith("/app/maas/api/v1/gateways"):
                return {"success": True, "data": {"objects": [{"name": "edge-gw-01", "status": "Connected", "token": "one-time"}], "total": 1}}
            msg = f"unexpected {method} {url}"
            raise AssertionError(msg)
        calls = fake_http(self, impl, routes)
        return impl, sent, calls

    def test_only_reading_commands_are_ever_sent(self):
        for ok in ("login", "logout", "keepalive", "show-hosts", "show-access-rulebase"):
            self.assertTrue(checkpoint.allowed(ok))
        for bad in ("publish", "discard", "set-host", "add-host", "delete-host", "install-policy", "run-script", "show hosts", "SHOW-HOSTS", "show-"):
            self.assertFalse(checkpoint.allowed(bad))
        impl, sent, _ = self._impl()
        with self.assertRaisesRegex(ConnectorError, "only reads"):
            impl.call("install-policy", {"policy-package": "Perimeter"})
        self.assertEqual([], sent)

    def test_tls_is_verified_whatever_the_box_says_and_web_api_is_added(self):
        impl, _sent, _ = self._impl()
        self.assertTrue(impl.http.verify)
        self.assertEqual("https://mgmt.example.com/web_api", impl.base)

    def test_the_session_is_read_only_and_closed(self):
        impl, sent, _ = self._impl()
        msg = impl.test()
        self.assertIn("read-only session, API 1.9", msg)
        self.assertIn("3 gateway(s) and server(s), 2 policy package(s)", msg)
        self.assertEqual(["login", "show-gateways-and-servers", "show-packages", "logout"], [s[0] for s in sent])
        self.assertEqual({"read-only": True, "session-timeout": 900, "api-key": "cp-key"}, sent[0][1])
        self.assertNotIn("X-chkp-sid", sent[0][2])
        self.assertEqual("sid-1", sent[1][2]["X-chkp-sid"])

    def test_a_session_that_is_not_read_only_is_refused(self):
        impl, sent, _ = self._impl(answer=lambda c, p: cp_answer(c, p, read_only=False))
        with self.assertRaisesRegex(ConnectorError, "not read-only"):
            impl.collect()
        self.assertEqual(["login", "logout"], [s[0] for s in sent])

    def test_user_name_and_password_or_a_domain_can_be_used(self):
        impl, sent, _ = self._impl(secrets={"password": "pw"}, username="reader", domain="Branch")
        impl.login()
        self.assertEqual({"read-only": True, "session-timeout": 900, "user": "reader", "password": "pw", "domain": "Branch"}, sent[0][1])
        impl2, _sent, _ = self._impl(name="Check Point without credentials", secrets={})
        with self.assertRaisesRegex(ConnectorError, "No credentials"):
            impl2.login()

    def test_a_run_reads_the_policy_and_reports_what_the_internet_reaches(self):
        impl, sent, _ = self._impl(product_name="Perimeter")
        res = impl.collect()
        self.assertEqual("logout", sent[-1][0])
        self.assertEqual({"edge-gw-01": "firewall", "cloud-gw-01": "firewall", "mgmt-01": "server"}, {a.name: a.asset_type for a in res.assets})
        batch = res.batches[0]
        self.assertEqual(("OraSec Check Point", "Perimeter"), (batch.scan_type, batch.product_name))
        by_title = {f["title"]: f for f in batch.payload["findings"]}
        self.assertEqual({"Internet-facing ports on web-01", "Internet-facing ports on mail-01", "Internet-facing ports on portal-01",
                          "Broad firewall rule: Perimeter #6 Legacy HTTPS anywhere"}, set(by_title))
        self.assertIn("tcp 80, 443", by_title["Internet-facing ports on web-01"]["description"])
        self.assertEqual("Info", by_title["Internet-facing ports on web-01"]["severity"])
        self.assertEqual("Medium", by_title["Broad firewall rule: Perimeter #6 Legacy HTTPS anywhere"]["severity"])
        # reachable: web, mail and portal by anyone, app-01 by the partner network; db-01 is latent
        self.assertEqual((4, 1, 1, ["Perimeter", "Cloud"]),
                         (res.stats["machines_reachable"], res.stats["latent"], res.stats["broad_rules"], res.stats["packages"]))
        exposed = set(InventoryAsset.objects.filter(internet_exposed=True).values_list("name", flat=True))
        self.assertEqual({"web-01", "mail-01", "portal-01"}, exposed)  # app-01 is reached by the partner only, db-01 is latent

    def test_an_admin_port_open_to_anyone_is_a_high_finding(self):
        impl, _sent, _ = self._impl(answer=lambda c, p: cp_answer(c, p, layers=cp_layers(ssh_drop_enabled=False)))
        findings = impl.collect().batches[0].payload["findings"]
        ssh = [f for f in findings if f["severity"] == "High"]
        self.assertEqual(["Internet can reach web-01 on tcp/22 (SSH)"], [f["title"] for f in ssh])
        self.assertEqual("checkpoint:mgmt.example.com:172.31.250.10:tcp:22", ssh[0]["unique_id"])
        self.assertIn("through static NAT on 198.51.100.10", ssh[0]["description"])

    def test_only_the_wanted_packages_are_read(self):
        impl, sent, _ = self._impl(packages=["Cloud"])
        res = impl.collect()
        self.assertEqual(["Cloud"], res.stats["packages"])
        self.assertEqual([{"uid": "layer-2"}], [{"uid": s[1]["uid"]} for s in sent if s[0] == "show-access-rulebase"])

    def test_a_list_that_changes_size_or_stops_short_imports_nothing(self):
        def moving(command, payload):
            r = cp_answer(command, payload)
            if command == "show-hosts":
                r = {"objects": r["objects"][:1], "total": 6 + int(payload.get("offset", 0))}
            return r
        impl, _sent, _ = self._impl(answer=moving)
        impl.each = lambda command, payload, key="objects", limit=1, _each=impl.each: _each(command, payload, key, 1)
        with self.assertRaisesRegex(ConnectorError, "changed size"):
            impl.collect()

        def short(command, payload):
            r = cp_answer(command, payload)
            if command == "show-access-rulebase" and int(payload.get("offset", 0)) == 0:
                r = {**r, "rulebase": [], "total": 8}
            return r
        impl, _sent, _ = self._impl(name="Check Point short read", answer=short)
        with self.assertRaisesRegex(ConnectorError, "stopped at 0 of 8"):
            impl.collect()

    def test_rules_are_read_page_by_page(self):
        impl, _sent, _ = self._impl()
        impl.login()
        with mock.patch.object(impl, "call", wraps=impl.call) as call:
            rules, dictionary = impl.rulebase("show-access-rulebase", {"uid": "layer-1"})
        self.assertEqual(["r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8"], [r["uid"] for r in rules])
        self.assertEqual("Inbound", rules[0]["_section"])
        self.assertIn("any", dictionary)
        self.assertTrue(call.call_args[0][1]["use-object-dictionary"])

    def test_portal_mode_builds_the_management_address_and_sends_the_token(self):
        impl, sent, calls = self._impl(base_url="https://portal.example.com/auth/external", auth_mode="portal", client_id="cid",
                                       secrets={"portal_secret": "ps", "api_key": "cp-key"})
        msg = impl.test()
        self.assertIn("Portal key accepted: Smart-1 Cloud service tenant1 (version R82), 1 gateway(s) registered.", msg)
        self.assertEqual("https://tenant1.maas.checkpoint.com/ctx-123/web_api", impl.base)
        self.assertEqual({"clientId": "cid", "accessKey": "ps"}, calls[0][2]["json"])
        self.assertEqual("Bearer portal-token", sent[0][2]["Authorization"])
        with self.assertRaisesRegex(ConnectorError, "only reads the service details"):
            impl._portal_get("gateways/register")

    def test_the_address_with_the_tenant_context_stays_out_of_the_log(self):
        c = Connector(name="CP log", kind="checkpoint", base_url="https://t.maas.checkpoint.com/ctx-secret/web_api")
        c.set_secrets({"api_key": "k"})
        c.save()
        impl = get_connector_class("checkpoint")(c)

        class Resp:
            status_code = 200

            def json(self):
                return {"sid": "s", "read-only": True}
        with mock.patch.object(impl.http.session, "request", return_value=Resp()) as req:
            impl.login()
        self.assertEqual("https://t.maas.checkpoint.com/ctx-secret/web_api/login", req.call_args[0][1])
        self.assertTrue(req.call_args[1]["verify"])
        self.assertEqual(1, len(impl.log))
        self.assertIn("web_api/login", impl.log[0])
        self.assertNotIn("ctx-secret", impl.log[0])

    def test_portal_mode_without_a_management_login_keeps_the_gateways_and_imports_no_findings(self):
        def refuse(command, payload):
            if command == "login":
                msg = "POST web_api/login: HTTP 400 Missing parameter: api-key is required"
                raise ConnectorError(msg)
            return cp_answer(command, payload)
        impl, _sent, _ = self._impl(answer=refuse, base_url="https://portal.example.com/auth/external", auth_mode="portal", client_id="cid",
                                    secrets={"portal_secret": "ps"})
        res = impl.collect()
        self.assertEqual(["edge-gw-01"], [a.name for a in res.assets])
        self.assertNotIn("token", res.assets[0].attributes)  # the one-time registration token is not kept
        self.assertEqual([], res.batches)  # an empty batch would close every finding of the last good run
        self.assertIn("rule base was not read", res.warnings[0])


# ---------------------------------------------------------------------------
# AWS: the ways to sign in (the checks themselves are not touched here)
# ---------------------------------------------------------------------------
ROLE_ARN = "arn:aws:iam::{}:role/OraSecReadOnly".format("2" * 12)  # a made-up account


@versioned_fixtures
class TestAwsSignIn(OraSecTestCase):
    fixtures = ["orasec_testdata.json"]

    def _impl(self, username="AKIAEXAMPLE", secrets=None, **options):
        c = Connector(name=f"AWS {Connector.objects.count()}", kind="aws", base_url="https://aws.amazon.com", username=username, options=options)
        c.set_secrets(secrets if secrets is not None else {"secret_access_key": "sk"})
        c.save()
        return get_connector_class("aws")(c)

    def _boto(self, expires_in=3600):
        import datetime  # noqa: PLC0415
        sessions = []

        def session(**kw):
            s = mock.Mock(name="Session", kw=kw)
            s.client.return_value.assume_role.return_value = {"Credentials": {
                "AccessKeyId": "ASIAROLE", "SecretAccessKey": "role-secret", "SessionToken": "role-token",
                "Expiration": datetime.datetime.now(datetime.UTC) + datetime.timedelta(seconds=expires_in)}}
            sessions.append(s)
            return s
        p = mock.patch("boto3.session.Session", side_effect=session)
        p.start()
        self.addCleanup(p.stop)
        return sessions

    def test_key_pair_as_before(self):
        sessions = self._boto()
        self._impl(regions=["ap-southeast-2"])._session()
        self.assertEqual({"aws_access_key_id": "AKIAEXAMPLE", "aws_secret_access_key": "sk", "aws_session_token": None, "region_name": "ap-southeast-2"},
                         sessions[0].kw)
        self.assertEqual(1, len(sessions))

    def test_temporary_credentials_and_the_servers_own_identity(self):
        sessions = self._boto()
        self._impl(secrets={"secret_access_key": "sk", "session_token": "tok"})._session("eu-west-1")
        self.assertEqual(("tok", "eu-west-1"), (sessions[0].kw["aws_session_token"], sessions[0].kw["region_name"]))
        self._impl(username="", secrets={})._session()
        self.assertEqual({"region_name": "us-east-1"}, sessions[1].kw)  # no key: the usual AWS credential chain

    def test_a_role_in_another_account_is_assumed_once_for_the_run(self):
        sessions = self._boto()
        impl = self._impl(role_arn=ROLE_ARN, external_id="ext-1")
        impl._session()
        impl._session("us-west-2")
        own, role = sessions[0], sessions[1]
        own.client.assert_called_once_with("sts")
        own.client.return_value.assume_role.assert_called_once_with(RoleArn=ROLE_ARN,
                                                                    RoleSessionName="orasec-connector", DurationSeconds=3600, ExternalId="ext-1")
        self.assertEqual(("ASIAROLE", "role-secret", "role-token"),
                         (role.kw["aws_access_key_id"], role.kw["aws_secret_access_key"], role.kw["aws_session_token"]))
        sessions[2].client.return_value.assume_role.assert_not_called()  # second call: the role credentials are reused
        self.assertEqual("us-west-2", sessions[3].kw["region_name"])
        self.assertEqual(["sts.assume_role -> ok"], impl.log)

    def test_role_credentials_about_to_expire_are_renewed_and_a_refusal_is_explained(self):
        sessions = self._boto(expires_in=60)
        impl = self._impl(role_arn=ROLE_ARN)
        impl._session()
        impl._session()
        self.assertEqual(2, sum(s.client.return_value.assume_role.call_count for s in sessions))
        impl2 = self._impl(role_arn=ROLE_ARN.replace("OraSecReadOnly", "Nope"))
        with mock.patch("boto3.session.Session") as sess:
            sess.return_value.client.return_value.assume_role.side_effect = RuntimeError("AccessDenied")
            with self.assertRaisesRegex(ConnectorError, "could not be assumed"):
                impl2._session()

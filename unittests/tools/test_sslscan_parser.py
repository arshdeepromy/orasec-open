
from orasec.models import Test
from orasec.tools.sslscan.parser import SslscanParser
from unittests.orasec_test_case import OraSecTestCase, get_unit_tests_scans_path


class TestSslscanParser(OraSecTestCase):

    def test_parse_file_with_no_vuln_has_no_findings(self):
        with (get_unit_tests_scans_path("sslscan") / "sslscan_no_vuln.xml").open(encoding="utf-8") as testfile:
            parser = SslscanParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_file_with_one_vuln_has_one_findings(self):
        with (get_unit_tests_scans_path("sslscan") / "sslscan_one_vuln.xml").open(encoding="utf-8") as testfile:
            parser = SslscanParser()
            findings = parser.get_findings(testfile, Test())
            self.validate_locations(findings)
            self.assertEqual(1, len(findings))

    def test_parse_file_with_multiple_vuln_has_multiple_finding(self):
        with (get_unit_tests_scans_path("sslscan") / "sslscan_many_vuln.xml").open(encoding="utf-8") as testfile:
            parser = SslscanParser()
            findings = parser.get_findings(testfile, Test())
            self.validate_locations(findings)
            self.assertEqual(2, len(findings))

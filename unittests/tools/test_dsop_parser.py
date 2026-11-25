from orasec.models import Test
from orasec.tools.dsop.parser import DsopParser
from unittests.orasec_test_case import OraSecTestCase, get_unit_tests_scans_path


class TestDsopParser(OraSecTestCase):
    def test_zero_findings(self):
        with (get_unit_tests_scans_path("dsop") / "zero_vuln.xlsx").open("rb") as testfile:
            parser = DsopParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(len(findings), 0)

    def test_many_findings(self):
        with (get_unit_tests_scans_path("dsop") / "many_vuln.xlsx").open("rb") as testfile:
            parser = DsopParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(len(findings), 4)
            finding = findings[0]
            self.assertEqual("Low", finding.severity)
            self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
            self.assertEqual("CVE-2019-15587", finding.unsaved_vulnerability_ids[0])

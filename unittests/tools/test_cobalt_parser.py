from orasec.models import Test
from orasec.tools.cobalt.parser import CobaltParser
from unittests.orasec_test_case import OraSecTestCase, get_unit_tests_scans_path


class TestCobaltParser(OraSecTestCase):

    def test_parse_file_with_no_vuln_has_no_findings(self):

        with (get_unit_tests_scans_path("cobalt") / "cobalt_no_vuln.csv").open(encoding="utf-8") as testfile:
            parser = CobaltParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_file_with_one_vuln_has_one_findings(self):
        with (get_unit_tests_scans_path("cobalt") / "cobalt_one_vuln.csv").open(encoding="utf-8") as testfile:
            parser = CobaltParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))

    def test_parse_file_with_multiple_vuln_has_multiple_finding(self):
        with (get_unit_tests_scans_path("cobalt") / "cobalt_many_vuln.csv").open(encoding="utf-8") as testfile:
            parser = CobaltParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(9, len(findings))

from orasec.models import Test
from orasec.tools.brakeman.parser import BrakemanParser
from unittests.orasec_test_case import OraSecTestCase, get_unit_tests_scans_path


class TestBrakemanParser(OraSecTestCase):

    def test_parse_file_no_finding(self):
        with (get_unit_tests_scans_path("brakeman") / "no_finding.json").open(encoding="utf-8") as testfile:
            parser = BrakemanParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_file_has_two_findings(self):
        with (get_unit_tests_scans_path("brakeman") / "two_findings.json").open(encoding="utf-8") as testfile:
            parser = BrakemanParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(2, len(findings))

    def test_parse_file_has_many_findings(self):
        with (get_unit_tests_scans_path("brakeman") / "many_findings.json").open(encoding="utf-8") as testfile:
            parser = BrakemanParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(18, len(findings))

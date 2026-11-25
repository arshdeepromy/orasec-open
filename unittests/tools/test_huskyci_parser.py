from orasec.models import Test
from orasec.tools.huskyci.parser import HuskyCIParser
from unittests.orasec_test_case import OraSecTestCase, get_unit_tests_scans_path


class TestHuskyCIParser(OraSecTestCase):

    def test_parse_file_no_finding(self):
        with (get_unit_tests_scans_path("huskyci") / "huskyci_report_no_finding.json").open(encoding="utf-8") as testfile:
            parser = HuskyCIParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_file_has_one_finding_one_tool(self):
        with (
            get_unit_tests_scans_path("huskyci") / "huskyci_report_one_finding_one_tool.json").open(encoding="utf-8",
        ) as testfile:
            parser = HuskyCIParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))

    def test_parse_file_has_many_finding_one_tool(self):
        with (
            get_unit_tests_scans_path("huskyci") / "huskyci_report_many_finding_one_tool.json").open(encoding="utf-8",
        ) as testfile:
            parser = HuskyCIParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(3, len(findings))

    def test_parse_file_has_many_finding_two_tools(self):
        with (
            get_unit_tests_scans_path("huskyci") / "huskyci_report_many_finding_two_tools.json").open(encoding="utf-8",
        ) as testfile:
            parser = HuskyCIParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(15, len(findings))

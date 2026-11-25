from orasec.models import Test
from orasec.tools.ggshield.parser import GgshieldParser
from unittests.orasec_test_case import OraSecTestCase, get_unit_tests_scans_path


class TestGgshieldParser(OraSecTestCase):

    def test_parse_empty(self):
        with (get_unit_tests_scans_path("ggshield") / "no_finding.json").open(encoding="utf-8") as testfile:
            parser = GgshieldParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        with (get_unit_tests_scans_path("ggshield") / "one_finding.json").open(encoding="utf-8") as testfile:
            parser = GgshieldParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("wapf/settings.py", finding.file_path)
            self.assertEqual("Hard coded Django Secret Key found in wapf/settings.py", finding.title)
            self.assertIsNotNone(finding.description)
            self.assertEqual("2021-07-05", finding.date)

    def test_parse_many_finding(self):
        with (get_unit_tests_scans_path("ggshield") / "many_findings.json").open(encoding="utf-8") as testfile:
            parser = GgshieldParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(2, len(findings))
            finding = findings[0]
            self.assertEqual("wapf/settings.py", finding.file_path)
            self.assertEqual("Hard coded Django Secret Key found in wapf/settings.py", finding.title)
            self.assertIsNotNone(finding.description)
            self.assertEqual("2021-03-13", finding.date)
            finding = findings[1]
            self.assertEqual("wapf/settings.py", finding.file_path)
            self.assertEqual("Hard coded Django Secret Key found in wapf/settings.py", finding.title)
            self.assertIsNotNone(finding.description)
            self.assertEqual("2021-07-05", finding.date)

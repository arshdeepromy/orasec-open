from orasec.models import Test
from orasec.tools.progpilot.parser import ProgpilotParser
from unittests.orasec_test_case import OraSecTestCase, get_unit_tests_scans_path


class TestProgpilotParser(OraSecTestCase):

    def test_progpilotparser_single_has_many_findings(self):
        testfile = (get_unit_tests_scans_path("progpilot") / "progpilot.json").open(encoding="utf-8")
        parser = ProgpilotParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(2, len(findings))
        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual("Medium", finding.severity)
            self.assertIsNotNone(finding.description)
            self.assertGreater(len(finding.description), 0)
            self.assertEqual(89, finding.cwe)
            self.assertEqual("sql_injection", finding.title)
            self.assertEqual("/home/User/Modules/progpilot/Order.php", finding.file_path)
            self.assertEqual(593, finding.line)

    def test_progpilotparser_single_has_one_finding(self):
        testfile = (get_unit_tests_scans_path("progpilot") / "progpilot2.json").open(encoding="utf-8")
        parser = ProgpilotParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(findings))

    def test_progpilotparser_single_has_many_findings3(self):
        testfile = (get_unit_tests_scans_path("progpilot") / "progpilot3.json").open(encoding="utf-8")
        parser = ProgpilotParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(3, len(findings))

    def test_progpilotparser_single_has_many_findings4(self):
        testfile = (get_unit_tests_scans_path("progpilot") / "progpilot4.json").open(encoding="utf-8")
        parser = ProgpilotParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(2, len(findings))

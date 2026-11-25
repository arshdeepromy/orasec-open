from orasec.models import Test
from orasec.tools.eslint.parser import ESLintParser
from unittests.orasec_test_case import OraSecTestCase, get_unit_tests_scans_path


class TestESLintParser(OraSecTestCase):
    def test_parse_file_has_two_findings(self):
        testfile = (get_unit_tests_scans_path("eslint") / "scan.json").open(encoding="utf-8")
        parser = ESLintParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(2, len(findings))

    def test_parse_empty_file(self):
        testfile = (get_unit_tests_scans_path("eslint") / "empty.json").open(encoding="utf-8")
        parser = ESLintParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_parse_file_with_no_finding(self):
        testfile = (get_unit_tests_scans_path("eslint") / "no_finding.json").open(encoding="utf-8")
        parser = ESLintParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

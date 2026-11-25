from orasec.models import Test
from orasec.tools.kubescape.parser import KubescapeParser
from unittests.orasec_test_case import OraSecTestCase, get_unit_tests_scans_path


class TestKubescapeParser(OraSecTestCase):
    def test_parse_file_has_many_findings(self):
        with (get_unit_tests_scans_path("kubescape") / "many_findings.json").open(encoding="utf-8") as testfile:
            parser = KubescapeParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(349, len(findings))

    def test_parse_file_has_many_results(self):
        with (get_unit_tests_scans_path("kubescape") / "results.json").open(encoding="utf-8") as testfile:
            parser = KubescapeParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_file_with_a_failure(self):
        with (get_unit_tests_scans_path("kubescape") / "with_a_failure.json").open(encoding="utf-8") as testfile:
            parser = KubescapeParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(3, len(findings))

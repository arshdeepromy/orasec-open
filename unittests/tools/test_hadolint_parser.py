from orasec.models import Test
from orasec.tools.hadolint.parser import HadolintParser
from unittests.orasec_test_case import OraSecTestCase, get_unit_tests_scans_path


class TesthadolintParser(OraSecTestCase):

    def test_parse_file_with_one_dockerfile(self):
        testfile = (get_unit_tests_scans_path("hadolint") / "one_dockerfile.json").open(encoding="utf-8")
        parser = HadolintParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(4, len(findings))
        finding = list(findings)[0]
        self.assertEqual(finding.line, 9)
        self.assertEqual(finding.file_path, "django-OraSec\\Dockerfile.django")

    def test_parse_file_with_many_dockerfile(self):
        testfile = (get_unit_tests_scans_path("hadolint") / "many_dockerfile.json").open(encoding="utf-8")
        parser = HadolintParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(12, len(findings))

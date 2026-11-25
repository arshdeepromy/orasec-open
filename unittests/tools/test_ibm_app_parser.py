
from orasec.models import Test
from orasec.tools.ibm_app.parser import IbmAppParser
from unittests.orasec_test_case import OraSecTestCase, get_unit_tests_scans_path


class TestIbmAppParser(OraSecTestCase):

    def test_parse_file(self):
        testfile = (get_unit_tests_scans_path("ibm_app") / "testfire.xml").open(encoding="utf-8")
        parser = IbmAppParser()
        findings = parser.get_findings(testfile, Test())
        self.validate_locations(findings)
        testfile.close()
        self.assertEqual(27, len(findings))

        finding = findings[15]
        self.assertEqual("High", finding.severity)
        self.assertEqual(79, finding.cwe)
        self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
        self.assertEqual("CVE-2022-00001", finding.unsaved_vulnerability_ids[0])

        finding = findings[1]
        self.assertEqual("Info", finding.severity)
        self.assertEqual(True, finding.fix_available)

"""Connector endpoint: the role matrix. For each role type: tools listed, records visible, writes allowed or refused."""
from django.test import override_settings

from orasec.mcp import registry
from orasec.mcp.models import McpProposal
from orasec.posture import compliance
from orasec.posture.grc_models import ChangeRequest
from orasec.posture.models import ComplianceControl, ControlEvidence, FindingAssignment, RiskRegisterEntry
from unittests.mcp_testing import McpCase

STATUS = {"posture_summary", "sla_status"}
STATUS_ORG = {"compliance_status", "connectors_health"}
FINDINGS = {"prioritise", "find_findings", "finding_detail", "evaluate_risk", "my_work"}
FINDINGS_ORG = {"asset_detail", "asset_inventory", "attacks", "code_security"}
GRC = {"grc_risks", "grc_risk", "grc_changes", "grc_change", "grc_exceptions", "grc_exception", "grc_controls", "grc_control",
       "grc_check_results", "grc_evidence"}
WRITE = {"propose_action", "confirm_action"}
ORG_ALL = STATUS | STATUS_ORG | FINDINGS | FINDINGS_ORG | GRC | WRITE | {"risk_register", "leavers", "propose_decision"}
EXPECTED_TOOLS = {
    "admin": ORG_ALL,
    "engineer": ORG_ALL,
    "compliance": STATUS | FINDINGS | GRC | WRITE | {"propose_decision"},
    "reader": STATUS | FINDINGS | WRITE,
    "limited": STATUS | FINDINGS | WRITE,
}
SUPERUSER_KINDS = {"create_risk", "link_risk", "campaign", "run_connector", "start_leaver", "leaver_step", "leaver_reassign", "leaver_signoff"}
EXPECTED_KINDS = {
    "admin": {"assign", "note", "close", "recompute_priorities"} | SUPERUSER_KINDS,
    "engineer": {"assign", "note", "close", "recompute_priorities"} | SUPERUSER_KINDS,
    "compliance": {"assign", "note", "close"},
    "reader": {"assign", "note", "close"},
    "limited": {"assign", "note", "close"},
}


class TestMcpRoleMatrix(McpCase):

    def setUp(self):
        super().setUp()
        compliance.seed()
        self.control = ComplianceControl.objects.filter(ref="A.8.32").first() or ComplianceControl.objects.first()
        self.change = ChangeRequest.objects.create(title="Open port 8443 on the firewall", reason="r", impact="i",
                                                   requested_by=self.admin)
        self.risk = RiskRegisterEntry.objects.create(title="Unpatched edge device", likelihood=4, impact=4, owner=self.admin)

    def test_every_tool_is_in_the_matrix(self):
        self.assertEqual({t.name for t in registry.TOOLS}, ORG_ALL)

    def test_tools_listed_per_role(self):
        for role, user in self.roles.items():
            with self.subTest(role=role):
                self.assertEqual(EXPECTED_TOOLS[role], set(self.tools(user)))

    def test_tools_not_listed_cannot_be_called(self):
        for role, user in self.roles.items():
            for name in sorted(ORG_ALL - EXPECTED_TOOLS[role]):
                with self.subTest(role=role, tool=name):
                    self.assertTrue(self.refused_tool(user, name, {}), f"{role} could call {name}")

    def test_change_kinds_offered_per_role(self):
        for role, user in self.roles.items():
            with self.subTest(role=role):
                r = self.rpc("tools/list", user=user)
                tool = next(t for t in r.json()["result"]["tools"] if t["name"] == "propose_action")
                self.assertEqual(EXPECTED_KINDS[role], set(tool["inputSchema"]["properties"]["kind"]["enum"]))

    def test_findings_visible_per_role(self):
        both = {f"F-{self.finding_a.id}", f"F-{self.finding_b.id}"}
        expected = {"admin": both, "engineer": both, "compliance": set(), "reader": set(), "limited": {f"F-{self.finding_a.id}"}}
        for role, user in self.roles.items():
            with self.subTest(role=role):
                data, is_error = self.call(user, "find_findings", {"text": "in product", "limit": 15})
                self.assertFalse(is_error)
                self.assertEqual(expected[role], {i["ref"] for i in data["items"]} & both)

    def test_another_products_finding_by_id_is_refused(self):
        for user in (self.limited, self.reader, self.compliance):
            with self.subTest(user=user.username):
                data, is_error = self.call(user, "finding_detail", {"finding_id": self.finding_b.id})
                self.assertTrue(is_error)
                self.assertNotIn("nginx", str(data).lower())
                data, is_error = self.call(user, "evaluate_risk", {"finding_id": self.finding_b.id})
                self.assertTrue(is_error)
                for kind, params in (("note", {"finding_id": self.finding_b.id, "text": "seen"}),
                                     ("assign", {"finding_ids": [self.finding_b.id], "assignee": "me"}),
                                     ("close", {"finding_ids": [self.finding_b.id], "reason": "false_positive", "note": "n"})):
                    data, is_error = self.call(user, "propose_action", {"kind": kind, "params": params})
                    self.assertTrue(is_error, f"{user.username} could propose {kind}")
                    self.assertNotIn("nginx", str(data).lower())
        self.assertEqual(0, McpProposal.objects.count())
        data, is_error = self.call(self.limited, "finding_detail", {"finding_id": self.finding_a.id})
        self.assertFalse(is_error)
        self.assertIn("openssl", data["title"].lower())

    def test_governance_records_visible_per_role(self):
        for role, user in self.roles.items():
            with self.subTest(role=role):
                if role in ("admin", "engineer", "compliance"):
                    data, is_error = self.call(user, "grc_changes", {"limit": 5})
                    self.assertFalse(is_error)
                    self.assertIn(self.change.ref, [i["ref"] for i in data["items"]])
                    data, _ = self.call(user, "grc_risk", {"ref": self.risk.ref})
                    self.assertEqual(16, data["score"])
                    data, _ = self.call(user, "grc_control", {"ref": self.control.ref})
                    self.assertEqual(self.control.ref, data["ref"])
                else:
                    for name, args in (("grc_changes", {}), ("grc_change", {"ref": self.change.ref}), ("grc_risk", {"ref": self.risk.ref}),
                                       ("risk_register", {}), ("grc_evidence", {}), ("compliance_status", {})):
                        self.assertTrue(self.refused_tool(user, name, args), f"{role} could call {name}")

    def test_writes_allowed_or_refused_per_role(self):
        # assign to me: only where the person may see (and so edit) the finding
        can = {"admin": True, "engineer": True, "compliance": False, "reader": False, "limited": True}
        for role, user in self.roles.items():
            with self.subTest(role=role, write="assign"):
                data, is_error = self.call(user, "propose_action", {"kind": "assign", "params": {
                    "finding_ids": [self.finding_a.id], "assignee": "me"}})
                self.assertEqual(not can[role], is_error, data)
                if can[role]:
                    done, is_error = self.call(user, "confirm_action", {"proposal_id": data["proposal_id"]})
                    self.assertFalse(is_error, done)
                    self.assertEqual(user, FindingAssignment.objects.get(finding=self.finding_a).assignee)
        # assigning to someone else needs the security team
        data, is_error = self.call(self.limited, "propose_action", {"kind": "assign", "params": {
            "finding_ids": [self.finding_a.id], "assignee": "site-admin"}})
        self.assertTrue(is_error)
        # register, campaigns and connectors: superusers only; the kind is not even offered to the others
        for role, user in self.roles.items():
            with self.subTest(role=role, write="create_risk"):
                data, is_error = self.call(user, "propose_action", {"kind": "create_risk", "params": {
                    "title": "New risk", "likelihood": 3, "impact": 3}})
                self.assertEqual(role not in ("admin", "engineer"), is_error, data)
        # decisions on changes: people who may decide, and never the person who raised it
        expected = {"admin": "You raised this change", "engineer": None, "compliance": None}
        for role, why in expected.items():
            with self.subTest(role=role, write="approve"):
                data, is_error = self.call(self.roles[role], "propose_decision", {"ref": self.change.ref, "decision": "approve"})
                self.assertEqual(bool(why), is_error, data)
                if why:
                    self.assertIn(why, data["error"])

    @override_settings(ORASEC_MCP_DATA_LEVELS="status,grc")
    def test_default_levels_keep_findings_and_people_inside(self):
        self.assertEqual(STATUS | STATUS_ORG | GRC | {"risk_register", "propose_decision", "propose_action", "confirm_action"},
                         set(self.tools(self.admin)))
        self.assertEqual(STATUS, set(self.tools(self.limited)))
        self.assertTrue(self.refused_tool(self.admin, "find_findings", {"text": "openssl"}))
        self.assertTrue(self.refused_tool(self.admin, "leavers", {}))
        data, _ = self.call(self.admin, "sla_status")
        self.assertNotIn("items", data)                     # counts only
        r = self.rpc("tools/list", user=self.admin)
        tool = next(t for t in r.json()["result"]["tools"] if t["name"] == "propose_action")
        self.assertEqual({"recompute_priorities", "run_connector"}, set(tool["inputSchema"]["properties"]["kind"]["enum"]))
        data, is_error = self.call(self.admin, "propose_action", {"kind": "note", "params": {"finding_id": self.finding_a.id, "text": "x"}})
        self.assertTrue(is_error)

    @override_settings(ORASEC_MCP_DATA_LEVELS="")
    def test_no_level_no_tools(self):
        self.assertEqual([], self.tools(self.admin))

    def test_evidence_is_titles_only_and_restricted_stays_inside(self):
        ControlEvidence.objects.create(control=self.control, title="Change procedure v2", classification="internal",
                                       description="see the secret appendix", url="https://pol.example/doc/1",
                                       file="evidence/2026/11/proc-file-marker.txt")
        ControlEvidence.objects.create(control=self.control, title="Internal pen test 2026 results", classification="restricted")
        data, is_error = self.call(self.compliance, "grc_evidence", {"control": self.control.ref})
        self.assertFalse(is_error)
        text = str(data)
        self.assertIn("Change procedure v2", text)
        self.assertNotIn("pen test", text)
        self.assertEqual(1, data["restricted_items_withheld"])
        for leak in ("proc-file-marker", "secret appendix", "pol.example", "evidence/"):
            self.assertNotIn(leak, text)
        data, _ = self.call(self.compliance, "grc_control", {"ref": self.control.ref})
        self.assertNotIn("pen test", str(data))
        self.assertNotIn("proc-file-marker", str(data))
        with override_settings(ORASEC_MCP_RESTRICTED_EVIDENCE_TITLES=True):
            data, _ = self.call(self.compliance, "grc_evidence", {"control": self.control.ref})
            self.assertIn("Internal pen test 2026 results", str(data))
            self.assertNotIn("proc-file-marker", str(data))

    def test_lists_are_paged(self):
        for i in range(30):
            ChangeRequest.objects.create(title=f"Change {i}", reason="r", impact="i", requested_by=self.admin)
        first, _ = self.call(self.engineer, "grc_changes", {"limit": 10})
        self.assertEqual((31, 10, 10), (first["total"], len(first["items"]), first["next_offset"]))
        second, _ = self.call(self.engineer, "grc_changes", {"limit": 10, "offset": first["next_offset"]})
        self.assertFalse({i["ref"] for i in first["items"]} & {i["ref"] for i in second["items"]})
        capped, _ = self.call(self.engineer, "grc_changes", {"limit": 25})
        self.assertEqual(25, len(capped["items"]))
        huge, is_error = self.call(self.engineer, "grc_changes", {"limit": 500})
        self.assertFalse(is_error)
        self.assertEqual(25, len(huge["items"]))              # the server caps the page size

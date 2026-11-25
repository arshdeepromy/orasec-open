"""Connector endpoint: protocol (current revision and the earlier handshake), 401 with the metadata pointer, call log."""
import base64
import json

from django.test import override_settings

from orasec.mcp import guard
from orasec.mcp.models import McpCall
from unittests.mcp_testing import CLIENT_ID, ISS, V_MODERN, McpCase

META = "http://testserver/.well-known/oauth-protected-resource/mcp"


class TestMcpProtocol(McpCase):

    # ---- switched off, sign-in pointer --------------------------------------------------
    @override_settings(ORASEC_MCP_ENABLED=False)
    def test_off_by_default_answers_404(self):
        self.assertEqual(404, self.rpc("tools/list", user=self.admin).status_code)
        self.assertEqual(404, self.client.get("/.well-known/oauth-protected-resource/mcp").status_code)

    def test_no_token_gets_401_with_metadata_pointer(self):
        r = self.rpc("tools/list")
        self.assertEqual(401, r.status_code)
        challenge = r.headers["WWW-Authenticate"]
        self.assertTrue(challenge.startswith("Bearer "))
        self.assertIn(f'resource_metadata="{META}"', challenge)
        self.assertIn('scope="openid email profile"', challenge)
        self.assertNotIn("tools", r.content.decode())

    def test_metadata_names_the_identity_provider(self):
        for path in ("/.well-known/oauth-protected-resource/mcp", "/.well-known/oauth-protected-resource"):
            r = self.client.get(path)
            self.assertEqual(200, r.status_code)
            doc = r.json()
            self.assertEqual("http://testserver/mcp", doc["resource"])
            self.assertEqual([ISS], doc["authorization_servers"])
            self.assertEqual(["header"], doc["bearer_methods_supported"])

    def test_web_session_alone_is_not_accepted(self):
        self.client.force_login(self.admin)   # a signed-in browser session, but no token on the request
        self.assertEqual(401, self.rpc("tools/list").status_code)

    def test_token_in_the_address_is_not_accepted(self):
        r = self.client.post(f"/mcp?access_token={self.token(self.admin)}", data="{}", content_type="application/json")
        self.assertEqual(401, r.status_code)

    def test_get_is_405_and_no_session_is_made(self):
        r = self.client.get("/mcp", headers={"Authorization": f"Bearer {self.token(self.admin)}"})
        self.assertEqual(405, r.status_code)
        self.assertEqual("POST", r.headers["Allow"])

    # ---- current revision: every request carries its own version ----------------------
    def test_discover(self):
        r = self.rpc("server/discover", user=self.admin)
        self.assertEqual(200, r.status_code, r.content)
        self.assertEqual("application/json", r.headers["Content-Type"])
        res = r.json()["result"]
        self.assertEqual("complete", res["resultType"])
        self.assertIn(V_MODERN, res["supportedVersions"])
        self.assertIn("tools", res["capabilities"])
        self.assertEqual("private", res["cacheScope"])
        self.assertGreaterEqual(res["ttlMs"], 0)
        self.assertEqual("orasec", res["_meta"]["io.modelcontextprotocol/serverInfo"]["name"])
        self.assertNotIn("Mcp-Session-Id", r.headers)

    def test_tools_list_and_call(self):
        r = self.rpc("tools/list", user=self.admin)
        res = r.json()["result"]
        self.assertEqual(("complete", "private"), (res["resultType"], res["cacheScope"]))
        by_name = {t["name"]: t for t in res["tools"]}
        self.assertEqual("object", by_name["finding_detail"]["inputSchema"]["type"])
        self.assertFalse(by_name["finding_detail"]["inputSchema"]["additionalProperties"])
        self.assertTrue(by_name["finding_detail"]["annotations"]["readOnlyHint"])
        self.assertFalse(by_name["confirm_action"]["annotations"]["readOnlyHint"])
        r = self.rpc("tools/call", {"name": "finding_detail", "arguments": {"finding_id": self.finding_a.id}}, user=self.admin)
        res = r.json()["result"]
        self.assertFalse(res["isError"])
        self.assertTrue(res["content"][0]["text"].startswith(guard.NOTICE))
        self.assertEqual(f"F-{self.finding_a.id}", res["structuredContent"]["ref"])

    def test_headers_must_match_the_body(self):
        cases = [({"MCP-Protocol-Version": None}, "tools/list", {}),
                 ({"MCP-Protocol-Version": "2025-06-18"}, "tools/list", {}),
                 ({"Mcp-Method": "tools/call"}, "tools/list", {}),
                 ({"Mcp-Method": None}, "tools/list", {}),
                 ({"Mcp-Name": "posture_summary"}, "tools/call", {"name": "finding_detail", "arguments": {"finding_id": 1}}),
                 ({"Mcp-Name": None}, "tools/call", {"name": "finding_detail", "arguments": {"finding_id": 1}})]
        for headers, method, params in cases:
            with self.subTest(headers=headers):
                r = self.rpc(method, params, user=self.admin, headers=headers)
                self.assertEqual(400, r.status_code, r.content)
                self.assertEqual(-32020, r.json()["error"]["code"])

    def test_base64_name_header_is_decoded(self):
        coded = "=?base64?" + base64.b64encode(b"posture_summary").decode() + "?="
        r = self.rpc("tools/call", {"name": "posture_summary", "arguments": {}}, user=self.admin, headers={"Mcp-Name": coded})
        self.assertEqual(200, r.status_code, r.content)

    def test_unsupported_version_lists_the_supported_ones(self):
        body = {"jsonrpc": "2.0", "id": 7, "method": "tools/list", "params": {"_meta": {
            "io.modelcontextprotocol/protocolVersion": "1900-01-01", "io.modelcontextprotocol/clientCapabilities": {}}}}
        r = self.client.post("/mcp", data=json.dumps(body), content_type="application/json", headers={
            "Authorization": f"Bearer {self.token(self.admin)}", "MCP-Protocol-Version": "1900-01-01", "Mcp-Method": "tools/list"})
        self.assertEqual(400, r.status_code)
        err = r.json()["error"]
        self.assertEqual(-32022, err["code"])
        self.assertEqual("1900-01-01", err["data"]["requested"])
        self.assertIn(V_MODERN, err["data"]["supported"])

    def test_missing_client_capabilities_is_invalid_params(self):
        body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list",
                "params": {"_meta": {"io.modelcontextprotocol/protocolVersion": V_MODERN}}}
        r = self.client.post("/mcp", data=json.dumps(body), content_type="application/json", headers={
            "Authorization": f"Bearer {self.token(self.admin)}", "MCP-Protocol-Version": V_MODERN, "Mcp-Method": "tools/list"})
        self.assertEqual((400, -32602), (r.status_code, r.json()["error"]["code"]))

    def test_unknown_method_is_404_with_a_json_rpc_error(self):
        r = self.rpc("resources/list", user=self.admin)
        self.assertEqual((404, -32601), (r.status_code, r.json()["error"]["code"]))
        r = self.rpc("initialize", user=self.admin)   # the handshake does not exist in the current revision
        self.assertEqual((404, -32601), (r.status_code, r.json()["error"]["code"]))

    # ---- earlier revisions: initialize, then tools/list and tools/call ------------------
    def test_legacy_initialize_list_call(self):
        tok = self.token(self.admin)
        r = self.rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                    "clientInfo": {"name": "old-client", "version": "0.9"}}, token=tok, modern=False)
        self.assertEqual(200, r.status_code, r.content)
        res = r.json()["result"]
        self.assertEqual("2025-06-18", res["protocolVersion"])
        self.assertEqual("orasec", res["serverInfo"]["name"])
        self.assertIn("tools", res["capabilities"])
        self.assertNotIn("resultType", res)
        self.assertNotIn("Mcp-Session-Id", r.headers)   # stateless: no session is created
        r = self.rpc("notifications/initialized", token=tok, modern=False, rid=None)
        self.assertEqual((202, b""), (r.status_code, r.content))
        r = self.rpc("ping", token=tok, modern=False)
        self.assertEqual({}, r.json()["result"])
        r = self.rpc("tools/list", token=tok, modern=False)
        self.assertIn("posture_summary", [t["name"] for t in r.json()["result"]["tools"]])
        r = self.rpc("tools/call", {"name": "finding_detail", "arguments": {"finding_id": self.finding_a.id}}, token=tok, modern=False)
        self.assertFalse(r.json()["result"]["isError"])
        self.assertEqual("old-client 0.9", McpCall.objects.filter(tool="finding_detail").latest("id").client_name)

    def test_legacy_initialize_with_unknown_version_gets_the_latest_legacy_one(self):
        r = self.rpc("initialize", {"protocolVersion": "2024-01-01", "capabilities": {}}, user=self.admin, modern=False)
        self.assertEqual("2025-11-25", r.json()["result"]["protocolVersion"])

    def test_legacy_unknown_method(self):
        r = self.rpc("resources/list", user=self.admin, modern=False)
        self.assertEqual((200, -32601), (r.status_code, r.json()["error"]["code"]))

    # ---- malformed requests, origin, rate limit -------------------------------------------
    def test_bad_json_and_batches_are_rejected(self):
        h = {"Authorization": f"Bearer {self.token(self.admin)}"}
        r = self.client.post("/mcp", data="{not json", content_type="application/json", headers=h)
        self.assertEqual((400, -32700), (r.status_code, r.json()["error"]["code"]))
        r = self.client.post("/mcp", data="[]", content_type="application/json", headers=h)
        self.assertEqual((400, -32600), (r.status_code, r.json()["error"]["code"]))

    def test_foreign_origin_is_refused(self):
        r = self.rpc("tools/list", user=self.admin, headers={"Origin": "https://evil.example"})
        self.assertEqual(403, r.status_code)
        r = self.rpc("tools/list", user=self.admin, headers={"Origin": "http://testserver"})
        self.assertEqual(200, r.status_code)
        with override_settings(ORASEC_MCP_ALLOWED_ORIGINS="http://localhost:6274"):
            r = self.rpc("tools/list", user=self.admin, headers={"Origin": "http://localhost:6274"})
            self.assertEqual(200, r.status_code)
            self.assertEqual("http://localhost:6274", r.headers["Access-Control-Allow-Origin"])

    @override_settings(ORASEC_MCP_RATE_PER_MINUTE=3)
    def test_rate_limit_per_person(self):
        codes = [self.rpc("tools/list", user=self.admin).status_code for _ in range(5)]
        self.assertEqual([200, 200, 200, 429, 429], codes)
        self.assertEqual(200, self.rpc("tools/list", user=self.engineer).status_code)   # another person is not affected

    def test_refused_calls_from_one_address_are_limited(self):
        codes = [self.rpc("tools/list", token="a.b.c").status_code for _ in range(32)]
        self.assertEqual(401, codes[0])
        self.assertEqual(429, codes[-1])

    # ---- unknown tool, "act as" -----------------------------------------------------------
    def test_unknown_tool(self):
        r = self.rpc("tools/call", {"name": "delete_everything", "arguments": {}}, user=self.admin)
        self.assertEqual(-32602, r.json()["error"]["code"])

    def test_there_is_no_act_as_argument(self):
        for extra in ({"user": "site-admin"}, {"as_user": self.admin.id}, {"act_as": "admin"}):
            data, is_error = self.call(self.limited, "finding_detail", {"finding_id": self.finding_b.id, **extra})
            self.assertTrue(is_error)
            self.assertIn("Unknown argument", data)

    # ---- call log ---------------------------------------------------------------------------
    def test_every_call_is_logged(self):
        self.rpc("tools/list")                                   # refused: no token
        self.call(self.limited, "find_findings", {"text": "openssl", "limit": 5}, client="Desk Client",
                  headers={"X-Forwarded-For": "203.0.113.9"})
        refused = McpCall.objects.filter(outcome="refused").latest("id")
        self.assertIsNone(refused.user)
        self.assertEqual("no token", refused.detail)
        row = McpCall.objects.filter(tool="find_findings").latest("id")
        self.assertEqual(self.limited, row.user)
        self.assertEqual(("limited", "oauth", CLIENT_ID, "ok", False), (row.username, row.via, row.client_id, row.outcome, row.write))
        self.assertEqual("Desk Client 1.0", row.client_name)
        self.assertEqual("203.0.113.9", row.ip)
        self.assertIn("openssl", row.args)
        self.assertIsNotNone(row.created)

    def test_log_and_clients_pages(self):
        self.call(self.limited, "my_work")
        self.client.force_login(self.limited)
        self.assertEqual(302, self.client.get("/orasec/mcp/log/").status_code)       # admins only
        r = self.client.get("/orasec/mcp/clients/")
        self.assertContains(r, "test-client 1.0")
        self.client.force_login(self.admin)
        r = self.client.get("/orasec/mcp/log/")
        self.assertContains(r, "my_work")
        self.assertContains(r, "limited")

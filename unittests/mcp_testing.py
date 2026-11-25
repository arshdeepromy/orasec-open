"""Shared set-up for the connector endpoint tests (unittests/test_mcp_*.py)."""
import json
from unittest import mock

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.cache import cache
from django.test import override_settings
from django.utils import timezone

from orasec.mcp import auth
from orasec.models import Engagement, Finding, OraSec_User, Product, Test
from unittests.orasec_test_case import OraSecTestCase, versioned_fixtures

User = get_user_model()
ISS = "https://sso.example.test/application/o/orasec-mcp/"
CLIENT_ID = "orasec-mcp"
STAFF_GROUP = "OraSec Users"
V_MODERN, V_LEGACY = "2026-07-28", "2025-06-18"
SETTINGS = {
    "ORASEC_MCP_ENABLED": True, "ORASEC_MCP_OIDC_ISSUER": ISS, "ORASEC_MCP_OIDC_CLIENT_IDS": CLIENT_ID,
    "ORASEC_MCP_DATA_LEVELS": "status,grc,findings,people", "ORASEC_MCP_ALLOW_API_TOKEN": True,
    "ORASEC_MCP_RESOURCE_URL": "", "ORASEC_MCP_RATE_PER_MINUTE": 1000,
    "ORASEC_OIDC_ALLOWED_GROUP": STAFF_GROUP, "ORASEC_OIDC_TRUST_UNVERIFIED_EMAIL": False,
    "API_TOKENS_ENABLED": True, "API_TOKEN_DEFAULT_EXPIRY_DAYS": 30,
}
_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


class _FakeSigningKey:
    def __init__(self, pub):
        self.key = pub


@versioned_fixtures
@override_settings(**SETTINGS)
class McpCase(OraSecTestCase):

    """People of every role type, two products with one finding each, and a stand-in identity provider.

    ``self.directory`` plays the identity provider's current view of each person (what its user-info
    answer would be): changing it changes the answer on the next call, with the same token.
    """

    fixtures = ["orasec_testdata.json"]

    def setUp(self):
        super().setUp()
        cache.clear()
        director, _ = Group.objects.get_or_create(name="Director")
        compliance, _ = Group.objects.get_or_create(name="Compliance Officer")

        def mk(*args, **kwargs):
            return OraSec_User.objects.get(pk=User.objects.create_user(*args, **kwargs).pk)

        self.admin = mk("site-admin", "admin@example.test", "x-unused-x", is_superuser=True, is_staff=True,
                        first_name="Ada", last_name="Admin")
        self.admin.groups.add(director)
        self.engineer = mk("cloud-engineer", "engineer@example.test", "x-unused-x", is_superuser=True, is_staff=True,
                           first_name="Eli", last_name="Engineer")
        self.compliance = mk("compliance", "compliance@example.test", "x-unused-x", first_name="Cora", last_name="Compliance")
        self.compliance.groups.add(compliance)
        self.reader = mk("reader", "reader@example.test", "x-unused-x")
        self.limited = mk("limited", "limited@example.test", "x-unused-x")
        self.product_a, self.product_b = Product.objects.get(id=1), Product.objects.get(id=2)
        self.product_a.authorized_users.add(self.limited)
        self.finding_a = self._finding(self.product_a, "CVE-2026-0001 openssl in product A", cve="CVE-2026-0001", known_exploited=True)
        self.finding_b = self._finding(self.product_b, "CVE-2026-0002 nginx in product B", cve="CVE-2026-0002")
        self.roles = {"admin": self.admin, "engineer": self.engineer, "compliance": self.compliance,
                      "reader": self.reader, "limited": self.limited}
        self.directory = {u.email: {"sub": u.email, "email": u.email, "email_verified": True, "groups": [STAFF_GROUP]}
                          for u in self.roles.values()}
        self.idp_down = False

        def userinfo(token):
            if self.idp_down:
                import requests  # noqa: PLC0415
                raise requests.ConnectionError("down")
            sub = jwt.decode(token, options={"verify_signature": False}).get("sub")
            if sub not in self.directory:
                raise auth.Refused(401, "invalid_token", "The identity provider no longer accepts this token.", "userinfo answered 401")
            return dict(self.directory[sub])

        jwks = mock.patch.object(auth, "_jwks_client")
        self.addCleanup(jwks.stop)
        jwks.start().return_value.get_signing_key_from_jwt.return_value = _FakeSigningKey(_KEY.public_key())
        for target, value in (("discovery", {"issuer": ISS, "jwks_uri": ISS + "jwks/", "userinfo_endpoint": ISS + "userinfo/"}),):
            p = mock.patch.object(auth, target, return_value=value)
            self.addCleanup(p.stop)
            p.start()
        p = mock.patch.object(auth, "_userinfo", side_effect=userinfo)
        self.addCleanup(p.stop)
        p.start()

    # ---- data ---------------------------------------------------------------------------
    def _finding(self, product, title, **extra):
        today = timezone.now().date()
        eng = Engagement.objects.create(product=product, target_start=today, target_end=today)
        test = Test.objects.create(engagement=eng, test_type_id=120, target_start=timezone.now(), target_end=timezone.now())
        return Finding.objects.create(title=title, test=test, severity="High", active=True, reporter=self.admin, **extra)

    # ---- tokens ---------------------------------------------------------------------------
    def token(self, user, key=None, **claims):
        now = int(timezone.now().timestamp())
        body = {"iss": ISS, "aud": CLIENT_ID, "sub": user.email, "iat": now, "exp": now + 300}
        body.update(claims)
        body = {k: v for k, v in body.items() if v is not None}
        return jwt.encode(body, key or _KEY, algorithm="RS256")

    def other_key(self):
        return _OTHER_KEY

    # ---- calls ----------------------------------------------------------------------------
    def rpc(self, method, params=None, *, user=None, token=None, modern=True, headers=None, rid=1, client="test-client"):
        """POST one JSON-RPC request the way a client of the current (or an earlier) revision does."""
        params = dict(params or {})
        h = {"Accept": "application/json, text/event-stream"}
        if token is None and user is not None:
            token = self.token(user)
        if token:
            h["Authorization"] = f"Bearer {token}"
        if modern:
            params["_meta"] = {"io.modelcontextprotocol/protocolVersion": V_MODERN,
                               "io.modelcontextprotocol/clientInfo": {"name": client, "version": "1.0"},
                               "io.modelcontextprotocol/clientCapabilities": {}}
            h.update({"MCP-Protocol-Version": V_MODERN, "Mcp-Method": method})
            if method == "tools/call":
                h["Mcp-Name"] = str(params.get("name"))
        elif method != "initialize":
            h["MCP-Protocol-Version"] = V_LEGACY
        h.update(headers or {})
        h = {k: v for k, v in h.items() if v is not None}
        body = {"jsonrpc": "2.0", "method": method, "params": params}
        if rid is not None:
            body["id"] = rid
        return self.client.post("/mcp", data=json.dumps(body), content_type="application/json", headers=h)

    def tools(self, user, **kw):
        r = self.rpc("tools/list", user=user, **kw)
        self.assertEqual(200, r.status_code, r.content)
        return [t["name"] for t in r.json()["result"]["tools"]]

    def call(self, user, name, args=None, **kw):
        """``(data, is_error)`` of a tool call; fails the test when the call is not answered as a tool result."""
        r = self.rpc("tools/call", {"name": name, "arguments": args or {}}, user=user, **kw)
        self.assertEqual(200, r.status_code, r.content)
        res = r.json()["result"]
        return res.get("structuredContent", res["content"][0]["text"]), res["isError"]

    def refused_tool(self, user, name, args=None):
        """True when the tool does not exist for this person (same answer as an unknown tool)."""
        r = self.rpc("tools/call", {"name": name, "arguments": args or {}}, user=user)
        return r.status_code == 400 and r.json()["error"]["code"] == -32602 and "Unknown tool" in r.json()["error"]["message"]

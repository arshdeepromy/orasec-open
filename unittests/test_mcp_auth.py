"""Connector endpoint: sign-in. Identity comes only from the token; every bad or stale token is refused."""
import datetime

import jwt
from django.test import override_settings
from django.utils import timezone
from rest_framework.authtoken.models import Token

from orasec.mcp.models import McpAccess, McpCall, McpClient
from orasec.models import UserContactInfo
from unittests.mcp_testing import CLIENT_ID, STAFF_GROUP, McpCase


class TestMcpOAuth(McpCase):

    def _status(self, token):
        return self.rpc("tools/list", token=token).status_code

    def test_valid_token_is_the_person_it_names(self):
        self.assertEqual(200, self._status(self.token(self.limited)))
        self.assertEqual(self.limited, McpCall.objects.latest("id").user)

    def test_expired_token(self):
        now = int(timezone.now().timestamp())
        r = self.rpc("tools/list", token=self.token(self.admin, iat=now - 4000, exp=now - 3600))
        self.assertEqual(401, r.status_code)
        self.assertIn('error="invalid_token"', r.headers["WWW-Authenticate"])
        self.assertIn("resource_metadata=", r.headers["WWW-Authenticate"])

    def test_wrong_audience(self):
        # A token issued for the web sign-in application (or any other application) is not for this endpoint.
        for aud in ("orasec", "some-other-app", ["orasec", "grafana"]):
            with self.subTest(aud=aud):
                self.assertEqual(401, self._status(self.token(self.admin, aud=aud)))
        self.assertEqual("wrong audience", McpCall.objects.latest("id").detail)
        self.assertEqual(200, self._status(self.token(self.admin, aud=[CLIENT_ID])))

    def test_wrong_issuer(self):
        self.assertEqual(401, self._status(self.token(self.admin, iss="https://sso.example.test/application/o/orasec/")))

    def test_wrong_signature_and_unsigned_tokens(self):
        self.assertEqual(401, self._status(self.token(self.admin, key=self.other_key())))
        now = int(timezone.now().timestamp())
        claims = {"iss": "x", "aud": CLIENT_ID, "sub": self.admin.email, "iat": now, "exp": now + 300}
        self.assertEqual(401, self._status(jwt.encode(claims, "shared-secret-shared-secret-shared-secret", algorithm="HS256")))
        self.assertEqual(401, self._status(jwt.encode(claims, None, algorithm="none")))

    def test_token_without_expiry_is_refused(self):
        self.assertEqual(401, self._status(self.token(self.admin, exp=None)))

    def test_deactivated_user_is_refused_on_the_next_call(self):
        tok = self.token(self.limited)
        self.assertEqual(200, self._status(tok))
        self.limited.is_active = False
        self.limited.save(update_fields=["is_active"])
        self.assertEqual(401, self._status(tok))            # same token, next call

    def test_removed_from_the_sso_group_is_refused_on_the_next_call(self):
        tok = self.token(self.limited, groups=[STAFF_GROUP])   # the token still says the person is in the group
        self.assertEqual(200, self._status(tok))
        self.directory[self.limited.email]["groups"] = ["Other"]
        self.assertEqual(401, self._status(tok))
        self.assertIn("not in group", McpCall.objects.latest("id").detail)

    def test_disabled_at_the_identity_provider_is_refused_on_the_next_call(self):
        tok = self.token(self.limited)
        self.assertEqual(200, self._status(tok))
        del self.directory[self.limited.email]                 # the provider no longer accepts the token
        self.assertEqual(401, self._status(tok))

    def test_identity_provider_unreachable_means_refused(self):
        self.idp_down = True
        r = self.rpc("tools/list", token=self.token(self.admin))
        self.assertEqual(503, r.status_code)
        self.assertNotIn("tools", r.content.decode())

    def test_unknown_or_unverified_email(self):
        ghost = type("U", (), {"email": "ghost@example.test"})()
        self.directory[ghost.email] = {"sub": ghost.email, "email": ghost.email, "email_verified": True, "groups": [STAFF_GROUP]}
        self.assertEqual(401, self._status(self.token(ghost)))
        self.directory[self.limited.email]["email_verified"] = False
        self.assertEqual(401, self._status(self.token(self.limited)))

    def test_userinfo_for_another_subject_is_refused(self):
        self.directory[self.limited.email]["sub"] = self.admin.email
        self.assertEqual(401, self._status(self.token(self.limited)))

    @override_settings(ORASEC_MCP_OIDC_ISSUER="", ORASEC_MCP_ALLOW_API_TOKEN=False)
    def test_nothing_configured_refuses_everything(self):
        r = self.rpc("tools/list", token=self.token(self.admin))
        self.assertEqual(401, r.status_code)
        self.assertNotIn("resource_metadata", r.headers["WWW-Authenticate"])
        self.assertEqual(404, self.client.get("/.well-known/oauth-protected-resource/mcp").status_code)

    # ---- blocks: the person's own switch and per client -------------------------------------
    def test_blocked_client_and_account_switch(self):
        tok = self.token(self.limited)
        self.assertEqual(200, self.rpc("tools/list", token=tok, client="Phone").status_code)
        self.assertEqual(200, self.rpc("tools/list", token=tok, client="Laptop").status_code)
        self.client.force_login(self.limited)
        phone = McpClient.objects.get(user=self.limited, client_name="Phone 1.0")
        self.client.post("/orasec/mcp/clients/", {"action": "block_client", "id": phone.id})
        self.client.logout()
        self.assertEqual(403, self.rpc("tools/list", token=tok, client="Phone").status_code)
        self.assertEqual(200, self.rpc("tools/list", token=tok, client="Laptop").status_code)
        self.client.force_login(self.limited)
        self.client.post("/orasec/mcp/clients/", {"action": "block_all"})
        self.client.logout()
        self.assertEqual(403, self.rpc("tools/list", token=tok, client="Laptop").status_code)
        self.assertEqual(200, self.rpc("tools/list", user=self.admin).status_code)       # only that person is switched off
        McpAccess.objects.filter(user=self.limited).update(blocked_at=None)
        self.assertEqual(200, self.rpc("tools/list", token=tok, client="Laptop").status_code)

    def test_a_person_cannot_block_or_allow_someone_elses_client(self):
        self.rpc("tools/list", user=self.admin, client="Admin Laptop")
        theirs = McpClient.objects.get(user=self.admin)
        self.client.force_login(self.limited)
        r = self.client.post("/orasec/mcp/clients/", {"action": "block_client", "id": theirs.id})
        self.assertEqual(404, r.status_code)
        theirs.refresh_from_db()
        self.assertIsNone(theirs.blocked_at)


class TestMcpApiToken(McpCase):

    def _token(self, user, **explicit):
        tok = Token.objects.create(user=user)
        if explicit:
            UserContactInfo.objects.update_or_create(user=user, defaults=explicit)
        return tok.key

    def test_expiring_api_token_is_accepted(self):
        key = self._token(self.limited)
        r = self.rpc("tools/list", token=key)
        self.assertEqual(200, r.status_code, r.content)
        row = McpCall.objects.latest("id")
        self.assertEqual((self.limited, "api_token"), (row.user, row.via))

    @override_settings(API_TOKEN_DEFAULT_EXPIRY_DAYS=0)
    def test_api_token_without_expiry_is_refused(self):
        key = self._token(self.limited)
        self.assertEqual(401, self.rpc("tools/list", token=key).status_code)
        self.assertIn("no expiry", McpCall.objects.latest("id").detail)
        UserContactInfo.objects.update_or_create(user=self.limited, defaults={"token_expiry": timezone.now() + datetime.timedelta(days=7)})
        self.assertEqual(200, self.rpc("tools/list", token=key).status_code)

    def test_expired_api_token_is_refused(self):
        key = self._token(self.limited, token_expiry=timezone.now() - datetime.timedelta(minutes=1))
        self.assertEqual(401, self.rpc("tools/list", token=key).status_code)

    def test_api_token_of_a_deactivated_user_is_refused(self):
        key = self._token(self.limited)
        self.assertEqual(200, self.rpc("tools/list", token=key).status_code)
        self.limited.is_active = False
        self.limited.save(update_fields=["is_active"])
        self.assertEqual(401, self.rpc("tools/list", token=key).status_code)

    @override_settings(ORASEC_MCP_ALLOW_API_TOKEN=False)
    def test_api_tokens_are_off_unless_switched_on(self):
        self.assertEqual(401, self.rpc("tools/list", token=self._token(self.limited)).status_code)

    def test_made_up_token(self):
        self.assertEqual(401, self.rpc("tools/list", token="0123456789abcdef0123456789abcdef01234567").status_code)

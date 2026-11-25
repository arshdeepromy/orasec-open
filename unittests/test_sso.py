"""Tests for SSO sign-in and back-channel logout (orasec.sso)."""
import datetime
import uuid
from unittest import mock

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from django.contrib.auth import get_user_model
from django.contrib.sessions.backends.db import SessionStore
from django.contrib.sessions.models import Session
from django.test import TestCase, override_settings
from django.utils import timezone

from orasec.sso import oidc, views

ISS = "https://sso.example.test/application/o/orasec/"
SSO = {"ORASEC_OIDC_ENABLED": True, "ORASEC_OIDC_ISSUER": ISS, "ORASEC_OIDC_CLIENT_ID": "orasec",
       "ORASEC_OIDC_CLIENT_SECRET": "x", "ORASEC_OIDC_ALLOWED_GROUP": "OraSec Users"}


def _key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


class _FakeSigningKey:
    def __init__(self, pub):
        self.key = pub


@override_settings(**SSO)
class SsoTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        U = get_user_model()
        cls.alice = U.objects.create_user("alice", "alice@example.com", "x-unused-x")
        cls.bob = U.objects.create_user("bob", "bob@example.com", "x-unused-x")

    def setUp(self):
        self.priv = _key()
        p = mock.patch.object(oidc, "_jwks_client")
        self.addCleanup(p.stop)
        jwks = p.start()
        jwks.return_value.get_signing_key_from_jwt.return_value = _FakeSigningKey(self.priv.public_key())
        d = mock.patch.object(oidc, "discovery", return_value={
            "authorization_endpoint": "https://sso.example.test/application/o/authorize/",
            "token_endpoint": "https://sso.example.test/application/o/token/",
            "jwks_uri": "https://sso.example.test/application/o/orasec/jwks/"})
        self.addCleanup(d.stop)
        d.start()

    def _session_for(self, user, sso=None):
        s = SessionStore()
        s["_auth_user_id"] = str(user.pk)
        s["_auth_user_backend"] = "django.contrib.auth.backends.ModelBackend"
        if sso:
            s["sso"] = sso
        s.create()
        return s.session_key

    def _logout_token(self, **extra):
        now = int(timezone.now().timestamp())
        claims = {"iss": ISS, "aud": "orasec", "iat": now, "jti": uuid.uuid4().hex,
                  "events": {oidc.BACKCHANNEL_EVENT: {}}, "sub": "alice@example.com"}
        claims.update(extra)
        claims = {k: v for k, v in claims.items() if v is not None}
        return jwt.encode(claims, self.priv, algorithm="RS256")

    def test_login_page_shows_sso_button_and_break_glass_form(self):
        r = self.client.get("/login")
        self.assertContains(r, "Sign in with SSO")
        self.assertContains(r, "or break-glass login")
        self.assertContains(r, 'name="password"')

    def test_sso_login_redirects_to_provider_with_pkce(self):
        r = self.client.get("/sso/login/")
        self.assertEqual(r.status_code, 302)
        self.assertIn("code_challenge_method=S256", r["Location"])
        self.assertIn("client_id=orasec", r["Location"])

    def test_redirect_uri_can_be_pinned_for_proxies(self):
        with override_settings(ORASEC_OIDC_REDIRECT_URI="https://orasec.example.test/sso/callback/"):
            r = self.client.get("/sso/login/")
        self.assertIn("redirect_uri=https%3A%2F%2Forasec.example.test%2Fsso%2Fcallback%2F", r["Location"])

    def test_callback_rejects_state_mismatch(self):
        self.client.get("/sso/login/")
        r = self.client.get("/sso/callback/?state=wrong&code=abc")
        self.assertRedirects(r, "/login", fetch_redirect_response=False)
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_backchannel_logout_ends_all_sessions_of_that_person_only(self):
        a1 = self._session_for(self.alice, {"sub": "alice@example.com", "sid": "s1"})
        a2 = self._session_for(self.alice)  # break-glass/local session is ended too (offboarding)
        b1 = self._session_for(self.bob, {"sub": "bob@example.com", "sid": "s9"})
        r = self.client.post("/sso/backchannel-logout/", {"logout_token": self._logout_token(sid="s1")})
        self.assertEqual(r.status_code, 200)
        self.assertFalse(Session.objects.filter(session_key__in=[a1, a2]).exists())
        self.assertTrue(Session.objects.filter(session_key=b1).exists())

    def test_backchannel_rejects_missing_wrong_audience_nonce_and_replay(self):
        self.assertEqual(self.client.post("/sso/backchannel-logout/", {}).status_code, 400)
        self.assertEqual(self.client.post("/sso/backchannel-logout/",
                                          {"logout_token": self._logout_token(aud="other")}).status_code, 400)
        self.assertEqual(self.client.post("/sso/backchannel-logout/",
                                          {"logout_token": self._logout_token(nonce="n")}).status_code, 400)
        tok = self._logout_token(jti="replay-" + uuid.uuid4().hex)
        self.assertEqual(self.client.post("/sso/backchannel-logout/", {"logout_token": tok}).status_code, 200)
        self.assertEqual(self.client.post("/sso/backchannel-logout/", {"logout_token": tok}).status_code, 400)

    def test_backchannel_rejects_token_signed_by_another_key(self):
        other = _key()
        now = int(timezone.now().timestamp())
        tok = jwt.encode({"iss": ISS, "aud": "orasec", "iat": now, "jti": "x",
                          "events": {oidc.BACKCHANNEL_EVENT: {}}, "sub": "alice@example.com"}, other, algorithm="RS256")
        a1 = self._session_for(self.alice)
        self.assertEqual(self.client.post("/sso/backchannel-logout/", {"logout_token": tok}).status_code, 400)
        self.assertTrue(Session.objects.filter(session_key=a1).exists())

    def test_callback_refuses_people_outside_the_group_or_without_account(self):
        def run(claims):
            self.client.get("/sso/login/")
            state = self.client.session["oidc"]["state"]
            with mock.patch.object(oidc, "finish", return_value=(claims, "/")):
                return self.client.get(f"/sso/callback/?state={state}&code=c")
        r = run({"email": "alice@example.com", "email_verified": True, "groups": ["Other"], "sub": "a"})
        self.assertRedirects(r, "/login", fetch_redirect_response=False)
        r = run({"email": "nobody@example.com", "email_verified": True, "groups": ["OraSec Users"], "sub": "n"})
        self.assertRedirects(r, "/login", fetch_redirect_response=False)
        r = run({"email": "alice@example.com", "email_verified": False, "groups": ["OraSec Users"], "sub": "a"})
        self.assertRedirects(r, "/login", fetch_redirect_response=False)
        r = run({"email": "ALICE@example.com", "email_verified": True, "groups": ["OraSec Users"], "sub": "a", "sid": "z"})
        self.assertEqual(r.status_code, 302)
        self.assertEqual(self.client.session["_auth_user_id"], str(self.alice.pk))
        self.assertLessEqual(self.client.session.get_expiry_age(), 12 * 3600)

    def test_disabled_when_not_configured(self):
        with override_settings(ORASEC_OIDC_ENABLED=False):
            self.assertNotContains(self.client.get("/login"), "Sign in with SSO")
            self.assertEqual(self.client.post("/sso/backchannel-logout/", {"logout_token": "x"}).status_code, 404)


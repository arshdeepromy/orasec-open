"""Tests for the Microsoft Entra ID and Okta sign-in providers and for Active Directory sign-in (orasec.sso)."""
import time
from unittest import mock

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from django.contrib.auth import authenticate as django_authenticate
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import RequestFactory, TestCase, override_settings
from django.urls import Resolver404, resolve

from orasec.plugins import registry
from orasec.sso import ldap, oidc, providers

TENANT = "11111111-2222-3333-4444-555555555555"
OTHER_TENANT = "99999999-8888-7777-6666-555555555555"
ENTRA = {"ORASEC_ENTRA_ENABLED": True, "ORASEC_ENTRA_TENANT_ID": TENANT, "ORASEC_ENTRA_CLIENT_ID": "entra-app", "ORASEC_ENTRA_CLIENT_SECRET": "s"}
OKTA = {"ORASEC_OKTA_ENABLED": True, "ORASEC_OKTA_DOMAIN": "https://example.okta.com/", "ORASEC_OKTA_CLIENT_ID": "okta-app", "ORASEC_OKTA_CLIENT_SECRET": "s"}
LDAP = {"ORASEC_LDAP_ENABLED": True, "ORASEC_LDAP_HOST": "dc01.corp.example.com", "ORASEC_LDAP_BASE_DN": "OU=Staff,DC=corp,DC=example,DC=com",
        "ORASEC_LDAP_BIND_DN": "CN=svc-orasec,OU=Service Accounts,DC=corp,DC=example,DC=com", "ORASEC_LDAP_BIND_PASSWORD": "svc-pw",
        "AUTHENTICATION_BACKENDS": ("django.contrib.auth.backends.ModelBackend", "orasec.sso.ldap.LDAPBackend")}
PRIV = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def authenticate(_request, **credentials):
    """The login form's call: every backend in turn, with a request (the failed-login log needs one)."""
    request = RequestFactory().post("/login")
    request.META["REMOTE_ADDR"] = "192.0.2.10"
    return django_authenticate(request, **credentials)


class _Key:
    key = PRIV.public_key()


class _Resp:
    status_code = 200

    def __init__(self, body):
        self._body = body

    def json(self):
        return self._body

    def raise_for_status(self):
        pass


class ProviderCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        U = get_user_model()
        cls.alice = U.objects.create_user("alice", "alice@example.com", "x-unused-x")
        cls.bob = U.objects.create_user("bob", "bob@example.com", "x-unused-x", is_active=False)

    def setUp(self):
        cache.clear()
        p = mock.patch.object(oidc, "_jwks_client")
        p.start().return_value.get_signing_key_from_jwt.return_value = _Key()
        self.addCleanup(p.stop)

    def discovery(self, issuer):
        base = issuer.replace("{tenantid}", "common")
        p = mock.patch.object(oidc, "discovery", return_value={"issuer": issuer, "authorization_endpoint": base + "/authorize",
                                                               "token_endpoint": base + "/token", "jwks_uri": base + "/keys"})
        p.start()
        self.addCleanup(p.stop)

    def sign_in(self, provider, claims, issuer, aud):
        """The whole flow through the two views, with a token signed by our key."""
        r = self.client.get(f"/sso/{provider}/login/?next=/dashboard")
        self.assertEqual(302, r.status_code, r.content[:200])
        pending = self.client.session["oidc"]
        now = int(time.time())
        token = jwt.encode({"iss": issuer, "aud": aud, "iat": now, "exp": now + 300, "nonce": pending["nonce"], "sub": "subject-1", **claims},
                           PRIV, algorithm="RS256")
        with mock.patch.object(oidc.requests, "post", return_value=_Resp({"id_token": token})) as post:
            r = self.client.get(f"/sso/{provider}/callback/?state={pending['state']}&code=abc")
        self.token_request = post.call_args
        return r

    def signed_in(self):
        return self.client.session.get("_auth_user_id")


# ---------------------------------------------------------------------------
# Microsoft Entra ID
# ---------------------------------------------------------------------------
@override_settings(**ENTRA)
class EntraTests(ProviderCase):
    ISS = f"https://login.microsoftonline.com/{TENANT}/v2.0"

    def test_button_and_addresses(self):
        r = self.client.get("/login")
        self.assertContains(r, "Sign in with Microsoft")
        self.assertContains(r, "/sso/entra/login/")
        self.assertNotContains(r, "Sign in with Okta")
        p = providers.get("entra")
        self.assertEqual(f"https://login.microsoftonline.com/{TENANT}/v2.0/.well-known/openid-configuration", p.discovery_url)

    def test_sign_in_with_the_sign_in_name_when_there_is_no_email_claim(self):
        self.discovery(self.ISS)
        r = self.sign_in("entra", {"preferred_username": "Alice@Example.com", "tid": TENANT}, self.ISS, "entra-app")
        self.assertRedirects(r, "/dashboard", fetch_redirect_response=False)
        self.assertEqual(str(self.alice.pk), self.signed_in())
        self.assertEqual("entra", self.client.session["sso"]["provider"])
        self.assertEqual(("entra-app", "s"), self.token_request[1]["auth"])
        self.assertIn("/sso/entra/callback/", self.token_request[1]["data"]["redirect_uri"])

    def test_token_of_another_tenant_another_app_or_another_key_is_refused(self):
        self.discovery(self.ISS)
        r = self.sign_in("entra", {"email": "alice@example.com", "tid": OTHER_TENANT}, f"https://login.microsoftonline.com/{OTHER_TENANT}/v2.0", "entra-app")
        self.assertRedirects(r, "/login", fetch_redirect_response=False)
        r = self.sign_in("entra", {"email": "alice@example.com"}, self.ISS, "someone-elses-app")
        self.assertRedirects(r, "/login", fetch_redirect_response=False)
        self.assertIsNone(self.signed_in())

    def test_no_account_or_a_disabled_account_is_refused(self):
        self.discovery(self.ISS)
        for email in ("nobody@example.com", "bob@example.com"):
            r = self.sign_in("entra", {"email": email}, self.ISS, "entra-app")
            self.assertRedirects(r, "/login", fetch_redirect_response=False)
        self.assertIsNone(self.signed_in())

    @override_settings(ORASEC_ENTRA_ALLOWED_GROUP="OraSec.Reader")
    def test_allowed_group_can_be_a_group_id_or_an_app_role(self):
        self.discovery(self.ISS)
        r = self.sign_in("entra", {"email": "alice@example.com", "groups": ["aaaa-bbbb"]}, self.ISS, "entra-app")
        self.assertRedirects(r, "/login", fetch_redirect_response=False)
        r = self.sign_in("entra", {"email": "alice@example.com", "roles": ["OraSec.Reader"]}, self.ISS, "entra-app")
        self.assertRedirects(r, "/dashboard", fetch_redirect_response=False)

    @override_settings(ORASEC_ENTRA_ALLOWED_GROUP="aaaa-bbbb")
    def test_group_overage_reads_as_cannot_tell(self):
        claims = {"email": "alice@example.com", "_claim_names": {"groups": "src1"}}
        user, why = oidc.user_for_claims(claims, "entra")
        self.assertIsNone(user)
        self.assertIn("too many groups", why[0])
        self.assertIn("overage", why[1])

    @override_settings(ORASEC_ENTRA_TENANT_ID="organizations")
    def test_a_multi_tenant_registration_needs_the_list_of_tenants(self):
        p = providers.get("entra")
        self.assertFalse(p.configured)
        self.assertIn("ORASEC_ENTRA_ALLOWED_TENANTS", p.missing)
        self.assertNotContains(self.client.get("/login"), "Sign in with Microsoft")
        self.assertRedirects(self.client.get("/sso/entra/login/"), "/login", fetch_redirect_response=False)
        row = next(r for r in registry.snapshot() if r["key"] == "sso.entra")
        self.assertEqual((True, False, False), (row["on"], row["available"], row["active"]))

    @override_settings(ORASEC_ENTRA_TENANT_ID="organizations", ORASEC_ENTRA_ALLOWED_TENANTS=f"{TENANT}, 00000000-0000-0000-0000-000000000000")
    def test_multi_tenant_issuer_is_filled_in_from_an_allowed_tenant_only(self):
        self.discovery("https://login.microsoftonline.com/{tenantid}/v2.0")
        r = self.sign_in("entra", {"email": "alice@example.com", "tid": TENANT}, self.ISS, "entra-app")
        self.assertRedirects(r, "/dashboard", fetch_redirect_response=False)
        self.client.logout()
        # a real token of a tenant that is not on the list: right issuer for its own tenant, still refused
        r = self.sign_in("entra", {"email": "alice@example.com", "tid": OTHER_TENANT}, f"https://login.microsoftonline.com/{OTHER_TENANT}/v2.0", "entra-app")
        self.assertRedirects(r, "/login", fetch_redirect_response=False)
        # a token that claims an allowed tenant but was issued for another one
        r = self.sign_in("entra", {"email": "alice@example.com", "tid": TENANT}, f"https://login.microsoftonline.com/{OTHER_TENANT}/v2.0", "entra-app")
        self.assertRedirects(r, "/login", fetch_redirect_response=False)
        self.assertIsNone(self.signed_in())

    def test_the_answer_must_come_back_to_the_provider_it_started_with(self):
        self.discovery(self.ISS)
        self.client.get("/sso/entra/login/")
        state = self.client.session["oidc"]["state"]
        with override_settings(ORASEC_OIDC_ENABLED=True, ORASEC_OIDC_ISSUER="https://sso.example.test/o/", ORASEC_OIDC_CLIENT_ID="orasec"):
            r = self.client.get(f"/sso/callback/?state={state}&code=abc")
        self.assertRedirects(r, "/login", fetch_redirect_response=False)
        self.assertIsNone(self.signed_in())

    def test_plugin_switch_turns_the_provider_off(self):
        self.addCleanup(cache.clear)
        registry.set_on("sso.entra", False)
        self.assertFalse(oidc.enabled("entra"))
        self.assertNotContains(self.client.get("/login"), "Sign in with Microsoft")
        self.assertRedirects(self.client.get("/sso/entra/login/"), "/login", fetch_redirect_response=False)
        registry.set_on("sso.entra", True)
        self.assertTrue(oidc.enabled("entra"))

    def test_unknown_provider_has_no_address(self):
        with self.assertRaises(Resolver404):
            resolve("/sso/github/login/")
        self.assertEqual("oidc_provider_login", resolve("/sso/okta/login/").url_name)
        self.assertIsNone(providers.get("github"))


# ---------------------------------------------------------------------------
# Okta
# ---------------------------------------------------------------------------
@override_settings(**OKTA)
class OktaTests(ProviderCase):

    def test_issuer_follows_the_authorization_server(self):
        p = providers.get("okta")
        self.assertEqual(("https://example.okta.com/oauth2/default", "https://example.okta.com/oauth2/default/.well-known/openid-configuration"),
                         (p.issuer, p.discovery_url))
        with override_settings(ORASEC_OKTA_AUTH_SERVER="org"):
            p = providers.get("okta")
            self.assertEqual(("https://example.okta.com", "https://example.okta.com/.well-known/openid-configuration"), (p.issuer, p.discovery_url))
        with override_settings(ORASEC_OKTA_AUTH_SERVER="aus1abc"):
            self.assertEqual("https://example.okta.com/oauth2/aus1abc", providers.get("okta").issuer)
        with override_settings(ORASEC_OKTA_DOMAIN="example.okta.com/evil?x="):
            self.assertFalse(providers.get("okta").configured)

    def test_sign_in_asks_for_groups_and_checks_the_issuer(self):
        self.discovery("https://example.okta.com/oauth2/default")
        r = self.client.get("/sso/okta/login/")
        self.assertIn("scope=openid+email+profile+groups", r["Location"])
        self.assertIn("client_id=okta-app", r["Location"])
        r = self.sign_in("okta", {"email": "alice@example.com", "email_verified": True}, "https://example.okta.com/oauth2/default", "okta-app")
        self.assertEqual(str(self.alice.pk), self.signed_in())
        self.client.logout()
        r = self.sign_in("okta", {"email": "alice@example.com"}, "https://example.okta.com", "okta-app")  # the org server's issuer
        self.assertRedirects(r, "/login", fetch_redirect_response=False)
        self.assertIsNone(self.signed_in())

    @override_settings(ORASEC_OKTA_ALLOWED_GROUP="OraSec Users")
    def test_allowed_group_and_unverified_email(self):
        self.discovery("https://example.okta.com/oauth2/default")
        iss = "https://example.okta.com/oauth2/default"
        r = self.sign_in("okta", {"email": "alice@example.com", "groups": ["Everyone"]}, iss, "okta-app")
        self.assertRedirects(r, "/login", fetch_redirect_response=False)
        r = self.sign_in("okta", {"email": "alice@example.com", "email_verified": False, "groups": ["OraSec Users"]}, iss, "okta-app")
        self.assertRedirects(r, "/login", fetch_redirect_response=False)
        r = self.sign_in("okta", {"email": "alice@example.com", "email_verified": True, "groups": ["Everyone", "OraSec Users"]}, iss, "okta-app")
        self.assertEqual(str(self.alice.pk), self.signed_in())

    def test_login_page_shows_each_provider_that_is_set_up(self):
        with override_settings(**ENTRA):
            r = self.client.get("/login")
            self.assertContains(r, "Sign in with Okta")
            self.assertContains(r, "Sign in with Microsoft")
            self.assertContains(r, "or break-glass login")
        with override_settings(ORASEC_OKTA_ENABLED=False):
            self.assertNotContains(self.client.get("/login"), "Sign in with Okta")


class GenericProviderUnchangedTests(TestCase):

    @override_settings(ORASEC_OIDC_ENABLED=True, ORASEC_OIDC_ISSUER="https://sso.example.test/application/o/orasec", ORASEC_OIDC_CLIENT_ID="orasec")
    def test_generic_provider_keeps_its_issuer_addresses_and_discovery(self):
        p = providers.get()
        self.assertEqual("https://sso.example.test/application/o/orasec/", p.issuer)  # trailing slash, as before
        self.assertEqual("https://sso.example.test/application/o/orasec/.well-known/openid-configuration", p.discovery_url)
        self.assertEqual(("openid email profile", ("groups",), ("email",)), (p.scopes, p.group_claims, p.email_claims))
        self.assertEqual("https://sso.example.test/application/o/orasec/", oidc.expected_issuer("oidc", "not-even-a-token"))
        self.assertEqual([], providers.login_buttons())

    def test_nothing_is_on_by_default(self):
        for key in ("oidc", "entra", "okta"):
            self.assertFalse(providers.is_enabled(key))
        self.assertFalse(ldap.enabled())
        from django.conf import settings  # noqa: PLC0415
        self.assertNotIn("orasec.sso.ldap.LDAPBackend", settings.AUTHENTICATION_BACKENDS)


# ---------------------------------------------------------------------------
# Active Directory
# ---------------------------------------------------------------------------
class FakeDirectory:

    """Stands in for ldap._connect: knows the service account, people and their passwords."""

    def __init__(self):
        self.binds = []
        self.people = {
            "alice": {"dn": "CN=Alice Example,OU=Staff,DC=corp,DC=example,DC=com", "password": "alice-pw",
                      "attributes": {"mail": "Alice@Example.com", "sAMAccountName": "alice", "userPrincipalName": "alice@corp.example.com",
                                     "memberOf": ["CN=OraSec Users,OU=Groups,DC=corp,DC=example,DC=com", "CN=Staff,OU=Groups,DC=corp,DC=example,DC=com"],
                                     "userAccountControl": 512}},
        }
        self.down = False

    def connect(self, user, password):
        self.binds.append(user)
        if self.down:
            msg = "connection refused"
            raise OSError(msg)
        ok = (user == LDAP["ORASEC_LDAP_BIND_DN"] and password == "svc-pw") or any(
            p["dn"] == user and p["password"] == password for p in self.people.values())
        if not ok:
            return None
        directory = self

        class Conn:
            response = []

            def search(self, base, flt, attributes=None, size_limit=0):
                self.response = [{"type": "searchResEntry", "dn": p["dn"], "attributes": p["attributes"]}
                                 for p in directory.people.values() if f"(sAMAccountName={p['attributes']['sAMAccountName']})" in flt]
                self.response.append({"type": "searchResRef", "uri": ["ldap://other.example.com"]})

            def unbind(self):
                pass
        return Conn()


@override_settings(**LDAP)
class LdapTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        U = get_user_model()
        cls.alice = U.objects.create_user("alice.example", "alice@example.com", "local-pw-not-used")
        cls.admin = U.objects.create_user("admin", "breakglass@example.com", "local-admin-pw", is_superuser=True)

    def setUp(self):
        cache.clear()
        self.directory = FakeDirectory()
        for name, value in (("_connect", self.directory.connect), ("_escape", lambda v: v.replace("(", "\\28").replace(")", "\\29").replace("*", "\\2a")),
                            ("available", lambda: True)):
            p = mock.patch.object(ldap, name, side_effect=value)
            p.start()
            self.addCleanup(p.stop)

    def test_directory_password_signs_in_the_account_with_that_email(self):
        user = authenticate(None, username="alice", password="alice-pw")  # noqa: S106
        self.assertEqual(self.alice, user)
        self.assertEqual([LDAP["ORASEC_LDAP_BIND_DN"], self.directory.people["alice"]["dn"]], self.directory.binds)

    def test_wrong_password_unknown_person_or_two_matches_are_refused(self):
        self.assertIsNone(authenticate(None, username="alice", password="wrong"))  # noqa: S106
        self.assertIsNone(authenticate(None, username="mallory", password="x"))  # noqa: S106
        # two entries answer for the same name: never guess between two people
        self.directory.people["second"] = {**self.directory.people["alice"], "dn": "CN=Other Alice,OU=Staff,DC=corp,DC=example,DC=com"}
        self.assertIsNone(authenticate(None, username="alice", password="alice-pw"))  # noqa: S106

    def test_an_empty_password_never_reaches_the_directory(self):
        for pw in ("", "   ", None):
            self.assertIsNone(ldap.LDAPBackend().authenticate(None, username="alice", password=pw))
        self.assertEqual([], self.directory.binds)

    def test_a_directory_account_called_admin_does_not_open_the_local_admin(self):
        self.directory.people["admin"] = {"dn": "CN=admin,OU=Staff,DC=corp,DC=example,DC=com", "password": "ad-admin-pw",
                                          "attributes": {"sAMAccountName": "admin", "userPrincipalName": "admin@corp.example.com", "memberOf": []}}
        self.assertIsNone(ldap.LDAPBackend().authenticate(None, username="admin", password="ad-admin-pw"))  # noqa: S106
        self.assertEqual(self.admin, authenticate(None, username="admin", password="local-admin-pw"))  # noqa: S106 - break-glass still works

    def test_disabled_directory_account_and_inactive_account_are_refused(self):
        self.directory.people["alice"]["attributes"]["userAccountControl"] = 514
        self.assertIsNone(authenticate(None, username="alice", password="alice-pw"))  # noqa: S106
        self.directory.people["alice"]["attributes"]["userAccountControl"] = 512
        get_user_model().objects.filter(pk=self.alice.pk).update(is_active=False)
        self.assertIsNone(authenticate(None, username="alice", password="alice-pw"))  # noqa: S106

    def test_allowed_group_by_name_or_dn(self):
        with override_settings(ORASEC_LDAP_ALLOWED_GROUP="orasec users"):
            self.assertEqual(self.alice, authenticate(None, username="alice", password="alice-pw"))  # noqa: S106
        with override_settings(ORASEC_LDAP_ALLOWED_GROUP="CN=OraSec Users,OU=Groups,DC=corp,DC=example,DC=com"):
            self.assertEqual(self.alice, authenticate(None, username="alice", password="alice-pw"))  # noqa: S106
        with override_settings(ORASEC_LDAP_ALLOWED_GROUP="Domain Admins"):
            self.assertIsNone(authenticate(None, username="alice", password="alice-pw"))  # noqa: S106
        self.assertEqual("OraSec Users", ldap.group_cn("CN=OraSec Users,OU=Groups,DC=corp,DC=example"))

    def test_the_login_name_is_escaped_in_the_search_filter(self):
        seen = []
        orig = self.directory.connect

        def spy(user, password):
            conn = orig(user, password)
            if conn is not None:
                inner = conn.search
                conn.search = lambda base, flt, **k: (seen.append(flt), inner(base, flt, **k))[1]
            return conn
        with mock.patch.object(ldap, "_connect", side_effect=spy):
            authenticate(None, username="*)(objectClass=*", password="x")  # noqa: S106
        self.assertIn("(sAMAccountName=\\2a\\29\\28objectClass=\\2a)", seen[0])

    def test_directory_down_plugin_off_or_not_set_up_leave_local_sign_in_working(self):
        self.directory.down = True
        self.assertIsNone(authenticate(None, username="alice", password="alice-pw"))  # noqa: S106
        self.assertEqual(self.admin, authenticate(None, username="admin", password="local-admin-pw"))  # noqa: S106
        self.directory.down = False
        self.addCleanup(cache.clear)
        registry.set_on("sso.ldap", False)
        self.assertIsNone(authenticate(None, username="alice", password="alice-pw"))  # noqa: S106
        registry.set_on("sso.ldap", True)
        with override_settings(ORASEC_LDAP_BIND_PASSWORD=""):
            self.assertFalse(ldap.configured())
            self.assertIsNone(authenticate(None, username="alice", password="alice-pw"))  # noqa: S106

    def test_plugins_page_says_what_is_missing(self):
        rows = {r["key"]: r for r in registry.snapshot()}
        self.assertTrue(rows["sso.ldap"]["active"])
        with mock.patch.object(ldap, "available", return_value=False):
            row = next(r for r in registry.snapshot() if r["key"] == "sso.ldap")
            self.assertEqual((False, "The ldap3 package is not installed on this server."), (row["available"], row["missing"]))
        with override_settings(ORASEC_LDAP_ENABLED=False):
            self.assertIn("ORASEC_LDAP_ENABLED", next(r for r in registry.snapshot() if r["key"] == "sso.ldap")["missing"])


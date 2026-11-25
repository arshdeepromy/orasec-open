import datetime

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.utils import timezone

from orasec.home import metrics
from orasec.mobile.models import MobileDevice, MobileLinkCode
from orasec.models import Engagement, Finding, Test
from unittests.orasec_test_case import OraSecTestCase, versioned_fixtures

User = get_user_model()
BASE = "/api/v2/orasec/mobile"


@versioned_fixtures
class TestMobileApi(OraSecTestCase):
    fixtures = ["orasec_testdata.json"]

    def setUp(self):
        cache.clear()
        self.admin = User.objects.get(username="admin")
        engagement = Engagement.objects.create(product_id=2, target_start=timezone.now().date(), target_end=timezone.now().date())
        test = Test.objects.create(engagement=engagement, test_type_id=120, target_start=timezone.now(), target_end=timezone.now(),
                                  title="Wazuh vulnerabilities: web-01")
        self.finding = Finding.objects.create(title="CVE-2026-0001 openssl", test=test, severity="High", verified=False,
                                              active=True, cve="CVE-2026-0001", reporter=self.admin)

    def _link(self, user=None):
        _obj, code = MobileLinkCode.create_for(user or self.admin)
        r = self.client.post(f"{BASE}/link/", {"code": code, "device_name": "Test phone", "platform": "ios"}, content_type="application/json")
        return r, code

    def _get(self, path, token, **kw):
        return self.client.get(f"{BASE}/{path}", HTTP_AUTHORIZATION=f"Bearer {token}", **kw)

    def _post(self, path, token, body):
        return self.client.post(f"{BASE}/{path}", body, content_type="application/json", HTTP_AUTHORIZATION=f"Bearer {token}")

    def test_link_code_is_single_use_and_token_is_hashed(self):
        r, code = self._link()
        self.assertEqual(201, r.status_code)
        token = r.json()["token"]
        self.assertTrue(token.startswith("osm_"))
        self.assertFalse(MobileDevice.objects.filter(token_hash=token).exists())  # only the hash is stored
        again = self.client.post(f"{BASE}/link/", {"code": code}, content_type="application/json")
        self.assertEqual(400, again.status_code)

    def test_expired_code_is_rejected(self):
        obj, code = MobileLinkCode.create_for(self.admin)
        MobileLinkCode.objects.filter(pk=obj.pk).update(expires=timezone.now() - datetime.timedelta(seconds=1))
        r = self.client.post(f"{BASE}/link/", {"code": code}, content_type="application/json")
        self.assertEqual(400, r.status_code)

    def test_user_without_org_wide_access_cannot_link(self):
        user = User.objects.get(username="user1")
        r, _ = self._link(user)
        self.assertEqual(403, r.status_code)

    def test_requires_valid_token(self):
        self.assertEqual(401, self.client.get(f"{BASE}/me/").status_code)
        self.assertEqual(401, self._get("me/", "osm_not-a-real-token").status_code)

    def test_revoked_device_is_signed_out(self):
        token = self._link()[0].json()["token"]
        self.assertEqual(200, self._get("me/", token).status_code)
        self.assertEqual(200, self._post("logout/", token, {}).status_code)
        self.assertEqual(401, self._get("me/", token).status_code)

    def test_idle_device_expires(self):
        token = self._link()[0].json()["token"]
        MobileDevice.objects.update(last_seen=timezone.now() - datetime.timedelta(days=61))
        self.assertEqual(401, self._get("me/", token).status_code)

    def test_read_endpoints(self):
        token = self._link()[0].json()["token"]
        cache.delete(metrics.CACHE_KEY)
        for path in ("me/", "dashboard/", "findings/", "findings/?kev=1", "assets/", "code/", "risks/", "compliance/", "connectors/",
                     "my-work/", "attacks/?range=7d", f"findings/{self.finding.id}/"):
            self.assertEqual(200, self._get(path, token).status_code, path)
        rows = self._get("findings/?q=openssl", token).json()["results"]
        self.assertEqual([self.finding.id], [r["id"] for r in rows])
        asset = self._get("assets/web-01/", token)
        self.assertEqual(200, asset.status_code)
        self.assertEqual(1, asset.json()["total"])

    def test_note_assign_and_close(self):
        token = self._link()[0].json()["token"]
        fid = self.finding.id
        self.assertEqual(201, self._post(f"findings/{fid}/note/", token, {"text": "looked at it"}).status_code)
        self.assertTrue(self._post(f"findings/{fid}/assign/", token, {}).json()["assigned_to_me"])
        self.assertEqual(400, self._post(f"findings/{fid}/close/", token, {}).status_code)  # a note is required
        closed = self._post(f"findings/{fid}/close/", token, {"reason": "mitigated", "note": "patched"}).json()
        self.assertFalse(closed["active"])
        self.assertTrue(closed["mitigated"])
        self.finding.refresh_from_db()
        self.assertEqual(self.admin, self.finding.mitigated_by)
        self.assertEqual(409, self._post(f"findings/{fid}/close/", token, {"note": "again"}).status_code)


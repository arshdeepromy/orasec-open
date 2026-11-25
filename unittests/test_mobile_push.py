"""Tests for the mobile app's push notifications: the API, the rules (orasec.mobile.notify) and delivery (orasec.mobile.push)."""
import datetime
import json
import tempfile
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone

from orasec.mobile import notify, push
from orasec.mobile.models import MobileDevice, MobileLinkCode, MobilePushPrefs, MobilePushSent
from orasec.models import Engagement, Finding, Test
from orasec.posture.grc_models import ChangeRequest, GovernanceException
from orasec.posture.models import AttackEvent, Connector, FindingAssignment, FindingPriority
from unittests.orasec_test_case import OraSecTestCase, versioned_fixtures

User = get_user_model()
BASE = "/api/v2/orasec/mobile"
TOKEN_A = "fcm-token-" + "a" * 40
TOKEN_B = "b" * 64
SECRET_WORDS = ("CVE-", "openssl", "web-01", "admin", "bob")


def at(hour):
    """A time today at this hour, local time."""
    return timezone.make_aware(datetime.datetime.combine(timezone.localdate(), datetime.time(hour, 0)))


class Outbox:

    """Stands in for push.send: keeps what would be sent."""

    def __init__(self, result=None):
        self.sent, self.result = [], result or push.Result(ok=True, detail="test")

    def __call__(self, kind, token, title, body, data=None, ttl=0):
        self.sent.append({"kind": kind, "token": token, "title": title, "body": body, "data": data or {}})
        return self.result

    def kinds(self):
        return [m["data"]["kind"] for m in self.sent]


@versioned_fixtures
class PushCase(OraSecTestCase):
    fixtures = ["orasec_testdata.json"]

    def setUp(self):
        cache.clear()
        self.admin = User.objects.get(username="admin")
        self.bob = User.objects.create_user("bob", "bob@example.test", "x-unused-x", is_staff=True)
        engagement = Engagement.objects.create(product_id=2, target_start=timezone.now().date(), target_end=timezone.now().date())
        self.test = Test.objects.create(engagement=engagement, test_type_id=120, target_start=timezone.now(), target_end=timezone.now(),
                                        title="Wazuh vulnerabilities: web-01")
        available = mock.patch.object(push, "configured", return_value={"fcm": True, "apns": True})
        self.addCleanup(available.stop)
        available.start()

    def finding(self, severity="Critical", **extra):
        return Finding.objects.create(title="CVE-2026-0001 openssl", test=self.test, severity=severity, verified=False, active=True,
                                      cve="CVE-2026-0001", reporter=self.admin, **extra)

    def link(self, user=None, platform="android"):
        _obj, code = MobileLinkCode.create_for(user or self.admin)
        r = self.client.post(f"{BASE}/link/", {"code": code, "device_name": "Test phone", "platform": platform}, content_type="application/json")
        return r.json()["token"]

    def post(self, path, token, body=None):
        return self.client.post(f"{BASE}/{path}", body or {}, content_type="application/json", HTTP_AUTHORIZATION=f"Bearer {token}")

    def get(self, path, token):
        return self.client.get(f"{BASE}/{path}", HTTP_AUTHORIZATION=f"Bearer {token}")

    def phone(self, user=None, platform="android", push_token=TOKEN_A):
        token = self.link(user, platform)
        self.assertEqual(200, self.post("push/register/", token, {"token": push_token}).status_code)
        return token


class PushApiTests(PushCase):
    def test_register_stores_the_address_and_creates_the_settings(self):
        token = self.link()
        state = self.get("push/settings/", token).json()
        self.assertEqual({"available": True, "registered": False,
                          "settings": {"critical": True, "approvals": True, "alerts": True, "overdue": True}}, state)
        r = self.post("push/register/", token, {"token": TOKEN_A})
        self.assertEqual(200, r.status_code)
        self.assertTrue(r.json()["registered"])
        device = MobileDevice.objects.get(user=self.admin)
        self.assertEqual((TOKEN_A, "fcm"), (device.push_token, device.push_kind))
        self.assertIsNotNone(device.push_updated)
        self.assertTrue(MobilePushPrefs.objects.filter(user=self.admin).exists())
        self.assertTrue(self.get("me/", token).json()["push"]["available"])

    def test_bad_addresses_are_refused(self):
        token = self.link()
        for bad in ("", "short", "x" * 513, "has space " + "a" * 30, "<script>" + "a" * 30, None, 12345):
            self.assertEqual(400, self.post("push/register/", token, {"token": bad}).status_code, bad)
        self.assertEqual("", MobileDevice.objects.get(user=self.admin).push_token)

    def test_browser_preview_has_no_notifications(self):
        token = self.link(platform="web")
        self.assertEqual(400, self.post("push/register/", token, {"token": TOKEN_A}).status_code)
        self.assertFalse(self.get("push/settings/", token).json()["available"])

    def test_needs_a_linked_phone(self):
        for path in ("push/register/", "push/unregister/", "push/settings/", "push/test/"):
            self.assertEqual(401, self.client.post(f"{BASE}/{path}", {}, content_type="application/json").status_code, path)
            self.assertEqual(401, self.post(path, "osm_wrong").status_code, path)

    def test_an_address_belongs_to_one_linked_phone_only(self):
        first = self.phone()
        second = self.phone()  # the same install, linked again
        tokens = list(MobileDevice.objects.filter(user=self.admin).order_by("id").values_list("push_token", flat=True))
        self.assertEqual(["", TOKEN_A], tokens)
        self.assertFalse(self.get("push/settings/", first).json()["registered"])
        self.assertTrue(self.get("push/settings/", second).json()["registered"])

    def test_unregister_sign_out_and_revoke_remove_the_address(self):
        token = self.phone()
        self.assertFalse(self.post("push/unregister/", token).json()["registered"])
        self.post("push/register/", token, {"token": TOKEN_A})
        self.post("logout/", token)
        self.assertEqual("", MobileDevice.objects.get(user=self.admin).push_token)
        self.phone()
        device = MobileDevice.objects.filter(user=self.admin, revoked_at=None).get()
        self.client.force_login(self.admin)
        self.client.post(f"/orasec/mobile/devices/{device.id}/revoke/")
        device.refresh_from_db()
        self.assertIsNotNone(device.revoked_at)
        self.assertEqual("", device.push_token)

    def test_settings_are_per_person_and_only_take_true_or_false(self):
        token = self.phone()
        r = self.post("push/settings/", token, {"overdue": False, "alerts": "no", "nonsense": True})
        self.assertEqual({"critical": True, "approvals": True, "alerts": True, "overdue": False}, r.json()["settings"])
        other = self.phone(self.bob, push_token=TOKEN_B)
        self.assertTrue(self.get("push/settings/", other).json()["settings"]["overdue"])

    def test_test_notification(self):
        token = self.link()
        self.assertEqual(400, self.post("push/test/", token).status_code)  # not switched on yet
        self.post("push/register/", token, {"token": TOKEN_A})
        box = Outbox()
        with mock.patch.object(push, "send", box):
            for _ in range(2):  # one call was used above
                self.assertTrue(self.post("push/test/", token).json()["ok"])
            self.assertEqual(429, self.post("push/test/", token).status_code)
        self.assertEqual(("fcm", TOKEN_A, "test"), (box.sent[0]["kind"], box.sent[0]["token"], box.sent[0]["data"]["kind"]))

    def test_test_notification_reports_failure_without_details(self):
        token = self.phone()
        with mock.patch.object(push, "send", Outbox(push.Result(ok=False, detail="fcm 500 secret-internal-text"))):
            body = self.post("push/test/", token).json()
        self.assertFalse(body["ok"])
        self.assertNotIn("secret-internal-text", json.dumps(body))


class NotifyRuleTests(PushCase):
    def run_at(self, hour=10, box=None):
        box = box or Outbox()
        cache.delete("orasec:mobile:push:run")
        return notify.run(now=at(hour), send=box), box

    def test_nothing_that_was_already_there_is_announced(self):
        self.finding()
        self.finding("High", known_exploited=True)
        self.phone()
        stats, box = self.run_at()
        self.assertEqual([], box.sent)
        self.assertEqual(1, stats["people"])

    def test_new_critical_finding_is_announced_once_without_details(self):
        self.phone()
        self.finding()
        _stats, box = self.run_at(hour=2)  # critical findings are announced at night too
        self.assertEqual(["critical"], box.kinds())
        message = box.sent[0]
        self.assertEqual("A new critical or known-exploited finding needs attention.", message["body"])
        self.assertEqual({"kind": "critical", "path": "/vulns", "count": 1}, message["data"])
        for word in SECRET_WORDS:
            self.assertNotIn(word, message["title"] + message["body"] + json.dumps(message["data"]))
        self.assertEqual([], self.run_at()[1].sent)

    def test_known_exploited_flag_on_an_old_finding_counts_as_new(self):
        finding = self.finding("High")
        self.phone()
        self.assertEqual([], self.run_at()[1].sent)
        Finding.objects.filter(pk=finding.pk).update(known_exploited=True)
        self.finding()
        _stats, box = self.run_at()
        self.assertEqual("2 new critical or known-exploited findings need attention.", box.sent[0]["body"])

    def test_closed_duplicate_and_lower_findings_are_not_announced(self):
        self.phone()
        self.finding("High")
        self.finding(duplicate=True)
        Finding.objects.filter(pk=self.finding().pk).update(active=False)
        self.assertEqual([], self.run_at()[1].sent)

    def test_every_phone_of_a_person_gets_it_and_a_switched_off_kind_gets_nothing(self):
        self.phone()
        self.phone(platform="ios", push_token=TOKEN_B)
        bob_phone = self.phone(self.bob, push_token="c" * 40)
        self.post("push/settings/", bob_phone, {"critical": False})
        self.finding()
        _stats, box = self.run_at()
        self.assertEqual({("fcm", TOKEN_A), ("apns", TOKEN_B)}, {(m["kind"], m["token"]) for m in box.sent})

    def test_a_kind_switched_back_on_starts_from_now(self):
        token = self.phone()
        self.post("push/settings/", token, {"critical": False})
        self.finding()
        self.assertEqual([], self.run_at()[1].sent)
        self.post("push/settings/", token, {"critical": True})
        self.assertEqual([], self.run_at()[1].sent)
        self.finding()
        self.assertEqual(["critical"], self.run_at()[1].kinds())

    def test_notifications_switched_back_on_start_from_now(self):
        token = self.phone()
        self.post("push/unregister/", token)
        self.finding()
        self.assertEqual(0, self.run_at()[0]["people"])
        self.assertEqual(200, self.post("push/register/", token, {"token": TOKEN_A}).status_code)
        self.assertEqual([], self.run_at()[1].sent)
        self.finding()
        self.assertEqual(["critical"], self.run_at()[1].kinds())

    def test_a_second_phone_does_not_hide_what_the_person_has_not_been_told_yet(self):
        self.phone()
        self.finding()
        self.phone(push_token=TOKEN_B)
        self.assertEqual({"critical"}, set(self.run_at()[1].kinds()))

    def test_only_active_people_with_access_and_a_linked_phone(self):
        self.phone(self.bob)
        self.finding()
        User.objects.filter(pk=self.bob.pk).update(is_staff=False)  # no organisation-wide access any more
        self.assertEqual([], self.run_at()[1].sent)
        User.objects.filter(pk=self.bob.pk).update(is_staff=True, is_active=False)
        self.assertEqual([], self.run_at()[1].sent)
        User.objects.filter(pk=self.bob.pk).update(is_active=True)
        MobileDevice.objects.filter(user=self.bob).update(revoked_at=timezone.now())
        self.assertEqual([], self.run_at()[1].sent)

    def test_a_phone_not_used_for_60_days_gets_nothing_and_loses_its_address(self):
        self.phone()
        self.finding()
        MobileDevice.objects.filter(user=self.admin).update(last_seen=timezone.now() - datetime.timedelta(days=61))
        stats, box = self.run_at()
        self.assertEqual((0, []), (stats["people"], box.sent))
        notify.prune(timezone.now())
        self.assertEqual("", MobileDevice.objects.get(user=self.admin).push_token)

    def test_approvals_go_only_to_the_person_who_may_decide_and_only_by_day(self):
        self.phone()
        self.phone(self.bob, push_token=TOKEN_B)
        ChangeRequest.objects.create(title="Rotate the keys", reason="r", impact="i", requested_by=self.admin)
        self.assertEqual([], self.run_at(hour=23)[1].sent)
        _stats, box = self.run_at(hour=9)
        self.assertEqual([(TOKEN_B, "approvals")], [(m["token"], m["data"]["kind"]) for m in box.sent])  # not the requester
        self.assertEqual("1 item is waiting for your approval or review. Open OraSec on the web to decide.", box.sent[0]["body"])
        self.assertNotIn("Rotate", box.sent[0]["body"])
        self.assertEqual([], self.run_at(hour=9)[1].sent)

    def test_exception_waiting_for_a_decision(self):
        self.phone(self.bob)
        GovernanceException.objects.create(title="Old TLS on the printer", description="d", requested_by=self.admin,
                                           expiry=timezone.localdate() + datetime.timedelta(days=30))
        self.assertIn(self.run_at(hour=9)[1].kinds(), (["approvals"], []))  # depends on how many approvals the rule asks for
        refs = notify.approval_refs(self.bob)
        self.assertEqual(refs, set(MobilePushSent.objects.filter(user=self.bob, kind="approvals").values_list("ref", flat=True)))
        self.assertEqual(set(), notify.approval_refs(self.admin))  # the requester never decides their own

    def test_alerts_only_high_level_recent_and_not_blocked(self):
        self.phone()
        now = at(10)

        def event(n, action, detail, age_hours=1):
            AttackEvent.objects.create(source="wazuh", event_id=f"e{n}", occurred_at=now - datetime.timedelta(hours=age_hours),
                                       action=action, rule="sshd: brute force", detail=detail, target="web-01")
        event(1, "alert", "level 5 authentication_failed")
        event(2, "block", "level 15 security alert firewall_drop")
        event(3, "alert", "level 14 security alert attack", age_hours=30)
        event(6, "alert", "level 15 attack")  # high, but not a break-in attempt, break-in or ransomware: not marked
        self.assertEqual([], self.run_at()[1].sent)
        event(4, "alert", "level 12 security alert attack,exploit_attempt")
        event(5, "allow", "")
        _stats, box = self.run_at(hour=10)
        self.assertEqual(["alerts"], box.kinds())
        self.assertEqual("2 security alerts came in: suspected break-ins or ransomware.", box.sent[0]["body"])
        self.assertNotIn("sshd", box.sent[0]["body"])

    def test_only_marked_security_alerts_are_announced(self):
        self.phone()
        now = at(10)

        def event(n, detail, action="alert"):
            AttackEvent.objects.create(source="wazuh", event_id=f"s{n}", occurred_at=now - datetime.timedelta(hours=1), action=action,
                                       rule="Possible kernel level rootkit", detail=detail, target="srv1")
        event(1, "level 9 sca")  # below the level and not marked
        event(2, "level 5 sshd,authentication_failed")
        self.assertEqual([], self.run_at()[1].sent)
        event(3, "level 12 syslog,authentication_failed")  # high but not marked: not announced
        event(4, "level 7 security alert ossec,syscheck")  # a file that gives access was changed
        event(5, "level 15 security alert ossec", action="block")  # blocked traffic is never announced
        _stats, box = self.run_at(hour=10)
        self.assertEqual(["alerts"], box.kinds())
        self.assertEqual("A security alert came in: a suspected break-in or ransomware.", box.sent[0]["body"])
        self.assertNotIn("rootkit", box.sent[0]["body"])
        self.assertEqual("security alert", notify.SECURITY_ALERT)  # the words orasec.posture.geo.SECURITY_ALERT writes

    def test_overdue_findings_by_day_with_the_persons_own_count(self):
        self.phone()
        yesterday = timezone.localdate() - datetime.timedelta(days=1)
        mine, other = self.finding("High"), self.finding("Medium")
        for f in (mine, other):
            FindingPriority.objects.update_or_create(finding=f, defaults={"due_date": yesterday})
        FindingAssignment.objects.create(finding=mine, assignee=self.admin)
        self.assertEqual([], self.run_at(hour=6)[1].sent)
        _stats, box = self.run_at(hour=8)
        self.assertEqual(["overdue"], box.kinds())
        self.assertEqual("2 findings passed their fix-by date. 1 of them is assigned to you.", box.sent[0]["body"])
        self.assertEqual("/my-work", box.sent[0]["data"]["path"])

    def test_a_failed_delivery_is_tried_again_and_a_dead_address_is_removed(self):
        self.phone()
        self.finding()
        self.assertEqual(0, self.run_at(box=Outbox(push.Result(ok=False, detail="fcm 500")))[0]["sent"])
        self.assertEqual(TOKEN_A, MobileDevice.objects.get(user=self.admin).push_token)
        self.assertEqual(1, self.run_at()[0]["sent"])  # the next pass delivers it
        self.finding()
        self.run_at(box=Outbox(push.Result(ok=False, detail="fcm 404", gone=True)))
        self.assertEqual("", MobileDevice.objects.get(user=self.admin).push_token)

    def test_nothing_runs_when_push_is_not_set_up_or_another_pass_is_running(self):
        self.phone()
        self.finding()
        with mock.patch.object(push, "configured", return_value={"fcm": False, "apns": False}):
            self.assertEqual("not set up", self.run_at()[0]["skipped"])
        cache.add("orasec:mobile:push:run", 1, 60)
        box = Outbox()
        self.assertEqual("another pass is running", notify.run(now=at(10), send=box)["skipped"])
        self.assertEqual([], box.sent)

    def test_wording(self):
        self.assertEqual("3 items are waiting for your approval or review. Open OraSec on the web to decide.",
                         notify.build("approvals", {"a", "b", "c"}).body)
        self.assertEqual("1 finding passed its fix-by date. It is assigned to you.", notify.build("overdue", {"o1"}, mine=1).body)
        self.assertEqual("5 findings passed their fix-by date. 2 of them are assigned to you.",
                         notify.build("overdue", set("abcde"), mine=2).body)
        self.assertEqual(0, notify.alert_level("no level here"))


class InstantAlertTests(PushCase):

    """A new security alert reaches the phone within seconds, not at the next 5-minute pass."""

    def run_at(self, hour=10, box=None):
        box = box or Outbox()
        cache.delete("orasec:mobile:push:run")
        return notify.run(now=at(hour), send=box), box

    def alert(self, n=1):
        return AttackEvent.objects.create(source="wazuh", event_id=f"i{n}", occurred_at=at(10) - datetime.timedelta(minutes=1), action="alert",
                                          rule="Ransomware: canary file changed", detail="level 13 security alert orasec,ransomware", target="srv1")

    def test_the_alerts_pass_sends_only_alerts(self):
        self.phone()
        self.finding()  # a new critical finding waits for the 5-minute pass
        self.alert()
        box = Outbox()
        cache.delete("orasec:mobile:push:run")
        notify.run(now=at(10), send=box, kinds=("alerts",))
        self.assertEqual(["alerts"], box.kinds())
        _stats, later = self.run_at(hour=10)  # the 5-minute pass: the critical finding, not the alert again
        self.assertEqual(["critical"], later.kinds())

    def test_alerts_soon_queues_one_pass_for_alerts_arriving_together(self):
        from orasec.mobile import tasks  # noqa: PLC0415
        with mock.patch.object(tasks.mobile_push_alerts, "apply_async") as queued:
            tasks.alerts_soon()
            tasks.alerts_soon()
            tasks.alerts_soon()
        queued.assert_called_once_with(countdown=tasks.SOON_DELAY)

    def test_alerts_soon_never_breaks_the_caller(self):
        from orasec.mobile import tasks  # noqa: PLC0415
        with mock.patch.object(tasks.mobile_push_alerts, "apply_async", side_effect=RuntimeError("broker down")):
            tasks.alerts_soon()  # no exception: the 5-minute pass still sends it

    def test_the_webhook_starts_the_alerts_pass_only_for_a_newly_stored_alert(self):
        from orasec.mobile import tasks  # noqa: PLC0415
        connector = Connector.objects.create(name="Wazuh t", kind="wazuh", base_url="https://wazuh.test:55000")
        connector.set_secrets({"webhook_token": "tok-for-test"})
        connector.save()
        doc = {"id": "1795.1", "timestamp": "2026-11-20T04:30:00.000+0000", "agent": {"id": "001", "name": "srv1"},
               "rule": {"level": 13, "groups": ["ransomware"], "description": "OraSec: canary file changed", "id": "100520"}}
        noise = dict(doc, id="1795.2", rule={"level": 3, "groups": ["syslog"], "description": "small", "id": "1"})
        with mock.patch.object(tasks, "alerts_soon") as soon:
            for body in (doc, doc, noise):  # new, the same again, not a security alert
                self.client.post(reverse("orasec_wazuh_alert"), data=json.dumps(body), content_type="application/json",
                                 HTTP_AUTHORIZATION="Bearer tok-for-test")
        self.assertEqual(1, soon.call_count)


class DeliveryTests(OraSecTestCase):

    """orasec.mobile.push with the network replaced: what is sent to Google and Apple, and how answers are read."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.dir = tempfile.TemporaryDirectory()
        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
        ec_key = ec.generate_private_key(ec.SECP256R1()).private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
        cls.fcm = Path(cls.dir.name) / "fcm.json"
        cls.fcm.write_text(json.dumps({"client_email": "svc@test-project.example", "private_key": rsa_key, "project_id": "test-project"}))
        cls.apns = Path(cls.dir.name) / "apns.p8"
        cls.apns.write_text(ec_key)
        cls.settings = override_settings(ORASEC_PUSH_ENABLED=True, ORASEC_PUSH_FCM_CREDENTIALS=str(cls.fcm),
                                         ORASEC_PUSH_APNS_KEY_PATH=str(cls.apns), ORASEC_PUSH_APNS_KEY_ID="KEYID12345",
                                         ORASEC_PUSH_APNS_TEAM_ID="TEAMID1234", ORASEC_PUSH_APNS_SANDBOX=False)
        cls.settings.enable()

    @classmethod
    def tearDownClass(cls):
        cls.settings.disable()
        cls.dir.cleanup()
        super().tearDownClass()

    def setUp(self):
        push._cache.clear()

    @staticmethod
    def answer(status, body=None, text=""):
        r = mock.Mock(status_code=status, text=text or json.dumps(body or {}))
        r.json.return_value = body or {}
        return r

    def test_no_push_setting_is_named_like_a_docker_secret(self):
        # docker/secret-file-loader.sh (uwsgi and celery start through it) turns every ORASEC_*_FILE variable into the
        # content of the file and removes the variable. A path setting with such a name is empty on a real server.
        from django.conf import settings  # noqa: PLC0415
        names = [name for name in dir(settings) if name.startswith("ORASEC_PUSH_")]
        self.assertIn("ORASEC_PUSH_APNS_KEY_PATH", names)
        self.assertEqual([], [name for name in names if name.endswith("_FILE")])

    def test_configured_needs_the_switch_and_the_files(self):
        self.assertEqual({"fcm": True, "apns": True}, push.configured())
        with override_settings(ORASEC_PUSH_ENABLED=False):
            self.assertEqual({"fcm": False, "apns": False}, push.configured())
            self.assertFalse(push.send("fcm", TOKEN_A, "t", "b").ok)
        with override_settings(ORASEC_PUSH_FCM_CREDENTIALS="/nowhere/fcm.json", ORASEC_PUSH_APNS_KEY_ID=""):
            self.assertEqual({"fcm": False, "apns": False}, push.configured())

    def test_android_message(self):
        token_answer = self.answer(200, {"access_token": "ya29.test", "expires_in": 3600})
        with mock.patch.object(push.httpx, "post", side_effect=[token_answer, self.answer(200, {"name": "x"}), self.answer(200)]) as post:
            self.assertTrue(push.send("fcm", TOKEN_A, "New critical findings", "2 new ...", {"kind": "critical", "count": 2}).ok)
            self.assertTrue(push.send("fcm", TOKEN_A, "t", "b").ok)  # the access token is reused
        self.assertEqual(3, post.call_count)
        url, sent = post.call_args_list[1].args[0], post.call_args_list[1].kwargs
        self.assertEqual("https://fcm.googleapis.com/v1/projects/test-project/messages:send", url)
        self.assertEqual("Bearer ya29.test", sent["headers"]["Authorization"])
        message = sent["json"]["message"]
        self.assertEqual(TOKEN_A, message["token"])
        self.assertEqual({"kind": "critical", "count": "2"}, message["data"])  # data values are text
        self.assertEqual(("orasec", "PRIVATE"), (message["android"]["notification"]["channel_id"],
                                                 message["android"]["notification"]["visibility"]))

    def test_android_address_that_is_gone(self):
        with mock.patch.object(push.httpx, "post", side_effect=[self.answer(200, {"access_token": "t"}),
                                                                self.answer(404, text='{"error":{"status":"UNREGISTERED"}}')]):
            result = push.send("fcm", TOKEN_A, "t", "b")
        self.assertEqual((False, True), (result.ok, result.gone))

    def test_iphone_message_and_the_other_apple_service_for_development_builds(self):
        client = mock.MagicMock()
        client.__enter__.return_value = client
        client.post.side_effect = [self.answer(400, {"reason": "BadDeviceToken"}), self.answer(200)]
        with mock.patch.object(push.httpx, "Client", return_value=client) as make:
            result = push.send("apns", TOKEN_B, "Security alert", "1 alert", {"kind": "alerts", "path": "/attacks"})
        self.assertEqual((True, "apns-sandbox"), (result.ok, result.detail))
        self.assertTrue(make.call_args.kwargs["http2"])
        first, second = client.post.call_args_list
        self.assertEqual(f"https://api.push.apple.com/3/device/{TOKEN_B}", first.args[0])
        self.assertEqual(f"https://api.sandbox.push.apple.com/3/device/{TOKEN_B}", second.args[0])
        headers, payload = first.kwargs["headers"], first.kwargs["json"]
        self.assertEqual(("nz.co.oraflows.orasec", "alert"), (headers["apns-topic"], headers["apns-push-type"]))
        self.assertTrue(headers["authorization"].startswith("bearer ey"))
        self.assertEqual({"title": "Security alert", "body": "1 alert"}, payload["aps"]["alert"])
        self.assertEqual("/attacks", payload["path"])

    def test_iphone_address_that_is_gone(self):
        client = mock.MagicMock()
        client.__enter__.return_value = client
        client.post.return_value = self.answer(410, {"reason": "Unregistered"})
        with mock.patch.object(push.httpx, "Client", return_value=client):
            result = push.send("apns", TOKEN_B, "t", "b")
        self.assertEqual((False, True), (result.ok, result.gone))

    def test_send_never_raises_and_keeps_secrets_out_of_the_result(self):
        with mock.patch.object(push.httpx, "post", side_effect=OSError("boom with private text")):
            result = push.send("fcm", TOKEN_A, "t", "b")
        self.assertEqual((False, "error: OSError"), (result.ok, result.detail))
        self.assertFalse(push.send("fcm", "", "t", "b").ok)
        self.assertFalse(push.send("web", TOKEN_A, "t", "b").ok)

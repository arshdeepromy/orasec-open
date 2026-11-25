"""Security alerts: a suspected hack or unauthorised action from Wazuh, never a vulnerability."""
import datetime
from unittest import mock

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.urls import reverse
from django.utils import timezone

from orasec.mobile.models import MobileLinkCode
from orasec.posture import geo, security_alerts
from orasec.posture.connectors import wazuh
from orasec.posture.connectors.base import ConnectorError
from orasec.posture.models import AttackEvent, Connector
from unittests.orasec_test_case import OraSecTestCase, versioned_fixtures

User = get_user_model()
NOW = datetime.datetime(2026, 11, 20, 5, 0, tzinfo=datetime.UTC)


def hit(doc_id, level, groups, description, *, agent="srv-01", data=None, syscheck=None, timestamp="2026-11-20T04:30:00.000+0000"):
    source = {"timestamp": timestamp, "agent": {"name": agent}, "rule": {"level": level, "groups": groups, "description": description, "id": "1"}}
    if data:
        source["data"] = data
    if syscheck:
        source["syscheck"] = syscheck
    return {"_id": doc_id, "_source": source}


ROOTKIT = hit("r1", 11, ["ossec", "rootcheck"], "Possible kernel level rootkit", data={"title": "Process '14895' hidden from /proc."})
WRONG_PASSWORD = hit("p1", 10, ["syslog", "access_control", "authentication_failed"], "syslog: User missed the password more than one time",
                     agent="dev-box", data={"srcip": "192.168.20.95"})
BRUTE_FORCE = hit("b1", 10, ["sshd", "authentication_failures"], "sshd: brute force trying to get access to the system",
                  agent="lms", data={"srcip": "8.8.8.8", "dstport": "22"})
SUDOERS = hit("f1", 7, ["ossec", "syscheck", "syscheck_entry_modified"], "Integrity checksum changed.",
              syscheck={"path": "/etc/sudoers.d/90-admins", "event": "modified"})
NEW_USER = hit("u1", 8, ["syslog", "adduser"], "New user added to the system.")


class TestAlertRule(OraSecTestCase):

    """The rule itself: what counts as a security alert."""

    def test_query_never_takes_vulnerabilities_checks_or_health(self):
        q = wazuh.security_alert_query({}, NOW)
        self.assertEqual([{"terms": {"rule.groups": ["vulnerability-detector", "sca", "service_availability", "low_diskspace"]}}], q["bool"]["must_not"])
        self.assertEqual({"range": {"timestamp": {"gte": "2026-11-20T05:00:00Z"}}}, q["bool"]["filter"][0])
        wanted = q["bool"]["filter"][1]["bool"]
        self.assertEqual(1, wanted["minimum_should_match"])
        self.assertEqual({"bool": {"filter": [{"terms": {"rule.groups": list(wazuh.ALERT_KINDS[0][1])}}, {"range": {"rule.level": {"gte": 10}}}]}},
                         wanted["should"][0])
        self.assertEqual(len(wazuh.ALERT_KINDS) + 1, len(wanted["should"]))  # each kind, files that give access
        self.assertNotIn({"range": {"rule.level": {"gte": 10}}}, wanted["should"])  # no "any alert at level 10" any more

    def test_query_start_is_given_in_utc(self):
        local = datetime.datetime(2026, 11, 20, 18, 0, tzinfo=datetime.timezone(datetime.timedelta(hours=13)))
        self.assertEqual("2026-11-20T05:00:00Z", wazuh.security_alert_query({}, local)["bool"]["filter"][0]["range"]["timestamp"]["gte"])

    def test_options_change_the_rule_without_a_release(self):
        q = wazuh.security_alert_query({"alert_kinds": [["Ransomware", ["ransomware"], 12]], "alert_watch_paths": [], "alert_exclude_groups": []}, NOW)
        self.assertEqual([{"bool": {"filter": [{"terms": {"rule.groups": ["ransomware"]}}, {"range": {"rule.level": {"gte": 12}}}]}}],
                         q["bool"]["filter"][1]["bool"]["should"])
        self.assertNotIn("must_not", q["bool"])

    def test_one_alert_is_judged_like_the_query(self):
        yes = [(11, ["ossec", "rootcheck"], ""), (10, ["sshd", "authentication_failures"], ""), (10, ["syslog", "authentication_failed"], ""),
               (12, ["pam", "authentication_success"], ""), (8, ["syslog", "adduser"], ""), (3, ["ossec", "ransomware"], ""),
               (10, ["ossec", "syscheck", "orasec_access_change"], ""), (12, ["web", "attack"], ""),
               (7, ["ossec", "syscheck"], "/home/alex/.ssh/authorized_keys"), (7, ["syscheck"], "/etc/ssh/sshd_config.d/00-cis.conf"),
               (7, ["syscheck"], "/etc/cron.d/backup")]
        no = [(13, ["vulnerability-detector"], ""), (9, ["sca"], ""), (12, ["syslog", "linuxkernel", "service_availability"], ""),
              (7, ["ossec", "low_diskspace"], ""), (3, ["syslog", "adduser"], ""), (7, ["syscheck"], "/etc/hosts"),
              (7, ["syscheck"], "/etc/sudoers.d/README.dpkg-new"), (7, ["syslog", "dpkg"], "/etc/sudoers"), (5, ["sshd", "authentication_failed"], ""),
              (10, ["pfsense", "multiple_blocks"], ""), (12, ["syslog", "something_else"], ""), (7, ["ossec", "rootcheck"], ""),
              (3, ["pam", "authentication_success"], ""), (10, ["web", "web_scan"], "")]
        for level, groups, path in yes:
            self.assertTrue(wazuh.is_security_alert({}, level, groups, path), (level, groups, path))
        for level, groups, path in no:
            self.assertFalse(wazuh.is_security_alert({}, level, groups, path), (level, groups, path))

    def test_alert_on_a_machine_becomes_an_event_without_an_address(self):
        e = wazuh.security_alert_event(ROOTKIT)
        self.assertEqual(("r1", "srv-01", "", "alert", True), (e["event_id"], e["target"], e["src_ip"], e["action"], e["host_alert"]))
        self.assertEqual("Break-in: Possible kernel level rootkit: Process '14895' hidden from /proc.", e["rule"])
        self.assertEqual("level 11 security alert ossec,rootcheck", e["detail"])
        self.assertEqual(datetime.datetime(2026, 11, 20, 4, 30, tzinfo=datetime.UTC), e["occurred_at"])

    def test_file_change_names_the_file_and_is_marked_below_level_10(self):
        e = wazuh.security_alert_event(SUDOERS)
        self.assertEqual("Break-in: Integrity checksum changed.: /etc/sudoers.d/90-admins", e["rule"])
        self.assertTrue(e["detail"].startswith("level 7 security alert "))

    def test_alert_sent_by_syslog_names_the_sender_not_the_manager(self):
        h = hit("s1", 10, ["pfsense", "multiple_blocks"], "Multiple pfSense firewall blocks events from same source.", agent="wazuh.manager",
                data={"srcip": "10.20.2.10"})
        h["_source"]["agent"]["id"] = "000"
        h["_source"]["predecoder"] = {"hostname": "OPNsense.internal"}
        self.assertEqual("OPNsense.internal", wazuh.security_alert_event(h)["target"])
        del h["_source"]["predecoder"]
        self.assertEqual("wazuh.manager", wazuh.security_alert_event(h)["target"])

    def test_the_mark_is_the_one_the_phone_notifications_look_for(self):
        self.assertEqual("security alert", geo.SECURITY_ALERT)  # orasec.mobile.notify matches these words

    def test_attack_map_text_is_only_marked_for_security_alerts(self):
        self.assertEqual("level 5 sshd,authentication_failed", wazuh.alert_detail({}, {"level": 5, "groups": ["sshd", "authentication_failed"]}))
        self.assertEqual("level 10 sshd", wazuh.alert_detail({}, {"level": 10, "groups": ["sshd"]}))  # high, but not one of the kinds
        self.assertEqual("level 10 security alert sshd,authentication_failures",
                         wazuh.alert_detail({}, {"level": 10, "groups": ["sshd", "authentication_failures"]}))


class TestConnectorRead(OraSecTestCase):
    def setUp(self):
        self.connector = Connector.objects.create(name="Wazuh t", kind="wazuh", base_url="https://wazuh.test:55000",
                                                  options={"indexer_url": "https://indexer.test:9200"})

    def test_one_search_with_the_rule_and_no_server_login(self):
        c = wazuh.WazuhConnector(self.connector)
        with mock.patch.object(wazuh.Http, "request", autospec=True, return_value={"hits": {"hits": [ROOTKIT, BRUTE_FORCE]}}) as request:
            events = c.collect_security_alerts(NOW)
        self.assertEqual(1, request.call_count)
        _http, method, path = request.call_args.args
        self.assertEqual(("POST", "/wazuh-alerts-*/_search"), (method, path))
        body = request.call_args.kwargs["json"]
        self.assertEqual(wazuh.security_alert_query(self.connector.options, NOW), body["query"])
        self.assertEqual([{"timestamp": "desc"}], body["sort"])
        self.assertEqual(["r1", "b1"], [e["event_id"] for e in events])
        self.assertEqual(22, events[1]["dst_port"])

    def test_connector_without_indexer_address_says_so(self):
        self.connector.options = {}
        with self.assertRaises(ConnectorError):
            wazuh.WazuhConnector(self.connector).collect_security_alerts(NOW)


class TestStore(OraSecTestCase):
    def test_host_alerts_are_kept_without_a_public_address(self):
        events = [wazuh.security_alert_event(h) for h in (ROOTKIT, WRONG_PASSWORD, BRUTE_FORCE)]
        self.assertEqual(3, geo.store_events("wazuh", events))
        rows = {e.event_id: e for e in AttackEvent.objects.filter(source="wazuh")}
        self.assertIsNone(rows["r1"].src_ip)
        self.assertEqual(("192.168.20.95", ""), (rows["p1"].src_ip, rows["p1"].src_country))  # inside the network: no country looked up
        self.assertEqual("8.8.8.8", rows["b1"].src_ip)
        self.assertEqual(0, geo.store_events("wazuh", events))  # read twice, stored once

    def test_a_host_name_in_the_address_field_does_not_lose_the_alert(self):
        e = wazuh.security_alert_event(hit("h1", 10, ["sshd"], "sshd: something", data={"srcip": "gateway.local"}))
        self.assertEqual(1, geo.store_events("wazuh", [e]))
        self.assertIsNone(AttackEvent.objects.get(event_id="h1").src_ip)

    def test_blocked_traffic_from_inside_is_still_dropped(self):
        now = timezone.now()
        self.assertEqual(0, geo.store_events("unifi", [{"event_id": "x1", "occurred_at": now, "src_ip": "192.168.10.20", "action": "block"},
                                                       {"event_id": "x2", "occurred_at": now, "src_ip": "", "action": "block"}]))


class TestFiveMinuteRead(OraSecTestCase):
    def setUp(self):
        cache.delete(security_alerts.STATE_KEY)
        self.connector = Connector.objects.create(name="Wazuh t", kind="wazuh", base_url="https://wazuh.test:55000",
                                                  options={"indexer_url": "https://indexer.test:9200"})
        self.addCleanup(cache.delete, security_alerts.STATE_KEY)

    def _read(self, now, hits=(), error=None):
        events = [wazuh.security_alert_event(h) for h in hits]
        with mock.patch.object(wazuh.WazuhConnector, "collect_security_alerts", autospec=True,
                               side_effect=error, return_value=None if error else events) as collect:
            state = security_alerts.refresh(now)
        return state[str(self.connector.id)], collect

    def test_first_read_goes_back_24_hours_and_later_reads_overlap(self):
        st, collect = self._read(NOW, [ROOTKIT, NEW_USER])
        self.assertEqual(NOW - datetime.timedelta(hours=24), collect.call_args.args[1])
        self.assertEqual((True, 2, 2), (st["ok"], st["read"], st["new"]))
        later = NOW + datetime.timedelta(minutes=5)
        st, collect = self._read(later, [ROOTKIT])
        self.assertEqual(NOW - datetime.timedelta(minutes=10), collect.call_args.args[1])
        self.assertEqual((1, 0), (st["read"], st["new"]))
        self.assertEqual(2, AttackEvent.objects.filter(source="wazuh").count())

    def test_a_failed_read_is_remembered_and_the_gap_is_read_afterwards(self):
        self._read(NOW)
        failed, _ = self._read(NOW + datetime.timedelta(minutes=5), error=ConnectorError("POST /wazuh-alerts-*/_search: HTTP 403"))
        self.assertFalse(failed["ok"])
        self.assertEqual((NOW + datetime.timedelta(minutes=5)).isoformat(), failed["failing_since"])
        still, _ = self._read(NOW + datetime.timedelta(minutes=10), error=ConnectorError("HTTP 403"))
        self.assertEqual(failed["failing_since"], still["failing_since"])
        feed = security_alerts.feed_status(NOW + datetime.timedelta(minutes=10))
        self.assertEqual((True, False, failed["failing_since"]), (feed["connected"], feed["ok"], feed["failing_since"]))
        self.assertNotIn("error", feed)
        ok, collect = self._read(NOW + datetime.timedelta(minutes=15))
        self.assertEqual(NOW - datetime.timedelta(minutes=10), collect.call_args.args[1])  # from the last good read, not from now
        self.assertNotIn("failing_since", ok)
        self.assertTrue(security_alerts.feed_status(NOW + datetime.timedelta(minutes=15))["ok"])

    def test_feed_is_not_ok_when_nothing_was_read_for_a_while(self):
        self.assertEqual({"connected": False, "ok": False, "last_ok": None, "failing_since": None}, security_alerts.feed_status(NOW))
        self._read(NOW)
        self.assertTrue(security_alerts.feed_status(NOW + datetime.timedelta(minutes=19))["ok"])
        self.assertFalse(security_alerts.feed_status(NOW + datetime.timedelta(minutes=21))["ok"])

    def test_disabled_connector_is_not_read(self):
        Connector.objects.filter(id=self.connector.id).update(enabled=False)
        with mock.patch.object(wazuh.WazuhConnector, "collect_security_alerts", autospec=True) as collect:
            self.assertEqual({}, security_alerts.refresh(NOW))
        collect.assert_not_called()

    def test_task_is_scheduled_every_five_minutes(self):
        entry = settings.CELERY_BEAT_SCHEDULE["orasec-security-alerts"]
        self.assertEqual("orasec.posture.tasks.refresh_security_alerts", entry["task"])
        self.assertEqual(datetime.timedelta(minutes=5), entry["schedule"])
        from orasec.posture import tasks  # noqa: PLC0415
        with mock.patch.object(security_alerts, "refresh") as refresh:
            tasks.refresh_security_alerts()
            tasks.refresh_security_alerts()  # the lock is released after each run
        self.assertEqual(2, refresh.call_count)


@versioned_fixtures
class TestAttacksScreen(OraSecTestCase):
    fixtures = ["orasec_testdata.json"]

    def setUp(self):
        cache.clear()
        self.admin = User.objects.get(username="admin")
        now = timezone.now()
        for n, h in enumerate((ROOTKIT, WRONG_PASSWORD, SUDOERS)):
            e = wazuh.security_alert_event(h)
            e["occurred_at"] = now - datetime.timedelta(hours=2 + n)
            geo.store_events("wazuh", [e])
        # blocked traffic, a low-level Wazuh alert and a high alert of another kind: on the map, not among the security alerts
        geo.store_events("unifi", [{"event_id": f"u{i}", "occurred_at": now - datetime.timedelta(minutes=i), "src_ip": f"8.8.4.{i + 1}",
                                    "action": "block", "target": "WAN", "rule": "Blocked inbound"} for i in range(70)])
        geo.store_events("wazuh", [{"event_id": "low", "occurred_at": now, "src_ip": "8.8.8.8", "action": "alert", "target": "lms",
                                    "rule": "sshd: authentication failed.", "detail": "level 5 sshd,authentication_failed"}])
        geo.store_events("opnsense", [{"event_id": "o1", "occurred_at": now, "src_ip": "1.1.1.1", "action": "alert", "target": "cloud-fw",
                                       "rule": "IDS: exploit attempt", "detail": "level 12 ids"}])

    def test_web_lists_security_alerts_apart_from_blocked_traffic(self):
        self.client.force_login(self.admin)
        data = self.client.get(reverse("orasec_attacks_api"), {"range": "7d"}).json()
        self.assertEqual(["Break-in: Possible kernel level rootkit: Process '14895' hidden from /proc.",
                          "Break-in attempt: syslog: User missed the password more than one time",
                          "Break-in: Integrity checksum changed.: /etc/sudoers.d/90-admins"],
                         [a["rule"] for a in data["alerts"]])  # the level 12 IDS alert alone is no longer announced
        rootkit, password = data["alerts"][0], data["alerts"][1]
        self.assertEqual((None, True, 11, "srv-01"), (rootkit["ip"], rootkit["internal"], rootkit["level"], rootkit["target"]))
        self.assertEqual(("192.168.20.95", True, ""), (password["ip"], password["internal"], password["cc"]))
        self.assertEqual({"connected": False, "ok": False, "last_ok": None, "failing_since": None}, data["alert_feed"])
        self.assertEqual(70 + 5, data["total"])

    def test_source_filter_applies_to_the_alerts(self):
        self.client.force_login(self.admin)
        data = self.client.get(reverse("orasec_attacks_api"), {"range": "7d", "source": "unifi"}).json()
        self.assertEqual([], data["alerts"])

    def test_phone_app_shows_security_alerts_first(self):
        _obj, code = MobileLinkCode.create_for(self.admin)
        token = self.client.post("/api/v2/orasec/mobile/link/", {"code": code, "device_name": "Test phone", "platform": "ios"},
                                 content_type="application/json").json()["token"]
        data = self.client.get("/api/v2/orasec/mobile/attacks/?range=7d", HTTP_AUTHORIZATION=f"Bearer {token}").json()
        self.assertEqual(3, len(data["alerts"]))
        self.assertEqual([a["rule"] for a in data["alerts"]], [e["rule"] for e in data["recent"][:3]])
        self.assertEqual("Host alert", data["recent"][0]["ip"])  # the app shows the address as the heading
        self.assertEqual(60, len(data["recent"]))
        self.assertEqual(1, sum(1 for e in data["recent"] if e["rule"] == "IDS: exploit attempt"))  # not listed twice

    def test_page_has_the_security_alerts_panel(self):
        self.client.force_login(self.admin)
        html = self.client.get(reverse("orasec_attacks")).content.decode()
        for part in ('id="alerts"', 'id="alerts-feed"', "Security alerts", "No suspected hack or unauthorised action in this range."):
            self.assertIn(part, html)

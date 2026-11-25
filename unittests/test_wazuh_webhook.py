"""Wazuh manager integration: an alert reaches OraSec the moment Wazuh raises it."""
import json

from django.core.cache import cache
from django.test import Client
from django.urls import reverse

from orasec.posture import geo
from orasec.posture.connectors import wazuh
from orasec.posture.models import AttackEvent, Connector
from unittests.orasec_test_case import OraSecTestCase

TOKEN = "t0ken-for-the-test-only"


def alert(alert_id, level, groups, description, *, agent="srv-01", syscheck=None, data=None):
    doc = {"id": alert_id, "timestamp": "2026-11-20T04:30:00.000+0000", "agent": {"id": "001", "name": agent},
           "rule": {"level": level, "groups": groups, "description": description, "id": "510"}}
    if syscheck:
        doc["syscheck"] = syscheck
    if data:
        doc["data"] = data
    return doc


ROOTKIT = alert("1794815245.1", 11, ["ossec", "rootcheck"], "Possible kernel level rootkit", data={"title": "Process hidden"})
CVE = alert("1794815245.2", 13, ["vulnerability-detector"], "CVE-2026-0001 affects openssl")
CIS = alert("1794815245.3", 10, ["sca"], "CIS: password policy")
NOISE = alert("1794815245.4", 3, ["syslog"], "Something small")
FIREWALL = alert("1794815245.6", 10, ["pfsense", "multiple_blocks"], "Multiple pfSense firewall blocks events from same source.")
RANSOM_NOTE = alert("1794815245.7", 12, ["ossec", "syscheck", "ransomware"], "OraSec: ransom note or encrypted file name",
                    syscheck={"path": "/home/alex/Documents/HOW_TO_DECRYPT.txt"})
SUDOERS = alert("1794815245.5", 7, ["ossec", "syscheck"], "Integrity checksum changed.", syscheck={"path": "/etc/sudoers.d/90-x"})


class TestWebhook(OraSecTestCase):
    def setUp(self):
        cache.clear()
        self.connector = Connector.objects.create(name="Wazuh t", kind="wazuh", base_url="https://wazuh.test:55000")
        self.connector.set_secrets({"webhook_token": TOKEN})
        self.connector.save()
        self.url = reverse("orasec_wazuh_alert")
        self.client = Client()  # not signed in: the endpoint checks its own token

    def post(self, body, token=TOKEN, raw=False):
        headers = {"HTTP_AUTHORIZATION": f"Bearer {token}"} if token is not None else {}
        data = body if raw else json.dumps(body)
        return self.client.post(self.url, data=data, content_type="application/json", **headers)

    def test_a_missing_or_wrong_token_is_refused_and_nothing_is_stored(self):
        self.assertEqual(403, self.post(ROOTKIT, token=None).status_code)
        self.assertEqual(403, self.post(ROOTKIT, token="wrong").status_code)
        self.assertEqual(403, self.post(ROOTKIT, token="").status_code)
        self.assertEqual(0, AttackEvent.objects.count())

    def test_no_token_set_on_the_connector_refuses_everything(self):
        self.connector.set_secrets({})
        self.connector.save()
        self.assertEqual(403, self.post(ROOTKIT, token="").status_code)
        self.assertEqual(403, self.post(ROOTKIT, token="anything").status_code)

    def test_only_post_is_allowed(self):
        self.assertEqual(405, self.client.get(self.url, HTTP_AUTHORIZATION=f"Bearer {TOKEN}").status_code)

    def test_a_security_alert_is_stored_at_once(self):
        r = self.post(ROOTKIT)
        self.assertEqual((200, 1), (r.status_code, r.json()["stored"]))
        e = AttackEvent.objects.get()
        self.assertEqual(("wazuh", "1794815245.1", "alert", "srv-01"), (e.source, e.event_id, e.action, e.target))
        self.assertIn("security alert", e.detail)
        self.assertIn("Possible kernel level rootkit", e.rule)

    def test_vulnerabilities_cis_and_small_alerts_are_not_stored(self):
        for doc in (CVE, CIS, NOISE, FIREWALL):
            r = self.post(doc)
            self.assertEqual((200, 0), (r.status_code, r.json()["stored"]), doc["rule"]["description"])
        self.assertEqual(0, AttackEvent.objects.count())

    def test_a_changed_sudoers_file_is_stored_at_level_7(self):
        self.assertEqual(1, self.post(SUDOERS).json()["stored"])

    def test_the_same_alert_twice_is_stored_once(self):
        self.post(ROOTKIT)
        self.assertEqual(0, self.post(ROOTKIT).json()["stored"])
        self.assertEqual(1, AttackEvent.objects.count())

    def test_an_alert_that_arrives_by_the_webhook_and_by_the_five_minute_read_is_stored_once(self):
        self.post(ROOTKIT)
        read = wazuh.security_alert_event({"_id": "AbCdEf-indexer-id", "_source": ROOTKIT}, self.connector.options)
        self.assertEqual(0, geo.store_events("wazuh", [read]))
        self.assertEqual(1, AttackEvent.objects.count())

    def test_bad_bodies(self):
        self.assertEqual(400, self.post("not json", raw=True).status_code)
        self.assertEqual(400, self.post([1, 2]).status_code)
        self.assertEqual(400, self.post({"rule": {"level": 12}}).status_code)  # no alert id
        self.assertEqual(413, self.post({"x": "y" * 70000}).status_code)
        self.assertEqual(0, AttackEvent.objects.count())

    def test_a_disabled_connector_does_not_accept_alerts(self):
        self.connector.enabled = False
        self.connector.save()
        self.assertEqual(403, self.post(ROOTKIT).status_code)

    def test_ransomware_is_stored_and_named(self):
        self.assertEqual(1, self.post(RANSOM_NOTE).json()["stored"])
        e = AttackEvent.objects.get()
        self.assertTrue(e.rule.startswith("Ransomware: OraSec: ransom note"), e.rule)
        self.assertIn("security alert", e.detail)

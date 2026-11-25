"""Tests for plugins (orasec.plugins): the registry, the on/off switch, the page, and every place that obeys the switch."""
from unittest import mock

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import override_settings
from django.urls import reverse

from orasec.mobile import push
from orasec.mobile.models import MobileLinkCode
from orasec.models import System_Settings
from orasec.plugins import registry
from orasec.plugins.models import PluginState
from orasec.posture import tasks
from orasec.posture.models import Connector
from unittests.orasec_test_case import OraSecTestCase, versioned_fixtures

User = get_user_model()
BASE = "/api/v2/orasec/mobile"


@versioned_fixtures
class TestPlugins(OraSecTestCase):
    fixtures = ["orasec_testdata.json"]

    def setUp(self):
        cache.clear()
        self.admin = User.objects.get(username="admin")
        self.user = User.objects.create_user(username="reader", password="x" * 14, is_staff=False)  # noqa: S106

    def _link(self):
        _obj, code = MobileLinkCode.create_for(self.admin)
        r = self.client.post(f"{BASE}/link/", {"code": code, "device_name": "Test phone", "platform": "ios"}, content_type="application/json")
        return r

    # --- registry ---------------------------------------------------------
    def test_every_connector_kind_is_a_plugin_and_keys_are_unique(self):
        keys = [p.key for p in registry.all_plugins()]
        self.assertEqual(len(keys), len(set(keys)))
        for kind, _label in Connector.KIND_CHOICES:
            self.assertIn(f"source.{kind}", keys)
        for key in ("intel.kev", "intel.epss", "ora", "sso", "mobile", "push", "mcp", "jira", "slack", "mail", "webhooks"):
            self.assertIn(key, keys)

    def test_a_plugin_with_no_saved_state_is_on(self):
        self.assertEqual(0, PluginState.objects.count())
        self.assertTrue(registry.is_on("source.wazuh"))
        self.assertTrue(registry.is_on("mobile"))
        self.assertTrue(registry.is_on("no.such.plugin"))

    def test_switch_is_saved_and_the_cache_is_dropped(self):
        self.assertTrue(registry.is_on("source.aws"))  # fills the cache
        registry.set_on("source.aws", False, self.admin)
        self.assertFalse(registry.is_on("source.aws"))
        row = PluginState.objects.get(key="source.aws")
        self.assertFalse(row.enabled)
        self.assertEqual(self.admin, row.updated_by)
        registry.set_on("source.aws", True, self.admin)
        self.assertTrue(registry.is_on("source.aws"))
        self.assertEqual(1, PluginState.objects.filter(key="source.aws").count())

    def test_unknown_plugin_cannot_be_switched(self):
        with self.assertRaises(KeyError):
            registry.set_on("no.such.plugin", False, self.admin)

    def test_system_setting_plugins_write_the_system_setting(self):
        registry.set_on("jira", True, self.admin)
        self.assertTrue(System_Settings.objects.get(no_cache=True).enable_jira)
        self.assertTrue(registry.is_on("jira"))
        registry.set_on("jira", False, self.admin)
        self.assertFalse(System_Settings.objects.get(no_cache=True).enable_jira)
        self.assertFalse(registry.is_on("jira"))
        self.assertFalse(PluginState.objects.filter(key="jira").exists())  # one source of truth

    def test_ora_plugin_follows_the_ora_setting(self):
        from orasec.ora import config as ora_config  # noqa: PLC0415
        registry.set_on("ora", False, self.admin)
        self.assertFalse(ora_config.get_config(fresh=True)["enabled"])
        self.assertFalse(registry.is_on("ora"))
        registry.set_on("ora", True, self.admin)
        self.assertTrue(ora_config.get_config(fresh=True)["enabled"])

    @override_settings(ORASEC_OIDC_ENABLED=False, ORASEC_MCP_ENABLED=False, ORASEC_PUSH_ENABLED=False)
    def test_a_plugin_the_server_is_not_set_up_for_is_not_active(self):
        rows = {r["key"]: r for r in registry.snapshot()}
        for key in ("sso", "mcp", "push"):
            self.assertTrue(rows[key]["on"])
            self.assertFalse(rows[key]["available"])
            self.assertFalse(rows[key]["active"])
            self.assertTrue(rows[key]["missing"])
        self.assertTrue(rows["intel.kev"]["active"])

    # --- what obeys the switch --------------------------------------------
    def test_connectors_of_a_plugin_that_is_off_do_not_run(self):
        on = Connector.objects.create(name="Wazuh test", kind="wazuh", base_url="https://wazuh.example.com")
        off = Connector.objects.create(name="AWS test", kind="aws", base_url="https://aws.example.com")
        registry.set_on("source.aws", False, self.admin)
        with mock.patch.object(tasks.run_connector_task, "delay") as delay:
            tasks.run_due_connectors()
        self.assertEqual([mock.call(on.id, "schedule")], delay.call_args_list)
        with mock.patch("orasec.posture.connectors.base.run_connector") as run, mock.patch.object(tasks.refresh_priorities, "delay"):
            tasks.run_connector_task(off.id, "manual", self.admin.id)
            run.assert_not_called()
            tasks.run_connector_task(on.id, "manual", self.admin.id)
            run.assert_called_once()

    def test_manual_run_of_a_connector_whose_plugin_is_off_is_refused(self):
        c = Connector.objects.create(name="AWS test", kind="aws", base_url="https://aws.example.com")
        registry.set_on("source.aws", False, self.admin)
        self.client.force_login(self.admin)
        with mock.patch.object(tasks.run_connector_task, "delay") as delay:
            r = self.client.post(reverse("orasec_connector_run", args=[c.id]))
        self.assertEqual(302, r.status_code)
        delay.assert_not_called()

    def test_intel_feeds_follow_their_plugins(self):
        registry.set_on("intel.epss", False, self.admin)
        with mock.patch("orasec.posture.intel.refresh_kev") as kev, mock.patch("orasec.posture.intel.refresh_epss") as epss, \
                mock.patch("orasec.posture.intel.apply_intel"), mock.patch("orasec.posture.evidence.from_intel_refresh"), \
                mock.patch.object(tasks.refresh_priorities, "delay"):
            tasks.refresh_intel()
        kev.assert_called_once()
        epss.assert_not_called()

    def test_wazuh_alert_endpoint_is_gone_when_wazuh_is_off(self):
        url = reverse("orasec_wazuh_alert")
        self.assertEqual(403, self.client.post(url, "{}", content_type="application/json").status_code)  # on: asks for a token
        registry.set_on("source.wazuh", False, self.admin)
        self.assertEqual(404, self.client.post(url, "{}", content_type="application/json").status_code)
        with mock.patch("orasec.posture.security_alerts.refresh") as refresh:
            tasks.refresh_security_alerts()
        refresh.assert_not_called()

    def test_mobile_api_is_refused_when_the_mobile_plugin_is_off(self):
        token = self._link().json()["token"]
        self.assertEqual(200, self.client.get(f"{BASE}/me/", HTTP_AUTHORIZATION=f"Bearer {token}").status_code)
        registry.set_on("mobile", False, self.admin)
        r = self.client.get(f"{BASE}/me/", HTTP_AUTHORIZATION=f"Bearer {token}")
        self.assertEqual(403, r.status_code)
        self.assertEqual("plugin_off", r.json()["code"])
        self.assertEqual(403, self._link().status_code)
        self.assertEqual(403, self.client.get(f"{BASE}/server/").status_code)
        registry.set_on("mobile", True, self.admin)
        self.assertEqual(200, self.client.get(f"{BASE}/me/", HTTP_AUTHORIZATION=f"Bearer {token}").status_code)  # still linked

    def test_me_tells_the_app_which_plugins_work(self):
        token = self._link().json()["token"]
        registry.set_on("source.github", False, self.admin)
        plugins = self.client.get(f"{BASE}/me/", HTTP_AUTHORIZATION=f"Bearer {token}").json()["plugins"]
        self.assertFalse(plugins["source.github"])
        self.assertTrue(plugins["source.wazuh"])
        self.assertTrue(plugins["mobile"])
        self.assertEqual({p.key for p in registry.all_plugins()}, set(plugins))

    def test_app_can_list_plugins_but_only_when_linked(self):
        self.assertEqual(401, self.client.get(f"{BASE}/plugins/").status_code)
        token = self._link().json()["token"]
        registry.set_on("intel.epss", False, self.admin)
        rows = {r["key"]: r for r in self.client.get(f"{BASE}/plugins/", HTTP_AUTHORIZATION=f"Bearer {token}").json()["plugins"]}
        self.assertEqual({p.key for p in registry.all_plugins()}, set(rows))
        self.assertFalse(rows["intel.epss"]["active"])
        self.assertEqual({"key", "name", "group", "on", "available", "active"}, set(rows["intel.kev"]))

    def test_server_info_needs_no_sign_in_and_gives_nothing_away(self):
        r = self.client.get(f"{BASE}/server/")
        self.assertEqual(200, r.status_code)
        self.assertEqual({"product", "api", "min_app_version"}, set(r.json()))
        self.assertEqual("OraSec", r.json()["product"])

    def test_data_sources_in_the_app_show_the_plugin_state(self):
        Connector.objects.create(name="AWS test", kind="aws", base_url="https://aws.example.com", last_status="ok")
        token = self._link().json()["token"]
        registry.set_on("source.aws", False, self.admin)
        row = self.client.get(f"{BASE}/connectors/", HTTP_AUTHORIZATION=f"Bearer {token}").json()["connectors"][0]
        self.assertFalse(row["plugin_on"])
        self.assertFalse(row["enabled"])
        self.assertFalse(row["healthy"])

    def test_push_is_off_when_its_plugin_is_off(self):
        with override_settings(ORASEC_PUSH_ENABLED=True, ORASEC_PUSH_FCM_CREDENTIALS=__file__, ORASEC_PUSH_APNS_KEY_PATH=""):
            self.assertTrue(push.configured()["fcm"])
            registry.set_on("push", False, self.admin)
            self.assertFalse(push.configured()["fcm"])
            self.assertFalse(push.available())

    @override_settings(ORASEC_MCP_ENABLED=True, ORASEC_OIDC_ENABLED=True, ORASEC_OIDC_ISSUER="https://id.example.com",
                       ORASEC_OIDC_CLIENT_ID="orasec")
    def test_mcp_and_sso_follow_their_plugins(self):
        from orasec.mcp import config as mcp_config  # noqa: PLC0415
        from orasec.sso import oidc  # noqa: PLC0415
        self.assertTrue(mcp_config.enabled())
        self.assertTrue(oidc.enabled())
        registry.set_on("mcp", False, self.admin)
        registry.set_on("sso", False, self.admin)
        self.assertFalse(mcp_config.enabled())
        self.assertFalse(oidc.enabled())
        self.assertNotContains(self.client.get(reverse("login")), "orasec/sso/")

    # --- the page -----------------------------------------------------------
    def test_page_lists_every_plugin_and_only_an_administrator_gets_switches(self):
        self.client.force_login(self.admin)
        r = self.client.get(reverse("orasec_plugins"))
        self.assertEqual(200, r.status_code)
        for p in registry.all_plugins():
            self.assertContains(r, f'data-plugin="{p.key}"')
        self.assertContains(r, 'data-testid="toggle-source.wazuh"')
        self.client.force_login(self.user)
        r = self.client.get(reverse("orasec_plugins"))
        self.assertEqual(200, r.status_code)
        self.assertNotContains(r, 'data-testid="toggle-source.wazuh"')

    def test_toggle_needs_an_administrator_and_a_post(self):
        url = reverse("orasec_plugin_toggle", args=["source.unifi"])
        self.assertEqual(302, self.client.post(url, {"on": "0"}).status_code)  # not signed in: to the sign-in page
        self.assertTrue(registry.is_on("source.unifi"))
        self.client.force_login(self.user)
        self.assertEqual(403, self.client.post(url, {"on": "0"}).status_code)
        self.assertTrue(registry.is_on("source.unifi"))
        self.client.force_login(self.admin)
        self.assertEqual(405, self.client.get(url).status_code)
        self.assertEqual(302, self.client.post(url, {"on": "0"}).status_code)
        self.assertFalse(registry.is_on("source.unifi"))
        self.assertEqual(302, self.client.post(url, {"on": "1"}).status_code)
        self.assertTrue(registry.is_on("source.unifi"))
        self.assertEqual(302, self.client.post(reverse("orasec_plugin_toggle", args=["nope"]), {"on": "0"}).status_code)
        self.assertFalse(PluginState.objects.filter(key="nope").exists())


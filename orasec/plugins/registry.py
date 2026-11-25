"""
Plugins: every integration OraSec can talk to is a plugin that an administrator turns on or off.

A plugin is one outside system or optional service: a data source (Wazuh, a firewall, a cloud account), a threat
intelligence feed, the Ora assistant, single sign-on, the mobile app, phone notifications, the MCP server, the ticket
and chat integrations. The core (findings, assets, risks, compliance) is not a plugin and cannot be turned off.

Rules
- A plugin with no saved state is ON, so adding this module to a running server changes nothing.
- "Available" means the server has what the plugin needs (for example the single sign-on settings). A plugin that is
  not available stays off whatever the switch says; the Plugins page says what is missing.
- Where a switch existed before (system settings, the Ora settings) that switch stays the single source of truth and
  the plugin reads and writes it.
- Code asks ``plugins.is_on("source.wazuh")``. The answer is cached for a minute and dropped on every change.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

from django.conf import settings
from django.core.cache import cache

logger = logging.getLogger(__name__)

CACHE_KEY = "orasec.plugins.off.v1"
CACHE_SECONDS = 60

GROUP_SOURCES = "Data sources"
GROUP_INTEL = "Threat intelligence"
GROUP_ASSISTANT = "Assistant"
GROUP_ACCESS = "Sign-in and apps"
GROUP_TICKETS = "Tickets and messages"


@dataclass(frozen=True)
class Plugin:

    key: str
    name: str
    group: str
    summary: str
    icon: str = "fa-plug"
    # Where the on/off state lives: "state" (PluginState), "system:<field>" (system settings), "ora" (Ora settings).
    store: str = "state"
    # Name of a function in this module that says whether the server is set up for the plugin, and what is missing.
    check: str = ""
    # Shown under the switch when turning the plugin off has an effect people may not expect.
    off_note: str = ""


SOURCE_SUMMARIES = {
    "wazuh": "Agents, hardware and software inventory, vulnerabilities, failed hardening checks and security alerts.",
    "opnsense": "Firewall package vulnerabilities, firmware updates, certificate expiry, accounts without MFA, blocked traffic.",
    "unifi": "Network devices and firmware, clients, Wi-Fi security, firewall policies, networks, WAN and VPN.",
    "patchmon": "Outstanding security and package updates per host, reboot required, agents not reporting.",
    "semaphore": "Runs patch deployments through Semaphore UI (Ansible).",
    "aws": "Cloud inventory, security groups and cloud security posture findings.",
    "cloudflare": "DNS, TLS, web application firewall and blocked threats.",
    "github": "Repositories, Dependabot alerts, code scanning and secret scanning.",
    "beszel": "Host health: CPU, memory, disk and network.",
    "isms": "Two-way sync with the policy tool (documents, risks, controls).",
}
SOURCE_ICONS = {
    "wazuh": "fa-shield-virus", "opnsense": "fa-fire", "unifi": "fa-wifi", "patchmon": "fa-bandage", "semaphore": "fa-rocket",
    "aws": "fa-cloud", "cloudflare": "fa-cloud-bolt", "github": "fa-code-branch", "beszel": "fa-heart-pulse", "isms": "fa-file-shield",
}


def _source_plugins() -> list[Plugin]:
    from orasec.posture.models import Connector  # noqa: PLC0415
    out = []
    for kind, label in Connector.KIND_CHOICES:
        out.append(Plugin(
            key=f"source.{kind}", name=label, group=GROUP_SOURCES,
            summary=SOURCE_SUMMARIES.get(kind, "Scheduled connector that brings findings and assets into OraSec."),
            icon=SOURCE_ICONS.get(kind, "fa-plug"), check="check_source",
            off_note="Connectors of this type stop running. What they already collected stays.",
        ))
    return out


def _fixed_plugins() -> list[Plugin]:
    return [
        Plugin("intel.kev", "CISA known exploited vulnerabilities", GROUP_INTEL,
               "Daily list of vulnerabilities that are being exploited. Used for priority and due dates.", "fa-triangle-exclamation",
               off_note="The list is no longer refreshed. Existing marks on findings stay."),
        Plugin("intel.epss", "EPSS exploit prediction", GROUP_INTEL,
               "Likelihood that a vulnerability will be exploited, from FIRST. Used for priority.", "fa-chart-line",
               off_note="Scores are no longer refreshed. Existing scores stay."),
        Plugin("ora", "Ora assistant", GROUP_ASSISTANT,
               "The built-in assistant on the web and in the mobile app. Needs an AI provider.", "fa-comments",
               store="ora", check="check_ora"),
        Plugin("sso", "Single sign-on (OpenID Connect)", GROUP_ACCESS,
               "Sign in through your identity provider.", "fa-right-to-bracket", check="check_sso",
               off_note="People sign in with their OraSec user name and password while this is off."),
        Plugin("mobile", "Mobile app", GROUP_ACCESS,
               "Lets linked phones and tablets read OraSec through the mobile API.", "fa-mobile-screen",
               off_note="Every linked device stops working until this is on again. Devices stay linked."),
        Plugin("push", "Phone notifications", GROUP_ACCESS,
               "Sends notifications to linked phones (critical findings, security alerts, approvals, overdue items).",
               "fa-bell", check="check_push"),
        Plugin("mcp", "MCP server", GROUP_ACCESS,
               "Lets approved AI tools read OraSec and propose changes through the Model Context Protocol.", "fa-robot",
               check="check_mcp"),
        Plugin("jira", "Jira", GROUP_TICKETS, "Creates and syncs Jira issues for findings.", "fa-ticket", store="system:enable_jira"),
        Plugin("github_issues", "GitHub issues", GROUP_TICKETS, "Creates GitHub issues for findings.", "fa-code-branch",
               store="system:enable_github"),
        Plugin("slack", "Slack notifications", GROUP_TICKETS, "Sends notifications to Slack.", "fa-hashtag",
               store="system:enable_slack_notifications"),
        Plugin("msteams", "Microsoft Teams notifications", GROUP_TICKETS, "Sends notifications to Microsoft Teams.", "fa-people-group",
               store="system:enable_msteams_notifications"),
        Plugin("mail", "Email notifications", GROUP_TICKETS, "Sends notifications by email.", "fa-envelope",
               store="system:enable_mail_notifications"),
        Plugin("webhooks", "Webhook notifications", GROUP_TICKETS, "Sends notifications to your own webhook endpoints.", "fa-link",
               store="system:enable_webhooks_notifications"),
    ]


def all_plugins() -> list[Plugin]:
    return _source_plugins() + _fixed_plugins()


def get(key: str) -> Plugin | None:
    for p in all_plugins():
        if p.key == key:
            return p
    return None


# ---------------------------------------------------------------------------
# Is the server set up for the plugin? Each returns (available, what is missing).
# ---------------------------------------------------------------------------
def check_source(plugin: Plugin) -> tuple[bool, str]:
    from orasec.posture.models import Connector  # noqa: PLC0415
    kind = plugin.key.split(".", 1)[1]
    n = Connector.objects.filter(kind=kind).count()
    return (True, "") if n else (True, "No connector of this type yet. Add one under Automation, Connectors.")


def check_ora(plugin: Plugin) -> tuple[bool, str]:
    from orasec.ora import config as ora_config  # noqa: PLC0415
    ok = ora_config.is_configured(ora_config.get_config())
    return (ok, "" if ok else "No AI provider is set. Add one on the Ora settings page.")


def check_sso(plugin: Plugin) -> tuple[bool, str]:
    ok = bool(getattr(settings, "ORASEC_OIDC_ENABLED", False) and getattr(settings, "ORASEC_OIDC_ISSUER", "")
              and getattr(settings, "ORASEC_OIDC_CLIENT_ID", ""))
    return (ok, "" if ok else "Set ORASEC_OIDC_ENABLED, ORASEC_OIDC_ISSUER and ORASEC_OIDC_CLIENT_ID on the server.")


def check_push(plugin: Plugin) -> tuple[bool, str]:
    from pathlib import Path  # noqa: PLC0415
    on = bool(getattr(settings, "ORASEC_PUSH_ENABLED", False))
    fcm = getattr(settings, "ORASEC_PUSH_FCM_CREDENTIALS", "")
    apns = getattr(settings, "ORASEC_PUSH_APNS_KEY_PATH", "")
    ok = bool(on and ((fcm and Path(fcm).is_file()) or (apns and Path(apns).is_file())))
    return (ok, "" if ok else "Set ORASEC_PUSH_ENABLED and the Firebase or Apple key files on the server.")


def check_mcp(plugin: Plugin) -> tuple[bool, str]:
    ok = bool(getattr(settings, "ORASEC_MCP_ENABLED", False))
    return (ok, "" if ok else "Set ORASEC_MCP_ENABLED on the server.")


def availability(plugin: Plugin) -> tuple[bool, str]:
    if not plugin.check:
        return True, ""
    try:
        return globals()[plugin.check](plugin)
    except Exception:  # a broken check must never take a page or a task down
        logger.exception("plugin check failed: %s", plugin.key)
        return True, ""


# ---------------------------------------------------------------------------
# The switch
# ---------------------------------------------------------------------------
def _off_states() -> frozenset:
    off = cache.get(CACHE_KEY)
    if off is None:
        from orasec.plugins.models import PluginState  # noqa: PLC0415
        try:
            off = frozenset(PluginState.objects.filter(enabled=False).values_list("key", flat=True))
        except Exception:  # table not there yet (first start before migrate): everything is on
            logger.debug("plugin state not readable; treating every plugin as on", exc_info=True)
            return frozenset()
        cache.set(CACHE_KEY, off, CACHE_SECONDS)
    return off


def invalidate() -> None:
    cache.delete(CACHE_KEY)


def switched_on(plugin: Plugin) -> bool:
    """What the switch says, without looking at whether the server is set up."""
    if plugin.store == "state":
        return plugin.key not in _off_states()
    if plugin.store == "ora":
        from orasec.ora import config as ora_config  # noqa: PLC0415
        return bool(ora_config.get_config().get("enabled"))
    if plugin.store.startswith("system:"):
        from orasec.utils import get_system_setting  # noqa: PLC0415
        return bool(get_system_setting(plugin.store.split(":", 1)[1], False))
    return True


def is_on(key: str) -> bool:
    """True when the plugin is switched on. An unknown key is on (code for a plugin that was removed keeps working)."""
    plugin = get(key)
    return True if plugin is None else switched_on(plugin)


def source_on(kind: str) -> bool:
    return is_on(f"source.{kind}")


def set_on(key: str, on: bool, user=None) -> Plugin:
    plugin = get(key)
    if plugin is None:
        msg = f"Unknown plugin: {key}"
        raise KeyError(msg)
    on = bool(on)
    if plugin.store == "state":
        from orasec.plugins.models import PluginState  # noqa: PLC0415
        PluginState.objects.update_or_create(key=key, defaults={"enabled": on, "updated_by": user if getattr(user, "pk", None) else None})
        invalidate()
    elif plugin.store == "ora":
        from orasec.ora import config as ora_config  # noqa: PLC0415
        ora_config.save({"enabled": on}, user)
    elif plugin.store.startswith("system:"):
        from orasec.models import System_Settings  # noqa: PLC0415
        field = plugin.store.split(":", 1)[1]
        ss = System_Settings.objects.get(no_cache=True)
        setattr(ss, field, on)
        ss.save()
    logger.info("plugin %s turned %s by %s", key, "on" if on else "off", getattr(user, "username", "system"))
    return plugin


def snapshot() -> list[dict]:
    """Every plugin with its state, for the Plugins page and the mobile app."""
    rows = []
    for p in all_plugins():
        available, missing = availability(p)
        on = switched_on(p)
        rows.append({"key": p.key, "name": p.name, "group": p.group, "summary": p.summary, "icon": p.icon,
                     "on": on, "available": available, "missing": missing, "active": bool(on and available),
                     "off_note": p.off_note})
    return rows


def active_map() -> dict[str, bool]:
    """key -> working right now (switched on and the server is set up). What the mobile app gets."""
    return {r["key"]: r["active"] for r in snapshot()}


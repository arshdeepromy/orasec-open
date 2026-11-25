import contextlib

# import the settings file
from django.conf import settings
from django.contrib import messages

from orasec import site as site_profile
from orasec.announcement.github_star import should_show_github_star_prompt
from orasec.announcement.os_message import OS_MESSAGE_DISMISSED_KEY, get_os_banner
from orasec.labels import get_labels
from orasec.location.feature import locations_enabled
from orasec.middleware import READ_ONLY_MODE_MESSAGE
from orasec.models import System_Settings, UserAnnouncement


def _plugin_on(key):
    from orasec.plugins import registry  # noqa: PLC0415
    return registry.is_on(key)


def globalize_vars(request):
    # return the value you want as a dictionnary. you may add multiple values in there.
    context = {
        "FORGOT_PASSWORD": settings.FORGOT_PASSWORD,
        "FORGOT_USERNAME": settings.FORGOT_USERNAME,
        "CLASSIC_AUTH_ENABLED": settings.CLASSIC_AUTH_ENABLED,
        "OIDC_ENABLED": bool(getattr(settings, "ORASEC_OIDC_ENABLED", False) and getattr(settings, "ORASEC_OIDC_ISSUER", "")
                             and _plugin_on("sso")),
        "OIDC_BUTTON_TEXT": getattr(settings, "ORASEC_OIDC_BUTTON_TEXT", "Sign in with SSO"),
        "ORG_NAME": site_profile.org_name(),
        "SECURITY_CONTACT": site_profile.get("security_contact") or "",
        "ISSUES_URL": site_profile.get("issues_url") or "",
        "MCP_ENABLED": bool(getattr(settings, "ORASEC_MCP_ENABLED", False) and _plugin_on("mcp")),
        "DOCUMENTATION_URL": settings.DOCUMENTATION_URL,
        "API_TOKENS_ENABLED": settings.API_TOKENS_ENABLED,
        "API_TOKEN_AUTH_ENDPOINT_ENABLED": settings.API_TOKEN_AUTH_ENDPOINT_ENABLED,
        # The user-menu Pro link follows the same switch as the promo banner, so
        # ORASEC_OS_MESSAGE_ENABLED=False turns both off.
        "SHOW_PLG_LINK": settings.OS_MESSAGE_ENABLED,
        # V3 Feature Flags
        "V3_FEATURE_LOCATIONS": locations_enabled(),
        "SHOW_A11Y_REQUIRED_FIELDS_NOTICE": settings.SHOW_A11Y_REQUIRED_FIELDS_NOTICE,
        "SHOW_GITHUB_STAR_PROMPT": should_show_github_star_prompt(getattr(request, "user", None)),
    }

    additional_banners = []

    if System_Settings.objects.get().read_only_mode:
        additional_banners.append({"source": "read_only_mode", "message": str(READ_ONLY_MODE_MESSAGE), "style": "warning"})

    if (os_banner := get_os_banner()) is not None:
        token = os_banner.get("dismiss_token", "")
        user = getattr(request, "user", None)
        dismissible = bool(token and getattr(user, "is_authenticated", False))
        if not (dismissible and _os_message_dismissed(user, token)):
            additional_banners.append({
                "source": "os",
                "message": os_banner["message"],
                "style": "info",
                "url": "",
                "link_text": "",
                "expanded_html": os_banner["expanded_html"],
                "dismissible": dismissible,
                "dismiss_token": token,
            })

    if hasattr(request, "session"):
        for banner in request.session.pop("_product_banners", []):
            if banner.get("source") == "product_announcement":
                continue  # upsell banners left in sessions migrated from the upstream product
            additional_banners.append(banner)

    if additional_banners:
        context["additional_banners"] = additional_banners

    return context


def _os_message_dismissed(user, token):
    contact = getattr(user, "usercontactinfo", None)
    if contact is None:
        return False
    return (contact.user_state_details or {}).get(OS_MESSAGE_DISMISSED_KEY) == token


def bind_system_settings(request):
    """Load system settings and display warning if there's a database error."""
    try:
        system_settings = System_Settings.objects.get()
        # Check if there was an error stored on the request (from middleware)
        if hasattr(request, "system_settings_error"):
            error_msg = request.system_settings_error
            messages.add_message(
                request,
                messages.WARNING,
                f"Warning: Unable to load system settings from database: {error_msg}. "
                "Default values are being used. Please check your database configuration and run migrations if needed.",
                extra_tags="alert-warning",
            )
            # Clear after adding message
            delattr(request, "system_settings_error")
    except Exception:
        # If we can't get settings, return empty dict (will cause errors elsewhere, but that's expected)
        return {}

    return {"system_settings": system_settings}


def bind_announcement(request):
    with contextlib.suppress(Exception):  # TODO: this should be replaced with more meaningful exception
        if request.user.is_authenticated:
            user_announcement = UserAnnouncement.objects.select_related(
                "announcement",
            ).get(user=request.user)
            return {"announcement": user_announcement.announcement}
    return {}


from orasec.notifications.context_processors import (  # noqa: E402, F401  -- backward compat
    bind_alert_count,
    session_expiry_notification,
)


def labels(request):
    return {
        "labels": get_labels(),
    }

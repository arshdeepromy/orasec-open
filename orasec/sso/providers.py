"""
Identity providers for single sign-on. Each one is a plugin that an administrator turns on or off.

- ``oidc``   any OpenID Connect provider (tested with Authentik). Settings ORASEC_OIDC_*.
- ``entra``  Microsoft Entra ID through the v2.0 endpoint. Settings ORASEC_ENTRA_*.
- ``okta``   Okta, org or custom authorization server. Settings ORASEC_OKTA_*.

Active Directory over LDAPS is not OpenID Connect and lives in ``orasec.sso.ldap``.

The same rules hold for every provider: only an existing, active OraSec account can sign in (matched by e-mail
address), no account is created, no permission is changed by a sign-in, and the local login stays available as
break-glass.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from django.conf import settings

GENERIC = "oidc"
MULTI_TENANT = {"common", "organizations", "consumers"}


@dataclass(frozen=True)
class Provider:

    key: str
    plugin: str                 # key in orasec.plugins.registry
    label: str                  # text of the button on the login page
    switched_on: bool           # the ORASEC_*_ENABLED setting
    discovery_url: str
    client_id: str
    client_secret: str
    # Issuer every ID token must carry. "" takes it from the discovery document (Entra, where a multi-tenant
    # registration advertises a template that is filled in from the token's own tenant, checked against the list).
    issuer: str = ""
    scopes: str = "openid email profile"
    allowed_group: str = ""
    group_claims: tuple = ("groups",)
    email_claims: tuple = ("email",)
    allowed_tenants: tuple = ()
    redirect_uri: str = ""
    missing: str = ""           # what is not set yet, for the Plugins page

    @property
    def configured(self) -> bool:
        return bool(self.switched_on and self.discovery_url and self.client_id and not self.missing)


def _s(name, default=""):
    return str(getattr(settings, name, default) or "").strip()


def _split(text):
    return tuple(x for x in re.split(r"[\s,]+", text or "") if x)


def generic() -> Provider:
    iss = _s("ORASEC_OIDC_ISSUER")
    iss = iss if not iss or iss.endswith("/") else iss + "/"
    return Provider(
        key=GENERIC, plugin="sso", label=_s("ORASEC_OIDC_BUTTON_TEXT", "Sign in with SSO") or "Sign in with SSO",
        switched_on=bool(getattr(settings, "ORASEC_OIDC_ENABLED", False)),
        discovery_url=iss + ".well-known/openid-configuration" if iss else "", issuer=iss,
        client_id=_s("ORASEC_OIDC_CLIENT_ID"), client_secret=_s("ORASEC_OIDC_CLIENT_SECRET"),
        allowed_group=_s("ORASEC_OIDC_ALLOWED_GROUP"), redirect_uri=_s("ORASEC_OIDC_REDIRECT_URI"),
        missing="" if iss and _s("ORASEC_OIDC_CLIENT_ID") else "Set ORASEC_OIDC_ENABLED, ORASEC_OIDC_ISSUER and ORASEC_OIDC_CLIENT_ID on the server.")


def entra() -> Provider:
    tenant = _s("ORASEC_ENTRA_TENANT_ID")
    allowed = _split(_s("ORASEC_ENTRA_ALLOWED_TENANTS"))
    multi = tenant.lower() in MULTI_TENANT
    missing = ""
    if not tenant or not _s("ORASEC_ENTRA_CLIENT_ID"):
        missing = "Set ORASEC_ENTRA_ENABLED, ORASEC_ENTRA_TENANT_ID, ORASEC_ENTRA_CLIENT_ID and ORASEC_ENTRA_CLIENT_SECRET on the server."
    elif multi and not allowed:
        # without the list every Microsoft tenant in the world could reach the sign-in
        missing = "This is a multi-tenant registration: list the tenants that may sign in in ORASEC_ENTRA_ALLOWED_TENANTS."
    elif not re.fullmatch(r"[A-Za-z0-9.\-]+", tenant):
        missing = "ORASEC_ENTRA_TENANT_ID must be a tenant id (GUID) or a verified domain."
    return Provider(
        key="entra", plugin="sso.entra", label=_s("ORASEC_ENTRA_BUTTON_TEXT") or "Sign in with Microsoft",
        switched_on=bool(getattr(settings, "ORASEC_ENTRA_ENABLED", False)),
        discovery_url=f"https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration" if tenant and not missing else "",
        client_id=_s("ORASEC_ENTRA_CLIENT_ID"), client_secret=_s("ORASEC_ENTRA_CLIENT_SECRET"),
        allowed_group=_s("ORASEC_ENTRA_ALLOWED_GROUP"), group_claims=("groups", "roles"),
        email_claims=("email", "preferred_username", "upn"), allowed_tenants=allowed if multi else (),
        redirect_uri=_s("ORASEC_ENTRA_REDIRECT_URI"), missing=missing)


def okta() -> Provider:
    domain = re.sub(r"^https?://", "", _s("ORASEC_OKTA_DOMAIN")).rstrip("/")
    server = _s("ORASEC_OKTA_AUTH_SERVER", "default") or "default"
    missing = ""
    if not domain or not _s("ORASEC_OKTA_CLIENT_ID"):
        missing = "Set ORASEC_OKTA_ENABLED, ORASEC_OKTA_DOMAIN, ORASEC_OKTA_CLIENT_ID and ORASEC_OKTA_CLIENT_SECRET on the server."
    elif not re.fullmatch(r"[A-Za-z0-9.\-]+", domain) or not re.fullmatch(r"[A-Za-z0-9_\-]+", server):
        missing = "ORASEC_OKTA_DOMAIN must be a host name such as example.okta.com, and ORASEC_OKTA_AUTH_SERVER an id."
    # "org" is the Org authorization server (issuer at the root); anything else is a custom server, "default"
    # unless renamed, and then both the metadata path and the iss claim carry /oauth2/<id>.
    issuer = (f"https://{domain}" if server == "org" else f"https://{domain}/oauth2/{server}") if domain and not missing else ""
    return Provider(
        key="okta", plugin="sso.okta", label=_s("ORASEC_OKTA_BUTTON_TEXT") or "Sign in with Okta",
        switched_on=bool(getattr(settings, "ORASEC_OKTA_ENABLED", False)),
        discovery_url=issuer + "/.well-known/openid-configuration" if issuer else "", issuer=issuer,
        client_id=_s("ORASEC_OKTA_CLIENT_ID"), client_secret=_s("ORASEC_OKTA_CLIENT_SECRET"),
        # "groups" only produces a claim when the app's ID token group filter allows it
        scopes="openid email profile groups", allowed_group=_s("ORASEC_OKTA_ALLOWED_GROUP"),
        redirect_uri=_s("ORASEC_OKTA_REDIRECT_URI"), missing=missing)


BUILDERS = {GENERIC: generic, "entra": entra, "okta": okta}


def get(key=GENERIC) -> Provider | None:
    build = BUILDERS.get(key or GENERIC)
    return build() if build else None


def is_enabled(key=GENERIC) -> bool:
    """Configured on the server and its plugin switched on."""
    p = get(key)
    if not p or not p.configured:
        return False
    from orasec.plugins import registry as plugins  # noqa: PLC0415
    return plugins.is_on(p.plugin)


def login_buttons() -> list[dict]:
    """The extra providers for the login page. The generic one keeps its own button and address."""
    return [{"key": k, "label": get(k).label} for k in BUILDERS if k != GENERIC and is_enabled(k)]


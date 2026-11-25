"""OpenID Connect sign-in for OraSec ("Sign in with SSO").

Authorization code flow with PKCE against your identity provider
(tested with Authentik). No extra dependencies: PyJWT verifies the
ID token and the back-channel logout token against the provider's JWKS.

Providers (``orasec.sso.providers``): the generic one (ORASEC_OIDC_*), Microsoft Entra ID
(ORASEC_ENTRA_*) and Okta (ORASEC_OKTA_*). Every function here takes the provider key and
defaults to the generic one.

Rules:
- Only existing, active OraSec accounts can sign in (matched by e-mail). No
  account is created and no permission is changed by a sign-in.
- The person must be in the allowed group (ORASEC_OIDC_ALLOWED_GROUP).
- An SSO session lasts at most ORASEC_OIDC_SESSION_HOURS.
- The local username/password login stays available (break-glass).
"""
import base64
import hashlib
import logging
import secrets
import time

import jwt
import requests
from django.conf import settings
from django.core.cache import cache

from orasec.sso import providers

logger = logging.getLogger(__name__)

BACKCHANNEL_EVENT = "http://schemas.openid.net/event/backchannel-logout"
# A clear user agent: Cloudflare bot protection in front of the identity provider blocks default library agents.
HEADERS = {"User-Agent": "OraSec-SSO/1.0"}
_JWKS_CLIENTS = {}


def enabled(provider=providers.GENERIC):
    return providers.is_enabled(provider)


def _provider(provider=providers.GENERIC):
    p = providers.get(provider)
    if p is None:
        msg = f"unknown sign-in provider: {provider}"
        raise ValueError(msg)
    return p


def _issuer():
    return _provider().issuer


def discovery(provider=providers.GENERIC):
    p = _provider(provider)
    key = "orasec:oidc:discovery" if p.key == providers.GENERIC else f"orasec:oidc:discovery:{p.key}"
    doc = cache.get(key)
    if not doc:
        r = requests.get(p.discovery_url, headers=HEADERS, timeout=10)
        r.raise_for_status()
        doc = r.json()
        for required in ("issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"):
            if not doc.get(required):
                msg = f"the discovery document has no {required}"
                raise ValueError(msg)
        cache.set(key, doc, 3600)
    return doc


def _jwks_client(provider=providers.GENERIC):
    uri = discovery(provider)["jwks_uri"]
    if uri not in _JWKS_CLIENTS:
        _JWKS_CLIENTS[uri] = jwt.PyJWKClient(uri, cache_keys=True, lifespan=3600, headers=HEADERS)
    return _JWKS_CLIENTS[uri]


def expected_issuer(provider, id_token):
    """The issuer this particular ID token must carry.

    Nearly always the provider's own issuer. The exception is a multi-tenant Entra registration, whose discovery
    document advertises the template ``https://login.microsoftonline.com/{tenantid}/v2.0`` because the real issuer
    depends on the tenant the person signed in from. Skipping the issuer check there would accept every Microsoft
    tenant, so the template is filled in from the token's ``tid`` claim, and ``tid`` must be on the allow-list.
    The token is not trusted at this point: the signature and this issuer are verified right after."""
    p = _provider(provider)
    if p.issuer:
        return p.issuer
    issuer = str(discovery(provider)["issuer"])
    if "{tenantid}" not in issuer:
        return issuer
    tid = str(jwt.decode(id_token, options={"verify_signature": False}).get("tid") or "")
    if not tid or tid.lower() not in {t.lower() for t in p.allowed_tenants}:
        raise ValueError("the sign-in came from a tenant that is not allowed")
    return issuer.replace("{tenantid}", tid)


def _b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def start(request, redirect_uri, next_url, provider=providers.GENERIC):
    """Return the provider URL to send the browser to, and remember state in the session."""
    p = _provider(provider)
    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)
    verifier = secrets.token_urlsafe(48)
    challenge = _b64url(hashlib.sha256(verifier.encode()).digest())
    request.session["oidc"] = {"state": state, "nonce": nonce, "verifier": verifier,
                               "next": next_url, "ts": int(time.time()), "provider": p.key}
    params = {
        "response_type": "code",
        "client_id": p.client_id,
        "redirect_uri": redirect_uri,
        "scope": p.scopes,
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    return requests.Request("GET", discovery(p.key)["authorization_endpoint"], params=params).prepare().url


def finish(request, redirect_uri, provider=providers.GENERIC):
    """Validate the callback and return the verified ID-token claims (raises ValueError)."""
    p = _provider(provider)
    pending = request.session.pop("oidc", None)
    if not pending:
        raise ValueError("no sign-in in progress")
    if pending.get("provider", providers.GENERIC) != p.key:
        raise ValueError("the answer came back to a different provider than the one the sign-in started with")
    if time.time() - pending["ts"] > 600:
        raise ValueError("sign-in took too long")
    if not secrets.compare_digest(request.GET.get("state", ""), pending["state"]):
        raise ValueError("state mismatch")
    if request.GET.get("error"):
        raise ValueError("provider error: " + request.GET.get("error_description", request.GET["error"])[:200])
    code = request.GET.get("code")
    if not code:
        raise ValueError("no code")
    r = requests.post(discovery(p.key)["token_endpoint"], data={
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "code_verifier": pending["verifier"],
    }, auth=(p.client_id, p.client_secret), headers=HEADERS, timeout=15)
    if r.status_code != 200:
        raise ValueError(f"token endpoint returned {r.status_code}")
    id_token = r.json().get("id_token")
    if not id_token:
        raise ValueError("no id_token")
    issuer = expected_issuer(p.key, id_token)
    key = _jwks_client(p.key).get_signing_key_from_jwt(id_token)
    claims = jwt.decode(id_token, key.key, algorithms=["RS256", "ES256"],
                        audience=p.client_id, issuer=issuer, leeway=30)
    if claims.get("nonce") != pending["nonce"]:
        raise ValueError("nonce mismatch")
    return claims, pending.get("next") or settings.LOGIN_REDIRECT_URL


def claim_email(claims, provider=providers.GENERIC):
    """The e-mail address the provider vouches for. Entra often sends no ``email`` and puts the sign-in name,
    which has the form of an address, in ``preferred_username``."""
    for name in _provider(provider).email_claims:
        value = str(claims.get(name) or "").strip()
        if value and "@" in value and " " not in value:
            return value
    return ""


def claim_groups(claims, provider=providers.GENERIC):
    """Group names or ids (and Entra app roles) from the token, and whether the provider left groups out.

    Entra leaves ``groups`` out when a person is in more groups than fit in a token and sends a pointer in
    ``_claim_names`` instead. That must read as "cannot tell", not as "in no group"."""
    names = claims.get("_claim_names")
    overage = isinstance(names, dict) and "groups" in names
    out = []
    for name in _provider(provider).group_claims:
        value = claims.get(name) or []
        out.extend(str(v) for v in ([value] if isinstance(value, str) else value))
    return out, overage


def user_for_claims(claims, provider=providers.GENERIC):
    """The OraSec account for verified identity-provider claims.

    Returns ``(user, None)``, or ``(None, (message, log_reason))`` when the person may not use OraSec.
    One rule for every way in (SSO sign-in and the connector endpoint): a verified e-mail address,
    membership of the allowed group, and exactly one active OraSec account with that address."""
    from django.contrib.auth import get_user_model  # noqa: PLC0415

    p = _provider(provider)
    email = claim_email(claims, p.key)
    if not email or claims.get("email_verified") is False and not settings.ORASEC_OIDC_TRUST_UNVERIFIED_EMAIL:
        return None, ("Your SSO account has no verified e-mail address.", f"no usable email for {claims.get('sub')}")
    groups, overage = claim_groups(claims, p.key)
    allowed = p.allowed_group
    if allowed and allowed not in groups:
        if overage:
            return None, ("Your account is in too many groups for the sign-in to check. Ask an administrator.",
                          f"{email}: the provider left groups out of the token (overage); use an app role as the allowed group")
        return None, ("Your SSO account is not allowed to use OraSec.", f"{email} not in group {allowed}")
    users = list(get_user_model().objects.filter(email__iexact=email))
    if len(users) != 1:
        return None, ("There is no OraSec account for your SSO e-mail address. Ask an administrator.",
                      f"{len(users)} OraSec accounts match {email}")
    user = users[0]
    if not user.is_active:
        return None, ("Your OraSec account is disabled.", f"{email} is inactive in OraSec")
    return user, None


def verify_logout_token(token):
    """Verify an OIDC back-channel logout token; return its claims (raises on failure)."""
    key = _jwks_client().get_signing_key_from_jwt(token)
    claims = jwt.decode(token, key.key, algorithms=["RS256", "ES256"],
                        audience=settings.ORASEC_OIDC_CLIENT_ID, issuer=_issuer(), leeway=30,
                        options={"require": ["iat", "events"]})
    if BACKCHANNEL_EVENT not in (claims.get("events") or {}):
        raise ValueError("not a back-channel logout token")
    if "nonce" in claims:
        raise ValueError("logout token must not contain a nonce")
    if not (claims.get("sub") or claims.get("sid")):
        raise ValueError("logout token has no sub or sid")
    jti = claims.get("jti")
    if jti:
        if not cache.add(f"orasec:oidc:jti:{jti}", 1, 3600):
            raise ValueError("logout token replayed")
    return claims


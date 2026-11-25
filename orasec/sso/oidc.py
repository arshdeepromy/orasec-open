"""OpenID Connect sign-in for OraSec ("Sign in with SSO").

Authorization code flow with PKCE against your identity provider
(tested with Authentik). No extra dependencies: PyJWT verifies the
ID token and the back-channel logout token against the provider's JWKS.

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

logger = logging.getLogger(__name__)

BACKCHANNEL_EVENT = "http://schemas.openid.net/event/backchannel-logout"
# A clear user agent: Cloudflare bot protection in front of the identity provider blocks default library agents.
HEADERS = {"User-Agent": "OraSec-SSO/1.0"}
_JWKS_CLIENTS = {}


def enabled():
    if not (getattr(settings, "ORASEC_OIDC_ENABLED", False) and settings.ORASEC_OIDC_ISSUER and settings.ORASEC_OIDC_CLIENT_ID):
        return False
    from orasec.plugins import registry as plugins  # noqa: PLC0415
    return plugins.is_on("sso")


def _issuer():
    iss = settings.ORASEC_OIDC_ISSUER
    return iss if iss.endswith("/") else iss + "/"


def discovery():
    key = "orasec:oidc:discovery"
    doc = cache.get(key)
    if not doc:
        r = requests.get(_issuer() + ".well-known/openid-configuration", headers=HEADERS, timeout=10)
        r.raise_for_status()
        doc = r.json()
        cache.set(key, doc, 3600)
    return doc


def _jwks_client():
    uri = discovery()["jwks_uri"]
    if uri not in _JWKS_CLIENTS:
        _JWKS_CLIENTS[uri] = jwt.PyJWKClient(uri, cache_keys=True, lifespan=3600, headers=HEADERS)
    return _JWKS_CLIENTS[uri]


def _b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def start(request, redirect_uri, next_url):
    """Return the provider URL to send the browser to, and remember state in the session."""
    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)
    verifier = secrets.token_urlsafe(48)
    challenge = _b64url(hashlib.sha256(verifier.encode()).digest())
    request.session["oidc"] = {"state": state, "nonce": nonce, "verifier": verifier,
                               "next": next_url, "ts": int(time.time())}
    params = {
        "response_type": "code",
        "client_id": settings.ORASEC_OIDC_CLIENT_ID,
        "redirect_uri": redirect_uri,
        "scope": "openid email profile",
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    return requests.Request("GET", discovery()["authorization_endpoint"], params=params).prepare().url


def finish(request, redirect_uri):
    """Validate the callback and return the verified ID-token claims (raises ValueError)."""
    pending = request.session.pop("oidc", None)
    if not pending:
        raise ValueError("no sign-in in progress")
    if time.time() - pending["ts"] > 600:
        raise ValueError("sign-in took too long")
    if not secrets.compare_digest(request.GET.get("state", ""), pending["state"]):
        raise ValueError("state mismatch")
    if request.GET.get("error"):
        raise ValueError("provider error: " + request.GET.get("error_description", request.GET["error"])[:200])
    code = request.GET.get("code")
    if not code:
        raise ValueError("no code")
    r = requests.post(discovery()["token_endpoint"], data={
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "code_verifier": pending["verifier"],
    }, auth=(settings.ORASEC_OIDC_CLIENT_ID, settings.ORASEC_OIDC_CLIENT_SECRET), headers=HEADERS, timeout=15)
    if r.status_code != 200:
        raise ValueError(f"token endpoint returned {r.status_code}")
    id_token = r.json().get("id_token")
    if not id_token:
        raise ValueError("no id_token")
    key = _jwks_client().get_signing_key_from_jwt(id_token)
    claims = jwt.decode(id_token, key.key, algorithms=["RS256", "ES256"],
                        audience=settings.ORASEC_OIDC_CLIENT_ID, issuer=_issuer(), leeway=30)
    if claims.get("nonce") != pending["nonce"]:
        raise ValueError("nonce mismatch")
    return claims, pending.get("next") or settings.LOGIN_REDIRECT_URL


def user_for_claims(claims):
    """The OraSec account for verified identity-provider claims.

    Returns ``(user, None)``, or ``(None, (message, log_reason))`` when the person may not use OraSec.
    One rule for every way in (SSO sign-in and the connector endpoint): a verified e-mail address,
    membership of the allowed group, and exactly one active OraSec account with that address."""
    from django.contrib.auth import get_user_model  # noqa: PLC0415

    email = (claims.get("email") or "").strip()
    if not email or claims.get("email_verified") is False and not settings.ORASEC_OIDC_TRUST_UNVERIFIED_EMAIL:
        return None, ("Your SSO account has no verified e-mail address.", f"no usable email for {claims.get('sub')}")
    groups = claims.get("groups") or []
    allowed = settings.ORASEC_OIDC_ALLOWED_GROUP
    if allowed and allowed not in groups:
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


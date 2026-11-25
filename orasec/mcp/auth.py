"""
Who is calling the connector endpoint.

Identity comes only from the bearer token on the request. There is no service account and
no "act as" argument anywhere. Two kinds of token are accepted:

1. An OAuth access token from the identity provider (your SSO). Signature, issuer, audience
   and expiry are checked, then the provider is asked about the token (so a person who was
   disabled or removed from the group is refused on the next call), and the person is mapped to
   an OraSec account by the same rule as SSO sign-in (``orasec.sso.oidc.user_for_claims``).
2. Optionally, the person's own API token, only when that token has an expiry date.
"""
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from typing import Any

import jwt
import requests
from django.core.cache import cache

from orasec.mcp import config
from orasec.sso import oidc

logger = logging.getLogger(__name__)
_JWKS_CLIENTS: dict[str, Any] = {}


class Refused(Exception):  # noqa: N818 -- an answer to the caller, not a program error

    """The call is not accepted. ``status`` is the HTTP status; ``error`` the OAuth error code, if any."""

    def __init__(self, status: int, error: str, message: str, log: str = ""):
        super().__init__(message)
        self.status, self.error, self.message, self.log = status, error, message, log or message


@dataclass
class Identity:
    user: Any
    via: str                      # "oauth" | "api_token"
    client_id: str = ""
    claims: dict[str, Any] = field(default_factory=dict)
    token_key: str = ""           # short hash of the token, only to label calls of one connection


def bearer(request) -> str | None:
    parts = (request.headers.get("Authorization") or "").split()
    if len(parts) == 2 and parts[0].lower() == "bearer" and parts[1]:
        return parts[1]
    return None


def discovery() -> dict[str, Any]:
    iss = config.issuer()
    key = "orasec:mcp:discovery:" + hashlib.sha256(iss.encode()).hexdigest()[:16]
    doc = cache.get(key)
    if not doc:
        r = requests.get(iss + ".well-known/openid-configuration", headers=oidc.HEADERS, timeout=10)
        r.raise_for_status()
        doc = r.json()
        cache.set(key, doc, 3600)
    return doc


def _jwks_client():
    uri = discovery()["jwks_uri"]
    if uri not in _JWKS_CLIENTS:
        _JWKS_CLIENTS[uri] = jwt.PyJWKClient(uri, cache_keys=True, lifespan=3600, headers=oidc.HEADERS)
    return _JWKS_CLIENTS[uri]


def _userinfo(token: str) -> dict[str, Any]:
    r = requests.get(discovery()["userinfo_endpoint"], headers={**oidc.HEADERS, "Authorization": f"Bearer {token}"}, timeout=8)
    if r.status_code in (400, 401, 403):
        raise Refused(401, "invalid_token", "The identity provider no longer accepts this token.",
                      f"userinfo answered {r.status_code}")
    r.raise_for_status()
    return r.json()


def _oauth(token: str) -> Identity:
    iss = config.issuer()
    try:
        key = _jwks_client().get_signing_key_from_jwt(token)
        claims = jwt.decode(token, key.key, algorithms=["RS256", "ES256"], audience=config.client_ids(), issuer=iss,
                            leeway=30, options={"require": ["exp", "iat", "iss", "aud", "sub"]})
    except jwt.ExpiredSignatureError:
        raise Refused(401, "invalid_token", "The access token has expired.") from None
    except jwt.InvalidAudienceError:
        raise Refused(401, "invalid_token", "The access token was not issued for this server.", "wrong audience") from None
    except jwt.InvalidIssuerError:
        raise Refused(401, "invalid_token", "The access token is from another issuer.", "wrong issuer") from None
    except (jwt.exceptions.PyJWKClientConnectionError, requests.RequestException) as e:
        raise Refused(503, "", "The identity provider cannot be reached, so the call is refused. Try again shortly.",
                      f"identity provider unreachable: {type(e).__name__}") from None
    except jwt.PyJWTError as e:
        raise Refused(401, "invalid_token", "The access token is not valid.", f"token rejected: {type(e).__name__}") from None
    if config.userinfo_check():
        try:
            info = _userinfo(token)
        except Refused:
            raise
        except (requests.RequestException, ValueError) as e:
            raise Refused(503, "", "The identity provider cannot be reached, so the call is refused. Try again shortly.",
                          f"userinfo unreachable: {type(e).__name__}") from None
        if info.get("sub") != claims.get("sub"):
            raise Refused(401, "invalid_token", "The access token is not valid.", "userinfo subject mismatch")
        claims = {**claims, **info}
    user, why = oidc.user_for_claims(claims)
    if not user:
        raise Refused(401, "invalid_token", why[0], why[1])
    aud = claims.get("aud")
    client_id = str(claims.get("azp") or (aud[0] if isinstance(aud, list) and aud else aud) or "")
    return Identity(user=user, via="oauth", client_id=client_id[:200], claims=claims)


def _api_token(token: str) -> Identity:
    from rest_framework.exceptions import AuthenticationFailed  # noqa: PLC0415

    from orasec.user.authentication import ExpiringTokenAuthentication, token_expires_at  # noqa: PLC0415

    try:
        user, tok = ExpiringTokenAuthentication().authenticate_credentials(token)
    except AuthenticationFailed as e:
        raise Refused(401, "invalid_token", "The API token is not valid, has expired, or the account is disabled.",
                      f"api token rejected: {e.detail}") from None
    if token_expires_at(tok) is None:
        raise Refused(401, "invalid_token", "API tokens without an expiry date are not accepted here.",
                      f"api token of {user.username} has no expiry")
    return Identity(user=user, via="api_token", client_id="api-token")


def authenticate(request) -> Identity:
    """The person behind this request, or :class:`Refused`. The token is read from the header only."""
    token = bearer(request)
    if not token:
        raise Refused(401, "", "Sign-in is required.", "no token")
    looks_like_jwt = token.count(".") == 2
    if looks_like_jwt and config.oauth_configured():
        ident = _oauth(token)
    elif not looks_like_jwt and config.api_token_allowed():
        ident = _api_token(token)
    else:
        raise Refused(401, "invalid_token", "This kind of token is not accepted.", "token kind not accepted")
    if not ident.user.is_active:
        raise Refused(401, "invalid_token", "Your OraSec account is disabled.", f"{ident.user.username} is inactive")
    ident.token_key = hashlib.sha256(token.encode()).hexdigest()[:32]
    return ident


def challenge(request, refused: Refused | None = None) -> str:
    """The ``WWW-Authenticate`` value: where a client finds the sign-in metadata."""
    parts = []
    if config.oauth_configured():
        parts.append(f'resource_metadata="{config.metadata_url(request)}"')
        parts.append(f'scope="{" ".join(config.SCOPES)}"')
    else:
        parts.append('realm="OraSec"')
    if refused is not None and refused.error:
        parts.append(f'error="{refused.error}"')
        parts.append('error_description="{}"'.format(refused.message.replace('"', "'")))
    return "Bearer " + ", ".join(parts)

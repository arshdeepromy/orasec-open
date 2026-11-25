"""Views for SSO sign-in and back-channel logout."""
import logging

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import get_user_model, login
from django.contrib.sessions.models import Session
from django.http import HttpResponse, HttpResponseBadRequest
from django.shortcuts import redirect
from django.urls import reverse
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from orasec.sso import oidc

logger = logging.getLogger(__name__)
SSO_BACKEND = "django.contrib.auth.backends.ModelBackend"


def _redirect_uri(request):
    # Behind Cloudflare/nginx the request looks like plain http, so production pins the exact URL.
    return settings.ORASEC_OIDC_REDIRECT_URI or request.build_absolute_uri(reverse("oidc_callback"))


def _fail(request, why, log_reason):
    logger.warning("sso: sign-in refused: %s", log_reason)
    messages.add_message(request, messages.ERROR, why, extra_tags="alert-danger")
    return redirect(settings.LOGIN_URL)


@never_cache
def oidc_login(request):
    if not oidc.enabled():
        return redirect(settings.LOGIN_URL)
    nxt = request.GET.get("next") or settings.LOGIN_REDIRECT_URL
    if not url_has_allowed_host_and_scheme(nxt, allowed_hosts={request.get_host()}, require_https=request.is_secure()):
        nxt = settings.LOGIN_REDIRECT_URL
    try:
        return redirect(oidc.start(request, _redirect_uri(request), nxt))
    except Exception as e:  # noqa: BLE001 - provider down: fall back to the local form
        logger.warning("sso: cannot reach the identity provider: %s", e)
        messages.add_message(request, messages.ERROR,
                             "Single sign-on is not reachable right now. Use the break-glass login if you must.",
                             extra_tags="alert-danger")
        return redirect(settings.LOGIN_URL)


@never_cache
def oidc_callback(request):
    if not oidc.enabled():
        return redirect(settings.LOGIN_URL)
    try:
        claims, nxt = oidc.finish(request, _redirect_uri(request))
    except Exception as e:  # noqa: BLE001
        return _fail(request, "SSO sign-in failed. Please try again.", str(e))
    user, why = oidc.user_for_claims(claims)
    if not user:
        return _fail(request, *why)
    login(request, user, backend=SSO_BACKEND)
    request.session["sso"] = {"sub": claims.get("sub"), "sid": claims.get("sid"), "iss": claims.get("iss")}
    request.session.set_expiry(int(settings.ORASEC_OIDC_SESSION_HOURS * 3600))
    logger.info("sso: %s signed in through SSO", user.username)
    return redirect(nxt)


def end_sessions_for(user_id=None, sid=None, sub=None):
    """Delete OraSec sessions of one person (all of them) or of one SSO session."""
    ended = 0
    for s in Session.objects.filter(expire_date__gt=timezone.now()).iterator():
        data = s.get_decoded()
        sso = data.get("sso") or {}
        if (user_id and str(data.get("_auth_user_id")) == str(user_id)) or (sid and sso.get("sid") == sid) \
                or (sub and sso.get("sub") == sub):
            s.delete()
            ended += 1
    return ended


@csrf_exempt
@require_POST
def oidc_backchannel_logout(request):
    """Called by the identity provider when a session ends or an account is disabled."""
    if not oidc.enabled():
        return HttpResponse(status=404)
    token = request.POST.get("logout_token")
    if not token:
        return HttpResponseBadRequest("logout_token missing")
    try:
        claims = oidc.verify_logout_token(token)
    except Exception as e:  # noqa: BLE001
        logger.warning("sso: back-channel logout rejected: %s", e)
        return HttpResponseBadRequest("invalid logout_token")
    sub, sid = claims.get("sub"), claims.get("sid")
    user_id = None
    if sub and "@" in sub:  # the provider sends the e-mail address as sub
        u = get_user_model().objects.filter(email__iexact=sub).first()
        user_id = u.pk if u else None
    ended = end_sessions_for(user_id=user_id, sid=sid, sub=sub)
    logger.info("sso: back-channel logout for sub=%s sid=%s ended %d session(s)", sub, sid, ended)
    resp = HttpResponse(status=200)
    resp["Cache-Control"] = "no-store"
    return resp


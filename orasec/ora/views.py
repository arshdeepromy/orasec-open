"""Ora endpoints.

* Web: ``/orasec/ora/api/...`` -- signed-in session, CSRF header (the page puts the
  token in ``<meta name="ora-csrf">``), JSON in and out.
* App: ``/api/v2/orasec/mobile/ora/...`` -- the mobile app's device token (``mobile_api``).
  Same handlers; every write is POST (the app's CORS allows GET/POST only).
* Superusers: ``/orasec/ora/settings/`` -- provider, limits, usage, unanswered questions, help articles.
"""
from __future__ import annotations

import datetime
import functools
import hashlib
import json
import logging
import pathlib

from django.contrib import messages
from django.contrib.auth.decorators import user_passes_test
from django.db.models import Count, Q, Sum
from django.db.models.functions import TruncDate
from django.http import HttpResponse, HttpResponseNotFound, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone

from orasec.mobile.auth import mobile_api
from orasec.ora import config as ora_config
from orasec.ora import guardrails, knowledge, model_catalog, service
from orasec.ora.models import PROVIDERS, OraKbArticle, OraMessage, OraUsage
from orasec.ora.providers.base import ProviderError, ProviderRequest, Turn

logger = logging.getLogger(__name__)
superuser_required = user_passes_test(lambda u: u.is_active and u.is_superuser)


def _json(request):
    try:
        v = json.loads(request.body or b"{}")
        return v if isinstance(v, dict) else {}
    except (ValueError, UnicodeDecodeError):
        return {}


def _ok(data, status=200):
    r = JsonResponse(data, status=status, safe=not isinstance(data, list), json_dumps_params={"default": str})
    r["Cache-Control"] = "no-store"
    return r


def _err(detail, status=400, code="bad_request", mood="sorry"):
    return _ok({"detail": detail, "code": code, "mood": mood}, status)


def web_api(methods=("GET",)):
    """Session JSON endpoint: 401 JSON (not a login redirect), method check, errors as JSON."""
    def deco(view):
        @functools.wraps(view)
        def wrapper(request, *a, **kw):
            if not (request.user.is_authenticated and request.user.is_active):
                return _err("Your session has ended. Sign in again.", 401, "signed_out")
            if request.method not in methods:
                return _err("Method not allowed.", 405)
            return _guard(view, request, *a, **kw)
        return wrapper
    return deco


def _guard(view, request, *a, **kw):
    try:
        return view(request, *a, **kw)
    except guardrails.GuardrailBlock as b:
        return _ok(b.body(), b.status_code)
    except service.ChatError as e:
        return _err(e.detail, e.status, e.code)


def app_api(methods=("GET",)):
    def deco(view):
        @functools.wraps(view)
        def inner(request, *a, **kw):
            return _guard(view, request, *a, **kw)
        return mobile_api(methods)(inner)
    return deco


# ---------------------------------------------------------------------------
# Shared handlers
# ---------------------------------------------------------------------------

def _surface(request):
    return "mobile" if getattr(request, "mobile_device", None) else "web"


def h_status(request):
    return _ok(service.status(request.user))


def h_chat(request):
    b = _json(request)
    page = b.get("page") if isinstance(b.get("page"), dict) else {}
    cid = b.get("conversation_id")
    return _ok(service.chat(request.user, message=str(b.get("message") or ""),
                            conversation_id=int(cid) if str(cid or "").isdigit() else None,
                            page={"path": str(page.get("path") or "")[:300], "title": str(page.get("title") or "")[:160]},
                            surface=_surface(request)))


def h_conversations(request):
    return _ok({"results": service.conversations(request.user)})


def h_conversation(request, cid):
    return _ok(service.conversation(request.user, cid))


def h_conversation_delete(request, cid):
    service.delete_conversation(request.user, cid)
    return _ok({"ok": True})


def h_feedback(request, mid):
    service.feedback(request.user, mid, int(_json(request).get("value") or 0))
    return _ok({"ok": True})


def h_proposal(request, pid):
    return _ok(service.decide(request.user, str(pid), bool(_json(request).get("confirm"))))


def h_preference(request):
    b = _json(request)
    return _ok(service.set_preference(request.user, hidden=b.get("hidden"), notice_ack=b.get("notice_ack")))


def h_memories(request):
    return _ok({"results": service.memories(request.user)})


def h_forget(request):
    mid = _json(request).get("id")
    service.forget(request.user, int(mid) if str(mid or "").isdigit() else None)
    return _ok({"ok": True})


def h_guide(request, gid):
    g = knowledge.guide(gid, request.user)
    if not g:
        return _err("No such guide.", 404, "not_found")
    return _ok(g)


# Web wrappers
status = web_api()(h_status)
chat = web_api(("POST",))(h_chat)
conversations = web_api()(h_conversations)
conversation = web_api()(h_conversation)
conversation_delete = web_api(("POST",))(h_conversation_delete)
feedback = web_api(("POST",))(h_feedback)
proposal = web_api(("POST",))(h_proposal)
preference = web_api(("POST",))(h_preference)
memories = web_api()(h_memories)
forget = web_api(("POST",))(h_forget)
guide = web_api()(h_guide)

# App wrappers
app_status = app_api()(h_status)
app_chat = app_api(("POST",))(h_chat)
app_conversations = app_api()(h_conversations)
app_conversation = app_api()(h_conversation)
app_conversation_delete = app_api(("POST",))(h_conversation_delete)
app_feedback = app_api(("POST",))(h_feedback)
app_proposal = app_api(("POST",))(h_proposal)
app_preference = app_api(("POST",))(h_preference)
app_memories = app_api()(h_memories)
app_forget = app_api(("POST",))(h_forget)


# ---------------------------------------------------------------------------
# Web assets (served by Django: the nginx image's static files are baked at build time)
# ---------------------------------------------------------------------------
_WEB = pathlib.Path(__file__).resolve().parent / "web"
_TYPES = {"ora.js": "application/javascript; charset=utf-8", "ora.css": "text/css; charset=utf-8"}


@functools.lru_cache(maxsize=4)
def _asset_bytes(name):
    return (_WEB / name).read_bytes()


def asset_version():
    return hashlib.sha256(b"".join(_asset_bytes(n) for n in sorted(_TYPES))).hexdigest()[:10]


def asset(request, name):
    if name not in _TYPES or not request.user.is_authenticated:
        return HttpResponseNotFound()
    r = HttpResponse(_asset_bytes(name), content_type=_TYPES[name])
    r["Cache-Control"] = "private, max-age=604800, immutable" if request.GET.get("v") == asset_version() else "private, no-cache"
    r["X-Content-Type-Options"] = "nosniff"
    return r


# ---------------------------------------------------------------------------
# Superuser settings page
# ---------------------------------------------------------------------------

def _usage(days=30):
    since = timezone.now() - datetime.timedelta(days=days)
    qs = OraUsage.objects.filter(created__gte=since)
    tot = qs.aggregate(i=Sum("input_tokens"), o=Sum("output_tokens"), n=Count("id"), bad=Count("id", filter=Q(ok=False)))
    by_feature = list(qs.values("feature").annotate(n=Count("id"), i=Sum("input_tokens"), o=Sum("output_tokens")).order_by("-n"))
    daily = list(qs.annotate(d=TruncDate("created")).values("d")
                 .annotate(n=Count("id"), t=Sum("input_tokens") + Sum("output_tokens")).order_by("d"))
    msgs = OraMessage.objects.filter(role="assistant", created__gte=since).exclude(tool__in=["proposal"])
    return {"calls": tot["n"] or 0, "errors": tot["bad"] or 0, "input": tot["i"] or 0, "output": tot["o"] or 0,
            "by_feature": by_feature, "daily": daily[-14:],
            "answers": msgs.count(), "unanswered": msgs.filter(answered=False).count(),
            "up": msgs.filter(feedback=1).count(), "down": msgs.filter(feedback=-1).count(),
            "off_topic": msgs.filter(in_scope=False).count(), "today_tokens": guardrails.tokens_today()}


def _unanswered(limit=30):
    out = []
    for m in OraMessage.objects.filter(role="assistant").filter(Q(answered=False) | Q(feedback=-1)) \
            .exclude(tool__in=["error", "guard"]).select_related("conversation").order_by("-created")[:limit]:
        q = OraMessage.objects.filter(conversation=m.conversation, role="user", id__lt=m.id).order_by("-id").first()
        if q:
            out.append({"question": guardrails.scrub(q.text)[:300], "answer": m.text[:300], "page": m.page_path,
                        "why": "thumbs down" if m.feedback == -1 else "not answered", "when": m.created})
    return out


@superuser_required
def settings_page(request):
    if request.method == "POST":
        action = request.POST.get("action")
        if action in ("save", "models"):
            data = {k: request.POST.get(k) for k in ("provider", "model", "base_url", "vertex_project", "vertex_region",
                                                     "rate_limit_per_minute", "daily_token_cap", "max_output_tokens",
                                                     "retention_days")}
            data["enabled"] = bool(request.POST.get("enabled"))
            data["memory_enabled"] = bool(request.POST.get("memory_enabled"))
            if request.POST.get("api_key"):
                data["api_key"] = request.POST["api_key"]
            if request.POST.get("clear_api_key"):
                data["clear_api_key"] = True
            if request.POST.get("vertex_service_account"):
                data["vertex_service_account"] = request.POST["vertex_service_account"]
            try:
                before = ora_config.get_config(fresh=True)
                ora_config.save(data, request.user)
                messages.success(request, "Ora settings saved.")
                cfg = ora_config.get_config(fresh=True)
                # Load the provider's model list when asked, or when the provider or key changed and no list is cached yet.
                changed = data.get("api_key") or cfg["provider"] != before["provider"] or cfg["base_url"] != before["base_url"]
                if cfg["provider"] in ("anthropic", "openai") and (action == "models" or (changed and not model_catalog.cached_models(cfg["provider"]))):
                    try:
                        models = model_catalog.fetch_models(cfg)
                        messages.success(request, f"{len(models)} models loaded. Choose the default model and save.")
                    except ProviderError as e:
                        messages.warning(request, f"Could not load the model list: {e}")
            except ora_config.ConfigError as e:
                messages.error(request, f"{e.field}: {e}")
        elif action == "test":
            cfg = ora_config.get_config(fresh=True)
            try:
                from orasec.ora import prompts  # noqa: PLC0415
                from orasec.ora.providers.router import call_ai  # noqa: PLC0415
                r = call_ai(ProviderRequest(system=prompts.TEST_SYSTEM, turns=[Turn("user", "ping")], max_tokens=50,
                                            task="test"), feature="test", user=request.user, cfg=cfg)
                ok = r.data.get("ok") is True
                (messages.success if ok else messages.warning)(
                    request, f"Connection {'OK' if ok else 'answered, but not as expected'} ({r.latency_ms} ms).")
            except ProviderError as e:
                messages.error(request, f"Connection failed: {e}")
        elif action == "kb_save":
            art = OraKbArticle.objects.filter(id=request.POST.get("id")).first() if request.POST.get("id") else OraKbArticle(created_by=request.user)
            art.title = request.POST.get("title", "").strip()[:160]
            art.path = request.POST.get("path", "").strip()[:200]
            art.keywords = [k.strip().lower() for k in request.POST.get("keywords", "").split(",") if k.strip()][:20]
            art.body = guardrails.scrub(request.POST.get("body", "").strip())[:4000]
            art.status = request.POST.get("status") if request.POST.get("status") in ("draft", "published", "archived") else "draft"
            if art.title and art.body:
                art.save()
                messages.success(request, f"Article '{art.title}' saved.")
            else:
                messages.error(request, "An article needs a title and text.")
        elif action == "kb_delete":
            get_object_or_404(OraKbArticle, id=request.POST.get("id")).delete()
            messages.success(request, "Article deleted.")
        return redirect("orasec_ora_settings")
    from orasec.utils import add_breadcrumb  # noqa: PLC0415
    add_breadcrumb(title="Ora assistant", top_level=True, request=request)
    edit = OraKbArticle.objects.filter(id=request.GET.get("kb")).first() if request.GET.get("kb") else None
    cfg_view = ora_config.public_view()
    return render(request, "orasec/ora/settings.html", {
        "cfg": cfg_view, "model_list": model_catalog.cached_models(cfg_view["provider"]),
        "providers": [p for p in PROVIDERS if p[0] != "scripted" or ora_config.scripted_allowed()],
        "usage": _usage(), "unanswered": _unanswered(), "articles": OraKbArticle.objects.order_by("-updated")[:100],
        "builtin": knowledge.ARTICLES, "edit": edit,
    })



"""
The connector endpoint: Streamable HTTP, stateless, plain JSON answers (no long-lived streams).

One POST is one JSON-RPC message. The current protocol revision carries its version and client
details in every request; clients of the earlier revisions start with ``initialize`` and are
served the same way, without a session. Every request must carry a valid token: without one the
answer is 401 with a pointer to the sign-in metadata (RFC 9728).

Each call is checked in this order: endpoint switched on, origin, sign-in, blocks, rate limit,
protocol, tool allowed for this person, arguments. Every call is written to the call log.
"""
from __future__ import annotations

import base64
import json
import logging
import time
from typing import Any
from urllib.parse import urlparse

from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.core.cache import cache
from django.db.models import F
from django.http import Http404, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET

from orasec.mcp import auth, config, guard, registry
from orasec.mcp.models import McpAccess, McpCall, McpClient
from orasec.mobile.auth import client_ip
from orasec.ora import injection
from orasec.posture.views import render, superuser_required

logger = logging.getLogger(__name__)

META_VERSION = "io.modelcontextprotocol/protocolVersion"
META_CLIENT = "io.modelcontextprotocol/clientInfo"
META_CAPS = "io.modelcontextprotocol/clientCapabilities"
META_SERVER = "io.modelcontextprotocol/serverInfo"
HEADER_MISMATCH, UNSUPPORTED_VERSION = -32020, -32022
PARSE_ERROR, INVALID_REQUEST, METHOD_NOT_FOUND, INVALID_PARAMS = -32700, -32600, -32601, -32602
BLOCKED, LIMITED = 4003, 4029      # application codes, outside the range JSON-RPC reserves
MAX_BODY = 256 * 1024
FAILURES_PER_MINUTE = 30
CORS_HEADERS = "authorization, content-type, accept, mcp-protocol-version, mcp-method, mcp-name"


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
def _bump(key: str, ttl: int = 60) -> int:
    try:
        if cache.add(key, 1, ttl):
            return 1
        return int(cache.incr(key))
    except Exception:  # noqa: BLE001 -- a cache outage must not open or break the endpoint
        logger.warning("mcp: rate-limit cache unavailable")
        return 0


def _clean_name(value: Any) -> str:
    text, _ = injection.clean_field(str(value or ""), 120)
    return guard._mask(text).strip()[:120]


def _origin_ok(request, origin: str) -> bool:
    if origin.rstrip("/") in config.allowed_origins():
        return True
    try:
        return urlparse(origin).netloc == request.get_host()
    except ValueError:
        return False


def _cors(request, resp):
    origin = request.headers.get("Origin")
    if origin and origin.rstrip("/") in config.allowed_origins():
        resp["Access-Control-Allow-Origin"] = origin
        resp["Access-Control-Allow-Headers"] = CORS_HEADERS
        resp["Access-Control-Allow-Methods"] = "POST, OPTIONS"
        resp["Access-Control-Expose-Headers"] = "WWW-Authenticate"
        resp["Vary"] = "Origin"
    resp["Cache-Control"] = "no-store"
    return resp


def _error(status: int, rid: Any, code: int, message: str, data: Any = None):
    err: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    body: dict[str, Any] = {"jsonrpc": "2.0", "error": err}
    if rid is not None:
        body["id"] = rid
    return JsonResponse(body, status=status)


def _header_value(raw: str | None) -> str | None:
    """A mirrored header value, decoded when it uses the Base64 form of the specification."""
    if raw is None:
        return None
    if raw.startswith("=?base64?") and raw.endswith("?="):
        try:
            return base64.b64decode(raw[9:-2], validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return None
    return raw


class _Log:

    """Collects what is known about a call and writes one line to the call log."""

    def __init__(self, request):
        self.t0 = time.monotonic()
        self.ip = (client_ip(request) or "")[:64]
        self.ident: auth.Identity | None = None
        self.client_name = _clean_name(request.headers.get("User-Agent"))
        self.method = self.tool = self.args = ""
        self.write = False

    def save(self, outcome: str, detail: str = "") -> None:
        user = self.ident.user if self.ident else None
        try:
            McpCall.objects.create(
                user=user, username=(user.username if user else "")[:150], via=self.ident.via if self.ident else "",
                client_id=(self.ident.client_id if self.ident else "")[:200], client_name=self.client_name, ip=self.ip,
                method=self.method[:40], tool=self.tool[:80], args=self.args[:300], outcome=outcome,
                detail=guard._mask(detail or "")[:300], write=self.write, ms=int((time.monotonic() - self.t0) * 1000))
        except Exception:  # noqa: BLE001 -- a logging problem is reported, the answer still goes out
            logger.exception("mcp: could not write the call log")


# ---------------------------------------------------------------------------
# The endpoint
# ---------------------------------------------------------------------------
@csrf_exempt
def endpoint(request):  # noqa: C901, PLR0911, PLR0912, PLR0915 -- one linear checklist, kept in one place on purpose
    if not config.enabled():
        raise Http404
    origin = request.headers.get("Origin")
    if request.method == "OPTIONS":
        if origin and origin.rstrip("/") in config.allowed_origins():
            return _cors(request, HttpResponse(status=204))
        return HttpResponse(status=403)
    if request.method != "POST":
        resp = _error(405, None, INVALID_REQUEST, "This endpoint accepts POST only.")
        resp["Allow"] = "POST"
        return resp
    log = _Log(request)

    def out(resp, outcome: str, detail: str = ""):
        log.save(outcome, detail)
        return _cors(request, resp)

    if origin and not _origin_ok(request, origin):
        return out(_error(403, None, INVALID_REQUEST, "This origin is not allowed."), "refused", f"origin {origin[:120]}")

    # ---- who is calling ------------------------------------------------------------------
    fail_key = f"mcp:fail:{log.ip}"
    try:
        too_many = int(cache.get(fail_key) or 0) >= FAILURES_PER_MINUTE
    except Exception:  # noqa: BLE001
        too_many = False
    if too_many:
        resp = _error(429, None, LIMITED, "Too many refused calls from this address. Wait a minute.")
        resp["Retry-After"] = "60"
        return _cors(request, resp)   # not logged again: the refused calls that led here already are
    try:
        ident = auth.authenticate(request)
    except auth.Refused as r:
        resp = JsonResponse({"error": r.error or "unauthorized", "error_description": r.message}, status=r.status)
        if r.status == 401:
            _bump(fail_key)
            resp["WWW-Authenticate"] = auth.challenge(request, r)
        elif r.status == 503:
            resp["Retry-After"] = "30"
        return out(resp, "refused", r.log)
    log.ident = ident
    user = ident.user

    # ---- the message ---------------------------------------------------------------------
    if len(request.body) > MAX_BODY:
        return out(_error(413, None, INVALID_REQUEST, "The request is too large."), "bad_request", "body too large")
    try:
        msg = json.loads(request.body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return out(_error(400, None, PARSE_ERROR, "The request is not valid JSON."), "bad_request", "parse error")
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" or not isinstance(msg.get("method"), str):
        return out(_error(400, None, INVALID_REQUEST, "Send one JSON-RPC 2.0 request per POST."), "bad_request", "not a request")
    method = msg["method"]
    params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
    is_notification = "id" not in msg
    rid = msg.get("id")
    if not is_notification and (isinstance(rid, bool) or not isinstance(rid, (str, int))):
        return out(_error(400, None, INVALID_REQUEST, "The request id must be a string or a number."), "bad_request", "bad id")
    log.method = method
    meta = params.get("_meta") if isinstance(params.get("_meta"), dict) else {}
    modern = META_VERSION in meta

    # ---- which client (a label for the person's list and the log; never used for access) ----
    label_key = f"mcp:label:{ident.token_key}"
    info = meta.get(META_CLIENT) if modern else (params.get("clientInfo") if method == "initialize" else None)
    if isinstance(info, dict) and info.get("name"):
        log.client_name = _clean_name(f"{info.get('name')} {info.get('version') or ''}")
        if not modern:
            cache.set(label_key, log.client_name, 86400)
    elif not modern:
        log.client_name = cache.get(label_key) or log.client_name

    # ---- blocks and rate limit -----------------------------------------------------------
    if McpAccess.objects.filter(user=user, blocked_at__isnull=False).exists():
        return out(_error(403, rid, BLOCKED, "Connector access is switched off for your account."), "refused", "account blocked")
    client, _ = McpClient.objects.get_or_create(user=user, kind=ident.via, client_id=ident.client_id, client_name=log.client_name)
    if client.blocked_at:
        return out(_error(403, rid, BLOCKED, "This client was blocked on your Connected clients page in OraSec."),
                   "refused", "client blocked")
    McpClient.objects.filter(pk=client.pk).update(last_seen=timezone.now(), last_ip=log.ip, calls=F("calls") + 1)
    if _bump(f"mcp:rl:{user.pk}") > config.rate_per_minute():
        resp = _error(429, rid, LIMITED, "Too many calls. Wait a minute and try again.")
        resp["Retry-After"] = "60"
        return out(resp, "limited", "rate limit")

    # ---- protocol ------------------------------------------------------------------------
    header_version = request.headers.get("MCP-Protocol-Version")
    supported = [*config.MODERN, *config.LEGACY]
    if modern:
        version = meta.get(META_VERSION)
        if header_version != version:
            return out(_error(400, rid, HEADER_MISMATCH, "Header mismatch: MCP-Protocol-Version does not match the request body."),
                       "bad_request", "version header mismatch")
        if version not in config.MODERN:
            return out(_error(400, rid, UNSUPPORTED_VERSION, "Unsupported protocol version",
                              {"supported": supported, "requested": version}), "bad_request", f"version {str(version)[:20]}")
        if request.headers.get("Mcp-Method") != method:
            return out(_error(400, rid, HEADER_MISMATCH, "Header mismatch: Mcp-Method does not match the request body."),
                       "bad_request", "method header mismatch")
        if not isinstance(meta.get(META_CAPS), dict):
            return out(_error(400, rid, INVALID_PARAMS, f"Missing {META_CAPS} in _meta."), "bad_request", "no client capabilities")
        if method == "tools/call" and _header_value(request.headers.get("Mcp-Name")) != params.get("name"):
            return out(_error(400, rid, HEADER_MISMATCH, "Header mismatch: Mcp-Name does not match the request body."),
                       "bad_request", "name header mismatch")
    elif header_version in config.MODERN:
        return out(_error(400, rid, INVALID_PARAMS, f"Missing {META_VERSION} in _meta."), "bad_request", "no version in body")
    elif header_version is not None and header_version not in config.LEGACY:
        return out(_error(400, rid, UNSUPPORTED_VERSION, "Unsupported protocol version",
                          {"supported": supported, "requested": header_version}), "bad_request", f"version {header_version[:20]}")
    if is_notification:
        return out(HttpResponse(status=202), "ok")

    def result(payload: dict[str, Any], outcome: str = "ok", detail: str = ""):
        if modern:
            payload = {"resultType": "complete", **payload, "_meta": {META_SERVER: config.SERVER_INFO}}
        return out(JsonResponse({"jsonrpc": "2.0", "id": rid, "result": payload}), outcome, detail)

    capabilities = {"tools": {"listChanged": False}}
    if method == "initialize" and not modern:
        asked = params.get("protocolVersion")
        return result({"protocolVersion": asked if asked in config.LEGACY else config.LEGACY[0], "capabilities": capabilities,
                       "serverInfo": config.SERVER_INFO, "instructions": config.INSTRUCTIONS})
    if method == "server/discover" and modern:
        return result({"supportedVersions": supported, "capabilities": capabilities, "instructions": config.INSTRUCTIONS,
                       "ttlMs": 300000, "cacheScope": "private"})
    if method == "ping":
        return result({})
    if method == "tools/list":
        tools = [t.describe(user) for t in registry.available(user)]
        payload: dict[str, Any] = {"tools": tools}
        if modern:
            payload.update(ttlMs=60000, cacheScope="private")
        return result(payload, detail=f"{len(tools)} tools")
    if method == "tools/call":
        name, args = params.get("name"), params.get("arguments")
        args = {} if args is None else args
        log.tool = _clean_name(name)[:80]
        log.args = guard.summarise_args(args)
        tool = registry.get(user, name)
        if tool is None:   # not there, or not for this person: the same answer for both
            return out(_error(200 if not modern else 400, rid, INVALID_PARAMS, f"Unknown tool: {log.tool}"), "denied", "unknown tool")
        log.write = tool.write
        problem = registry.check_args(tool, user, args)
        if problem:
            return result({"content": [{"type": "text", "text": problem}], "isError": True}, "tool_error", problem)
        try:
            raw = tool.run(registry.Ctx(user=user, client_name=log.client_name), args)
        except Exception:  # noqa: BLE001 -- a tool bug becomes a plain tool error, with the detail in the server log
            logger.exception("mcp: tool %s failed", tool.name)
            raw = {"error": "That did not work. Try again, or open the page in OraSec."}
        failed = isinstance(raw, dict) and bool(raw.get("error") or raw.get("denied"))
        safe, hits, _cut = guard.protect(raw)
        detail = str(raw.get("error") or raw.get("summary") or "")[:200] if failed else ""
        if hits:
            detail = (detail + f" [{hits} instruction-like text removed]").strip()
        return result({"content": [{"type": "text", "text": guard.as_text(safe)}], "structuredContent": safe, "isError": failed},
                      ("denied" if raw.get("denied") else "tool_error") if failed else "ok", detail)
    if modern:
        return out(_error(404, rid, METHOD_NOT_FOUND, f"Method not found. Supported protocol versions: {', '.join(supported)}."),
                   "bad_request", "unknown method")
    return out(_error(200, rid, METHOD_NOT_FOUND, "Method not found."), "bad_request", "unknown method")


@require_GET
def resource_metadata(request):
    """OAuth 2.0 Protected Resource Metadata (RFC 9728): tells a client where to sign in."""
    if not (config.enabled() and config.oauth_configured()):
        raise Http404
    issuer = config.issuer()
    try:
        issuer = auth.discovery().get("issuer") or issuer
    except Exception:  # noqa: BLE001 -- the configured issuer is the answer when the provider is not reachable
        logger.warning("mcp: identity provider discovery failed")
    resp = JsonResponse({"resource": config.resource_url(request), "authorization_servers": [issuer],
                         "scopes_supported": list(config.SCOPES), "bearer_methods_supported": ["header"],
                         "resource_name": "OraSec"})
    resp["Access-Control-Allow-Origin"] = "*"
    resp["Cache-Control"] = "public, max-age=300"
    return resp


# ---------------------------------------------------------------------------
# Pages: a person's connected clients, and the call log for admins
# ---------------------------------------------------------------------------
@login_required
def clients_page(request):
    me = request.user
    admin_view = me.is_superuser and request.GET.get("all") == "1"
    if request.method == "POST":
        action = request.POST.get("action")
        now = timezone.now()
        if action in ("block_client", "allow_client"):
            qs = McpClient.objects.all() if me.is_superuser else McpClient.objects.filter(user=me)
            c = get_object_or_404(qs, pk=request.POST.get("id"))
            c.blocked_at, c.blocked_by = (now, me) if action == "block_client" else (None, None)
            c.save(update_fields=["blocked_at", "blocked_by"])
            messages.success(request, f"{c.client_name or 'Client'} {'blocked' if c.blocked_at else 'allowed again'}.")
        elif action in ("block_all", "allow_all"):
            target = me
            if me.is_superuser and request.POST.get("user"):
                target = get_object_or_404(get_user_model(), pk=request.POST.get("user"))
            acc, _ = McpAccess.objects.get_or_create(user=target)
            acc.blocked_at, acc.blocked_by = (now, me) if action == "block_all" else (None, None)
            acc.save(update_fields=["blocked_at", "blocked_by"])
            messages.success(request, f"Connector access {'switched off' if acc.blocked_at else 'switched on'} for {target.username}.")
        else:
            messages.error(request, "That action is not allowed for you.")
        return redirect(request.get_full_path())
    clients = McpClient.objects.select_related("user") if admin_view else McpClient.objects.filter(user=me)
    blocked_users = McpAccess.objects.filter(blocked_at__isnull=False).select_related("user") if admin_view else []
    return render(request, "orasec/mcp/clients.html", {
        "clients": clients[:300], "admin_view": admin_view, "blocked_users": blocked_users, "enabled": config.enabled(),
        "me_blocked": McpAccess.objects.filter(user=me, blocked_at__isnull=False).exists(),
        "endpoint": config.resource_url(request), "page_title": "Connected clients"})


@superuser_required
def audit_page(request):
    qs = McpCall.objects.select_related("user")
    who, outcome = request.GET.get("user", "").strip(), request.GET.get("outcome", "").strip()
    if who:
        qs = qs.filter(username__iexact=who)
    if outcome:
        qs = qs.filter(outcome=outcome)
    if request.GET.get("writes") == "1":
        qs = qs.filter(write=True)
    try:
        page = max(1, int(request.GET.get("page", "1")))
    except ValueError:
        page = 1
    size = 100
    rows = list(qs[(page - 1) * size:page * size + 1])
    return render(request, "orasec/mcp/audit.html", {
        "rows": rows[:size], "page": page, "has_next": len(rows) > size, "who": who, "outcome": outcome,
        "writes": request.GET.get("writes") == "1", "total": qs.count(), "enabled": config.enabled(),
        "outcomes": ["ok", "tool_error", "denied", "refused", "limited", "bad_request"], "page_title": "Connector call log"})

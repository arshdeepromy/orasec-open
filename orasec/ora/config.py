"""Ora AI settings: read (30 s cache, secrets decrypted) and save (secrets encrypted).

Provider and model names are shown ONLY on the superuser Ora settings page;
they never reach a chat answer (``guardrails.filter_output`` blanks them).
"""
from __future__ import annotations

import json
import re
import time
from typing import Any

from django.conf import settings as dj_settings

from orasec.ora.models import OraSettings
from orasec.utils import orasec_crypto_encrypt, prepare_for_view

_CACHE: tuple[float, dict[str, Any]] | None = None
_TTL = 30.0
_MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@:/-]{0,99}$")


class ConfigError(ValueError):
    def __init__(self, field: str, message: str):
        super().__init__(message)
        self.field = field


def _dec(value: str) -> str:
    if not value:
        return ""
    try:
        return prepare_for_view(value) or ""
    except Exception:  # noqa: BLE001 -- a key that no longer decrypts is simply "not set"
        return ""


def get_config(*, fresh: bool = False) -> dict[str, Any]:
    global _CACHE  # noqa: PLW0603
    now = time.monotonic()
    if not fresh and _CACHE and now - _CACHE[0] < _TTL:
        return _CACHE[1]
    s = OraSettings.load()
    sa = _dec(s.vertex_service_account)
    try:
        sa_obj = json.loads(sa) if sa else None
    except ValueError:
        sa_obj = None
    cfg = {
        "enabled": s.enabled,
        "provider": s.provider,
        "model": s.model,
        "base_url": s.base_url or "",
        "api_key": _dec(s.api_key),
        "vertex_project": s.vertex_project,
        "vertex_region": s.vertex_region or "global",
        "vertex_service_account": sa_obj,
        "rate_limit_per_minute": s.rate_limit_per_minute,
        "daily_token_cap": s.daily_token_cap,
        "max_output_tokens": s.max_output_tokens,
        "retention_days": s.retention_days,
        "memory_enabled": s.memory_enabled,
        "updated": s.updated.isoformat() if s.updated else None,
    }
    _CACHE = (now, cfg)
    return cfg


def invalidate() -> None:
    global _CACHE  # noqa: PLW0603
    _CACHE = None


def scripted_allowed() -> bool:
    """The scripted provider is for test instances only (never with DEBUG off on production)."""
    return bool(getattr(dj_settings, "ORASEC_ORA_ALLOW_SCRIPTED", False))


def is_configured(cfg: dict[str, Any] | None = None) -> bool:
    c = cfg or get_config()
    p = c.get("provider")
    if p == "anthropic":
        return bool(c.get("api_key") and c.get("model"))
    if p == "openai":
        return bool(c.get("model") and c.get("base_url"))
    if p == "vertex":
        sa = c.get("vertex_service_account") or {}
        return bool(c.get("model") and c.get("vertex_project") and sa.get("client_email") and sa.get("private_key"))
    if p == "scripted":
        return scripted_allowed()
    return False


def configured_model_ids(cfg: dict[str, Any] | None = None) -> list[str]:
    """Model ids an answer must never mention (plus their short forms)."""
    c = cfg or get_config()
    m = (c.get("model") or "").strip()
    out = [m] if m else []
    if "/" in m:
        out.append(m.rsplit("/", 1)[-1])
    return [x for x in out if len(x) >= 4]


def public_view(cfg: dict[str, Any] | None = None) -> dict[str, Any]:
    """Settings for the superuser page: secrets shown only as 'set'."""
    c = dict(cfg or get_config(fresh=True))
    sa = c.pop("vertex_service_account", None) or {}
    c["api_key_set"] = bool(c.pop("api_key", ""))
    c["vertex_service_account_email"] = sa.get("client_email", "")
    c["configured"] = is_configured(cfg)
    c["scripted_allowed"] = scripted_allowed()
    return c


def save(payload: dict[str, Any], user) -> dict[str, Any]:
    s = OraSettings.load()
    if "enabled" in payload:
        s.enabled = bool(payload["enabled"])
    if "provider" in payload:
        p = str(payload["provider"])
        if p not in dict(OraSettings._meta.get_field("provider").choices):
            raise ConfigError("provider", "Unknown provider.")
        if p == "scripted" and not scripted_allowed():
            raise ConfigError("provider", "Scripted answers are only allowed on test instances.")
        s.provider = p
    if "model" in payload:
        m = str(payload["model"] or "").strip()
        if m and not _MODEL_RE.match(m):
            raise ConfigError("model", "Model id may only contain letters, digits, '.', '-', '_', '@', ':' and '/'.")
        s.model = m
    if "base_url" in payload:
        u = str(payload["base_url"] or "").strip().rstrip("/")
        if u and not re.match(r"^https://[A-Za-z0-9.-]+(?::\d+)?(?:/[A-Za-z0-9._~/-]*)?$", u) \
                and not re.match(r"^http://(?:localhost|127\.0\.0\.1|host\.docker\.internal|192\.168\.\d+\.\d+)(?::\d+)?(?:/[A-Za-z0-9._~/-]*)?$", u):
            raise ConfigError("base_url", "Use an https:// address (http:// only for a local server).")
        s.base_url = u
    if payload.get("api_key"):
        s.api_key = orasec_crypto_encrypt(str(payload["api_key"]).strip())
    if payload.get("clear_api_key"):
        s.api_key = ""
    if "vertex_project" in payload:
        s.vertex_project = str(payload["vertex_project"] or "").strip()[:100]
    if "vertex_region" in payload:
        s.vertex_region = (str(payload["vertex_region"] or "").strip() or "global")[:40]
    if payload.get("vertex_service_account"):
        raw = payload["vertex_service_account"]
        try:
            sa = json.loads(raw) if isinstance(raw, str) else raw
        except ValueError as exc:
            raise ConfigError("vertex_service_account", "Paste the service account key file (JSON).") from exc
        if not isinstance(sa, dict) or not sa.get("client_email") or not sa.get("private_key"):
            raise ConfigError("vertex_service_account", "That key file has no client_email / private_key.")
        s.vertex_service_account = orasec_crypto_encrypt(json.dumps(
            {"client_email": sa["client_email"], "private_key": sa["private_key"], "project_id": sa.get("project_id", "")}))
        if not s.vertex_project and sa.get("project_id"):
            s.vertex_project = sa["project_id"]
    for field, lo, hi in (("rate_limit_per_minute", 1, 200), ("daily_token_cap", 0, 50_000_000),
                          ("max_output_tokens", 200, 8000), ("retention_days", 1, 730)):
        if field in payload and payload[field] not in (None, ""):
            try:
                v = int(payload[field])
            except (TypeError, ValueError) as exc:
                raise ConfigError(field, "Enter a whole number.") from exc
            if not lo <= v <= hi:
                raise ConfigError(field, f"Enter a number from {lo} to {hi}.")
            setattr(s, field, v)
    if "memory_enabled" in payload:
        s.memory_enabled = bool(payload["memory_enabled"])
    s.updated_by = user
    s.save()
    invalidate()
    return public_view(get_config(fresh=True))


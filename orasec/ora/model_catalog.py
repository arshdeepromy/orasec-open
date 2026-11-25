"""List the models a provider offers, so an admin picks the default instead of typing an id.

Anthropic: GET https://api.anthropic.com/v1/models (paged). OpenAI-compatible: GET {base_url}/models.
Vertex AI has no simple per-project list, so its model id is still typed. The list is cached for 7 days.
"""
from __future__ import annotations

import re

import httpx
from django.core.cache import cache

from orasec.ora.providers.base import ProviderError

CACHE_KEY = "ora:model-catalog"
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@:/-]{0,99}$")
ANTHROPIC_MODELS_URL = "https://api.anthropic.com/v1/models"


def _get(client, url, **kw):
    try:
        r = client.get(url, **kw)
    except httpx.HTTPError as exc:
        raise ProviderError(f"network error: {type(exc).__name__}") from exc
    if r.status_code in (401, 403):
        raise ProviderError("the provider refused the API key (check the key and its permissions)")
    if r.status_code != 200:
        raise ProviderError(f"HTTP {r.status_code}")
    try:
        return r.json()
    except ValueError as exc:
        raise ProviderError("response was not JSON") from exc


def fetch_models(cfg: dict) -> list[dict]:
    """Ask the provider for its models, cache and return [{id, name}]. Raises ProviderError."""
    provider = cfg.get("provider")
    out = []
    with httpx.Client(timeout=20) as client:
        if provider == "anthropic":
            if not cfg.get("api_key"):
                raise ProviderError("save the API key first")
            after = None
            for _ in range(10):
                params = {"limit": 100, **({"after_id": after} if after else {})}
                data = _get(client, ANTHROPIC_MODELS_URL, params=params,
                            headers={"x-api-key": cfg["api_key"], "anthropic-version": "2023-06-01"})
                out += [{"id": m.get("id", ""), "name": m.get("display_name") or m.get("id", "")} for m in data.get("data", [])]
                if not data.get("has_more"):
                    break
                after = data.get("last_id")
        elif provider == "openai":
            if not cfg.get("base_url"):
                raise ProviderError("save the base URL first")
            headers = {"Authorization": f"Bearer {cfg['api_key']}"} if cfg.get("api_key") else {}
            data = _get(client, cfg["base_url"].rstrip("/") + "/models", headers=headers)
            out = [{"id": m.get("id", ""), "name": m.get("name") or m.get("id", "")} for m in data.get("data", [])]
        else:
            raise ProviderError("this provider has no model list; type the model id")
    models = {m["id"]: m for m in out if _ID_RE.match(m["id"] or "")}
    result = sorted(models.values(), key=lambda m: m["name"].lower())[:300]
    if not result:
        raise ProviderError("the provider returned no models")
    cache.set(CACHE_KEY, {"provider": provider, "models": result}, 7 * 86400)
    return result


def cached_models(provider: str) -> list[dict]:
    v = cache.get(CACHE_KEY)
    return v["models"] if v and v.get("provider") == provider else []


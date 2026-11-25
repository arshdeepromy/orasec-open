"""Pick the configured provider, call it, and record usage (token counts only)."""
from __future__ import annotations

import logging
from typing import Any

from orasec.ora import config as ora_config
from orasec.ora.models import OraUsage
from orasec.ora.providers.base import ProviderError, ProviderNotConfigured, ProviderRequest, ProviderResult

logger = logging.getLogger(__name__)


def build_provider(cfg: dict[str, Any]):
    p = cfg.get("provider")
    if not ora_config.is_configured(cfg):
        raise ProviderNotConfigured("not configured")
    if p == "anthropic":
        from orasec.ora.providers.remote import AnthropicProvider  # noqa: PLC0415
        return AnthropicProvider(api_key=cfg["api_key"], model=cfg["model"])
    if p == "openai":
        from orasec.ora.providers.remote import OpenAICompatProvider  # noqa: PLC0415
        return OpenAICompatProvider(base_url=cfg["base_url"], api_key=cfg.get("api_key", ""), model=cfg["model"])
    if p == "vertex":
        from orasec.ora.providers.remote import VertexProvider  # noqa: PLC0415
        return VertexProvider(project_id=cfg["vertex_project"], region=cfg["vertex_region"], model=cfg["model"],
                              service_account=cfg["vertex_service_account"])
    if p == "scripted":
        from orasec.ora.providers.scripted import ScriptedProvider  # noqa: PLC0415
        return ScriptedProvider()
    raise ProviderNotConfigured("not configured")


def call_ai(req: ProviderRequest, *, feature: str, user=None, cfg: dict[str, Any] | None = None) -> ProviderResult:
    cfg = cfg or ora_config.get_config()
    provider = build_provider(cfg)
    try:
        result = provider.generate_json(req)
    except ProviderError as exc:
        logger.warning("ora: %s call failed (%s)", feature, exc)
        OraUsage.objects.create(user=user, feature=feature, provider=getattr(provider, "name", ""),
                                model=getattr(provider, "model", ""), ok=False)
        raise
    OraUsage.objects.create(user=user, feature=feature, provider=result.provider, model=result.model,
                            input_tokens=result.input_tokens, output_tokens=result.output_tokens,
                            latency_ms=result.latency_ms, ok=True)
    return result


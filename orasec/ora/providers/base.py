"""The provider contract every Ora AI adapter implements.

``generate_json`` sends a system prompt and the recent turns and returns parsed
JSON plus token counts. Adapters raise :class:`ProviderError` for anything that
went wrong; its message is for logs and the superuser settings page only --
never shown in a chat (users get a fixed line from ``guardrails``).
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

PROVIDER_TIMEOUT_SECONDS = 25.0


class ProviderError(Exception):
    """A provider call failed (network, HTTP status, bad JSON, timeout)."""

    transient = False


class ProviderNotConfigured(ProviderError):
    """No provider is configured."""


@dataclass
class Turn:
    role: str  # "user" | "assistant"
    text: str


@dataclass
class ProviderResult:
    data: dict[str, Any]
    input_tokens: int = 0
    output_tokens: int = 0
    model: str = ""
    provider: str = ""
    latency_ms: int = 0
    raw_text: str = ""


@dataclass
class ProviderRequest:
    system: str
    turns: list[Turn]
    max_tokens: int = 1200
    task: str = "chat"  # chat | chat_tool | memory | test
    #: The structured context -- already inside ``turns`` for real providers; the scripted provider reads it.
    context: dict[str, Any] | None = None
    tool_result: dict[str, Any] | None = None
    question: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.IGNORECASE)


def parse_json_text(text: str) -> dict[str, Any]:
    """Parse the model's JSON answer (tolerates code fences / leading prose)."""
    if not isinstance(text, str) or not text.strip():
        raise ProviderError("empty response")
    t = _FENCE_RE.sub("", text.strip())
    try:
        val = json.loads(t)
    except ValueError:
        start, end = t.find("{"), t.rfind("}")
        if start < 0 or end <= start:
            raise ProviderError("response was not JSON") from None
        try:
            val = json.loads(t[start : end + 1])
        except ValueError as exc:
            raise ProviderError("response was not JSON") from exc
    if not isinstance(val, dict):
        raise ProviderError("response JSON was not an object")
    return val


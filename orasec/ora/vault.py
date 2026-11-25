"""Per-chat placeholders for people, emails and IP addresses.

Before anything goes to the AI, real values become ``[USER_1]``, ``[EMAIL_1]``,
``[IP_1]``; the mapping is kept on the conversation (``OraConversation.vault``)
so the same value gets the same placeholder for the whole chat, and answers
are restored before the user sees them. The AI never sees who is who.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any

from orasec.ora import guardrails

_IPV4_RE = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:/\d{1,2})?(?![\d.])")
_IPV6_RE = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}(?![0-9A-Fa-f:])")
_PH_RE = re.compile(r"\[(?:USER|EMAIL|IP)_\d+\]")
_names_cache: tuple[float, list[tuple[re.Pattern[str], str]]] | None = None


def _people() -> list[tuple[re.Pattern[str], str]]:
    """(regex, canonical) for every user's full name and username (>= 4 chars), longest first."""
    global _names_cache  # noqa: PLW0603
    import time  # noqa: PLC0415

    now = time.monotonic()
    if _names_cache and now - _names_cache[0] < 300:
        return _names_cache[1]
    from orasec.models import OraSec_User  # noqa: PLC0415

    seen: dict[str, str] = {}
    for first, last, username in OraSec_User.objects.values_list("first_name", "last_name", "username")[:2000]:
        full = f"{first or ''} {last or ''}".strip()
        canon = full or username
        for n in {full, username}:
            if n and len(n) >= 4 and n.lower() not in seen:
                seen[n.lower()] = canon
    pats = [(re.compile(rf"(?<![\w@.]){re.escape(n)}(?![\w@])", re.IGNORECASE), c)
            for n, c in sorted(seen.items(), key=lambda kv: -len(kv[0]))]
    _names_cache = (now, pats)
    return pats


class Vault:
    def __init__(self, data: dict[str, str] | None = None):
        self.data: dict[str, str] = dict(data or {})
        self._rev = {v: k for k, v in self.data.items()}

    def _ph(self, kind: str, value: str) -> str:
        key = value if kind == "USER" else value.lower()
        if key in self._rev:
            return self._rev[key]
        n = 1 + sum(1 for k in self.data if k.startswith(f"[{kind}_"))
        ph = f"[{kind}_{n}]"
        self.data[ph] = key
        self._rev[key] = ph
        return ph

    def tokenise(self, text: str) -> str:
        if not text or not isinstance(text, str):
            return text
        out = guardrails.EMAIL_RE.sub(lambda m: self._ph("EMAIL", m.group(0)), text)

        def _ip(m: re.Match[str]) -> str:
            v = m.group(0)
            try:
                ip = ipaddress.ip_network(v, strict=False) if "/" in v else ipaddress.ip_address(v)
            except ValueError:
                return v
            return self._ph("IP", str(ip))

        out = _IPV4_RE.sub(_ip, out)
        out = _IPV6_RE.sub(_ip, out)
        for rx, canon in _people():
            out = rx.sub(lambda m, c=canon: self._ph("USER", c), out)
        return out

    def tokenise_tree(self, value: Any, _depth: int = 0) -> Any:
        if _depth > 12:
            return value
        if isinstance(value, str):
            return self.tokenise(value)
        if isinstance(value, list):
            return [self.tokenise_tree(v, _depth + 1) for v in value]
        if isinstance(value, dict):
            return {k: (v if k in ("path", "ref", "id", "kind") else self.tokenise_tree(v, _depth + 1))
                    for k, v in value.items()}
        return value

    def restore(self, text: str) -> str:
        if not text or not isinstance(text, str) or "[" not in text:
            return text
        return _PH_RE.sub(lambda m: self.data.get(m.group(0), m.group(0)), text)

    def restore_tree(self, value: Any, _depth: int = 0) -> Any:
        if _depth > 12:
            return value
        if isinstance(value, str):
            return self.restore(value)
        if isinstance(value, list):
            return [self.restore_tree(v, _depth + 1) for v in value]
        if isinstance(value, dict):
            return {k: self.restore_tree(v, _depth + 1) for k, v in value.items()}
        return value

    def lookup(self, placeholder: str) -> str | None:
        return self.data.get((placeholder or "").strip())


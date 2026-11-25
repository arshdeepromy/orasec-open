"""Ora guardrails (ported from an earlier in-house implementation).

* :func:`scrub` -- removes emails, phone numbers, card numbers (Luhn) and
  secrets (API keys, tokens, private keys, passwords in ``key=value`` form)
  from text BEFORE it is stored or sent to the AI. Scanner output carries
  secrets (Gitleaks, SAST), so this matters more here than in a general assistant.
* :func:`asks_about_model` -- "what model are you / who made you" questions are
  answered with :data:`MODEL_REVEAL_LINE` without calling the AI.
* :func:`filter_output` -- AI text that names a model or vendor, or repeats
  Ora's own instructions, is replaced whole by :data:`MODEL_REVEAL_LINE`.
  OraSec difference: vendor words that also appear in the DATA Ora was given
  (a finding about the ``openai`` package, a Garak / Promptfoo result) are
  allowed, so a security answer about them is not blanked.
* rate limit (cache, 20 / minute / user), attack strikes (5 in 10 minutes =
  10-minute cool-down), daily token cap and the global kill switch -- each a
  friendly :class:`GuardrailBlock` (HTTP status + plain text + mood).

Nothing here ever names the provider or model to a user.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any, Iterable

from django.core.cache import cache

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Fixed lines (code-produced; never from the AI)
# ---------------------------------------------------------------------------

MODEL_REVEAL_LINE = (
    "Fair question! I'm Ora, OraSec's own assistant — what runs me behind the scenes stays behind the "
    "scenes. What can I help you get done in OraSec today?"
)
GUARD_LINE = (
    "I can't change how I work or share what goes on behind the scenes — but I'm all yours for OraSec. "
    "What would you like to get done?"
)
ATTACK_COOLDOWN_LINE = (
    "I've had a few messages in a row that I can't act on, so I'm taking a short break. "
    "Try again in a few minutes — I'm happy to help with anything in OraSec."
)
OFF_TOPIC_LINE = (
    "That one's outside what I can help with — I'm here for everything OraSec. Want a hand prioritising "
    "vulnerabilities, checking a risk or finding your way around?"
)
PROVIDER_ERROR_LINE = "Ora is having a moment — try again shortly."
NOT_SET_UP_LINE = "Ora isn't set up yet. A superuser can connect it in Ora settings."
RESTING_LINE = "Ora is resting right now. Please try again a bit later."
RATE_LIMIT_LINE = "That's a lot of questions at once! Give me a minute, then try again."
COST_CAP_LINE = "Ora has done a lot of work today and needs a rest. Please try again tomorrow."
UNSURE_LINE = "I'm not sure about that one. Try asking another way, or I can take you to the page that has it."
NOTHING_DONE_LINE = ("I haven't changed anything — I can only make a change through a card you confirm. "
                     "Tell me what you'd like and I'll prepare one.")
FIRST_RUN_NOTICE = (
    "I'm Ora, an AI helper inside OraSec. I can make mistakes, so check anything important. "
    "Emails, IP addresses, people's names and secrets are hidden from the AI, and I only change things "
    "after you confirm a card. Chats are kept for {days} days."
)
MEMORY_NOTICE_LINE = (
    "I keep short notes of our chats (never secrets or people's details) so I can pick up where we left off "
    "— you can see and delete them."
)

RATE_LIMIT_PER_MINUTE = 20
MAX_ANSWER_CHARS = 1100
MAX_SUGGESTIONS = 3


@dataclass
class GuardrailBlock(Exception):
    status_code: int
    detail: str
    code: str
    mood: str = "sleeping"

    def body(self) -> dict[str, Any]:
        return {"detail": self.detail, "code": self.code, "mood": self.mood}


# ---------------------------------------------------------------------------
# Scrubber: personal details and secrets
# ---------------------------------------------------------------------------

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}")
_CARD_RE = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")
# International numbers only, and NZ/AU mobiles: version strings and ports must not look like phones.
_PHONE_RE = re.compile(
    r"(?<![\w.])(?:"
    r"\+\d{1,3}[\s\-]?\(?\d{1,4}\)?(?:[\s\-]\d{2,4}){2,3}"
    r"|02\d[\s\-]\d{3,4}[\s\-]\d{3,4}"
    r"|04\d{2}[\s\-]\d{3}[\s\-]\d{3}"
    r")(?![\w.])"
)
#: Secrets scanners surface. Replaced outright -- never placeholders.
_SECRET_PATTERNS: tuple[str, ...] = (
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)",
    r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",                               # AWS access key id
    r"\bgh[pousr]_[A-Za-z0-9]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{40,}\b",  # GitHub tokens
    r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b",                              # Slack
    r"\bsk-(?:ant-|proj-|or-v1-)?[A-Za-z0-9_\-]{20,}\b",              # OpenAI / Anthropic / OpenRouter style keys
    r"\bAIza[0-9A-Za-z_\-]{35}\b",                                    # Google API key
    r"\bosm_[A-Za-z0-9_\-]{20,}\b",                                   # OraSec mobile device tokens
    r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b",  # JWT
    r"\b(?:bearer|token)\s+[A-Za-z0-9._\-]{24,}\b",
    r"\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|client[_-]?secret|auth[_-]?token|token)"
    r"\s*[:=]\s*['\"]?[^\s'\"<>]{6,}",
)
_SECRET_RE = re.compile("|".join(f"(?:{p})" for p in _SECRET_PATTERNS), re.IGNORECASE)


def luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


EMAIL_RE = _EMAIL_RE
PHONE_RE = _PHONE_RE


def scrub_secrets(text: str) -> str:
    return _SECRET_RE.sub("[secret removed]", text or "")


def scrub(text: str, *, emails: bool = True) -> str:
    """Remove secrets, card and phone numbers (and emails unless ``emails=False``,
    when the chat vault turns them into placeholders instead). Idempotent."""
    if not text:
        return text or ""
    out = scrub_secrets(text)
    if emails:
        out = _EMAIL_RE.sub("[email removed]", out)

    def _card(m: re.Match[str]) -> str:
        digits = re.sub(r"\D", "", m.group(0))
        return "[card number removed]" if 13 <= len(digits) <= 19 and luhn_ok(digits) else m.group(0)

    out = _CARD_RE.sub(_card, out)
    return _PHONE_RE.sub("[phone removed]", out)


# ---------------------------------------------------------------------------
# Model / vendor reveal
# ---------------------------------------------------------------------------

_STRONG_VENDOR = (
    r"gemini|vertex[\s-]*ai|google[\s-]*ai|google'?s\s+ai|google\s+(?:bard|deepmind)|deepmind|anthropic|"
    r"open[\s-]?ai|open[\s-]?router|chat[\s-]?gpt|gpt[\s-]?\d[\w.]*|gpt\s+models?|language\s+model\s+provider"
)
_SOFT_NAMES = r"claude|llama|mistral|opus|sonnet|haiku|flash[\s-]?lite|grok|copilot|perplexity|bard|qwen|deepseek"
_MODELISH = r"ai|a\.i\.|llms?|models?|language\s+models?|chat\s?bots?"
_CLAUDE_AS_MODEL = (
    r"claude[\s-]*(?:\d|ai\b|instant\b|haiku\b|sonnet\b|opus\b|code\b|models?\b|by\s+anthropic)"
    r"|(?:i\s+am|i'm|im|as|called|named|powered\s+by|built\s+(?:on|with)|based\s+on|runs?\s+on|running\s+on)\s+claude\b"
)
_OUTPUT_PATTERNS = [
    rf"\b(?:{_STRONG_VENDOR})\b",
    rf"\b(?:{_CLAUDE_AS_MODEL})",
    r"\b(?:llama|mistral)[\s-]*\d",
    rf"\b(?:{_SOFT_NAMES})[\s-]+(?:{_MODELISH})\b",
    rf"\b(?:{_MODELISH})\s+(?:called\s+|named\s+)?(?:{_SOFT_NAMES})\b",
]
_OUTPUT_RE = re.compile("|".join(_OUTPUT_PATTERNS), re.IGNORECASE)

_WHO_AM_I = r"you|u|ora|this|it|that|ora's"
_ASK_PATTERNS = [
    rf"\b(?:are|r)\s+(?:you|u)\s+(?:an?\s+)?(?:ai|a\.i\.|llm|bot|chatbot|robot|language model|gpt|{_SOFT_NAMES})\b",
    rf"\b(?:is|was)\s+(?:this|ora|it)\s+(?:an?\s+)?(?:ai|a\.i\.|llm|bot|chatbot|gpt|{_SOFT_NAMES})\b",
    rf"\b(?:what|which)\s+(?:ai|a\.i\.|llm|large language model|language model)\s+"
    rf"(?:is|are|was|powers?|runs?|drives?|do|does|did|is\s+behind|sits\s+behind)\s+(?:{_WHO_AM_I}|behind)\b",
    r"\b(?:what|which)\s+(?:model|engine|technology|tech)\s+(?:are|is|was|powers?|runs?|drives?|do|does|did|is\s+behind)\s+(?:you|u|ora|ora's)\b",
    r"\b(?:what|which)\s+(?:model|engine|technology|tech)\s+(?:powers?|runs?|drives?|is\s+behind|sits\s+behind)\s+(?:this|it|that)\b",
    r"\bwhat\s+(?:kind|type|sort)\s+of\s+(?:ai|a\.i\.|llm|model|bot|chatbot|language model)\s+(?:are|is)\s+(?:you|u|ora|this)\b",
    r"\bwho\s+(?:made|makes|built|created|trained|developed|owns|programmed|powers|runs)\s+(?:you|u|ora)\b",
    r"\b(?:what|which)\s+(?:ai|a\.i\.|llm|gpt|language)(?:\s+(?:model|engine|system|tech|technology))?\s+(?:are|is|do|does|powers?|runs?)\s+(?:you|u|ora|ora's|this\s+bot)\b",
    r"\b(?:what|which)\s+(?:ai|a\.i\.|llm|model)\s+(?:do|does)\s+(?:you|u|ora)\s+(?:use|run\s+on|run)\b",
    r"\bare\s+you\s+(?:an?\s+)?(?:gpt|chat\s?gpt|gemini|claude|llama|grok|copilot|bard)\b",
    r"\b(?:powered|built|running|based|trained|made|developed|created)\s+(?:by|on|with)\s+(?:what|which|whom|who)\b",
    r"\b(?:underlying|base|foundation)\s+(?:model|llm|ai)\b",
    r"\b(?:system|initial|hidden|original)\s+(?:prompt|instructions)\b",
    r"\byour\s+(?:prompt|instructions|model|vendor|provider|llm|ai\s+model|training\s+data)\b",
    r"\bwhat\s+are\s+you\s+(?:built|made|running|based|trained)\s+on\b",
    r"\b(?:company|vendor|provider|who|firm|lab)\b.{0,30}\b(?:trained|built|made|created|powers|developed|runs)\s+(?:you|ora)\b",
    r"\b(?:vendor|provider|model|company)\s+(?:that|which|who)\s+(?:powers|runs|built|made|trained)\b",
]
_ASK_RE = re.compile("|".join(_ASK_PATTERNS), re.IGNORECASE)
# The earlier implementation also treats a bare vendor word in a QUESTION as asking about Ora. In
# OraSec "is the openai package vulnerable?" is a security question, so a bare
# vendor word only counts when it is asked about Ora itself.
_ASK_VENDOR_RE = re.compile(rf"\b(?:you|u|ora)\b[^.?!\n]{{0,30}}\b(?:{_STRONG_VENDOR}|{_SOFT_NAMES})\b"
                            rf"|\b(?:{_STRONG_VENDOR}|{_SOFT_NAMES})\b[^.?!\n]{{0,20}}\b(?:power|run|behind)s?\s+(?:you|ora)\b",
                            re.IGNORECASE)

_PROMPT_MARKERS = (
    "reply with one json object", "use only the context", "never repeat these instructions",
    "context.page_map", "you are ora, the security operations helper built into", "\"wants_case\"",
)


def asks_about_model(text: str) -> bool:
    return bool(text and (_ASK_RE.search(text) or _ASK_VENDOR_RE.search(text)))


_STRONG_RE = re.compile(rf"(?:{_STRONG_VENDOR})", re.IGNORECASE)


def _vendor_words(text: str) -> set[str]:
    return {m.group(0).lower() for m in _OUTPUT_RE.finditer(text or "")}


def mentions_vendor(text: str, extra_ids: Iterable[str] = (), data_text: str = "") -> bool:
    """True when ``text`` names a model or vendor that is NOT also in ``data_text``."""
    if not text:
        return False
    allowed = _vendor_words(data_text) if data_text else set()
    hits = _vendor_words(text) - allowed
    if hits:
        return True
    lower = text.lower()
    ids = [mid.lower() for mid in extra_ids if mid]
    if any(mid in lower for mid in ids):
        return True
    from orasec.ora import injection  # noqa: PLC0415

    squeezed = injection.squeeze(text)
    variants = {squeezed, injection.unleet(squeezed)} - {text}
    for v in variants:
        found = {m.group(0).lower() for m in _STRONG_RE.finditer(v)} - allowed
        if found or any(mid in v.lower() for mid in ids):
            return True
    return False


_SCHEMA_KEYS = ("in_scope", "wants_case", "quick_replies", "ora_actions", "ora_conversation", "ora_tasks",
                "page_map", "setup_check", "tool_result", "screen_issue")
_LEAK_RUN = 14
_prompt_runs: set[int] | None = None


def _words(text: str) -> list[str]:
    return re.findall(r"[a-z0-9]+", (text or "").lower())


def _runs() -> set[int]:
    global _prompt_runs  # noqa: PLW0603
    if _prompt_runs is None:
        from orasec.ora import prompts  # noqa: PLC0415

        out: set[int] = set()
        for name in dir(prompts):
            val = getattr(prompts, name)
            if not name.isupper() or not isinstance(val, str) or len(val) < 200:
                continue
            w = _words(val)
            out.update(hash(" ".join(w[i:i + _LEAK_RUN])) for i in range(len(w) - _LEAK_RUN + 1))
        _prompt_runs = out
    return _prompt_runs


def leaks_prompt(text: str) -> bool:
    if not text:
        return False
    from orasec.ora import injection  # noqa: PLC0415

    for variant in {text, injection.squeeze(text)}:
        lower = variant.lower()
        if any(m in lower for m in _PROMPT_MARKERS):
            return True
        if sum(1 for k in _SCHEMA_KEYS if re.search(rf"(?<![a-z0-9_]){k}(?![a-z0-9_])", lower)) >= 2:
            return True
        w = _words(variant)
        if len(w) >= _LEAK_RUN:
            runs = _runs()
            if any(hash(" ".join(w[i:i + _LEAK_RUN])) in runs for i in range(len(w) - _LEAK_RUN + 1)):
                return True
    return False


# Ora cannot accept risk, close findings or change anything without a confirmed card.
_DONE_CLAIM_RE = re.compile(
    r"\b(?:i(?:'ve| have)|i've\s+now|i\s+just|has\s+been|have\s+been|is\s+now|are\s+now|successfully)\s+"
    r"(?:closed|resolved|assigned|accepted|created|added|linked|updated|deleted|marked|risk[\s-]accepted|"
    r"suppressed|muted|run|started|launched|triggered)\b",
    re.IGNORECASE,
)


def claims_done(text: str) -> bool:
    """AI text that says it already changed something (only a confirmed card can)."""
    return bool(text and _DONE_CLAIM_RE.search(text))


def filter_output(text: str, extra_ids: Iterable[str] = (), data_text: str = "") -> tuple[str, bool]:
    """(text, blocked): a vendor/model name or a repeat of Ora's instructions replaces the whole answer."""
    if mentions_vendor(text, extra_ids, data_text) or leaks_prompt(text):
        return MODEL_REVEAL_LINE, True
    return text, False


# ---------------------------------------------------------------------------
# Answer hygiene
# ---------------------------------------------------------------------------

_MD_LINK_RE = re.compile(r"\[([^\]]+)\]\((?!/)[^)]*\)")
_URL_RE = re.compile(r"\b(?:https?://|www\.)\S+", re.IGNORECASE)
_MD_HEADING_RE = re.compile(r"^\s{0,3}#{1,6}\s+", re.MULTILINE)


def clean_answer(text: str, limit: int = MAX_ANSWER_CHARS) -> str:
    text = (text or "").strip()
    text = _MD_LINK_RE.sub(r"\1", text)
    text = _URL_RE.sub("", text)
    text = _MD_HEADING_RE.sub("", text)
    text = text.replace("**", "")
    text = re.sub(r"[ \t]{2,}", " ", text).strip()
    if len(text) > limit:
        cut = text[:limit]
        dot = cut.rfind(". ")
        text = (cut[: dot + 1] if dot > limit // 2 else cut.rstrip() + "…")
    return text


def clean_suggestions(items: Any, extra_ids: Iterable[str] = (), data_text: str = "") -> list[str]:
    out: list[str] = []
    for s in items if isinstance(items, list) else []:
        if not isinstance(s, str):
            continue
        s = clean_answer(s, 100)
        if s and not mentions_vendor(s, extra_ids, data_text) and s not in out:
            out.append(s)
        if len(out) >= MAX_SUGGESTIONS:
            break
    return out


MAX_REDIRECT_CHARS = 260


def clean_redirect(text: Any, extra_ids: Iterable[str] = ()) -> str | None:
    """The model's own short, kind redirect for an off-topic question, or None."""
    if not isinstance(text, str):
        return None
    out = scrub(clean_answer(text))
    if not out or len(out) > MAX_REDIRECT_CHARS:
        return None
    if len(re.findall(r"[.!?](?:\s|$)", out)) > 2:
        return None
    out, blocked = filter_output(out, extra_ids)
    if blocked:
        return None
    return out


# ---------------------------------------------------------------------------
# Rate limit, attack strikes, daily cap, kill switch
# ---------------------------------------------------------------------------

ATTACK_WINDOW_SECONDS = 600
ATTACK_STRIKES = 5


def _bump(key: str, ttl: int) -> int:
    try:
        if cache.add(key, 1, ttl):
            return 1
        return int(cache.incr(key))
    except Exception:  # noqa: BLE001 -- a cache outage must not stop the chat
        logger.warning("ora: rate-limit cache unavailable")
        return 0


def check_rate_limit(user_id: int, limit: int = RATE_LIMIT_PER_MINUTE) -> None:
    if _bump(f"ora:rl:{user_id}", 60) > limit:
        raise GuardrailBlock(429, RATE_LIMIT_LINE, "rate_limited", mood="sleeping")


def note_attack(user_id: int) -> int:
    n = _bump(f"ora:atk:{user_id}", ATTACK_WINDOW_SECONDS)
    if n >= ATTACK_STRIKES:
        cache.set(f"ora:cool:{user_id}", 1, ATTACK_WINDOW_SECONDS)
    return n


def check_not_cooling(user_id: int) -> None:
    try:
        cooling = cache.get(f"ora:cool:{user_id}")
    except Exception:  # noqa: BLE001
        cooling = None
    if cooling:
        raise GuardrailBlock(429, ATTACK_COOLDOWN_LINE, "cooling_down", mood="sorry")


def tokens_today() -> int:
    from django.db.models import Sum  # noqa: PLC0415
    from django.utils import timezone  # noqa: PLC0415

    from orasec.ora.models import OraUsage  # noqa: PLC0415

    start = timezone.localtime().replace(hour=0, minute=0, second=0, microsecond=0)
    agg = OraUsage.objects.filter(created__gte=start).aggregate(
        i=Sum("input_tokens"), o=Sum("output_tokens"))
    return int((agg["i"] or 0) + (agg["o"] or 0))


def check_chat_allowed(user_id: int, cfg: dict[str, Any]) -> None:
    if not cfg.get("enabled", True):
        raise GuardrailBlock(503, RESTING_LINE, "resting", mood="sleeping")
    check_rate_limit(user_id, int(cfg.get("rate_limit_per_minute") or RATE_LIMIT_PER_MINUTE))
    cap = int(cfg.get("daily_token_cap") or 0)
    if cap and tokens_today() >= cap:
        raise GuardrailBlock(429, COST_CAP_LINE, "daily_cap", mood="sleeping")


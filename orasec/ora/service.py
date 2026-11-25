"""Ora chat orchestration (ported from an earlier in-house implementation), synchronous for Django.

One question:
 1. limits: enabled / set up, cool-down after attacks, 20 a minute, daily token cap
 2. secrets scrubbed, the message stored; direct prompt attacks and "what model are you"
    get a fixed line without calling the AI
 3. CONTEXT built; obvious questions run their tool first (answer-first)
 4. AI call (+ at most one tool round); everything sent goes through the chat's vault
    (people, emails, IPs as placeholders) and injection cleaning
 5. the reply is checked in code: vendor / prompt leaks, links, length, navigate paths
    against the page map, items against the tool's rows, proposals rebuilt into checked
    cards, "I did it" claims without a card replaced
 6. the reply is stored (placeholders restored) with its mood; usage logged as counts only
"""
from __future__ import annotations

import datetime
import logging
import re
from typing import Any

from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from orasec.ora import actions, context, guardrails, injection, knowledge, page_map, prompts, tools
from orasec.ora import config as ora_config
from orasec.ora.models import OraConversation, OraMemory, OraMessage, OraProposal, OraUserPreference
from orasec.ora.providers.base import ProviderError, ProviderNotConfigured, ProviderRequest, Turn
from orasec.ora.providers.router import call_ai
from orasec.ora.vault import Vault

logger = logging.getLogger(__name__)
MAX_MESSAGE = 2000
HISTORY_TURNS = 8
MAX_NAV = 2
REMOVED_TURN = "[message removed]"


class ChatError(Exception):
    def __init__(self, status: int, detail: str, code: str = "bad_request"):
        super().__init__(detail)
        self.status, self.detail, self.code = status, detail, code


def _first_name(user) -> str:
    return (user.first_name or "").strip()


# ---------------------------------------------------------------------------
# Status for the launcher
# ---------------------------------------------------------------------------

def status(user) -> dict[str, Any]:
    cfg = ora_config.get_config()
    pref = OraUserPreference.objects.filter(user=user).first()
    return {
        "available": bool(cfg.get("enabled") and ora_config.is_configured(cfg)),
        "enabled": bool(cfg.get("enabled")),
        "configured": ora_config.is_configured(cfg),
        "hidden": bool(pref and pref.hidden),
        "notice_ack": bool(pref and pref.notice_ack_at),
        "notice": guardrails.FIRST_RUN_NOTICE.format(days=cfg.get("retention_days") or 90),
        "memory_notice": guardrails.MEMORY_NOTICE_LINE if cfg.get("memory_enabled") else None,
        "first_name": _first_name(user),
        "guides": knowledge.guides_for(user),
        "superuser": bool(user.is_superuser),
    }


def set_preference(user, *, hidden: bool | None = None, notice_ack: bool | None = None) -> dict[str, Any]:
    pref, _ = OraUserPreference.objects.get_or_create(user=user)
    if hidden is not None:
        pref.hidden = bool(hidden)
    if notice_ack:
        pref.notice_ack_at = timezone.now()
    pref.save()
    return status(user)


# ---------------------------------------------------------------------------
# Conversations
# ---------------------------------------------------------------------------

def _message_json(m: OraMessage) -> dict[str, Any]:
    extra = m.actions if isinstance(m.actions, dict) else {"actions": m.actions or []}
    out = {"id": m.id, "role": m.role, "text": m.text, "mood": m.mood, "answered": m.answered,
           "feedback": m.feedback, "created": m.created.isoformat(), "suggestions": m.suggestions or [], "tool": m.tool,
           "actions": extra.get("actions", []), "steps": extra.get("steps", []), "items": extra.get("items", []),
           "quick_replies": extra.get("quick_replies", [])}
    pid = extra.get("proposal_id")
    if pid:
        pr = OraProposal.objects.filter(id=pid).first()
        if pr:
            out["proposal"] = proposal_json(pr)
    return out


def proposal_json(pr: OraProposal) -> dict[str, Any]:
    if pr.status == "pending" and timezone.now() - pr.created > datetime.timedelta(hours=24):
        pr.status = "expired"
        pr.save(update_fields=["status"])
    return {"id": str(pr.id), "kind": pr.kind, "status": pr.status, "card": pr.card, "result": pr.result or None}


def conversations(user, limit: int = 30) -> list[dict[str, Any]]:
    return [{"id": c.id, "title": c.title, "updated": c.updated.isoformat(), "surface": c.surface}
            for c in OraConversation.objects.filter(user=user).order_by("-updated")[:limit]]


def conversation(user, cid: int) -> dict[str, Any]:
    c = OraConversation.objects.filter(user=user, id=cid).first()
    if not c:
        raise ChatError(404, "That chat no longer exists.", "not_found")
    return {"id": c.id, "title": c.title, "messages": [_message_json(m) for m in c.messages.all()[:200]]}


def delete_conversation(user, cid: int) -> None:
    OraConversation.objects.filter(user=user, id=cid).delete()


def feedback(user, mid: int, value: int) -> None:
    m = OraMessage.objects.filter(id=mid, role="assistant", conversation__user=user).first()
    if not m:
        raise ChatError(404, "Message not found.", "not_found")
    m.feedback = 1 if value > 0 else -1 if value < 0 else None
    m.save(update_fields=["feedback"])


def memories(user) -> list[dict[str, Any]]:
    return [{"id": m.id, "summary": m.summary, "topics": m.topics, "created": m.created.isoformat()}
            for m in OraMemory.objects.filter(user=user)[:50]]


def forget(user, mid: int | None = None) -> None:
    qs = OraMemory.objects.filter(user=user)
    (qs.filter(id=mid) if mid else qs).delete()


# ---------------------------------------------------------------------------
# Proposals
# ---------------------------------------------------------------------------

def decide(user, pid: str, confirm: bool) -> dict[str, Any]:
    try:
        pr = OraProposal.objects.filter(id=pid, user=user).first()
    except (ValueError, ValidationError):  # not a uuid
        pr = None
    if not pr:
        raise ChatError(404, "That card no longer exists.", "not_found")
    with transaction.atomic():
        pr = OraProposal.objects.select_for_update().get(id=pr.id)
        if pr.status != "pending" or timezone.now() - pr.created > datetime.timedelta(hours=24):
            if pr.status == "pending":
                pr.status = "expired"
                pr.save(update_fields=["status"])
            raise ChatError(409, "This card has already been used or has expired. Ask me again for a fresh one.", "stale")
        pr.decided_at = timezone.now()
        if not confirm:
            pr.status = "cancelled"
            pr.result = {"ok": False, "message": "Cancelled — nothing was changed."}
            pr.save(update_fields=["status", "decided_at", "result"])
            return proposal_json(pr)
        try:
            pr.result = actions.execute(pr, user)
            pr.status = "confirmed"
        except PermissionError:
            pr.result = {"ok": False, "message": "You don't have permission for that any more, so nothing changed."}
            pr.status = "failed"
        except Exception:  # noqa: BLE001
            logger.exception("ora: proposal %s failed", pr.kind)
            pr.result = {"ok": False, "message": "That didn't work, so nothing changed. Try it on the page itself."}
            pr.status = "failed"
        pr.save(update_fields=["status", "decided_at", "result"])
    # A short assistant line records the outcome so follow-ups see it.
    OraMessage.objects.create(conversation=pr.conversation, role="assistant", text=pr.result["message"],
                              mood="happy" if pr.status == "confirmed" else "sorry",
                              actions={"actions": [{"type": "navigate", "path": pr.result["path"], "label": "Open"}]
                                       if pr.result.get("path") else []}, tool="proposal")
    return proposal_json(pr)


# ---------------------------------------------------------------------------
# Chat
# ---------------------------------------------------------------------------

def _history(conv: OraConversation, vault: Vault, before_id: int) -> list[Turn]:
    msgs = list(conv.messages.filter(id__lt=before_id).order_by("-id")[:HISTORY_TURNS])[::-1]
    turns: list[Turn] = []
    for m in msgs:
        if m.role == "user" and m.tool == "attack":
            text = REMOVED_TURN
        else:
            text = vault.tokenise(guardrails.scrub(m.text, emails=False))
        role = "assistant" if m.role == "assistant" else "user"
        if turns and turns[-1].role == role:
            turns[-1] = Turn(role, turns[-1].text + "\n" + text)
        else:
            turns.append(Turn(role, text))
    if turns and turns[0].role == "assistant":
        turns.insert(0, Turn("user", "(earlier in this chat)"))
    return turns


def _earlier(user, cfg) -> list[str]:
    if not cfg.get("memory_enabled"):
        return []
    return [f"{m.created.date().isoformat()}: {m.summary}" for m in OraMemory.objects.filter(user=user)[:4]]


def _prepare(value: Any, vault: Vault) -> tuple[Any, str]:
    """Scrub, clean injections and tokenise data for the AI. Returns (data, flat text for vendor checks)."""
    data, _ = injection.clean_tree(value)

    def _scrub(v, d=0):
        if d > 12:
            return v
        if isinstance(v, str):
            return guardrails.scrub(v, emails=False)
        if isinstance(v, list):
            return [_scrub(x, d + 1) for x in v]
        if isinstance(v, dict):
            return {k: _scrub(x, d + 1) for k, x in v.items()}
        return v

    data = vault.tokenise_tree(_scrub(data))
    import json  # noqa: PLC0415

    return data, json.dumps(data, default=str)


def _call(cfg, user, system: str, turns: list[Turn], feature: str):
    req = ProviderRequest(system=system, turns=turns, max_tokens=int(cfg.get("max_output_tokens") or 1400), task=feature)
    return call_ai(req, feature=feature, user=user, cfg=cfg)


def _pick_items(chosen: Any, tool_result: dict[str, Any] | None, vault: Vault) -> list[dict[str, Any]]:
    if not tool_result:
        return []
    pool: dict[str, dict[str, Any]] = {}
    for key in ("items", "fix_first", "matching_risks"):
        for row in tool_result.get(key) or []:
            if isinstance(row, dict) and row.get("ref"):
                pool[str(row["ref"]).upper()] = row
    out = []
    for it in chosen if isinstance(chosen, list) else []:
        if not isinstance(it, dict):
            continue
        ref = str(it.get("ref") or "").strip().upper()
        row = pool.get(ref)
        if not row or any(o["ref"] == row["ref"] for o in out):
            continue
        why = vault.restore(guardrails.clean_answer(str(it.get("why") or ""), 120))
        out.append({"ref": row["ref"], "kind": row.get("kind"), "title": row.get("title") or row.get("component"),
                    "severity": row.get("severity"), "band": row.get("band"), "score": row.get("score"),
                    "level": row.get("level"), "kev": row.get("kev"), "due": row.get("due"),
                    "overdue": row.get("overdue"), "asset": row.get("asset"), "path": row.get("path"), "why": why})
        if len(out) >= 6:
            break
    return out


def _nav_actions(raw: Any, tool_result: dict[str, Any] | None, user, surface: str) -> list[dict[str, Any]]:
    tool_paths = set()

    def _walk(v, d=0):
        if d > 6:
            return
        if isinstance(v, dict):
            if isinstance(v.get("path"), str):
                tool_paths.add(v["path"])
            for x in v.values():
                _walk(x, d + 1)
        elif isinstance(v, list):
            for x in v:
                _walk(x, d + 1)

    _walk(tool_result or {})
    out: list[dict[str, Any]] = []
    for a in raw if isinstance(raw, list) else []:
        if not isinstance(a, dict):
            continue
        if a.get("type") == "navigate":
            path = str(a.get("path") or "").strip()
            if not path.startswith("/") or "//" in path or len(path) > 200:
                continue
            if not (page_map.allowed(path, superuser=user.is_superuser) or path in tool_paths):
                continue
            if sum(1 for x in out if x["type"] == "navigate") >= MAX_NAV or any(x.get("path") == path for x in out):
                continue
            page = page_map.page_for(path)
            hl = a.get("highlight")
            if not (isinstance(hl, str) and re.match(r"^[#.\[\]a-zA-Z0-9_=\-'\"/: >]{1,120}$", hl)):
                hl = page_map.sidebar_selector(path)
            out.append({"type": "navigate", "path": path, "label": (page or {}).get("title") or "Open",
                        "where": (page or {}).get("where"), "highlight": hl,
                        "app_path": page_map.mobile_route(path)})
        elif a.get("type") == "guide" and surface != "mobile":
            g = knowledge.guide(str(a.get("id") or ""), user)
            if g and not any(x.get("type") == "guide" for x in out):
                out.append({"type": "guide", "id": g["id"], "label": g["title"]})
    return out


def _quick_replies(raw: Any, vault: Vault, ids: list[str]) -> list[dict[str, str]]:
    out = []
    for q in raw if isinstance(raw, list) else []:
        if isinstance(q, dict) and isinstance(q.get("label"), str) and isinstance(q.get("text"), str):
            label, text = guardrails.clean_answer(q["label"], 40), guardrails.clean_answer(q["text"], 200)
            if label and text and not guardrails.mentions_vendor(label + " " + text, ids):
                out.append({"label": vault.restore(label), "text": vault.restore(text)})
        if len(out) >= 4:
            break
    return out


def chat(user, *, message: str, conversation_id: int | None = None, page: dict[str, Any] | None = None,
         surface: str = "web") -> dict[str, Any]:
    cfg = ora_config.get_config()
    if not cfg.get("enabled"):
        raise guardrails.GuardrailBlock(503, guardrails.RESTING_LINE, "resting")
    if not ora_config.is_configured(cfg):
        raise guardrails.GuardrailBlock(503, guardrails.NOT_SET_UP_LINE, "not_set_up")
    guardrails.check_not_cooling(user.id)
    guardrails.check_chat_allowed(user.id, cfg)

    text = injection.strip_invisible(str(message or "")).strip()
    if not text:
        raise ChatError(400, "Type a question first.")
    text = text[:MAX_MESSAGE]
    surface = "mobile" if surface == "mobile" else "web"
    page = page or {}

    if conversation_id:
        conv = OraConversation.objects.filter(user=user, id=conversation_id).first()
        if not conv:
            raise ChatError(404, "That chat no longer exists.", "not_found")
    else:
        conv = OraConversation.objects.create(user=user, surface=surface,
                                              title=guardrails.scrub(text, emails=False)[:60] or "New chat")
    vault = Vault(conv.vault)
    stored = guardrails.scrub(text, emails=False)
    pinfo = context.page_info(str(page.get("path") or ""), surface, str(page.get("title") or ""), user)
    umsg = OraMessage.objects.create(conversation=conv, role="user", text=stored, page_path=pinfo["path"])

    def _reply(answer: str, *, mood="happy", in_scope=True, answered=True, tool="", extra=None,
               suggestions=None) -> dict[str, Any]:
        payload = extra or {}
        m = OraMessage.objects.create(conversation=conv, role="assistant", text=answer, mood=mood, in_scope=in_scope,
                                      answered=answered, tool=tool[:40], actions=payload, suggestions=suggestions or [],
                                      page_path=pinfo["path"])
        conv.vault, conv.updated = vault.data, timezone.now()
        conv.save(update_fields=["vault", "updated"])
        return {"conversation_id": conv.id, "title": conv.title, "message": _message_json(m)}

    # Fixed answers that never reach the AI.
    if injection.direct_attack(text):
        umsg.tool = "attack"
        umsg.save(update_fields=["tool"])
        n = guardrails.note_attack(user.id)
        line = guardrails.ATTACK_COOLDOWN_LINE if n >= guardrails.ATTACK_STRIKES else guardrails.GUARD_LINE
        return _reply(line, mood="sorry", in_scope=False, tool="guard")
    if guardrails.asks_about_model(text):
        return _reply(guardrails.MODEL_REVEAL_LINE, mood="happy", tool="model_question")

    ids = ora_config.configured_model_ids(cfg)
    ctx = context.build(user, question=text, page=pinfo, conversation=conv, surface=surface)
    ctx_data, ctx_text = _prepare(ctx, vault)
    q_tok = vault.tokenise(stored)
    earlier = [vault.tokenise(e) for e in _earlier(user, cfg)]
    history = _history(conv, vault, umsg.id)
    nonce = injection.new_nonce()

    tool_name, tool_result, tool_text = "", None, ""
    guessed = tools.guess(text, pinfo)
    if guessed:
        tool_name = guessed[0]
        tool_result, tool_text = _prepare(tools.run_tool(guessed[0], guessed[1], user), vault)

    def _ask(tr) -> dict[str, Any]:
        turn = prompts.chat_user_turn(q_tok, ctx_data, earlier=earlier, tool_result=tr, nonce=nonce)
        res = _call(cfg, user, prompts.CHAT_SYSTEM, [*history, Turn("user", turn)],
                    "chat_tool" if tr is not None else "chat")
        return res.data

    try:
        data = _ask(tool_result)
        want = data.get("tool") if isinstance(data.get("tool"), dict) else None
        if want and want.get("name") in tools.TOOLS and (want.get("name") != tool_name or tool_result is None):
            tool_name = str(want["name"])
            raw = tools.run_tool(tool_name, want.get("args") or {}, user)
            tool_result, tool_text = _prepare(raw, vault)
            data = _ask(tool_result)
    except ProviderNotConfigured as exc:
        raise guardrails.GuardrailBlock(503, guardrails.NOT_SET_UP_LINE, "not_set_up") from exc
    except ProviderError:
        return _reply(guardrails.PROVIDER_ERROR_LINE, mood="sorry", answered=False, tool="error")

    data_text = ctx_text + " " + tool_text

    # Out of scope: the model's own short redirect, or a fixed line.
    if data.get("in_scope") is False:
        line = guardrails.clean_redirect(data.get("redirect"), ids) or guardrails.OFF_TOPIC_LINE
        sugg = guardrails.clean_suggestions(data.get("suggestions"), ids, data_text)
        return _reply(vault.restore(line), mood="happy", in_scope=False, tool=tool_name,
                      suggestions=[vault.restore(s) for s in sugg])

    answer = guardrails.clean_answer(str(data.get("answer") or ""))
    steps = [guardrails.clean_answer(str(s), 200) for s in (data.get("steps") or [])[:6]
             if isinstance(s, str) and s.strip()] if isinstance(data.get("steps"), list) else []
    full = " ".join([answer, *steps])
    full, blocked = guardrails.filter_output(full, ids, data_text)
    if blocked:
        return _reply(guardrails.MODEL_REVEAL_LINE, mood="happy", tool=tool_name)
    if not answer:
        answer = guardrails.UNSURE_LINE

    extra: dict[str, Any] = {"steps": [vault.restore(s) for s in steps],
                             "items": _pick_items(data.get("items"), tool_result, vault),
                             "actions": _nav_actions(data.get("actions"), tool_result, user, surface),
                             "quick_replies": _quick_replies(data.get("quick_replies"), vault, ids)}
    if not extra["items"] and tool_result and tool_name in ("prioritise", "sla_status", "my_work", "find_findings") \
            and isinstance(tool_result.get("items"), list):
        extra["items"] = _pick_items([{"ref": r.get("ref")} for r in tool_result["items"][:3]], tool_result, vault)
    if not any(a["type"] == "navigate" for a in extra["actions"]) and tool_result and \
            isinstance(tool_result.get("path"), str) and page_map.allowed(tool_result["path"], superuser=user.is_superuser) \
            and tool_result["path"] != pinfo.get("path"):
        extra["actions"] = _nav_actions([{"type": "navigate", "path": tool_result["path"]}], tool_result, user, surface) + extra["actions"]

    mood = "happy" if data.get("answered", True) is not False else "sorry"
    proposal = data.get("proposal")
    made_card = False
    if isinstance(proposal, dict) and proposal.get("kind"):
        try:
            card, payload = actions.build(str(proposal["kind"]), proposal, user, vault)
            card = vault.restore_tree(card)
            pr = actions.create(conv, user, str(proposal["kind"]), card, payload)
            extra["proposal_id"] = str(pr.id)
            made_card = True
            if not re.search(r"\b(?:confirm|check)\b", answer, re.I):
                answer = (answer + " Check the card and tap Confirm.").strip()
        except actions.Clarify as c:
            answer, mood = c.message, "listening"
            extra["quick_replies"] = c.quick_replies or extra["quick_replies"]
        except PermissionError:
            answer, mood = ("You don't have permission to do that in OraSec, so I can't prepare it. "
                            "An OraSec admin can do it, or I can take you to the page."), "sorry"
    if not made_card and guardrails.claims_done(answer):
        answer, mood = guardrails.NOTHING_DONE_LINE, "sorry"

    sugg = [vault.restore(s) for s in guardrails.clean_suggestions(data.get("suggestions"), ids, data_text)]
    return _reply(vault.restore(guardrails.scrub(answer, emails=False)), mood=mood,
                  answered=data.get("answered", True) is not False, tool=tool_name, extra=extra, suggestions=sugg)


# ---------------------------------------------------------------------------
# Memory (Celery) and retention
# ---------------------------------------------------------------------------

_RULEY = re.compile(r"\b(?:always|never|from now on|must|should always|you will|remember to)\b", re.I)


def summarise_pending(limit: int = 20) -> int:
    cfg = ora_config.get_config(fresh=True)
    if not (cfg.get("enabled") and cfg.get("memory_enabled") and ora_config.is_configured(cfg)):
        return 0
    cutoff = timezone.now() - datetime.timedelta(minutes=20)
    done = 0
    import json  # noqa: PLC0415

    for conv in OraConversation.objects.filter(summarised=False, updated__lt=cutoff).select_related("user")[:limit]:
        msgs = list(conv.messages.exclude(tool__in=["attack", "guard"]).order_by("id")[:30])
        conv.summarised = True
        conv.save(update_fields=["summarised"])
        if sum(1 for m in msgs if m.role == "user") < 2:
            continue
        vault = Vault(conv.vault)
        body = {"messages": [{"role": m.role, "text": vault.tokenise(guardrails.scrub(m.text))[:600]} for m in msgs]}
        try:
            res = _call(cfg, conv.user, prompts.MEMORY_SUMMARY, [Turn("user", json.dumps(body))], "memory")
        except ProviderError:
            continue
        d = res.data
        summary = guardrails.clean_answer(str(d.get("summary") or ""), 280)
        if not d.get("remember") or not summary or "[" in summary or _RULEY.search(summary) \
                or guardrails.mentions_vendor(summary) or injection.suspicious(summary):
            continue
        topics = [t for t in (d.get("topics") or []) if isinstance(t, str) and len(t) <= 30][:6]
        OraMemory.objects.create(user=conv.user, conversation=conv, summary=summary, topics=topics,
                                 outcome=d.get("outcome") if d.get("outcome") in ("resolved", "open", "info") else "info")
        done += 1
    return done


def sweep() -> dict[str, int]:
    from orasec.ora.models import OraUsage  # noqa: PLC0415

    cfg = ora_config.get_config(fresh=True)
    days = int(cfg.get("retention_days") or 90)
    cutoff = timezone.now() - datetime.timedelta(days=days)
    convs = OraConversation.objects.filter(updated__lt=cutoff).delete()[0]
    mems = OraMemory.objects.filter(created__lt=cutoff).delete()[0]
    OraProposal.objects.filter(status="pending", created__lt=timezone.now() - datetime.timedelta(hours=24)).update(status="expired")
    usage = OraUsage.objects.filter(created__lt=timezone.now() - datetime.timedelta(days=400)).delete()[0]
    return {"conversations": convs, "memories": mems, "usage": usage}


"""Scripted answers for test instances (ORASEC_ORA_ALLOW_SCRIPTED=True only).

Behaves like a well-behaved model so the whole chat path -- tools, items,
navigation, guides, proposals, memory -- can be tested end to end without an
AI account. It reads the fenced sections exactly as a model would.
"""
from __future__ import annotations

import json
import re
import time
from typing import Any

from orasec.ora import injection, prompts
from orasec.ora.providers.base import ProviderRequest, ProviderResult


def _load(text: str | None) -> Any:
    try:
        return json.loads(text) if text else None
    except ValueError:
        return None


def _ids(q: str) -> list[int]:
    return [int(x) for x in re.findall(r"\b(?:F-|finding\s*#?)(\d{1,9})\b", q, re.I)]


class ScriptedProvider:
    name = "scripted"
    model = "scripted-test"

    def generate_json(self, req: ProviderRequest) -> ProviderResult:
        started = time.monotonic()
        last = req.turns[-1].text if req.turns else ""
        if req.system == prompts.TEST_SYSTEM:
            data: dict[str, Any] = {"ok": True}
        elif req.system == prompts.MEMORY_SUMMARY:
            body = _load(last) or {}
            first = next((m["text"] for m in body.get("messages", []) if m.get("role") == "user"), "")
            data = {"remember": True, "summary": f"Asked about {first[:120].rstrip('?.')} in OraSec.",
                    "topics": ["orasec"], "outcome": "info"}
        else:
            data = self._chat(last)
        return ProviderResult(data=data, input_tokens=len(last) // 4, output_tokens=len(json.dumps(data)) // 4,
                              model=self.model, provider=self.name,
                              latency_ms=int((time.monotonic() - started) * 1000), raw_text=json.dumps(data))

    def _chat(self, turn: str) -> dict[str, Any]:
        q = prompts.question_of(turn).strip()
        ql = q.lower()
        ctx = _load(injection.section(turn, "CONTEXT")) or {}
        tr = _load(injection.section(turn, "TOOL_RESULT"))
        allowed = set(ctx.get("ora_actions") or [])
        page = ctx.get("page") or {}

        if re.search(r"\b(?:poem|joke|recipe|weather|football|song)\b", ql):
            return {"in_scope": False, "redirect": "That's a fun one, but it's outside what I help with here. "
                    "I can tell you what to fix first across your assets instead.",
                    "suggestions": ["What should we fix first?", "How is our security posture?"]}

        # Changes
        ids = _ids(q) or ([page["finding_id"]] if page.get("finding_id") else [])
        if re.search(r"\bassign\b", ql) and ids and "assign" in allowed:
            return {"in_scope": True, "answer": "I've prepared that for you.",
                    "proposal": {"kind": "assign", "finding_ids": ids, "assignee": "me"}, "answered": True}
        if re.search(r"\bclose\b", ql) and ids and "close" in allowed:
            reason = "false_positive" if "false positive" in ql else "mitigated"
            note = q.split(":", 1)[1].strip() if ":" in q else ""
            return {"in_scope": True, "answer": "Here's the close card.",
                    "proposal": {"kind": "close", "finding_ids": ids, "reason": reason, "note": note}, "answered": True}
        if re.search(r"\bnote\b", ql) and ids and ":" in q:
            return {"in_scope": True, "answer": "Here's the note.",
                    "proposal": {"kind": "note", "finding_id": ids[0], "text": q.split(":", 1)[1].strip()}, "answered": True}
        if re.search(r"\b(?:recalculate|recompute) priorit", ql) and "recompute_priorities" in allowed:
            return {"in_scope": True, "answer": "I can start that.", "proposal": {"kind": "recompute_priorities"}}

        if tr is not None:
            return self._from_tool(ql, tr, allowed)

        # Where things are / how-to
        if re.search(r"\b(?:where|take me|how do i|how can i|open|find the)\b", ql):
            pm = ctx.get("page_map") or []
            words = [w for w in re.findall(r"[a-z0-9]+", ql) if len(w) > 3 and w not in
                     {"where", "take", "find", "open", "page", "what", "does", "there", "show", "with", "that", "this"}]
            best, score = None, 0
            for p in pm:
                hay = (p["title"] + " " + p.get("where", "") + " " + p.get("about", "")).lower()
                s = sum(2 if w in p["title"].lower() else 1 for w in words if w in hay)
                if s > score:
                    best, score = p, s
            if best:
                out: dict[str, Any] = {"in_scope": True, "answer": f"It's under {best['where']}.",
                                       "actions": [{"type": "navigate", "path": best["path"]}],
                                       "suggestions": ["What should we fix first?"], "answered": True}
                guides = {g["id"] for g in ctx.get("guides") or []}
                if re.search(r"\b(?:add|create|new)\b.*\brisk\b", ql) and "add_risk" in guides:
                    out["answer"] = "You add risks on the Risk Register. I can walk you through it."
                    out["steps"] = ["Open Governance → Risk Register", "Press Add risk", "Fill in likelihood, impact, treatment and owner", "Press Save"]
                    out["actions"].append({"type": "guide", "id": "add_risk"})
                if re.search(r"\blink\b.*\b(?:phone|app)\b", ql) and "link_phone" in guides:
                    out["actions"].append({"type": "guide", "id": "link_phone"})
                return out

        # Needs data: ask for a tool.
        for rx, name, args in ((r"\battack", "attacks", {"days": 7}), (r"\bconnector", "connectors_health", {}),
                               (r"\bcompliance|iso\b", "compliance_status", {}), (r"\brisks?\b", "risk_register", {}),
                               (r"\bcode\b", "code_security", {}), (r"\bpriorit|fix first", "prioritise", {"limit": 5})):
            if re.search(rx, ql):
                return {"in_scope": True, "answer": "Let me check.", "tool": {"name": name, "args": args}}

        kb = ctx.get("knowledge") or []
        if kb:
            first = re.split(r"(?<=\.)\s", kb[0]["text"])
            return {"in_scope": True, "answer": " ".join(first[:2]), "answered": True,
                    "suggestions": ["What should we fix first?"]}
        return {"in_scope": True, "answer": "I'm not sure about that one -- could you say it another way?",
                "answered": False, "quick_replies": [{"label": "What to fix first", "text": "What should we fix first?"}]}

    def _from_tool(self, ql: str, tr: dict[str, Any], allowed: set[str]) -> dict[str, Any]:
        if tr.get("denied"):
            return {"in_scope": True, "answer": tr.get("summary"), "answered": False}
        if tr.get("error"):
            return {"in_scope": True, "answer": tr["error"], "answered": False}
        if "likelihood" in tr and "evidence" in tr:
            ans = (f"{tr['subject']} rates likelihood {tr['likelihood']} × impact {tr['impact']} = {tr['score']} "
                   f"({tr['level']}): {', '.join(tr['evidence'][:2])}. {tr['treatment_plan']}")
            out: dict[str, Any] = {"in_scope": True, "answer": ans, "answered": True,
                                   "items": [{"ref": i["ref"], "why": ", ".join(i.get("factors", [])[:2])} for i in tr.get("items", [])[:3]],
                                   "suggestions": ["Add this to the risk register"]}
            if re.search(r"\b(?:register|record|add (?:it|this)|create (?:a )?risk)\b", ql) and "create_risk" in allowed:
                s = tr["suggested_risk"]
                out["proposal"] = {"kind": "create_risk", **s, "description": "; ".join(tr["evidence"])}
            return out
        if isinstance(tr.get("items"), list) and tr["items"]:
            top = tr["items"][0]
            label = top.get("title") or top.get("component") or top["ref"]
            ans = f"Start with {top['ref']} -- {label}."
            if top.get("factors"):
                ans += f" It's {', '.join(top['factors'][:3])}."
            if tr.get("fix_first"):
                c = tr["fix_first"][0]
                ans += f" Updating {c['component']} would clear {c['findings']} findings at once."
            return {"in_scope": True, "answer": ans, "answered": True,
                    "items": [{"ref": i["ref"], "why": ", ".join(i.get("factors", [])[:2]) or i.get("level") or ""}
                              for i in tr["items"][:5]],
                    "suggestions": ["Assign the top one to me", "Evaluate the risk of the top one"]}
        if "posture" in tr:
            p = tr["posture"]
            return {"in_scope": True, "answered": True,
                    "answer": f"Posture is {p['score']}/1000 with {tr['open_findings']} open findings; "
                              f"{tr['exploitable']['kev_findings']} are known exploited and {tr['sla']['overdue']} are overdue."}
        if "blocked_hits" in tr:
            top = (tr.get("countries") or [{}])[0]
            return {"in_scope": True, "answered": True,
                    "answer": f"{tr['blocked_hits']} attack hits were blocked in the last {tr['days']} days, most from {top.get('value')}."}
        return {"in_scope": True, "answer": "Here's what I found.", "answered": True}


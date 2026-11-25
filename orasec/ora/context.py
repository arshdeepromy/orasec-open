"""The CONTEXT Ora gets with each question: who is asking (role only), where they
are, what the page is about, the page map, help passages, guides, what Ora may
change for them and the cards already in this chat.
"""
from __future__ import annotations

import re
from typing import Any

from django.utils import timezone

from orasec.ora import actions, knowledge, page_map, tools

_WEB_DETAIL = [
    (re.compile(r"^/finding/(\d+)"), "finding_id"),
    (re.compile(r"^/orasec/risks/(\d+)/"), "risk_id"),
    (re.compile(r"^/orasec/inventory/(\d+)/"), "inventory_id"),
    (re.compile(r"^/orasec/vulnerabilities/([^/]+)/"), "vulnerability"),
    (re.compile(r"^/orasec/connectors/(\d+)/"), "connector_id"),
    (re.compile(r"^/orasec/compliance/controls/(\d+)/"), "control_id"),
    (re.compile(r"^/asset/(\d+)"), "product_id"),
]
_APP_DETAIL = [
    (re.compile(r"^/vulns/(\d+)"), "finding_id"),
    (re.compile(r"^/risks/(\d+)"), "risk_id"),
    (re.compile(r"^/assets/(.+)$"), "asset"),
]
_APP_TITLES = {"/": "Overview", "/vulns": "Vulnerabilities", "/assets": "Assets", "/attacks": "Attacks",
               "/governance": "Governance (risks, compliance)", "/code": "Code", "/connectors": "Connectors",
               "/my-work": "My work", "/more": "More"}


def page_info(path: str, surface: str, title: str, user) -> dict[str, Any]:
    path = (path or "/")[:300]
    out: dict[str, Any] = {"path": path, "surface": surface}
    if title:
        out["title"] = re.sub(r"\s+", " ", title)[:120]
    rules = _APP_DETAIL if surface == "mobile" else _WEB_DETAIL
    for rx, key in rules:
        m = rx.match(path)
        if m:
            val = m.group(1)
            out[key] = int(val) if val.isdigit() else val[:80]
    if surface == "mobile":
        base = "/" + path.strip("/").split("/")[0] if path.strip("/") else "/"
        out.setdefault("title", _APP_TITLES.get(base, ""))
    else:
        page = page_map.page_for(path)
        if page:
            out.setdefault("title", page["title"])
            out["where"], out["about"] = page["where"], page["about"]
    # Name the record so "this one" works.
    try:
        if "finding_id" in out:
            f = tools.findings_for(user).filter(id=out["finding_id"]).select_related("test__engagement__product").first()
            if f:
                out["record"] = {"finding": f"F-{f.id}", "title": f.title[:140], "severity": f.severity,
                                 "asset": f.test.engagement.product.name, "open": f.active}
                out["asset"] = f.test.engagement.product.name
        elif "inventory_id" in out and tools.org_wide(user):
            from orasec.posture.models import InventoryAsset  # noqa: PLC0415

            a = InventoryAsset.objects.filter(id=out["inventory_id"]).first()
            if a:
                out["asset"] = a.name
        elif "product_id" in out:
            from orasec.models import Product  # noqa: PLC0415

            p = Product.objects.filter(id=out["product_id"]).only("name").first()
            if p:
                out["asset"] = p.name
        elif "risk_id" in out and tools.org_wide(user):
            from orasec.posture.models import RiskRegisterEntry  # noqa: PLC0415

            r = RiskRegisterEntry.objects.filter(id=out["risk_id"]).first()
            if r:
                out["record"] = {"risk": r.ref, "title": r.title[:140], "likelihood": r.likelihood, "impact": r.impact}
        elif "vulnerability" in out and str(out["vulnerability"]).upper().startswith("CVE-"):
            out["cve"] = str(out["vulnerability"]).upper()
    except Exception:  # noqa: BLE001 -- context is best-effort
        pass
    return out


def snapshot(user) -> dict[str, Any] | None:
    if not tools.org_wide(user):
        return None
    d = tools._dashboard()
    if not d:
        return None
    kpi, sla, ex = d.get("kpi") or {}, d.get("sla") or {}, d.get("exploit") or {}
    return {"posture_score": (d.get("posture") or {}).get("score"), "open_findings": kpi.get("open"),
            "critical": kpi.get("critical"), "kev_findings": ex.get("kev_findings"), "overdue": sla.get("overdue"),
            "as_of": d.get("generated")}


def build(user, *, question: str, page: dict[str, Any], conversation, surface: str) -> dict[str, Any]:
    su = bool(user.is_superuser)
    pm = page_map.for_prompt(superuser=su)
    hits = {p["path"] for p in page_map.search(question, 4)}
    if page.get("path"):
        cur = page_map.page_for(page["path"])
        if cur:
            hits.add(cur["path"])
    slim = [{"path": p["path"], "title": p["title"], "where": p["where"], **({"about": p["about"]} if p["path"] in hits else {})}
            for p in pm]
    if surface == "mobile":
        slim = [dict(p, app=bool(page_map.mobile_route(p["path"]))) for p in slim]
    ctx: dict[str, Any] = {
        "today": timezone.localdate().isoformat(),
        "user": {"role": "superuser" if su else "security team" if tools.org_wide(user) else "user"},
        "surface": "phone app" if surface == "mobile" else "web",
        "page": page,
        "page_map": slim,
        "knowledge": knowledge.relevant(question, page.get("path", "")),
        "guides": knowledge.guides_for(user) if surface != "mobile" else [],
        "ora_actions": actions.allowed_kinds(user),
    }
    snap = snapshot(user)
    if snap:
        ctx["posture_now"] = snap
    convo = actions.describe_for_context(conversation)
    if convo:
        ctx["ora_conversation"] = convo
    if surface == "mobile":
        ctx["note"] = "In the phone app, pages marked app=false are only on the web; say so if you send them there."
    return ctx


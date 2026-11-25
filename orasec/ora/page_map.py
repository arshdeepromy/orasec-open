"""Where things are in OraSec -- the only paths Ora may send people to.

Every ``navigate`` action from the AI is checked against this map (exact path
or a known detail-path pattern); anything else is dropped. ``sel`` is the CSS
selector the spotlight highlights in the sidebar (web), ``where`` is how a
person finds it by hand, ``mobile`` is the matching app route (None = web only).
"""
from __future__ import annotations

import re
from typing import Any

#: key, path, title, where, sel, keywords, about, mobile
PAGES: list[dict[str, Any]] = [
    {"key": "dashboard", "path": "/dashboard", "title": "Dashboard", "where": "Sidebar → Dashboard",
     "kw": ["dashboard", "home", "overview", "summary", "chart", "kpi", "metrics"],
     "about": "Security posture at a glance: open vulnerabilities per asset, criticality chart, exploitable (KEV) "
              "count, attacks blocked, code vulnerabilities per product, resolution times, risk register list.",
     "mobile": "/"},
    {"key": "command_center", "path": "/orasec/command-center/", "title": "Command Center",
     "where": "Sidebar → Command Center", "kw": ["command center", "posture", "score", "today", "priorities"],
     "about": "Live posture score, the top prioritised findings, SLA breaches, connector health and what changed.",
     "mobile": "/"},
    {"key": "my_work", "path": "/orasec/my-work/", "title": "My Work", "where": "Sidebar → My Work",
     "kw": ["my work", "assigned to me", "my findings", "my tasks", "inbox", "queue"],
     "about": "Findings assigned to you, ordered by priority and due date.", "mobile": "/my-work"},
    {"key": "vulnerabilities", "path": "/orasec/vulnerabilities/", "title": "Vulnerability Explorer",
     "where": "Sidebar → Exposure → Vulnerability Explorer",
     "kw": ["vulnerabilities", "vulnerability explorer", "cve", "cves", "kev", "epss", "exploitable", "explorer"],
     "about": "Every open vulnerability grouped by CVE / rule, with KEV and EPSS, affected assets and priority band. "
              "Filter by severity, band, KEV, asset.", "mobile": "/vulns"},
    {"key": "remediation", "path": "/orasec/remediation/", "title": "Remediation Center",
     "where": "Sidebar → Exposure → Remediation Center",
     "kw": ["remediation", "campaign", "campaigns", "fix plan", "assign", "bulk assign", "sla", "overdue"],
     "about": "Remediation campaigns, assignments, SLA due dates and overdue findings.", "mobile": "/my-work"},
    {"key": "patch_center", "path": "/orasec/patching/", "title": "Patch Center",
     "where": "Sidebar → Exposure → Patch Center",
     "kw": ["patch", "patching", "patch center", "updates", "deploy patch", "apt", "windows update"],
     "about": "Missing patches per asset and patch deployments (with history of each run).", "mobile": None},
    {"key": "assets", "path": "/orasec/assets/", "title": "Asset Inventory dashboard",
     "where": "Sidebar → Asset Inventory → Dashboard",
     "kw": ["asset inventory", "assets dashboard", "inventory dashboard", "asset owners", "joint owners", "where assets sit",
            "cloud services", "internal tools", "information assets", "export inventory", "asset report", "a.5.9"],
     "about": "Live inventory of everything the organisation relies on: devices, cloud resources, code, domains, cloud services "
              "(from the supplier register), internal tools and information. Shows owners, where each asset sits, gaps, "
              "and exports to PDF / Excel or a custom report written by Ora.", "mobile": None},
    {"key": "assets_list", "path": "/orasec/assets/list/", "title": "All assets",
     "where": "Sidebar → Asset Inventory → All assets",
     "kw": ["all assets", "asset list", "filter assets", "assets by owner", "assets by location"],
     "about": "Every active asset with filters by group, owner, location and criticality; grouped view; exports.", "mobile": None},
    {"key": "leavers", "path": "/orasec/leavers/", "title": "Leavers and movers",
     "where": "Sidebar → Asset Inventory → Leavers and movers",
     "kw": ["leaver", "leavers", "mover", "offboarding", "offboard", "return of assets", "someone leaving", "lvr", "a.5.11"],
     "about": "Leaver and mover records: the FRM-002 checklist (devices back, accounts disabled, credentials rotated, "
              "sessions revoked, assets moved to a new owner), opened automatically when an account is deactivated, "
              "signed off by someone other than the leaver.", "mobile": None},
    {"key": "inventory", "path": "/orasec/inventory/", "title": "Asset Inventory",
     "where": "Sidebar → Exposure → Asset Inventory (device details)",
     "kw": ["asset", "assets", "inventory", "hosts", "servers", "machines", "devices", "criticality"],
     "about": "All discovered assets with owner, criticality, exposure (internet-facing) and open vulnerabilities.",
     "mobile": "/assets"},
    {"key": "scan_cadence", "path": "/orasec/scan-cadence/", "title": "Scan Cadence",
     "where": "Sidebar → Exposure → Scan Cadence",
     "kw": ["scan cadence", "scan schedule", "last scanned", "stale scans", "coverage"],
     "about": "How often each product is scanned and which scans are overdue.", "mobile": None},
    {"key": "insights", "path": "/orasec/insights/executive/", "title": "Insights",
     "where": "Sidebar → Exposure → Insights",
     "kw": ["insights", "executive", "trend", "trends", "report for management", "mttr", "board"],
     "about": "Executive insights: posture trend, mean time to remediate, risk by business unit.", "mobile": None},
    {"key": "code", "path": "/orasec/code/", "title": "Code & Repositories", "where": "Sidebar → Code & Repositories",
     "kw": ["code", "repository", "repositories", "repo", "github", "sast", "secrets", "dependabot", "semgrep",
            "gitleaks"],
     "about": "Code vulnerabilities per repository / product (SAST, dependencies, secrets) and how many were resolved.",
     "mobile": "/code"},
    {"key": "attacks", "path": "/orasec/attacks/", "title": "Attack Map", "where": "Sidebar → Network → Attack Map",
     "kw": ["attack", "attacks", "blocked", "firewall", "waf", "crowdsec", "attack map", "ips", "intrusion"],
     "about": "Attacks blocked by the firewall / WAF / CrowdSec, by country, source and target.", "mobile": "/attacks"},
    {"key": "topology", "path": "/orasec/topology/", "title": "Network Topology",
     "where": "Sidebar → Network → Network Topology",
     "kw": ["topology", "network map", "network topology", "subnets", "vlan"],
     "about": "Map of the network: subnets, assets and their links.", "mobile": None},
    {"key": "compliance", "path": "/orasec/compliance/", "title": "ISO 27001 Compliance",
     "where": "Sidebar → Governance → ISO 27001 Compliance",
     "kw": ["compliance", "iso", "iso 27001", "27001", "controls", "annex a", "soa", "statement of applicability",
            "evidence", "audit"],
     "about": "ISO 27001 controls, implementation status, evidence, automated checks and the SoA export.",
     "mobile": "/governance"},
    {"key": "risks", "path": "/orasec/risks/", "title": "Risk Register", "where": "Sidebar → Governance → Risk Register",
     "kw": ["risk register", "risks", "risk", "likelihood", "impact", "treatment", "risk owner"],
     "about": "The risk register: likelihood × impact, owner, treatment plan, linked findings and review dates.",
     "mobile": "/governance"},
    {"key": "risk_new", "path": "/orasec/risks/new/", "title": "New risk",
     "where": "Sidebar → Governance → Risk Register → New risk", "kw": ["add risk", "new risk", "create risk"],
     "about": "Add a risk to the register.", "mobile": None},
    {"key": "risk_acceptances", "path": "/orasec/risk-acceptances/", "title": "Risk Acceptances",
     "where": "Sidebar → Governance → Risk Acceptances",
     "kw": ["risk acceptance", "risk acceptances", "accept risk", "exception", "exceptions", "approve", "waiver"],
     "about": "Risk-acceptance requests waiting for a decision, and accepted findings with expiry dates.",
     "mobile": "/governance"},
    {"key": "connectors", "path": "/orasec/connectors/", "title": "Connectors", "where": "Sidebar → Automation → Connectors",
     "kw": ["connector", "connectors", "integration", "integrations", "scanner", "tenable", "wazuh", "nessus",
            "sync", "import"],
     "about": "Scanner and tool connectors, their health, last run and errors. Run or test a connector here.",
     "mobile": "/connectors"},
    {"key": "connector_new", "path": "/orasec/connectors/new/", "title": "Add a connector",
     "where": "Sidebar → Automation → Connectors → Add connector", "kw": ["add connector", "new connector"],
     "about": "Connect a new scanner or tool.", "mobile": None},
    {"key": "triage_rules", "path": "/orasec/triage-rules/", "title": "Triage Rules",
     "where": "Sidebar → Automation → Triage Rules",
     "kw": ["triage", "triage rules", "auto close", "suppress", "rules", "false positive rules"],
     "about": "Rules that automatically assign, re-rate or suppress incoming findings.", "mobile": None},
    {"key": "diagnostics", "path": "/orasec/diagnostics/", "title": "Diagnostics",
     "where": "Sidebar → Automation → Diagnostics", "kw": ["diagnostics", "jobs", "background jobs", "health"],
     "about": "Background jobs, last runs and errors; run a job by hand.", "mobile": None},
    {"key": "priority_settings", "path": "/orasec/settings/prioritisation/", "title": "Prioritisation & SLA",
     "where": "Sidebar → Automation → Prioritisation & SLA",
     "kw": ["prioritisation", "prioritization", "priority settings", "weights", "sla settings", "due dates", "bands"],
     "about": "How the priority score is weighted (severity, KEV, EPSS, exposure, criticality) and the SLA per band.",
     "mobile": None},
    {"key": "products", "path": "/asset", "title": "Assets (products)", "where": "Sidebar → Assets",
     "kw": ["product", "products", "applications", "apps", "product type", "asset list", "business unit"],
     "about": "Assets / products (applications, systems) and their engagements, tests and findings; findings "
              "are grouped under these.", "mobile": None},
    {"key": "engagements", "path": "/engagement", "title": "Engagements", "where": "Sidebar → Engagements",
     "kw": ["engagement", "engagements", "pentest", "penetration test", "assessment"],
     "about": "Engagements (scans, pentests, assessments) and their tests.", "mobile": None},
    {"key": "open_findings", "path": "/finding/open", "title": "Open findings", "where": "Sidebar → Findings → Open Findings",
     "kw": ["findings", "open findings", "all findings", "finding list"],
     "about": "Every open finding with filters (severity, product, date, verified, tags).", "mobile": "/vulns"},
    {"key": "accepted_findings", "path": "/finding/accepted", "title": "Accepted findings",
     "where": "Sidebar → Findings → Risk Accepted Findings", "kw": ["accepted findings", "risk accepted"],
     "about": "Findings that have an accepted risk.", "mobile": None},
    {"key": "closed_findings", "path": "/finding/closed", "title": "Closed findings",
     "where": "Sidebar → Findings → Closed Findings", "kw": ["closed findings", "resolved", "mitigated", "fixed"],
     "about": "Findings that were closed / mitigated.", "mobile": None},
    {"key": "endpoints", "path": "/endpoint", "title": "Endpoints", "where": "Sidebar → Endpoints",
     "kw": ["endpoint", "endpoints", "urls", "hosts list"], "about": "Endpoints (hosts, URLs) found by scans.",
     "mobile": None},
    {"key": "reports", "path": "/reports/builder", "title": "Report Builder", "where": "Sidebar → Reports",
     "kw": ["report", "reports", "report builder", "pdf report", "export findings"],
     "about": "Build a findings report (HTML / PDF / CSV).", "mobile": None},
    {"key": "metrics", "path": "/metrics", "title": "Metrics", "where": "Sidebar → Metrics",
     "kw": ["metrics", "statistics", "stats", "engineer metrics"], "about": "Finding metrics by product and period.",
     "mobile": None},
    {"key": "notifications", "path": "/notifications", "title": "Notifications",
     "where": "Sidebar → Configuration → Notifications", "kw": ["notifications", "alerts", "email alerts"],
     "about": "Which events notify you and how.", "mobile": None},
    {"key": "sla_config", "path": "/sla_config", "title": "SLA configuration",
     "where": "Sidebar → Configuration → SLA Configuration", "kw": ["sla configuration", "sla config"],
     "about": "SLA days per severity used by product SLA rules.", "mobile": None},
    {"key": "mobile_devices", "path": "/orasec/mobile/", "title": "Mobile app",
     "where": "Profile menu → Mobile app", "kw": ["mobile", "phone", "app", "link phone", "link code", "devices"],
     "about": "Link the OraSec phone app with a code, and see or revoke linked phones.", "mobile": "/more"},
    {"key": "ora_settings", "path": "/orasec/ora/settings/", "title": "Ora settings",
     "where": "Sidebar → Configuration → Ora assistant (superusers)", "kw": ["ora settings", "assistant settings", "ai settings"],
     "about": "Superusers: connect Ora, limits, usage, unanswered questions and help articles.", "mobile": None,
     "superuser": True},
]

#: Detail pages Ora may link to (the ids come from tool results, never invented).
DETAIL_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^/finding/\d+$"), "finding"),
    (re.compile(r"^/orasec/vulnerabilities/[A-Za-z0-9._:-]{1,80}/$"), "vulnerability"),
    (re.compile(r"^/orasec/inventory/\d+/$"), "asset"),
    (re.compile(r"^/orasec/leavers/\d+/$"), "leavers"),
    (re.compile(r"^/orasec/risks/\d+/$"), "risk"),
    (re.compile(r"^/orasec/connectors/\d+/$"), "connector"),
    (re.compile(r"^/orasec/compliance/controls/\d+/$"), "control"),
    (re.compile(r"^/asset/\d+$"), "product"),
    (re.compile(r"^/engagement/\d+$"), "engagement"),
]

_BY_PATH = {p["path"]: p for p in PAGES}


def _norm(path: str) -> str:
    return (path or "").split("?", 1)[0].split("#", 1)[0]


def allowed(path: str, *, superuser: bool = False) -> bool:
    p = _norm(path)
    page = _BY_PATH.get(p)
    if page:
        return superuser or not page.get("superuser")
    return any(rx.match(p) for rx, _ in DETAIL_PATTERNS)


def page_for(path: str) -> dict[str, Any] | None:
    p = _norm(path)
    if p in _BY_PATH:
        return _BY_PATH[p]
    best = None
    for page in PAGES:
        if p.startswith(page["path"].rstrip("/") + "/") and (best is None or len(page["path"]) > len(best["path"])):
            best = page
    return best


def sidebar_selector(path: str) -> str | None:
    page = _BY_PATH.get(_norm(path))
    if not page:
        return None
    return f'#os-sidebar a[href="{page["path"]}"]'


def mobile_route(path: str) -> str | None:
    p = _norm(path)
    page = _BY_PATH.get(p)
    if page:
        return page.get("mobile")
    m = re.match(r"^/finding/(\d+)$", p)
    if m:
        return f"/vulns/{m.group(1)}"
    m = re.match(r"^/orasec/risks/(\d+)/$", p)
    if m:
        return f"/risks/{m.group(1)}"
    return None


def for_prompt(*, superuser: bool = False) -> list[dict[str, str]]:
    return [{"path": p["path"], "title": p["title"], "where": p["where"], "about": p["about"]}
            for p in PAGES if superuser or not p.get("superuser")]


def search(text: str, limit: int = 3) -> list[dict[str, Any]]:
    """Pages whose keywords appear in ``text`` (longest keyword match wins)."""
    t = " " + re.sub(r"[^a-z0-9 ]+", " ", (text or "").lower()) + " "
    scored = []
    for p in PAGES:
        if p.get("superuser"):
            continue
        best = max((len(k) for k in p["kw"] if f" {k} " in t or (len(k) > 5 and k in t)), default=0)
        if best:
            scored.append((best, p))
    scored.sort(key=lambda x: -x[0])
    return [p for _, p in scored[:limit]]


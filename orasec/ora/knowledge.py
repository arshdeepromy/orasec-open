"""OraSec help passages and guided walkthroughs for Ora.

Built-in articles live here (reviewed with the code); superusers add more on
the Ora settings page (``OraKbArticle``). ``relevant()`` picks the passages a
question needs, so the prompt stays small.

Guides are click-by-click walkthroughs the web app runs with the spotlight:
each step names the page it happens on, the element to point at and what to
say. ``click`` steps wait for the user to press the element.
"""
from __future__ import annotations

import re
from typing import Any

ARTICLES: list[dict[str, Any]] = [
    {"id": "priority", "title": "How OraSec prioritises findings",
     "kw": ["priority", "prioritise", "prioritize", "score", "band", "urgent", "needs action", "fix first", "order"],
     "body": "Every open finding gets a priority score (0-100) from: severity, CISA KEV (known exploited), ransomware "
             "use, EPSS percentile (chance of exploitation in 30 days), internet exposure of the asset, asset "
             "criticality (1-5), whether a fix is available, and whether it is past its SLA. The score puts it in a "
             "band: Urgent, Needs Action, Medium or Low, and each band has an SLA (default 7 / 30 / 90 / 180 days). "
             "Weights, band thresholds and SLA days are on Automation → Prioritisation & SLA (superusers); saving "
             "recalculates every finding. Fix by band, then by score; the Remediation Center groups findings by the "
             "component whose single update clears most of them."},
    {"id": "kev_epss", "title": "KEV and EPSS",
     "kw": ["kev", "known exploited", "cisa", "epss", "exploit", "exploitable", "percentile", "ransomware"],
     "body": "KEV is CISA's Known Exploited Vulnerabilities catalogue: attackers are using these CVEs now, and CISA "
             "sets a due date. EPSS estimates the probability a CVE is exploited in the next 30 days; the percentile "
             "compares it to all CVEs (95th percentile = riskier than 95% of CVEs). OraSec refreshes both feeds "
             "daily (Automation → Diagnostics shows the feed status). Vulnerability Explorer has a 'Known exploited "
             "only' filter."},
    {"id": "risk_rating", "title": "Rating a risk (likelihood × impact)",
     "kw": ["likelihood", "impact", "risk rating", "rate risk", "evaluate risk", "assess", "heat map", "risk score"],
     "body": "The risk register scores likelihood and impact from 1 to 5; score = likelihood × impact (8-14 Medium, "
             "15+ High, 20+ Critical). Evidence that raises likelihood: KEV (5), high EPSS, internet exposure. Impact "
             "follows severity and how critical the asset is, plus ransomware use. Residual likelihood/impact record "
             "the rating after treatment. Treatments: mitigate (fix or add controls), accept (owner signs off, with a "
             "review date), transfer (insurance / third party) or avoid (stop the activity). Each risk has an owner "
             "and a review date; overdue reviews show on the dashboard."},
    {"id": "add_risk", "title": "Add or update a risk",
     "kw": ["add risk", "new risk", "create risk", "risk register", "link findings", "edit risk"],
     "body": "Governance → Risk Register → Add risk (superusers). Fill in the title, description, asset, threat, "
             "vulnerability, likelihood, impact, treatment and plan, owner, status and review date, link the ISO "
             "controls and findings it covers, then Save. Open a risk from the register to edit it. Ora can also "
             "prepare a risk from findings for you to confirm."},
    {"id": "risk_acceptance", "title": "Accepting risk on findings",
     "kw": ["accept risk", "risk acceptance", "exception", "waiver", "approve", "accepted findings", "expiry"],
     "body": "To accept the risk of a finding: open the finding, use its menu → Add Risk Acceptance, give the reason, "
             "owner and expiry date. OraSec holds new acceptances for approval: an approver (staff or superuser) "
             "decides on Governance → Risk Acceptances. Accepted findings drop out of the open counts until the "
             "acceptance expires. Ora cannot accept risk itself."},
    {"id": "close_finding", "title": "Closing a finding",
     "kw": ["close", "resolve", "mitigated", "false positive", "out of scope", "fixed", "mark fixed"],
     "body": "Open the finding and use Close Finding: choose mitigated (it was fixed), false positive or out of "
             "scope, and add a note saying how it was fixed or why. Scanner connectors also close findings "
             "automatically when the next scan no longer reports them. Ora can prepare a close card; you confirm it."},
    {"id": "assign", "title": "Assigning work and campaigns",
     "kw": ["assign", "owner", "my work", "campaign", "remediation", "team", "who"],
     "body": "Assign a finding from its page (Assign to) or from the Remediation Center. My Work lists findings "
             "assigned to you by priority and due date. Remediation campaigns (Exposure → Remediation Center) "
             "group the findings one component update fixes, with an owner and a target date, and track progress "
             "from the baseline count."},
    {"id": "connectors", "title": "Connectors and scans",
     "kw": ["connector", "integration", "scanner", "wazuh", "opnsense", "unifi", "patchmon", "semaphore", "aws",
            "cloudflare", "github", "sync", "import scan", "failing"],
     "body": "Automation → Connectors lists every scanner and tool OraSec pulls from, with status, last success and "
             "the last message. Open a connector to Test the connection, Run it now or see run logs. A failing "
             "connector usually means expired credentials or an unreachable host: the run log shows the error. "
             "Scans can also be uploaded by hand on a product (Assets → product → Import Scan Results). Scan "
             "Cadence shows products whose scans are overdue."},
    {"id": "triage", "title": "Triage rules",
     "kw": ["triage", "rule", "auto assign", "suppress", "noise", "false positives", "automatic"],
     "body": "Automation → Triage Rules run on incoming findings in order: conditions (JSON: severity, title, "
             "component, product, tags, CVE, KEV...) and actions (assign, set severity, add tag, mark false "
             "positive...). 'Stop processing' ends the chain for a match. Use Preview on a rule to see what it would "
             "match before enabling it."},
    {"id": "patching", "title": "Patch Center",
     "kw": ["patch", "patching", "update", "deploy", "apt", "missing patches", "semaphore"],
     "body": "Exposure → Patch Center shows missing patches per asset (from PatchMon) and lets superusers start a "
             "patch deployment through Semaphore, with a change reference; each run keeps its output. Ora does not "
             "deploy patches."},
    {"id": "attacks", "title": "Attacks and network",
     "kw": ["attack", "blocked", "firewall", "waf", "crowdsec", "country", "brute force", "topology", "network"],
     "body": "Network → Attack Map shows attacks blocked by the firewall, UniFi, Cloudflare WAF and CrowdSec: hits "
             "over time, top source countries, ports and targets. Network Topology draws subnets and assets. Blocked "
             "attacks are blocked -- the risk comes from what is exposed: check internet-exposed assets with open "
             "KEV findings."},
    {"id": "code", "title": "Code & repositories",
     "kw": ["code", "repository", "sast", "secret", "dependency", "dependabot", "semgrep", "gitleaks", "container"],
     "body": "Code & Repositories shows code findings per product split into SAST, secrets, dependencies, "
             "containers and GitHub alerts, with how many were resolved. A leaked secret must be rotated, not just "
             "deleted from the code. Dependency findings are usually fixed by upgrading to the fixed version shown."},
    {"id": "iso", "title": "ISO 27001 compliance",
     "kw": ["iso", "27001", "control", "annex", "evidence", "soa", "statement of applicability", "audit", "compliance"],
     "body": "Governance → ISO 27001 Compliance lists the Annex A controls with applicability, status, owner, "
             "evidence and automated checks (e.g. A.8.8 checks overdue vulnerabilities). 'Run checks' re-evaluates "
             "them; the SoA export downloads the Statement of Applicability. Open a control to add evidence (file or "
             "link with a valid-until date) and set its review date."},
    {"id": "posture", "title": "The posture score",
     "kw": ["posture", "score", "1000", "hygiene", "dashboard", "command center"],
     "body": "The posture score (0-1000) is 60% vulnerability exposure (weighted by priority band per asset and "
             "overdue findings), 25% ISO 27001 compliance and 15% hygiene (connector health, intel feed freshness, "
             "scan cadence). Command Center shows today's score and what changed; the Dashboard shows the charts."},
    {"id": "mobile", "title": "The OraSec phone app",
     "kw": ["mobile", "phone", "app", "android", "iphone", "link", "link code", "qr"],
     "body": "Open your profile menu → Mobile app, press 'Create a link code', and type the code into the OraSec "
             "app on your phone (codes last 10 minutes). The same page lists linked phones; Sign out removes one. "
             "The app shows the dashboard, vulnerabilities, assets, attacks, governance and your work, and has Ora "
             "too."},
    {"id": "sla", "title": "SLA and due dates",
     "kw": ["sla", "due", "overdue", "deadline", "breach"],
     "body": "Each finding's due date comes from its priority band's SLA (days from when it was found, or from "
             "when it reached the band -- set in Prioritisation & SLA); for KEV findings it can be capped at CISA's "
             "due date. Overdue findings lower the posture score and show in Remediation Center and on the dashboard."},
    {"id": "reports", "title": "Reports and exports",
     "kw": ["report", "export", "pdf", "csv", "management", "board"],
     "body": "Reports → Report Builder creates findings reports (HTML/PDF/CSV). The Risk Register and ISO 27001 "
             "pages have a PDF button; Insights has executive views of trends and time to remediate."},
]

GUIDES: list[dict[str, Any]] = [
    {"id": "add_risk", "title": "Add a risk to the register", "superuser": True, "steps": [
        {"path": "/orasec/risks/", "target": "a[href='/orasec/risks/new/']", "click": True,
         "caption": "This is the risk register. Press Add risk to start a new entry."},
        {"path": "/orasec/risks/new/", "target": "#id_title", "caption": "A short title: what could go wrong, on what."},
        {"path": "/orasec/risks/new/", "target": "#id_likelihood",
         "caption": "Likelihood 1-5. Known exploited (KEV) or internet-facing pushes this up. Ask me to evaluate it if unsure."},
        {"path": "/orasec/risks/new/", "target": "#id_impact", "caption": "Impact 1-5: how bad it would be for the business."},
        {"path": "/orasec/risks/new/", "target": "#id_treatment", "caption": "Mitigate, accept, transfer or avoid -- then describe the plan below."},
        {"path": "/orasec/risks/new/", "target": "#id_owner", "caption": "Every risk needs an owner and a review date."},
        {"path": "/orasec/risks/new/", "target": "form.card button.btn-p", "caption": "Check it over, then press Save."},
    ]},
    {"id": "link_phone", "title": "Link the OraSec phone app", "steps": [
        {"path": "/orasec/mobile/", "target": "form button.btn-p[type='submit']", "click": True,
         "caption": "Press this to create a link code."},
        {"path": "/orasec/mobile/", "target": "[data-ora='link-code']",
         "caption": "Type this code into the OraSec app on your phone. It works for 10 minutes."},
    ]},
    {"id": "add_connector", "title": "Connect a scanner or tool", "superuser": True, "steps": [
        {"path": "/orasec/connectors/", "target": "a[href='/orasec/connectors/new/']", "click": True,
         "caption": "Press Add connector."},
        {"path": "/orasec/connectors/new/", "target": "#id_kind", "caption": "Pick the tool you're connecting."},
        {"path": "/orasec/connectors/new/", "target": "#id_name", "caption": "Name it so the team recognises it."},
        {"path": "/orasec/connectors/new/", "target": "#id_base_url", "caption": "The tool's address. Its key or password goes in the secret field below."},
        {"path": "/orasec/connectors/new/", "target": "#id_interval_minutes", "caption": "How often OraSec pulls from it."},
        {"path": "/orasec/connectors/new/", "target": "form button.btn-p", "caption": "Save, then use Test on the next page."},
    ]},
    {"id": "triage_rule", "title": "Create a triage rule", "superuser": True, "steps": [
        {"path": "/orasec/triage-rules/", "target": "a[href='/orasec/triage-rules/new/']", "click": True,
         "caption": "Press New rule."},
        {"path": "/orasec/triage-rules/new/", "target": "#id_name", "caption": "Name the rule after what it does."},
        {"path": "/orasec/triage-rules/new/", "target": "#id_conditions_json", "caption": "Which findings it matches (JSON)."},
        {"path": "/orasec/triage-rules/new/", "target": "#id_actions_json", "caption": "What it does to them (JSON)."},
        {"path": "/orasec/triage-rules/new/", "target": "form button.btn-p", "caption": "Save -- use Preview on the rule before enabling it widely."},
    ]},
    {"id": "tune_priority", "title": "Tune prioritisation and SLA", "superuser": True, "steps": [
        {"path": "/orasec/settings/prioritisation/", "target": "#id_weights_json",
         "caption": "Points each factor adds to the score (severity, KEV, EPSS, exposure, criticality...)."},
        {"path": "/orasec/settings/prioritisation/", "target": "#id_bands_json", "caption": "The score each band starts at."},
        {"path": "/orasec/settings/prioritisation/", "target": "#id_sla_json", "caption": "Days to fix per band."},
        {"path": "/orasec/settings/prioritisation/", "target": "form button.btn-p",
         "caption": "Save and recalculate re-scores every open finding."},
    ]},
    {"id": "find_kev", "title": "Find known-exploited vulnerabilities", "steps": [
        {"path": "/orasec/vulnerabilities/", "target": "input[name='kev']", "click": True,
         "caption": "Tick 'Known exploited only' -- these are being used by attackers now."},
        {"path": "/orasec/vulnerabilities/", "target": "form.filters button.btn", "click": True, "caption": "Press Search."},
        {"path": "/orasec/vulnerabilities/", "target": "table", "caption": "Fix these first, starting with internet-facing assets."},
    ]},
    {"id": "campaign", "title": "Start a remediation campaign", "superuser": True, "steps": [
        {"path": "/orasec/remediation/", "target": "table", "caption": "Each row is a component whose update clears many findings."},
        {"path": "/orasec/remediation/", "target": "#newc", "caption": "Name the campaign, set the component, owner and target date."},
        {"path": "/orasec/remediation/", "target": "#newc button", "caption": "Save -- progress is tracked against today's count."},
    ]},
]

_WORD_RE = re.compile(r"[a-z0-9]+")


def _db_articles() -> list[dict[str, Any]]:
    from orasec.ora.models import OraKbArticle  # noqa: PLC0415

    return [{"id": f"kb{a.id}", "title": a.title, "kw": [k.lower() for k in a.keywords or []], "body": a.body,
             "path": a.path} for a in OraKbArticle.objects.filter(status="published")[:200]]


def relevant(question: str, page_path: str = "", limit: int = 3) -> list[dict[str, str]]:
    t = " " + " ".join(_WORD_RE.findall((question or "").lower())) + " "
    words = set(t.split())
    scored = []
    for a in ARTICLES + _db_articles():
        s = sum(3 + len(k) // 6 for k in a["kw"] if f" {k} " in t)
        s += sum(1 for w in _WORD_RE.findall(a["title"].lower()) if len(w) > 3 and w in words)
        if a.get("path") and page_path and page_path.startswith(a["path"]):
            s += 2
        if s:
            scored.append((s, a))
    scored.sort(key=lambda x: -x[0])
    return [{"title": a["title"], "text": a["body"]} for _, a in scored[:limit]]


def guides_for(user) -> list[dict[str, str]]:
    su = bool(user and user.is_superuser)
    return [{"id": g["id"], "title": g["title"]} for g in GUIDES if su or not g.get("superuser")]


def guide(gid: str, user) -> dict[str, Any] | None:
    su = bool(user and user.is_superuser)
    for g in GUIDES:
        if g["id"] == gid and (su or not g.get("superuser")):
            return g
    return None


"""Approved documents in the policy tool become OraSec control evidence. One way.

The tool keeps documents as markdown with YAML frontmatter in its git repository. Its REST API does not
return custom frontmatter (our "controls" list), so OraSec reads the repository itself over the tool's
git endpoint, read-only, with the same sync token.

For every document with status "approved" and a "controls" list, each listed ISO/IEC 27001:2022 control
gets one automated evidence item for that version, valid until the document's next review. A newer
approved version adds a new item and the older item is marked superseded (valid until today). Nothing is
deleted. Drafts and documents under review are not evidence.
"""
import datetime
import io
import logging
import os
import re
import subprocess
import tarfile
from pathlib import Path

import yaml
from django.utils import timezone

from orasec import site as site_profile
from orasec.posture.isms_sync import IsmsError, sync_writes

logger = logging.getLogger(__name__)
GIT_DIR = Path(os.environ.get("ORASEC_ISMS_GIT_CACHE", "/tmp/orasec-isms-docs.git"))
FRAMEWORK = "iso27001-2022"
PREFIX = "Policy tool: "
_FM = re.compile(r"\A---[ \t]*\r?\n(.*?)\r?\n---[ \t]*\r?\n", re.S)


def _git(conn, *args, binary=False, timeout=90):
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="http.extraHeader",
               GIT_CONFIG_VALUE_0="Authorization: Bearer " + conn.get_secrets().get("token", ""))
    if not conn.verify_tls:
        env["GIT_SSL_NO_VERIFY"] = "1"
    try:
        r = subprocess.run(["git", "--git-dir", str(GIT_DIR), *args], env=env, capture_output=True, timeout=timeout,
                           check=False)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise IsmsError(f"git {args[0]}: {e}") from e
    if r.returncode:
        raise IsmsError(f"git {args[0]}: {r.stderr.decode(errors='replace').strip()[:300]}")
    return r.stdout if binary else r.stdout.decode(errors="replace")


def read_documents(ctx):
    """Fetch the tool's main branch and return the parsed frontmatter of every document."""
    org = ctx.client._req("GET", "/me").get("organization_uuid")
    if not org:
        raise IsmsError("policy tool did not return the organisation id")
    url = ctx.conn.base_url.rstrip("/") + "/git/" + org
    if not (GIT_DIR / "HEAD").exists():
        GIT_DIR.mkdir(parents=True, exist_ok=True)
        _git(ctx.conn, "init", "--bare", "-q")
    _git(ctx.conn, "fetch", "-q", "--depth", "1", url, "+refs/heads/main:refs/heads/main")
    data = _git(ctx.conn, "archive", "--format=tar", "main", "documents", binary=True)
    docs = []
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        for m in tar.getmembers():
            if not m.isfile() or not m.name.endswith(".md"):
                continue
            text = tar.extractfile(m).read().decode("utf-8", errors="replace")
            hit = _FM.match(text)
            if not hit:
                continue
            try:
                fm = yaml.safe_load(hit.group(1)) or {}
            except yaml.YAMLError:
                logger.warning("isms-docs: bad frontmatter in %s", m.name)
                continue
            if isinstance(fm, dict) and fm.get("document_id"):
                fm["_path"] = m.name
                docs.append(fm)
    return docs


def _s(v):
    return "" if v is None else str(v).strip()


def doc_classification(fm) -> str:
    """The document's own classification label (first word: "Internal (Confidential when completed)" -> internal)."""
    v = _s(fm.get("classification")).strip().lower()
    for k in ("restricted", "confidential", "internal", "public"):
        if v.startswith(k):
            return k
    return "internal"


def evidence_title(fm):
    return f"{PREFIX}{_s(fm.get('document_id'))} {_s(fm.get('title'))} v{_s(fm.get('version'))}"[:300]


def sync_documents(ctx, st):
    """Create or supersede evidence for approved documents. Fills counters in st."""
    from orasec.posture.models import ComplianceControl, ControlEvidence  # noqa: PLC0415
    public = ((ctx.conn.options or {}).get("public_url") or ctx.conn.base_url).rstrip("/")
    # the tool's web app opens a document at /<organisation>/documents/<id>; /documents/<id> shows a blank page
    org = _s((ctx.conn.options or {}).get("organization") or (ctx.conn.options or {}).get("org") or site_profile.get("policy_tool.organization") or "").strip("/")
    controls = {c.ref: c for c in ComplianceControl.objects.filter(framework__code=FRAMEWORK)}
    today = timezone.localdate()
    for k in ("documents", "approved", "evidence_added", "evidence_superseded"):
        st.setdefault(k, 0)
    st.setdefault("unknown_controls", [])
    current = set()  # (control id, title) pairs that are current evidence
    for fm in read_documents(ctx):
        st["documents"] += 1
        if _s(fm.get("status")).lower() != "approved":
            continue
        refs = fm.get("controls") or []
        if not isinstance(refs, list) or not refs:
            continue
        st["approved"] += 1
        title = evidence_title(fm)
        url = f"{public}/{org}/documents/{_s(fm['document_id']).lower()}"
        try:
            valid = datetime.date.fromisoformat(_s(fm.get("next_review"))[:10]) if fm.get("next_review") else None
        except ValueError:
            valid = None
        bits = [f"Approved version {_s(fm.get('version'))} of {_s(fm.get('document_id'))} in the policy tool."]
        if fm.get("approved_by") or fm.get("approved_date"):
            bits.append(f"Approved by {_s(fm.get('approved_by')) or 'n/a'} on {_s(fm.get('approved_date')) or 'n/a'}"
                        + (f" under {_s(fm.get('change_ref'))}." if fm.get("change_ref") else "."))
        if fm.get("next_review"):
            bits.append(f"Next review {_s(fm.get('next_review'))}.")
        level = doc_classification(fm)
        for ref in refs:
            c = controls.get(_s(ref))
            if c is None:
                if _s(ref) not in st["unknown_controls"]:
                    st["unknown_controls"].append(_s(ref))
                continue
            current.add((c.pk, title))
            ev = ControlEvidence.objects.filter(control=c, source="auto", title=title).first()
            if ev is None:
                with sync_writes():
                    ControlEvidence.objects.create(control=c, source="auto", title=title, url=url,
                                                   description=" ".join(bits), valid_until=valid, classification=level)
                st["evidence_added"] += 1
            elif ev.valid_until != valid or ev.classification != level or ev.url != url:  # review date or label moved on the same version
                ev.valid_until, ev.url, ev.classification = valid, url, level
                ev.save(update_fields=["valid_until", "url", "classification"])
    # older versions, or documents no longer approved: superseded, never deleted
    for ev in ControlEvidence.objects.filter(source="auto", title__startswith=PREFIX):
        if (ev.control_id, ev.title) in current:
            continue
        if ev.valid_until is None or ev.valid_until > today:
            ev.valid_until = today
            if "Superseded" not in ev.description:
                ev.description = (ev.description + f" Superseded on {today.isoformat()}.").strip()
            ev.save(update_fields=["valid_until", "description"])
            st["evidence_superseded"] += 1
    return st


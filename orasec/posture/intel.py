"""
Exploit intelligence (CISA KEV, FIRST EPSS), priority scores, risk bands and SLA deadlines.

Feeds (refreshed daily by Celery; files can be loaded instead for air-gapped installs):
  KEV  https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
  EPSS https://api.first.org/data/v1/epss?cve=CVE-..,CVE-..   (only CVEs present in OraSec)
"""
import datetime
import logging
import time

import requests
from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from orasec.posture.models import EpssScore, FindingPriority, IntelFeed, InventoryAsset, KevEntry, PrioritySettings

logger = logging.getLogger(__name__)
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
CRITICALITY_POINTS = {"very high": 5, "high": 4, "medium": 3, "low": 2, "very low": 1, "none": 1}


def _feed(name):
    return IntelFeed.objects.get_or_create(name=name)[0]


def _date(s):
    try:
        return datetime.date.fromisoformat(str(s)[:10]) if s else None
    except ValueError:
        return None


def load_kev(data):
    rows = data.get("vulnerabilities", [])
    with transaction.atomic():
        existing = {k.cve: k for k in KevEntry.objects.all()}
        new, upd = [], []
        for v in rows:
            cve = v.get("cveID")
            if not cve:
                continue
            fields = {"vendor": v.get("vendorProject", "")[:200], "product": v.get("product", "")[:200],
                      "name": v.get("vulnerabilityName", "")[:500], "date_added": _date(v.get("dateAdded")),
                      "due_date": _date(v.get("dueDate")), "ransomware": str(v.get("knownRansomwareCampaignUse", "")).lower() == "known",
                      "required_action": v.get("requiredAction", "")}
            if cve in existing:
                obj = existing[cve]
                for k, val in fields.items():
                    setattr(obj, k, val)
                upd.append(obj)
            else:
                new.append(KevEntry(cve=cve, **fields))
        KevEntry.objects.bulk_create(new, batch_size=1000)
        KevEntry.objects.bulk_update(upd, list(fields.keys()), batch_size=1000)
    return len(rows)


def refresh_kev(data=None):
    feed = _feed("kev")
    try:
        if data is None:
            r = requests.get(KEV_URL, timeout=60)
            r.raise_for_status()
            data = r.json()
        n = load_kev(data)
        feed.status, feed.records, feed.message = "ok", n, f"catalog {data.get('catalogVersion', '')}"
    except Exception as e:
        logger.exception("KEV refresh failed")
        feed.status, feed.message = "error", f"{e.__class__.__name__}: {str(e)[:300]}"
    feed.last_refreshed = timezone.now()
    feed.save()
    return feed


def finding_cve_pairs(finding_ids=None, active_only=True):
    """(finding_id, CVE) pairs from both Finding.cve and the Vulnerability_Id table."""
    from orasec.models import Finding, Vulnerability_Id  # noqa: PLC0415
    fq = Finding.objects.filter(cve__istartswith="CVE-")
    vq = Vulnerability_Id.objects.filter(vulnerability_id__istartswith="CVE-")
    if active_only:
        fq, vq = fq.filter(active=True), vq.filter(finding__active=True)
    if finding_ids is not None:
        fq, vq = fq.filter(id__in=finding_ids), vq.filter(finding_id__in=finding_ids)
    pairs = {(fid, c.upper().strip()) for fid, c in fq.values_list("id", "cve")}
    pairs |= {(fid, c.upper().strip()) for fid, c in vq.values_list("finding_id", "vulnerability_id")}
    return pairs


def _finding_cves():
    return {c for _, c in finding_cve_pairs()}


def refresh_epss(cves=None):
    feed = _feed("epss")
    try:
        cves = sorted(cves or _finding_cves())
        got, failed, chunks = {}, [], 0
        for i in range(0, len(cves), 100):
            chunk = cves[i:i + 100]
            chunks += 1
            last_err = None
            for attempt in range(4):  # FIRST returns occasional 502/503; retry with back-off
                try:
                    r = requests.get(EPSS_URL, params={"cve": ",".join(chunk)}, timeout=60)
                    r.raise_for_status()
                    rows = r.json().get("data", [])
                    break
                except Exception as e:  # noqa: BLE001
                    last_err = e
                    time.sleep(5 * (attempt + 1))
            else:
                logger.warning("EPSS chunk %s-%s failed: %s", chunk[0], chunk[-1], last_err)
                failed.append(f"{chunk[0]}..{chunk[-1]}")
                continue
            for row in rows:
                got[row["cve"]] = (float(row["epss"]), float(row["percentile"]), _date(row.get("date")))
        if chunks and len(failed) > chunks * 0.1:
            raise RuntimeError(f"{len(failed)} of {chunks} EPSS requests failed after retries")
        with transaction.atomic():
            existing = {e.cve: e for e in EpssScore.objects.filter(cve__in=list(got))}
            new, upd = [], []
            for cve, (epss, pct, d) in got.items():
                if cve in existing:
                    o = existing[cve]
                    o.epss, o.percentile, o.score_date = epss, pct, d
                    upd.append(o)
                else:
                    new.append(EpssScore(cve=cve, epss=epss, percentile=pct, score_date=d))
            EpssScore.objects.bulk_create(new, batch_size=1000)
            EpssScore.objects.bulk_update(upd, ["epss", "percentile", "score_date"], batch_size=1000)
        feed.status, feed.records = "ok", len(got)
        feed.message = f"{len(got)} of {len(cves)} CVEs scored" + (f"; {len(failed)} batch(es) skipped after retries" if failed else "")
    except Exception as e:
        logger.exception("EPSS refresh failed")
        feed.status, feed.message = "error", f"{e.__class__.__name__}: {str(e)[:300]}"
    feed.last_refreshed = timezone.now()
    feed.save()
    return feed


def apply_intel():
    """Copy KEV/EPSS data onto findings (bulk, bypassing save hooks)."""
    from orasec.models import Finding  # noqa: PLC0415
    kev = {k.cve: k for k in KevEntry.objects.all()}
    epss = {e.cve: e for e in EpssScore.objects.all()}
    per = {}
    for fid, cve in finding_cve_pairs():
        per.setdefault(fid, []).append(cve)
    changed = []
    for f in Finding.objects.filter(id__in=list(per)).only("id", "epss_score", "epss_percentile", "known_exploited", "ransomware_used", "kev_date"):
        cves = per[f.id]
        k = [kev[c] for c in cves if c in kev]
        e = [epss[c] for c in cves if c in epss]
        new = (max((x.epss for x in e), default=None), max((x.percentile for x in e), default=None), bool(k),
               any(x.ransomware for x in k), min((x.date_added for x in k if x.date_added), default=None))
        if (f.epss_score, f.epss_percentile, f.known_exploited, f.ransomware_used, f.kev_date) != new:
            f.epss_score, f.epss_percentile, f.known_exploited, f.ransomware_used, f.kev_date = new
            changed.append(f)
    Finding.objects.bulk_update(changed, ["epss_score", "epss_percentile", "known_exploited", "ransomware_used", "kev_date"], batch_size=1000)
    return len(changed)


# ---------------------------------------------------------------------------
def band_for(score, bands):
    for name in ("Urgent", "Needs Action", "Medium"):
        if score >= bands.get(name, 999):
            return name
    return "Low"


def compute_priorities(finding_ids=None):
    """(Re)compute priority score, band and SLA due date for active findings."""
    from orasec.models import Finding  # noqa: PLC0415
    ps = PrioritySettings.load()
    w = {**PrioritySettings.DEFAULT_WEIGHTS, **(ps.weights or {})}
    bands = {**PrioritySettings.DEFAULT_BANDS, **(ps.bands or {})}
    sla = {**PrioritySettings.DEFAULT_SLA, **(ps.sla_days or {})}
    exposed_hosts = {h.lower() for h in InventoryAsset.objects.filter(internet_exposed=True).exclude(hostname="").values_list("hostname", flat=True)}
    crit_hosts = {h.lower(): c for h, c in InventoryAsset.objects.exclude(hostname="").values_list("hostname", "criticality")}
    kev_due = {k.cve: k.due_date for k in KevEntry.objects.exclude(due_date=None)}
    qs = Finding.objects.filter(active=True, duplicate=False).select_related("test__engagement__product")
    if finding_ids is not None:
        qs = qs.filter(id__in=finding_ids)
    ids = list(qs.values_list("id", flat=True))
    cves = {}
    for fid, cve in finding_cve_pairs(ids):
        cves.setdefault(fid, []).append(cve)
    hosts = {}
    try:
        from orasec.models import Endpoint  # noqa: PLC0415
        for fid, host in Endpoint.objects.filter(findings__id__in=ids).values_list("findings__id", "host"):
            hosts.setdefault(fid, set()).add((host or "").lower())
    except Exception:  # endpoints disabled in favour of locations
        logger.debug("endpoint lookup skipped", exc_info=True)
    today = timezone.now().date()
    existing = {p.finding_id: p for p in FindingPriority.objects.filter(finding_id__in=ids)}
    new, upd = [], []
    for f in qs.iterator(chunk_size=2000):
        prod = f.test.engagement.product
        fh = hosts.get(f.id, set())
        sev = w["severity"].get(f.severity, 0)
        factors = {"severity": sev}
        if f.known_exploited:
            factors["kev"] = w["kev"]
        if f.ransomware_used:
            factors["ransomware"] = w["ransomware"]
        if f.epss_percentile:
            factors["epss"] = round(w["epss_percentile"] * f.epss_percentile, 1)
        if prod.internet_accessible or (fh & exposed_hosts):
            factors["exposure"] = w["exposure"]
        crit = max([crit_hosts.get(h, 0) for h in fh] + [CRITICALITY_POINTS.get(prod.business_criticality or "", 3)])
        factors["criticality"] = w["criticality_per_point"] * crit
        if f.fix_available:
            factors["fix_available"] = w["fix_available"]
        score = int(min(100, round(sum(factors.values()))))
        band = band_for(score, bands)
        # SLA
        start, basis = f.date, "detection"
        if ps.sla_start == "publication" and f.publish_date:
            start, basis = f.publish_date, "publication"
        if f.sla_start_date:
            start, basis = f.sla_start_date, "risk acceptance expiry"
        due = start + datetime.timedelta(days=int(sla.get(band, 180)))
        basis = f"{band} {sla.get(band)}d from {basis}"
        if ps.cap_at_kev_due and f.known_exploited:
            kd = [kev_due[c] for c in cves.get(f.id, []) if c in kev_due]
            if kd and min(kd) < due:
                due, basis = min(kd), "CISA KEV due date"
        if due < today:
            factors["overdue"] = w["overdue"]
            score = min(100, score + w["overdue"])
            band = band_for(score, bands)
        p = existing.get(f.id)
        if p is None:
            new.append(FindingPriority(finding_id=f.id, score=score, band=band, factors=factors, due_date=due, sla_basis=basis))
        elif (p.score, p.band, p.due_date) != (score, band, due) or p.factors != factors:
            p.score, p.band, p.factors, p.due_date, p.sla_basis, p.computed_at = score, band, factors, due, basis, timezone.now()
            upd.append(p)
    FindingPriority.objects.bulk_create(new, batch_size=2000)
    FindingPriority.objects.bulk_update(upd, ["score", "band", "factors", "due_date", "sla_basis", "computed_at"], batch_size=2000)
    # drop priorities for findings that are no longer active
    if finding_ids is None:
        FindingPriority.objects.filter(Q(finding__active=False) | Q(finding__duplicate=True)).delete()
    return {"created": len(new), "updated": len(upd), "evaluated": len(ids)}


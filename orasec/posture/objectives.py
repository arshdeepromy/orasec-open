"""Automatic measurement of the information security objectives (ISO/IEC 27001 clause 6.2).

Runs every day with the automated control checks, after any action on an objective is closed,
and when the Compliance Officer presses "Measure now".
"""
import datetime

from django.utils import timezone

from orasec.posture.grc_models import SecurityObjective


def _findings_base():
    from orasec.posture.models import FindingPriority  # noqa: PLC0415
    return FindingPriority.objects.filter(finding__active=True, finding__duplicate=False, finding__risk_accepted=False,
                                          due_date__isnull=False)


def _evidence(prefix, max_days):
    from orasec.posture.models import ControlEvidence  # noqa: PLC0415
    last = ControlEvidence.objects.filter(title__istartswith=prefix).order_by("-collected_at").first()
    if not last:
        return False, f"No '{prefix}' record yet"
    fresh = last.collected_at >= timezone.now() - datetime.timedelta(days=max_days)
    return fresh, f"Last '{prefix}' record {last.collected_at:%d %b %Y}" + ("" if fresh else f" (older than {max_days} days)")


def measure(obj):
    """Measure one objective and save its status. Returns the objective."""
    today = timezone.now().date()
    met, value = False, ""
    if not obj.applicable:
        obj.status, obj.current_value = "not_applicable", "Not applicable yet"
        obj.last_measured = timezone.now()
        obj.save(update_fields=["status", "current_value", "last_measured", "updated"])
        return obj
    if obj.measure == "critical_overdue":
        over = _findings_base().filter(due_date__lt=today)
        crit, kev = over.filter(finding__severity="Critical").count(), over.filter(finding__known_exploited=True).count()
        met, value = crit == 0 and kev == 0, f"{crit} Critical and {kev} known-exploited findings past SLA"
    elif obj.measure == "sla_compliance":
        base = _findings_base()
        total, over = base.count(), base.filter(due_date__lt=today).count()
        pct = 100.0 if not total else (total - over) * 100.0 / total
        met, value = over == 0, f"{pct:.1f}% within SLA ({over} of {total} open findings overdue)"
    elif obj.measure == "endpoint_coverage":
        from orasec.posture.compliance import check_agent_coverage  # noqa: PLC0415
        result, detail, _ = check_agent_coverage()
        fv, fv_text = _evidence(obj.evidence_prefix or "FileVault", obj.evidence_max_days)
        met, value = result == "pass" and fv, f"{detail} {fv_text}."
    elif obj.measure == "evidence":
        met, value = _evidence(obj.evidence_prefix or obj.title, obj.evidence_max_days)
    else:
        met, value = obj.manual_met, ("Marked met" if obj.manual_met else "Not yet met (manual)")
    if met:
        status = "met"
    elif (obj.due_date and obj.due_date < today) or any(a.overdue for a in obj.actions.all()):
        status = "off_track"
    else:
        status = "on_track"
    obj.status, obj.current_value, obj.last_measured = status, value[:300], timezone.now()
    obj.save(update_fields=["status", "current_value", "last_measured", "updated"])
    return obj


def measure_all():
    return [measure(o) for o in SecurityObjective.objects.all()]

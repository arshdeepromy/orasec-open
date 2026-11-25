"""Leaver and mover records (A.5.11): list, detail, start, tick, reassign, sign off."""
from __future__ import annotations

from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from orasec.posture import leavers
from orasec.posture.grc_models import LeaverRecord

User = get_user_model()


def _org(u):
    return u.is_superuser or u.is_staff


@login_required
def leaver_list(request):
    if not _org(request.user):
        return HttpResponseForbidden("Organisation-wide access required.")
    return render(request, "orasec/posture/leavers.html", {
        "items": LeaverRecord.objects.select_related("person", "started_by", "signed_off_by"),
        "people": User.objects.filter(is_active=True).order_by("username"), "page_title": "Leavers and movers"})


@login_required
def leaver_detail(request, lid):
    if not _org(request.user):
        return HttpResponseForbidden("Organisation-wide access required.")
    rec = get_object_or_404(LeaverRecord, id=lid)
    return render(request, "orasec/posture/leaver_detail.html", {
        "r": rec, "pending": leavers.pending_assets(rec),
        "people": User.objects.filter(is_active=True).exclude(id=rec.person_id).order_by("username"),
        "can_sign": request.user.id not in (rec.person_id, rec.started_by_id) and rec.complete and rec.status == "open"})


@login_required
@require_POST
def leaver_action(request, lid=None):
    if not request.user.is_superuser:
        return HttpResponseForbidden("Superusers only.")
    act = request.POST.get("action")
    try:
        if act == "start":
            person = get_object_or_404(User, id=request.POST.get("person"))
            rec = leavers.start(person, by=request.user, kind=request.POST.get("kind") or "leaver",
                                leaving_date=request.POST.get("leaving_date") or None, reason=request.POST.get("reason", ""))
            messages.success(request, f"{rec.ref} started.")
            return redirect("orasec_leaver", lid=rec.id)
        rec = get_object_or_404(LeaverRecord, id=lid)
        if act == "tick":
            leavers.tick(rec, request.POST.get("step"), request.user, request.POST.get("note", ""))
        elif act == "reassign":
            n = leavers.reassign(rec, get_object_or_404(User, id=request.POST.get("new_owner")), request.user)
            messages.success(request, f"{n} asset(s) moved.")
        elif act == "signoff":
            leavers.sign_off(rec, request.user, request.POST.get("note", ""))
            messages.success(request, f"{rec.ref} signed off.")
    except leavers.Refused as e:
        messages.error(request, str(e))
    return redirect("orasec_leaver", lid=lid)

"""Web page for linking phones to the OraSec app and revoking them."""
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST

from orasec.mobile.auth import org_wide
from orasec.mobile.models import MobileDevice, MobileLinkCode
from orasec.utils import add_breadcrumb


@login_required
def devices(request):
    if not org_wide(request.user):
        return HttpResponseForbidden("The OraSec app needs organisation-wide access.")
    add_breadcrumb(title="Mobile app", top_level=True, request=request)
    code = request.session.pop("orasec_mobile_code", None)
    live = MobileLinkCode.objects.filter(user=request.user, used_at=None, expires__gt=timezone.now()).first()
    qs = MobileDevice.objects.filter(user=request.user)
    if request.user.is_superuser:
        qs = MobileDevice.objects.select_related("user")
    return render(request, "orasec/mobile/devices.html", {
        "code": code, "code_expires": live.expires if (live and code) else None,
        "active": qs.filter(revoked_at=None), "revoked": qs.exclude(revoked_at=None)[:10], "page_title": "Mobile app",
    })


@login_required
@require_POST
def new_code(request):
    if not org_wide(request.user):
        return HttpResponseForbidden("The OraSec app needs organisation-wide access.")
    _obj, code = MobileLinkCode.create_for(request.user)
    request.session["orasec_mobile_code"] = code  # shown once, on the next page load only
    return redirect("orasec_mobile_devices")


@login_required
@require_POST
def revoke(request, did):
    qs = MobileDevice.objects.all() if request.user.is_superuser else MobileDevice.objects.filter(user=request.user)
    device = get_object_or_404(qs, pk=did, revoked_at=None)
    device.revoked_at = timezone.now()
    device.push_token = ""  # a revoked phone gets no more notifications
    device.save(update_fields=["revoked_at", "push_token"])
    messages.success(request, f"{device.name} was signed out of the OraSec app.")
    return redirect("orasec_mobile_devices")


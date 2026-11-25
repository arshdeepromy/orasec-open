"""The Plugins page: every integration with an on/off switch. Anyone signed in can read it; superusers change it."""
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseForbidden
from django.shortcuts import redirect, render
from django.views.decorators.http import require_POST

from orasec.plugins import registry
from orasec.utils import add_breadcrumb


@login_required
def plugins_page(request):
    add_breadcrumb(title="Plugins", top_level=True, request=request)
    rows = registry.snapshot()
    groups = []
    for row in rows:
        if not groups or groups[-1]["name"] != row["group"]:
            groups.append({"name": row["group"], "rows": []})
        groups[-1]["rows"].append(row)
    return render(request, "orasec/plugins/plugins.html", {
        "groups": groups, "can_edit": request.user.is_superuser,
        "on_count": sum(1 for r in rows if r["active"]), "total": len(rows),
    })


@login_required
@require_POST
def plugin_toggle(request, key):
    if not (request.user.is_active and request.user.is_superuser):
        return HttpResponseForbidden("Only an administrator can turn plugins on or off.")
    plugin = registry.get(key)
    if plugin is None:
        messages.error(request, "That plugin does not exist.")
        return redirect("orasec_plugins")
    on = request.POST.get("on") == "1"
    registry.set_on(key, on, request.user)
    available, missing = registry.availability(plugin)
    if on and not available:
        messages.warning(request, f"{plugin.name} is switched on, but it will not work yet. {missing}")
    else:
        messages.success(request, f"{plugin.name} is now {'on' if on else 'off'}.")
    return redirect("orasec_plugins")

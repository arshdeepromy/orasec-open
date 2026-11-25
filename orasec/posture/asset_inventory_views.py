"""Asset Inventory pages: dashboard, list, groups, exports (A.5.9)."""
from __future__ import annotations

import io

from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, HttpResponseForbidden
from django.shortcuts import render
from django.utils import timezone

from orasec import site as site_profile
from orasec.posture import asset_inventory as ai

def title() -> str:
    return f"{site_profile.org_name()} - Asset Inventory (ISO/IEC 27001 A.5.9)"


def _org_wide(user):
    return user.is_superuser or user.is_staff


def org_wide_only(view):
    """Organisation-wide pages: superusers and staff only (same rule as the dashboard)."""
    import functools  # noqa: PLC0415

    @functools.wraps(view)
    def wrapped(request, *a, **kw):
        if not _org_wide(request.user):
            return HttpResponseForbidden("Organisation-wide access required.")
        return view(request, *a, **kw)
    return wrapped


@login_required
@org_wide_only
def dashboard(request):
    d = ai.dashboard(refresh=request.GET.get("refresh") == "1" and request.user.is_superuser)
    return render(request, "orasec/assets/dashboard.html", {"d": d})


@login_required
@org_wide_only
def asset_list(request, group=None):
    params = request.GET.copy()
    if group:
        params["group"] = group
    rs = ai.apply_row_filters(ai.rows(ai.filtered(params)), params)
    d = ai.dashboard()
    return render(request, "orasec/assets/list.html", {
        "rows": rs, "group": group, "group_label": ai.CATEGORY_LABEL.get(ai.CATEGORY_SLUG.get(group or ""), "All assets"),
        "d": d, "locations": [l for l, _ in d["by_location"]], "owners": [o for o, _ in d["by_owner"]],
        "categories": ai.CATEGORIES, "classes": ai.CLASSIFICATIONS, "qs": params.urlencode(),
        "grouped": request.GET.get("view") == "grouped"})


def _export_rows(request):
    params = request.GET.copy()
    network = request.GET.get("network") == "1" and request.user.is_superuser
    return ai.apply_row_filters(ai.rows(ai.filtered(params), network=network), params), network


COLS = [("name", "Asset"), ("category_label", "Category"), ("type", "Type"), ("location", "Where it sits"),
        ("owners", "Owner(s)"), ("classification", "Classification"), ("criticality", "Criticality"), ("business_critical", "Business critical"),
        ("sources", "Source"), ("online", "Online"), ("exposed", "Internet exposed"),
        ("open_vulns", "Open vulnerabilities"), ("last_seen", "Last seen")]
NET_COLS = [("hostname", "Hostname"), ("ip", "IP address"), ("mac", "MAC address")]


def _cell(r, k):
    v = r.get(k)
    if isinstance(v, list):
        return "; ".join(v)
    if isinstance(v, bool):
        return "Yes" if v else "No"
    if v is None:
        return ""
    if hasattr(v, "strftime"):
        return timezone.localtime(v).strftime("%Y-%m-%d %H:%M")
    return v


@login_required
@org_wide_only
def export_xlsx(request):
    from openpyxl import Workbook  # noqa: PLC0415
    from openpyxl.styles import Font, PatternFill  # noqa: PLC0415
    rs, network = _export_rows(request)
    cols = COLS + (NET_COLS if network else [])
    wb = Workbook()
    ws = wb.active
    ws.title = "Summary"
    now = timezone.localtime().strftime("%d %b %Y %H:%M")
    ws.append([title()])
    ws["A1"].font = Font(bold=True, size=13)
    ws.append([f"Generated {now} (live data)"])
    ws.append([])
    ws.append(["Category", "Assets"])
    for k, label in ai.CATEGORIES:
        ws.append([label, sum(1 for r in rs if r["category"] == k)])
    ws.append(["Total", len(rs)])
    ws.append([])
    ws.append(["Where it sits", "Assets"])
    from collections import Counter  # noqa: PLC0415
    for loc, n in Counter(r["location"] for r in rs).most_common():
        ws.append([loc, n])
    ws.column_dimensions["A"].width = 44
    head = PatternFill("solid", fgColor="0F766E")
    for k, label in ai.CATEGORIES:
        sub = [r for r in rs if r["category"] == k]
        if not sub:
            continue
        sh = wb.create_sheet(label[:31].replace("&", "and"))
        sh.append([c[1] for c in cols])
        for c in sh[1]:
            c.font, c.fill = Font(bold=True, color="FFFFFF"), head
        for r in sub:
            sh.append([_cell(r, c[0]) for c in cols])
        for i, w in enumerate([38, 20, 18, 36, 52, 11, 15, 22, 9, 15, 18, 18, 24, 16, 20]):
            if i < len(cols):
                sh.column_dimensions[chr(65 + i)].width = w
        sh.freeze_panes = "A2"
    buf = io.BytesIO()
    wb.save(buf)
    resp = HttpResponse(buf.getvalue(), content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    resp["Content-Disposition"] = f'attachment; filename="{site_profile.file_prefix()}-Asset-Inventory-{timezone.localdate():%Y-%m-%d}.xlsx"'
    return resp


def pdf_bytes(title: str, sections: list[tuple[str, list[str], list[list[str]]]], intro: list[str] | None = None) -> bytes:
    """Small dependency-free PDF writer (landscape A4, Helvetica) -- tables wrap onto new pages."""
    W, H, M = 842, 595, 36
    pages: list[list[str]] = []
    cur: list[str] = []
    y = [H - M]

    def esc(s):
        s = str(s).encode("latin-1", "replace").decode("latin-1")
        return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    def new():
        nonlocal cur
        if cur:
            pages.append(cur)
        cur = []
        y[0] = H - M

    def text(x, s, size=8, bold=False):
        cur.append(f"BT /{'F2' if bold else 'F1'} {size} Tf {x} {y[0]:.1f} Td ({esc(s)}) Tj ET")

    def need(h):
        if y[0] - h < M:
            new()

    text(M, title, 14, True)
    y[0] -= 16
    text(M, f"Generated {timezone.localtime().strftime('%d %b %Y %H:%M')} from live OraSec data", 8)
    y[0] -= 18
    for para in intro or []:
        for line in _wrap(para, 165):
            need(11)
            text(M, line, 9)
            y[0] -= 11
        y[0] -= 5
    for name, heads, body in sections:
        need(40)
        text(M, name, 11, True)
        y[0] -= 14
        if not heads:
            for para in body:
                for line in _wrap(para[0], 165):
                    need(11)
                    text(M, line, 9)
                    y[0] -= 11
            y[0] -= 6
            continue
        widths = _widths(heads, body, W - 2 * M)
        def header():
            x = M
            for h, w in zip(heads, widths):
                text(x, h[: int(w / 4.2)], 7.5, True)
                x += w
            y[0] -= 11
        header()
        for r in body:
            if y[0] - 10 < M:
                new()
                header()
            x = M
            for v, w in zip(r, widths):
                text(x, str(v)[: max(3, int(w / 4.0))], 7)
                x += w
            y[0] -= 10
        y[0] -= 10
    new()
    objs = ["<< /Type /Catalog /Pages 2 0 R >>", None,
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>"]
    kids = []
    for i, p in enumerate(pages):
        p.append(f"BT /F1 7 Tf {W - M - 60} 20 Td (Page {i + 1} of {len(pages)}) Tj ET")
        stream = "\n".join(p).encode("latin-1", "replace")
        objs.append(f"<< /Length {len(stream)} >>\nstream\n".encode() + stream + b"\nendstream")
        objs.append(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {W} {H}] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents {len(objs)} 0 R >>")
        kids.append(f"{len(objs)} 0 R")
    objs[1] = f"<< /Type /Pages /Kids [{' '.join(kids)}] /Count {len(kids)} >>"
    out = io.BytesIO()
    out.write(b"%PDF-1.4\n")
    offs = []
    for i, o in enumerate(objs, 1):
        offs.append(out.tell())
        body = o if isinstance(o, bytes) else o.encode("latin-1")
        out.write(f"{i} 0 obj\n".encode() + body + b"\nendobj\n")
    x = out.tell()
    out.write(f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode())
    for o in offs:
        out.write(f"{o:010d} 00000 n \n".encode())
    out.write(f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{x}\n%%EOF\n".encode())
    return out.getvalue()


def _wrap(s, n):
    words, line, out = str(s).split(), "", []
    for w in words:
        if len(line) + len(w) + 1 > n:
            out.append(line)
            line = w
        else:
            line = f"{line} {w}".strip()
    if line:
        out.append(line)
    return out or [""]


def _widths(heads, body, total):
    m = [max([len(str(h))] + [min(len(str(r[i])), 60) for r in body[:200]]) for i, h in enumerate(heads)]
    s = sum(m) or 1
    return [total * v / s for v in m]


@login_required
@org_wide_only
def export_pdf(request):
    rs, network = _export_rows(request)
    cols = COLS + (NET_COLS if network else [])
    keep = [c for c in cols if c[0] not in ("business_critical", "exposed")]
    from collections import Counter  # noqa: PLC0415
    summary = [[label, str(sum(1 for r in rs if r["category"] == k))] for k, label in ai.CATEGORIES] + [["Total", str(len(rs))]]
    where = [[loc, str(n)] for loc, n in Counter(r["location"] for r in rs).most_common()]
    sections = [("Summary by category", ["Category", "Assets"], summary), ("Where assets sit", ["Location", "Assets"], where)]
    for k, label in ai.CATEGORIES:
        sub = [r for r in rs if r["category"] == k]
        if sub:
            sections.append((label, [c[1] for c in keep], [[_cell(r, c[0]) for c in keep] for r in sub]))
    resp = HttpResponse(pdf_bytes(title(), sections), content_type="application/pdf")
    resp["Content-Disposition"] = f'attachment; filename="{site_profile.file_prefix()}-Asset-Inventory-{timezone.localdate():%Y-%m-%d}.pdf"'
    return resp


@login_required
def set_classification(request, aid):
    from django.shortcuts import get_object_or_404, redirect  # noqa: PLC0415
    from django.views.decorators.http import require_POST  # noqa: PLC0415, F401
    from orasec.posture.models import InventoryAsset  # noqa: PLC0415
    if request.method != "POST" or not request.user.is_superuser:
        return HttpResponseForbidden("Superusers only.")
    a = get_object_or_404(InventoryAsset, id=aid)
    ai.set_classification(a, request.POST.get("level", ""), request.user)
    return redirect(request.POST.get("next") or "orasec_assets_list")

"""
Plerion connector: cloud inventory and cloud security posture (CSPM) findings from every cloud account connected
to one Plerion tenant, through one read-only API key. No role to assume in each account.

Base URL: the region host of the tenant, https://{region}.api.plerion.com (for example https://au.api.plerion.com).
Secrets: {"api_key": "..."} (a read-only tenant API key, Plerion: Settings, API keys).
Options: {"providers": ["AWS"], "resource_types": ["AWS::EC2::Instance"], "findings": true,
          "severities": ["CRITICAL", "HIGH"], "product_name": "Cloud"}

  GET /v1/tenant                 tenant name (connection test)
  GET /v1/tenant/assets          page / perPage; meta.total is set on the first page only
  GET /v1/tenant/findings        cursor paged; statuses=FAILED, severityLevels, providers
  GET /v1/tenant/integrations    cursor paged; one row per connected cloud account, with its name

Only FAILED checks that are not exempted in Plerion become findings. Each finding is keyed on its Plerion id, so a
check that passes again is closed here by the next run.

Paging rules, learned against a live tenant: ``meta.total`` and ``meta.hasNextPage`` are reported on the first page
only. The asset loop is driven by the first page's total. The cursor loops stop on an empty page, a missing cursor
or a repeated cursor, never on ``hasNextPage``.
"""
from orasec.posture.connectors.base import (
    AssetRecord,
    BaseConnector,
    CollectResult,
    ConnectorError,
    TestBatch,
    register,
)

DEFAULT_TYPES = ["AWS::EC2::Instance"]
DEFAULT_SEVERITIES = ["CRITICAL", "HIGH"]
MAX_PAGES = 10000


def _list(value, default=()):
    """An option given as a list or as comma separated text."""
    if value is None:
        return list(default)
    if isinstance(value, str):
        value = value.split(",")
    return [str(v).strip() for v in value if str(v).strip()]


def _tag(row, key):
    for t in row.get("tags") or []:
        if isinstance(t, dict) and t.get("Key") == key:
            return str(t.get("Value") or "")
    return ""


@register
class PlerionConnector(BaseConnector):
    kind = "plerion"
    secret_fields = ("api_key",)

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.http.session.headers.update({"Authorization": f"Bearer {self.secrets.get('api_key', '')}", "Accept": "application/json"})

    def _get(self, path, **params):
        r = self.http.get(path, params={k: v for k, v in params.items() if v not in {None, ""}} or None)
        if not isinstance(r, dict):
            msg = f"{path}: unexpected response"
            raise ConnectorError(msg)
        return r

    # --- paging ---------------------------------------------------------------
    def _assets(self, **query):
        page, seen, total = 1, 0, None
        while page <= MAX_PAGES:
            body = self._get("/v1/tenant/assets", page=page, perPage=500, **query)
            rows = body.get("data") or []
            yield from rows
            seen += len(rows)
            if total is None:
                total = int((body.get("meta") or {}).get("total") or 0)
            if not rows or seen >= total:
                return
            page += 1

    def _cursor(self, path, per_page, **query):
        cursor, pages = "", 0
        while pages < MAX_PAGES:
            body = self._get(path, perPage=per_page, cursor=cursor, **query)
            rows = body.get("data") or []
            yield from rows
            nxt = str((body.get("meta") or {}).get("cursor") or "")
            if not rows or not nxt or nxt == cursor:
                return
            cursor = nxt
            pages += 1

    # --- connector ------------------------------------------------------------
    def test(self):
        tenant = self._get("/v1/tenant")
        td = tenant.get("data") if isinstance(tenant.get("data"), dict) else tenant
        name = td.get("name") or td.get("tenantName") or td.get("id") or "?"
        sample = self._get("/v1/tenant/assets", perPage=1)
        total = int((sample.get("meta") or {}).get("total") or 0)
        return f"Plerion tenant {name}: {total} assets visible"

    def collect(self):
        res = CollectResult()
        providers = _list(self.options.get("providers"), ["AWS"])
        types = _list(self.options.get("resource_types"), DEFAULT_TYPES)

        # account names: "123456789012" reads better as the name it was connected under
        accounts = {}
        try:
            for row in self._cursor("/v1/tenant/integrations", 100):
                acct = str(row.get("awsAccountId") or row.get("providerAccountId") or "")
                if acct and row.get("name"):
                    accounts[acct] = str(row["name"])
        except ConnectorError as e:
            res.warnings.append(f"account names not read ({e})")

        exposed = 0
        for row in self._assets(resourceTypes=",".join(types), providers=",".join(providers)):
            rid = str(row.get("resourceId") or "")
            if not rid:
                continue
            name = _tag(row, "Name") or str(row.get("resourceName") or "") or rid
            os_rows = row.get("operatingSystem") or {}
            os0 = os_rows[0] if isinstance(os_rows, list) and os_rows and isinstance(os_rows[0], dict) else os_rows if isinstance(os_rows, dict) else {}
            acct = str(row.get("providerAccountId") or "")
            public = bool(row.get("isPubliclyExposed"))
            exposed += public
            res.assets.append(AssetRecord(
                key=rid, name=name, hostname=name, asset_type="cloud_instance",
                os_name=str(os0.get("name") or os0.get("platform") or "")[:200], os_version=str(os0.get("version") or "")[:200],
                vendor=str(row.get("provider") or ""), model=str(row.get("resourceType") or "")[:120], internet_exposed=public,
                attributes={"resource_id": rid, "account_id": acct, "account_name": accounts.get(acct, ""), "region": row.get("region"),
                            "provider": row.get("provider"), "resource_type": row.get("resourceType"),
                            "first_observed": row.get("firstObservedAt"), "last_observed": row.get("lastObservedAt")}))
        res.stats["assets"] = len(res.assets)
        res.stats["publicly_exposed"] = exposed
        res.stats["accounts"] = len(accounts)

        if self.options.get("findings", True):
            findings = []
            sev = [s.upper() for s in _list(self.options.get("severities"), DEFAULT_SEVERITIES)]
            exempted = 0
            # A partial read must not be imported: the import closes every finding it does not see.
            for row in self._cursor("/v1/tenant/findings", 200, statuses="FAILED", severityLevels=",".join(sev), providers=",".join(providers)):
                prn = str(row.get("id") or "")
                if not prn:
                    continue
                if row.get("isExempted"):
                    exempted += 1
                    continue
                acct = str(row.get("providerAccountId") or "")
                resource = str(row.get("resourceName") or "")
                message = str(row.get("message") or row.get("detectionId") or "Plerion finding")
                title = message if not resource or resource in message else f"{message} ({resource})"
                where = accounts.get(acct) or acct
                desc = [message, "", f"- Resource: `{resource or '?'}` ({row.get('resourceType') or '?'})",
                        f"- Account: {where or '?'}" + (f" ({acct})" if where and where != acct else ""),
                        f"- Region: {row.get('region') or '?'}", f"- Detection: `{row.get('detectionId') or '?'}`"]
                if row.get("slaDueAt"):
                    desc.append(f"- Plerion due date: {str(row['slaDueAt'])[:10]}")
                findings.append({
                    "title": title[:500], "severity": str(row.get("severityLevel") or "info").lower(),
                    "description": "\n".join(desc), "references": str(row.get("resourceURL") or ""),
                    "mitigation": "Follow the remediation steps Plerion shows for this detection, then let the next run confirm it passes.",
                    "component_name": str(row.get("resourceType") or "cloud")[:200], "rule_id": str(row.get("detectionId") or "") or None,
                    "unique_id": f"plerion:{prn}", "date": str(row.get("firstObservedAt") or "")[:10] or None,
                    "tags": ["plerion", "cspm", *([str(row["provider"]).lower()] if row.get("provider") else [])]})
            res.stats["findings"] = len(findings)
            res.stats["findings_exempted"] = exempted
            res.batches.append(TestBatch(title="Plerion cloud posture", scan_type="OraSec Plerion", payload={"findings": findings},
                                         count=len(findings), product_name=self.options.get("product_name")))
        return res


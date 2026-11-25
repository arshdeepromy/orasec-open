"""Connector framework: HTTP client, result container, registry and run orchestration."""
import io
import json
import logging
import time
import traceback
from dataclasses import dataclass, field

import requests
from django.core.files.uploadedfile import SimpleUploadedFile
from django.db import transaction
from django.utils import timezone

from orasec import site as site_profile

logger = logging.getLogger(__name__)

CONNECTOR_SCAN_TYPES = {
    "opnsense": "OraSec OPNsense",
    "unifi": "OraSec UniFi",
    "patchmon": "OraSec PatchMon",
    "wazuh_sca": "OraSec Wazuh SCA",
    "aws": "OraSec AWS",
    "cloudflare": "OraSec Cloudflare",
    "github": "OraSec GitHub",
}


class ConnectorError(Exception):
    pass


@dataclass
class TestBatch:

    """Findings for one test, imported with one reimport call (closes what is no longer reported)."""

    title: str
    scan_type: str
    payload: dict  # parser input
    product_name: str | None = None
    count: int = 0


@dataclass
class AssetRecord:
    key: str               # stable id within the connector, e.g. "agent:001" or "mac:aa:bb:..."
    name: str
    asset_type: str = "other"
    hostname: str = ""
    ip_address: str = ""
    mac_address: str = ""
    os_name: str = ""
    os_version: str = ""
    vendor: str = ""
    model: str = ""
    firmware: str = ""
    online: bool | None = None
    internet_exposed: bool = False
    scanned: bool = False   # True when this run produced a vulnerability assessment for the asset
    attributes: dict = field(default_factory=dict)
    parent_key: str | None = None


@dataclass
class CollectResult:
    batches: list = field(default_factory=list)
    assets: list = field(default_factory=list)
    stats: dict = field(default_factory=dict)
    warnings: list = field(default_factory=list)


class Http:

    """Small requests wrapper: timeouts, TLS choice, JSON, and a log of every call (no secrets)."""

    def __init__(self, base_url, verify=True, timeout=60, log=None):
        self.base = base_url.rstrip("/")
        self.verify = verify
        self.timeout = timeout
        self.session = requests.Session()
        self.log = log if log is not None else []
        if not verify:
            requests.packages.urllib3.disable_warnings()  # LAN appliance with a self-signed certificate

    def request(self, method, path, expect_json=True, **kw):
        url = path if path.startswith("http") else self.base + path
        kw.setdefault("timeout", self.timeout)
        kw.setdefault("verify", self.verify)
        t0 = time.monotonic()
        try:
            r = self.session.request(method, url, **kw)
        except requests.RequestException as e:
            self.log.append(f"{method} {path} -> network error: {e.__class__.__name__}")
            msg = f"{method} {path}: {e.__class__.__name__}: {str(e)[:200]}"
            raise ConnectorError(msg) from e
        self.log.append(f"{method} {path} -> {r.status_code} ({int((time.monotonic() - t0) * 1000)} ms)")
        if r.status_code >= 400:
            msg = f"{method} {path}: HTTP {r.status_code} {r.text[:300]}"
            raise ConnectorError(msg)
        if not expect_json:
            return r
        try:
            return r.json()
        except ValueError as e:
            msg = f"{method} {path}: response is not JSON"
            raise ConnectorError(msg) from e

    def get(self, path, **kw):
        return self.request("GET", path, **kw)

    def post(self, path, **kw):
        return self.request("POST", path, **kw)


class BaseConnector:

    kind = ""
    # secret fields shown (masked) on the connector form
    secret_fields = ()

    def __init__(self, connector, log=None):
        self.connector = connector
        self.options = connector.options or {}
        self.secrets = connector.get_secrets()
        self.log = log if log is not None else []
        self.http = Http(connector.base_url, verify=connector.verify_tls, log=self.log)

    def test(self) -> str:
        """Cheap authenticated call; returns a one-line description or raises ConnectorError."""
        raise NotImplementedError

    def collect(self) -> CollectResult:
        raise NotImplementedError


REGISTRY = {}


def register(cls):
    REGISTRY[cls.kind] = cls
    return cls


def get_connector_class(kind):
    # import for side effects (registration)
    from orasec.posture.connectors import aws, beszel, cloudflare, github, isms, opnsense, patchmon, semaphore, unifi, wazuh  # noqa: F401, PLC0415
    if kind not in REGISTRY:
        msg = f"Unknown connector kind '{kind}'"
        raise ConnectorError(msg)
    return REGISTRY[kind]


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
def _upsert_assets(connector, records):
    from orasec.posture.models import InventoryAsset  # noqa: PLC0415
    now = timezone.now()
    by_key = {}
    created = updated = 0
    for rec in records:
        src_id = f"{connector.kind}:{rec.key}"
        asset = None
        # correlate across sources: same connector key, then MAC, then hostname
        asset = InventoryAsset.objects.filter(**{f"sources__{connector.kind}__id": src_id}).first()
        if asset is None and rec.mac_address:
            asset = InventoryAsset.objects.filter(mac_address__iexact=rec.mac_address).first()
        if asset is None and rec.hostname:
            asset = InventoryAsset.objects.filter(hostname__iexact=rec.hostname).first()
        if asset is None and rec.ip_address and rec.ip_address not in ("127.0.0.1", "0.0.0.0"):  # noqa: S104
            asset = (InventoryAsset.objects.filter(ip_address=rec.ip_address).exclude(asset_type="client").first()
                     or InventoryAsset.objects.filter(ip_address=rec.ip_address).first())
        if asset is None:
            asset = InventoryAsset(name=rec.name, first_seen=now)
            created += 1
        else:
            updated += 1
        for f in ("asset_type", "hostname", "ip_address", "mac_address", "os_name", "os_version",
                  "vendor", "model", "firmware"):
            val = getattr(rec, f)
            # don't let a weaker source downgrade a typed asset to "other"/"client"
            if f == "asset_type" and asset.pk and asset.asset_type not in ("other", "client") and val in ("other", "client"):
                continue
            if val:
                setattr(asset, f, val)
        if not asset.name or asset.name == asset.mac_address:
            asset.name = rec.name
        # names other systems use for this machine (Wazuh agent name, old hostnames): lookups keep working after a rename
        if asset.asset_type not in {"client", "application"}:
            asset.add_aliases(rec.name, rec.hostname)
        asset.last_seen = now
        if rec.online is not None:
            asset.online = rec.online
        asset.internet_exposed = asset.internet_exposed or rec.internet_exposed
        if rec.scanned:
            asset.last_scanned_at = now
        if connector.product_id and not asset.product_id:
            asset.product_id = connector.product_id
        attrs = dict(asset.attributes or {})
        attrs[connector.kind] = rec.attributes
        asset.attributes = attrs
        src = dict(asset.sources or {})
        src[connector.kind] = {"id": src_id, "connector": connector.name, "last_seen": now.isoformat()}
        asset.sources = src
        if not attrs.get("out_of_scope"):  # a device a person took out of scope stays out when it is seen again
            asset.retired = False
        asset.save()
        by_key[rec.key] = asset
    for rec in records:
        if rec.parent_key and rec.parent_key in by_key and rec.key in by_key:
            child = by_key[rec.key]
            if child.parent_id != by_key[rec.parent_key].id:
                child.parent = by_key[rec.parent_key]
                child.save(update_fields=["parent"])
    return created, updated


def _import_batch(connector, batch, user):
    from orasec.importers.services import auto_import_scan  # noqa: PLC0415
    product_name = batch.product_name or (connector.product.name if connector.product_id else "Infrastructure")
    payload = json.dumps(batch.payload).encode("utf-8")
    upload = SimpleUploadedFile(f"{connector.kind}.json", payload, content_type="application/json")
    result = auto_import_scan(
        user=user,
        scan_file=upload,
        scan_type=batch.scan_type,
        product_name=product_name,
        product_type_name=connector.product.prod_type.name if connector.product_id else site_profile.get("default_product_type"),
        engagement_name=connector.engagement_name,
        test_title=batch.title,
        auto_create_context=True,
        close_old_findings=True,
        do_not_reactivate=False,
        minimum_severity="Info",
        active=True,
        verified=True,
        scan_date=timezone.now(),
        deduplication_execution_mode="sync",
    )
    return {"test": batch.title, "test_id": result.test.id, "new": result.new, "closed": result.closed,
            "reactivated": result.reactivated, "untouched": result.untouched}


def run_connector(connector, triggered_by="schedule", user=None):
    """Run one connector end to end and record a ConnectorRun. Never raises."""
    from orasec.models import OraSec_User  # noqa: PLC0415
    from orasec.posture.models import ConnectorRun  # noqa: PLC0415

    log = []
    run = ConnectorRun.objects.create(connector=connector, triggered_by=triggered_by)
    connector.last_run_at = timezone.now()
    connector.last_status = "running"
    connector.save(update_fields=["last_run_at", "last_status"])
    user = user or OraSec_User.objects.filter(is_superuser=True, is_active=True).order_by("id").first()
    stats = {}
    try:
        impl = get_connector_class(connector.kind)(connector, log=log)
        res = impl.collect()
        stats.update(res.stats)
        with transaction.atomic():
            c, u = _upsert_assets(connector, res.assets)
        stats["assets_created"], stats["assets_updated"] = c, u
        imports = []
        for b in res.batches:
            imports.append(_import_batch(connector, b, user))
        stats["imports"] = imports
        stats["findings_new"] = sum(i["new"] for i in imports)
        stats["findings_closed"] = sum(i["closed"] for i in imports)
        status = "warning" if res.warnings else "ok"
        if res.warnings:
            log.extend(f"WARNING: {w}" for w in res.warnings)
        msg = (f"{len(res.assets)} assets, {sum(b.count for b in res.batches)} findings in {len(res.batches)} tests "
               f"(+{stats['findings_new']} new, {stats['findings_closed']} closed)")
        if res.warnings:
            msg += f"; {len(res.warnings)} warning(s)"
        run.status, run.error = status, ""
        connector.last_success_at = timezone.now()
    except Exception as e:  # recorded for the Diagnostics page
        logger.exception("connector %s failed", connector.name)
        status, msg = "error", f"{e.__class__.__name__}: {str(e)[:500]}"
        run.status, run.error = "error", traceback.format_exc()[-4000:]
    run.finished_at = timezone.now()
    run.stats = stats
    run.log = "\n".join(log)[-20000:]
    run.save()
    connector.last_status, connector.last_message = status, msg
    connector.save(update_fields=["last_status", "last_message", "last_success_at"])
    from orasec.posture import evidence  # noqa: PLC0415
    evidence.from_connector_run(run)
    return run


def stringio(data):
    return io.StringIO(json.dumps(data))


"""
OraSec security-posture models.

Connectors and inventory, exploit intelligence and prioritisation, governed risk
acceptance, ISO/IEC 27001:2022 compliance, risk register, remediation campaigns,
triage rules and posture history.
"""
import json

from django.conf import settings
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from orasec.utils import orasec_crypto_encrypt, prepare_for_view

USER = settings.AUTH_USER_MODEL


# ---------------------------------------------------------------------------
# Connectors and inventory
# ---------------------------------------------------------------------------
class Connector(models.Model):

    KIND_WAZUH = "wazuh"
    KIND_OPNSENSE = "opnsense"
    KIND_UNIFI = "unifi"
    KIND_PATCHMON = "patchmon"
    KIND_SEMAPHORE = "semaphore"
    KIND_CHOICES = [
        (KIND_WAZUH, "Wazuh (SIEM / XDR)"),
        (KIND_OPNSENSE, "OPNsense firewall"),
        (KIND_UNIFI, "UniFi Network"),
        (KIND_PATCHMON, "PatchMon (patch inventory)"),
        (KIND_SEMAPHORE, "Semaphore UI (Ansible patch deployment)"),
        ("aws", "AWS (inventory, security groups, CSPM)"),
        ("cloudflare", "Cloudflare (DNS, TLS, WAF, threats)"),
        ("github", "GitHub (repositories, Dependabot, code & secret scanning)"),
        ("beszel", "Beszel (host health: CPU, memory, disk, network)"),
        ("isms", "Policy tool (ISMS) two-way sync"),
    ]
    STATUS_CHOICES = [("never", "Never run"), ("running", "Running"), ("ok", "OK"), ("warning", "Warning"), ("error", "Error")]

    name = models.CharField(max_length=120, unique=True)
    kind = models.CharField(max_length=32, choices=KIND_CHOICES)
    enabled = models.BooleanField(default=True)
    base_url = models.CharField(max_length=500, help_text=_("e.g. https://wazuh.example.internal:55000"))
    verify_tls = models.BooleanField(default=True, help_text=_("Turn off only for LAN appliances with self-signed certificates."))
    username = models.CharField(max_length=200, blank=True, help_text=_("API user / key id, if the API uses one."))
    secret_encrypted = models.TextField(blank=True, editable=False)
    options = models.JSONField(default=dict, blank=True, help_text=_("Connector-specific options (JSON)."))
    product = models.ForeignKey("orasec.Product", null=True, blank=True, on_delete=models.SET_NULL,
                                help_text=_("Asset (product) that receives this connector's findings."))
    engagement_name = models.CharField(max_length=200, default="Continuous security scanning")
    interval_minutes = models.PositiveIntegerField(default=360, validators=[MinValueValidator(15)])
    last_run_at = models.DateTimeField(null=True, blank=True)
    last_success_at = models.DateTimeField(null=True, blank=True)
    last_status = models.CharField(max_length=16, choices=STATUS_CHOICES, default="never")
    last_message = models.TextField(blank=True)
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name

    # Secrets are a JSON object encrypted with the instance credential key (AES-256-GCM).
    def set_secrets(self, data: dict):
        self.secret_encrypted = orasec_crypto_encrypt(json.dumps(data)) if data else ""

    def get_secrets(self) -> dict:
        if not self.secret_encrypted:
            return {}
        try:
            return json.loads(prepare_for_view(self.secret_encrypted) or "{}")
        except (ValueError, TypeError):
            return {}

    @property
    def is_due(self):
        if not self.enabled:
            return False
        if self.last_run_at is None:
            return True
        return timezone.now() - self.last_run_at >= timezone.timedelta(minutes=self.interval_minutes)


class ConnectorRun(models.Model):
    connector = models.ForeignKey(Connector, related_name="runs", on_delete=models.CASCADE)
    started_at = models.DateTimeField(default=timezone.now)
    finished_at = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=16, default="running")
    triggered_by = models.CharField(max_length=60, default="schedule")
    stats = models.JSONField(default=dict, blank=True)
    log = models.TextField(blank=True)
    error = models.TextField(blank=True)

    class Meta:
        ordering = ["-started_at"]
        indexes = [models.Index(fields=["connector", "-started_at"], name="os_conn_run_recent")]

    @property
    def duration_seconds(self):
        if self.finished_at:
            return int((self.finished_at - self.started_at).total_seconds())
        return None


class InventoryAsset(models.Model):

    TYPE_CHOICES = [
        ("server", "Server"), ("workstation", "Workstation"), ("firewall", "Firewall / gateway"),
        ("switch", "Switch"), ("access_point", "Wireless access point"), ("network_device", "Network device"),
        ("client", "Network client"), ("cloud_instance", "Cloud instance"), ("container", "Container"),
        ("application", "Application"), ("other", "Other"),
    ]

    name = models.CharField(max_length=255)
    asset_type = models.CharField(max_length=32, choices=TYPE_CHOICES, default="other")
    hostname = models.CharField(max_length=255, blank=True, db_index=True)
    ip_address = models.CharField(max_length=64, blank=True)
    mac_address = models.CharField(max_length=32, blank=True, db_index=True)
    os_name = models.CharField(max_length=200, blank=True)
    os_version = models.CharField(max_length=200, blank=True)
    vendor = models.CharField(max_length=120, blank=True)
    model = models.CharField(max_length=120, blank=True)
    firmware = models.CharField(max_length=120, blank=True)
    product = models.ForeignKey("orasec.Product", null=True, blank=True, on_delete=models.SET_NULL, related_name="inventory_assets")
    parent = models.ForeignKey("self", null=True, blank=True, on_delete=models.SET_NULL, related_name="children",
                               help_text=_("Asset hierarchy: e.g. a client behind a switch, a container on a host."))
    sources = models.JSONField(default=dict, blank=True, help_text=_("{connector kind: {id, last_seen}}"))
    first_seen = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(default=timezone.now)
    online = models.BooleanField(null=True, blank=True)
    internet_exposed = models.BooleanField(default=False)
    criticality = models.PositiveSmallIntegerField(default=3, validators=[MinValueValidator(1), MaxValueValidator(5)],
                                                   help_text=_("Business criticality, 1 (low) to 5 (crown jewel)."))
    owner = models.ForeignKey(USER, null=True, blank=True, on_delete=models.SET_NULL, related_name="owned_inventory_assets")
    scan_cadence_days = models.PositiveSmallIntegerField(null=True, blank=True,
                                                         help_text=_("Expected vulnerability-scan interval; blank uses the default."))
    last_scanned_at = models.DateTimeField(null=True, blank=True)
    attributes = models.JSONField(default=dict, blank=True)
    retired = models.BooleanField(default=False)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name

    MAX_ALIASES = 25

    @classmethod
    def find(cls, name, *, include_retired=False):
        """Asset by display name, hostname or any earlier name (connector names and renames are kept as aliases)."""
        n = (name or "").strip()
        if not n:
            return None
        qs = cls.objects.all() if include_retired else cls.objects.filter(retired=False)
        return (qs.filter(models.Q(name__iexact=n) | models.Q(hostname__iexact=n)).first()
                or qs.filter(attributes__aliases__contains=[n.lower()]).first())

    def add_aliases(self, *names):
        """Remember other names for this asset; returns True when the list changed (caller saves)."""
        attrs = dict(self.attributes or {})
        cur = list(attrs.get("aliases") or [])
        new = [x.strip().lower() for x in names if x and x.strip() and x.strip().lower() != (self.name or "").lower()]
        merged = list(dict.fromkeys(cur + new))[-self.MAX_ALIASES:]
        if merged == cur:
            return False
        attrs["aliases"] = merged
        self.attributes = attrs
        return True

    @property
    def source_kinds(self):
        return sorted(self.sources.keys())


# ---------------------------------------------------------------------------
# Exploit intelligence and prioritisation
# ---------------------------------------------------------------------------
class IntelFeed(models.Model):
    name = models.CharField(max_length=40, unique=True)  # "kev" | "epss"
    last_refreshed = models.DateTimeField(null=True, blank=True)
    records = models.PositiveIntegerField(default=0)
    status = models.CharField(max_length=16, default="never")
    message = models.TextField(blank=True)


class KevEntry(models.Model):
    cve = models.CharField(max_length=32, unique=True)
    vendor = models.CharField(max_length=200, blank=True)
    product = models.CharField(max_length=200, blank=True)
    name = models.CharField(max_length=500, blank=True)
    date_added = models.DateField(null=True, blank=True)
    due_date = models.DateField(null=True, blank=True)
    ransomware = models.BooleanField(default=False)
    required_action = models.TextField(blank=True)


class EpssScore(models.Model):
    cve = models.CharField(max_length=32, unique=True)
    epss = models.FloatField()
    percentile = models.FloatField()
    score_date = models.DateField(null=True, blank=True)


class PrioritySettings(models.Model):

    """Singleton (pk=1): weights, risk-band thresholds and SLA policy."""

    weights = models.JSONField(default=dict, blank=True)
    bands = models.JSONField(default=dict, blank=True)
    sla_days = models.JSONField(default=dict, blank=True)
    sla_start = models.CharField(max_length=16, default="detection",
                                 choices=[("detection", "Detection date"), ("publication", "CVE publication date")])
    cap_at_kev_due = models.BooleanField(default=True, help_text=_("Never let a deadline run past the CISA KEV due date."))
    updated = models.DateTimeField(auto_now=True)

    DEFAULT_WEIGHTS = {
        "severity": {"Critical": 40, "High": 28, "Medium": 14, "Low": 4, "Info": 0},
        "kev": 25, "ransomware": 5, "epss_percentile": 15, "exposure": 10,
        "criticality_per_point": 2, "fix_available": 3, "overdue": 5,
    }
    DEFAULT_BANDS = {"Urgent": 70, "Needs Action": 45, "Medium": 25}  # below Medium -> Low
    DEFAULT_SLA = {"Urgent": 7, "Needs Action": 30, "Medium": 90, "Low": 180}

    @classmethod
    def load(cls):
        obj, _ = cls.objects.get_or_create(pk=1, defaults={
            "weights": cls.DEFAULT_WEIGHTS, "bands": cls.DEFAULT_BANDS, "sla_days": cls.DEFAULT_SLA})
        return obj


class FindingPriority(models.Model):
    BAND_CHOICES = [("Urgent", "Urgent"), ("Needs Action", "Needs Action"), ("Medium", "Medium"), ("Low", "Low")]
    finding = models.OneToOneField("orasec.Finding", related_name="priority", on_delete=models.CASCADE)
    score = models.PositiveSmallIntegerField(default=0)
    band = models.CharField(max_length=16, choices=BAND_CHOICES, default="Low", db_index=True)
    factors = models.JSONField(default=dict, blank=True)
    due_date = models.DateField(null=True, blank=True, db_index=True)
    sla_basis = models.CharField(max_length=120, blank=True)
    computed_at = models.DateTimeField(default=timezone.now)

    class Meta:
        indexes = [models.Index(fields=["band", "-score"], name="os_fprio_band_score")]


# ---------------------------------------------------------------------------
# Remediation, assignment, triage automation
# ---------------------------------------------------------------------------
class FindingAssignment(models.Model):
    finding = models.OneToOneField("orasec.Finding", related_name="assignment", on_delete=models.CASCADE)
    assignee = models.ForeignKey(USER, related_name="assigned_findings", on_delete=models.CASCADE)
    assigned_by = models.ForeignKey(USER, null=True, blank=True, related_name="+", on_delete=models.SET_NULL)
    assigned_at = models.DateTimeField(default=timezone.now)


class RemediationCampaign(models.Model):
    STATUS_CHOICES = [("planned", "Planned"), ("active", "Active"), ("done", "Done"), ("cancelled", "Cancelled")]
    name = models.CharField(max_length=200)
    component = models.CharField(max_length=300, help_text=_("Root cause: the component/package whose fix clears the findings."))
    product = models.ForeignKey("orasec.Product", null=True, blank=True, on_delete=models.SET_NULL,
                                help_text=_("Limit to one asset (blank = everywhere)."))
    description = models.TextField(blank=True)
    owner = models.ForeignKey(USER, null=True, blank=True, on_delete=models.SET_NULL, related_name="remediation_campaigns")
    target_date = models.DateField(null=True, blank=True)
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default="active")
    baseline_open = models.PositiveIntegerField(default=0)
    created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name


class TriageRule(models.Model):

    """
    No-code triage rule. ``conditions`` keys (all optional, AND-ed):
      severity_in [..], band_in [..], kev bool, epss_percentile_gte float, product_ids [..],
      scan_type_in [..], title_contains str, component_contains str, age_days_gte int
    ``actions`` keys: add_tags [..], assign_to user_id, mark_false_positive bool,
      mark_out_of_scope bool, notify_emails [..], notify_webhook url, planned_remediation_days int
    """

    name = models.CharField(max_length=160)
    enabled = models.BooleanField(default=True)
    order = models.PositiveSmallIntegerField(default=100)
    conditions = models.JSONField(default=dict)
    actions = models.JSONField(default=dict)
    stop_processing = models.BooleanField(default=False)
    match_count = models.PositiveIntegerField(default=0)
    last_matched_at = models.DateTimeField(null=True, blank=True)
    created_by = models.ForeignKey(USER, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")

    class Meta:
        ordering = ["order", "id"]

    def __str__(self):
        return self.name


class TriageRuleHit(models.Model):
    rule = models.ForeignKey(TriageRule, related_name="hits", on_delete=models.CASCADE)
    finding = models.ForeignKey("orasec.Finding", related_name="+", on_delete=models.CASCADE)
    applied_at = models.DateTimeField(default=timezone.now)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["rule", "finding"], name="os_rulehit_unique")]


# ---------------------------------------------------------------------------
# Governed risk acceptance
# ---------------------------------------------------------------------------
class RiskAcceptanceApproval(models.Model):
    STATUS_CHOICES = [("pending", "Pending approval"), ("approved", "Approved"), ("rejected", "Rejected")]
    risk_acceptance = models.OneToOneField("orasec.Risk_Acceptance", related_name="approval", on_delete=models.CASCADE)
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default="pending", db_index=True)
    requested_by = models.ForeignKey(USER, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    requested_at = models.DateTimeField(default=timezone.now)
    decided_by = models.ForeignKey(USER, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    decided_at = models.DateTimeField(null=True, blank=True)
    decision_note = models.TextField(blank=True)
    pending_findings = models.JSONField(default=list, blank=True,
                                        help_text=_("Finding ids held active until approval."))
    auto_cover_new = models.BooleanField(default=False,
                                         help_text=_("Also cover new findings that match (same title, CVE and asset)."))


# ---------------------------------------------------------------------------
# Compliance (ISO/IEC 27001:2022) and risk register
# ---------------------------------------------------------------------------
class ComplianceFramework(models.Model):
    code = models.CharField(max_length=40, unique=True)
    name = models.CharField(max_length=200)
    version = models.CharField(max_length=40, blank=True)
    description = models.TextField(blank=True)

    def __str__(self):
        return self.name


class ComplianceControl(models.Model):
    framework = models.ForeignKey(ComplianceFramework, related_name="controls", on_delete=models.CASCADE)
    ref = models.CharField(max_length=20)
    title = models.CharField(max_length=300)
    category = models.CharField(max_length=40)  # Clause | Organizational | People | Physical | Technological
    summary = models.TextField(blank=True)
    sort_key = models.CharField(max_length=40, blank=True)
    auto_check = models.CharField(max_length=60, blank=True, help_text=_("Automated evaluation available for this control."))

    class Meta:
        ordering = ["framework", "sort_key"]
        constraints = [models.UniqueConstraint(fields=["framework", "ref"], name="os_control_ref_unique")]

    def __str__(self):
        return f"{self.ref} {self.title}"


class ControlImplementation(models.Model):
    STATUS_CHOICES = [("not_started", "Not started"), ("in_progress", "In progress"),
                      ("implemented", "Implemented"), ("not_applicable", "Not applicable")]
    AUTO_CHOICES = [("pass", "Pass"), ("warn", "Warning"), ("fail", "Fail"), ("na", "No automated check"), ("unknown", "Not evaluated")]
    control = models.OneToOneField(ComplianceControl, related_name="implementation", on_delete=models.CASCADE)
    applicable = models.BooleanField(default=True)
    justification = models.TextField(blank=True, help_text=_("Statement of Applicability: why the control is included or excluded."))
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="not_started")
    owner = models.ForeignKey(USER, null=True, blank=True, on_delete=models.SET_NULL, related_name="owned_controls")
    implementation_notes = models.TextField(blank=True)
    auto_status = models.CharField(max_length=10, choices=AUTO_CHOICES, default="na")
    auto_detail = models.TextField(blank=True)
    auto_evaluated_at = models.DateTimeField(null=True, blank=True)
    last_reviewed = models.DateField(null=True, blank=True)
    review_due = models.DateField(null=True, blank=True)
    updated = models.DateTimeField(auto_now=True)


class ControlEvidence(models.Model):
    control = models.ForeignKey(ComplianceControl, related_name="evidence", on_delete=models.CASCADE)
    title = models.CharField(max_length=300)
    description = models.TextField(blank=True)
    url = models.CharField(max_length=1000, blank=True)
    file = models.FileField(upload_to="evidence/%Y/%m/", null=True, blank=True)
    source = models.CharField(max_length=16, default="manual", choices=[("manual", "Manual"), ("auto", "Automated")])
    collected_at = models.DateTimeField(default=timezone.now)
    valid_until = models.DateField(null=True, blank=True)
    CLASSIFICATION = [("public", "Public"), ("internal", "Internal"), ("confidential", "Confidential"), ("restricted", "Restricted")]
    classification = models.CharField(max_length=12, choices=CLASSIFICATION, default="internal",
                                      help_text=_("POL-010 classification of this evidence (label)."))
    created_by = models.ForeignKey(USER, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")

    class Meta:
        ordering = ["-collected_at"]


class ControlCheckResult(models.Model):
    control = models.ForeignKey(ComplianceControl, related_name="check_results", on_delete=models.CASCADE)
    evaluated_at = models.DateTimeField(default=timezone.now)
    result = models.CharField(max_length=10)
    detail = models.TextField(blank=True)
    metrics = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-evaluated_at"]


class RiskRegisterEntry(models.Model):
    TREATMENT = [("mitigate", "Mitigate"), ("accept", "Accept"), ("transfer", "Transfer"), ("avoid", "Avoid")]
    STATUS = [("open", "Open"), ("treating", "In treatment"), ("accepted", "Accepted"), ("closed", "Closed")]
    ref = models.CharField(max_length=20, unique=True, blank=True)
    title = models.CharField(max_length=300)
    description = models.TextField(blank=True)
    product = models.ForeignKey("orasec.Product", null=True, blank=True, on_delete=models.SET_NULL)
    threat = models.TextField(blank=True)
    vulnerability = models.TextField(blank=True)
    likelihood = models.PositiveSmallIntegerField(default=3, validators=[MinValueValidator(1), MaxValueValidator(5)])
    impact = models.PositiveSmallIntegerField(default=3, validators=[MinValueValidator(1), MaxValueValidator(5)])
    treatment = models.CharField(max_length=16, choices=TREATMENT, default="mitigate")
    treatment_plan = models.TextField(blank=True)
    residual_likelihood = models.PositiveSmallIntegerField(null=True, blank=True, validators=[MinValueValidator(1), MaxValueValidator(5)])
    residual_impact = models.PositiveSmallIntegerField(null=True, blank=True, validators=[MinValueValidator(1), MaxValueValidator(5)])
    owner = models.ForeignKey(USER, null=True, blank=True, on_delete=models.SET_NULL, related_name="owned_risks")
    status = models.CharField(max_length=16, choices=STATUS, default="open")
    review_date = models.DateField(null=True, blank=True)
    controls = models.ManyToManyField(ComplianceControl, blank=True, related_name="risks")
    findings = models.ManyToManyField("orasec.Finding", blank=True, related_name="register_risks")
    # Risk assessment detail (POL-002 section 5 register fields)
    category = models.CharField(max_length=60, blank=True)
    scope = models.CharField(max_length=200, blank=True, help_text=_("Company-wide, or the products affected."))
    existing_controls = models.TextField(blank=True)
    evidence_note = models.TextField(blank=True, help_text=_("What was found that supports this risk."))
    assessment = models.ForeignKey("orasec.RiskAssessment", null=True, blank=True, on_delete=models.SET_NULL, related_name="risks")
    source_ref = models.CharField(max_length=20, blank=True, help_text=_("Identifier in the assessment workbook, for example DR-01."))
    raised_on = models.DateField(null=True, blank=True)
    last_reviewed = models.DateField(null=True, blank=True)
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["ref"]

    def save(self, *args, **kwargs):
        if not self.ref:
            from orasec.posture.grc_models import next_ref  # noqa: PLC0415
            self.ref = next_ref(RiskRegisterEntry, "RSK-")
        if not self.raised_on:
            self.raised_on = timezone.now().date()
        super().save(*args, **kwargs)

    @property
    def inherent_score(self):
        return self.likelihood * self.impact

    @property
    def residual_score(self):
        if self.residual_likelihood and self.residual_impact:
            return self.residual_likelihood * self.residual_impact
        return None

    @staticmethod
    def rating(score):
        """POL-002 bands: Critical 20-25, High 12-19, Medium 6-11, Low 1-5."""
        from orasec.posture.grc_models import risk_band  # noqa: PLC0415
        return risk_band(score)

    @property
    def inherent_band(self):
        return self.rating(self.inherent_score)

    @property
    def residual_band(self):
        return self.rating(self.residual_score)


# ---------------------------------------------------------------------------
# Posture history and saved dashboards
# ---------------------------------------------------------------------------
class PostureSnapshot(models.Model):
    date = models.DateField(unique=True)
    score = models.PositiveSmallIntegerField()
    vuln_score = models.PositiveSmallIntegerField()
    compliance_score = models.PositiveSmallIntegerField()
    hygiene_score = models.PositiveSmallIntegerField()
    counts = models.JSONField(default=dict)

    class Meta:
        ordering = ["-date"]


class ProductScanCadence(models.Model):
    product = models.OneToOneField("orasec.Product", related_name="scan_cadence", on_delete=models.CASCADE)
    expected_days = models.PositiveSmallIntegerField(default=7)



# ---------------------------------------------------------------------------
# Patch deployment (Semaphore / Ansible)
# ---------------------------------------------------------------------------
class PatchDeployment(models.Model):
    STATUS_CHOICES = [("requested", "Requested"), ("waiting", "Queued in Semaphore"), ("running", "Running"),
                      ("success", "Succeeded"), ("error", "Failed"), ("stopped", "Stopped")]
    MODE_CHOICES = [("apply", "Apply updates"), ("check", "Check only (no changes)")]
    asset = models.ForeignKey(InventoryAsset, null=True, blank=True, on_delete=models.SET_NULL, related_name="patch_deployments")
    connector = models.ForeignKey(Connector, on_delete=models.CASCADE, related_name="patch_deployments")
    inventory_host = models.CharField(max_length=200)
    inventory_group = models.CharField(max_length=100, blank=True)
    mode = models.CharField(max_length=10, choices=MODE_CHOICES, default="apply")
    template_id = models.PositiveIntegerField()
    task_id = models.PositiveIntegerField(null=True, blank=True)
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default="requested", db_index=True)
    change_ref = models.CharField(max_length=120, blank=True, help_text=_("Change record / approval reference."))
    reason = models.TextField(blank=True)
    requested_by = models.ForeignKey(USER, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    created = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    output = models.TextField(blank=True)
    summary = models.CharField(max_length=500, blank=True)

    class Meta:
        ordering = ["-created"]

    @property
    def is_active(self):
        return self.status in ("requested", "waiting", "running")


# ---------------------------------------------------------------------------
# Attack telemetry (blocked / allowed edge events) and network topology snapshot
# ---------------------------------------------------------------------------
class AttackEvent(models.Model):
    source = models.CharField(max_length=20, db_index=True)  # cloudflare | opnsense | unifi | wazuh
    event_id = models.CharField(max_length=120)               # source-specific id / digest for de-duplication
    occurred_at = models.DateTimeField(db_index=True)
    action = models.CharField(max_length=20, default="block")  # block | challenge | alert | allow
    src_ip = models.GenericIPAddressField(unpack_ipv4=True, null=True, blank=True)  # null for aggregated (country-level) events
    src_country = models.CharField(max_length=2, blank=True, db_index=True)
    src_asn = models.CharField(max_length=20, blank=True)
    src_org = models.CharField(max_length=200, blank=True)
    dst_ip = models.CharField(max_length=64, blank=True)
    dst_port = models.PositiveIntegerField(null=True, blank=True)
    protocol = models.CharField(max_length=12, blank=True)
    target = models.CharField(max_length=200, blank=True, help_text=_("Site/host/zone that was targeted."))
    rule = models.CharField(max_length=300, blank=True)
    detail = models.CharField(max_length=500, blank=True)
    hits = models.PositiveIntegerField(default=1)

    class Meta:
        ordering = ["-occurred_at"]
        constraints = [models.UniqueConstraint(fields=["source", "event_id"], name="os_attack_unique")]
        indexes = [models.Index(fields=["-occurred_at", "source"], name="os_attack_recent")]


class TopologySnapshot(models.Model):
    created = models.DateTimeField(auto_now_add=True)
    graph = models.JSONField(default=dict)

    class Meta:
        ordering = ["-created"]


# GRC records: risk assessments, reviews, exceptions, suppliers, opportunities
from orasec.posture.grc_models import (  # noqa: E402, F401
    ChangeRequest,
    ExceptionDecision,
    GovernanceException,
    IsmsConflict,
    IsmsLink,
    IsmsSyncRun,
    LeaverRecord,
    Nonconformity,
    ObjectiveAction,
    Opportunity,
    RiskAssessment,
    RiskReview,
    SecurityObjective,
    Supplier,
    SupplierAssessment,
    SupplierAssessmentDecision,
)

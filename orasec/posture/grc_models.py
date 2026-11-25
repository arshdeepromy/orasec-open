"""
OraSec GRC records: risk assessments and reviews, exceptions and risk acceptances,
supplier register and supplier assessments, and opportunities.

Rules follow POL-002 Risk Management Policy (5x5 matrix, bands, acceptance
authority, exception limits) and POL-015 Supplier and Third-Party Security Policy
(tiers, lifecycle, approvals, annual review). Approvals are enforced in the views:
no one approves their own request, assessment or risk.
"""
import datetime

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.utils import timezone

USER = settings.AUTH_USER_MODEL
LI = [MinValueValidator(1), MaxValueValidator(5)]


def risk_band(score):
    """POL-002 section 4.5: Critical 20-25, High 12-19, Medium 6-11, Low 1-5."""
    if not score:
        return ""
    if score >= 20:
        return "Critical"
    if score >= 12:
        return "High"
    if score >= 6:
        return "Medium"
    return "Low"


def next_ref(model, prefix, width=3, field="ref"):
    """Next sequential reference such as RSK-001 or SA-2026-001."""
    nums = []
    for r in model.objects.filter(**{f"{field}__startswith": prefix}).values_list(field, flat=True):
        tail = r[len(prefix):]
        if tail.isdigit():
            nums.append(int(tail))
    return f"{prefix}{(max(nums) + 1) if nums else 1:0{width}d}"


# ---------------------------------------------------------------------------
# Risk assessments (ISO/IEC 27001 clauses 6.1.2 and 8.2)
# ---------------------------------------------------------------------------
class RiskAssessment(models.Model):
    STATUS = [("draft", "Draft"), ("submitted", "Awaiting approval"), ("approved", "Approved"), ("returned", "Returned")]
    ref = models.CharField(max_length=20, unique=True, blank=True)
    title = models.CharField(max_length=300)
    scope = models.TextField(blank=True)
    method = models.TextField(blank=True, default="POL-002 section 4 and PRC-009: 5x5 matrix, Score = Likelihood x Impact.")
    assessed_on = models.DateField(default=datetime.date.today)
    prepared_by = models.ForeignKey(USER, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    prepared_for = models.CharField(max_length=100, blank=True, help_text="Role the assessment was prepared for or on behalf of.")
    summary = models.TextField(blank=True)
    file = models.FileField(upload_to="grc/risk-assessments/%Y/", null=True, blank=True)
    status = models.CharField(max_length=16, choices=STATUS, default="draft", db_index=True)
    submitted_at = models.DateTimeField(null=True, blank=True)
    decided_by = models.ForeignKey(USER, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    decided_at = models.DateTimeField(null=True, blank=True)
    decision_note = models.TextField(blank=True)
    next_assessment = models.DateField(null=True, blank=True)
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-assessed_on", "-id"]

    def save(self, *args, **kwargs):
        if not self.ref:
            self.ref = next_ref(RiskAssessment, f"RA-{self.assessed_on:%Y}-", 2)
        if not self.next_assessment:
            self.next_assessment = self.assessed_on + datetime.timedelta(days=365)
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.ref} {self.title}"


class RiskReview(models.Model):
    """One review of a register risk: re-scored, status and next review date recorded."""
    risk = models.ForeignKey("orasec.RiskRegisterEntry", related_name="reviews", on_delete=models.CASCADE)
    reviewed_by = models.ForeignKey(USER, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    reviewed_at = models.DateTimeField(default=timezone.now)
    likelihood = models.PositiveSmallIntegerField(validators=LI)
    impact = models.PositiveSmallIntegerField(validators=LI)
    residual_likelihood = models.PositiveSmallIntegerField(null=True, blank=True, validators=LI)
    residual_impact = models.PositiveSmallIntegerField(null=True, blank=True, validators=LI)
    status = models.CharField(max_length=16, default="open")
    note = models.TextField(blank=True)
    next_review = models.DateField(null=True, blank=True)

    class Meta:
        ordering = ["-reviewed_at"]

    @property
    def score(self):
        return self.likelihood * self.impact


# ---------------------------------------------------------------------------
# Exceptions and risk acceptances (POL-002 sections 4.7 and 10, REG-003)
# ---------------------------------------------------------------------------
class GovernanceException(models.Model):
    KIND = [("policy_exception", "Policy exception"), ("risk_acceptance", "Risk acceptance")]
    STATUS = [("requested", "Awaiting approval"), ("approved", "Approved"), ("rejected", "Rejected"),
              ("expired", "Expired"), ("closed", "Closed")]
    ref = models.CharField(max_length=20, unique=True, blank=True)
    kind = models.CharField(max_length=20, choices=KIND, default="policy_exception")
    title = models.CharField(max_length=300)
    policy_ref = models.CharField(max_length=200, blank=True, help_text="Policy or standard and clause, for example STD-001 4.6.")
    description = models.TextField(help_text="What deviates from the policy, or what residual risk is accepted.")
    reason = models.TextField(blank=True)
    compensating_controls = models.TextField(blank=True)
    risk = models.ForeignKey("orasec.RiskRegisterEntry", null=True, blank=True, on_delete=models.SET_NULL, related_name="exceptions")
    control = models.ForeignKey("orasec.ComplianceControl", null=True, blank=True, on_delete=models.SET_NULL, related_name="exceptions")
    supplier = models.ForeignKey("orasec.Supplier", null=True, blank=True, on_delete=models.SET_NULL, related_name="exceptions")
    likelihood = models.PositiveSmallIntegerField(default=2, validators=LI, help_text="Residual likelihood while the exception applies.")
    impact = models.PositiveSmallIntegerField(default=3, validators=LI, help_text="Residual impact while the exception applies.")
    requested_by = models.ForeignKey(USER, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    requested_at = models.DateTimeField(default=timezone.now)
    start = models.DateField(default=datetime.date.today)
    expiry = models.DateField()
    status = models.CharField(max_length=16, choices=STATUS, default="requested", db_index=True)
    closed_note = models.TextField(blank=True)
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-requested_at"]

    @property
    def score(self):
        return self.likelihood * self.impact

    @property
    def band(self):
        return risk_band(self.score)

    def required_approvals(self):
        """Approvers needed; None means it cannot be approved (a Critical risk cannot be accepted)."""
        if self.kind == "policy_exception":
            return 2
        return {"Critical": None, "High": 2, "Medium": 1, "Low": 1}[self.band]

    def max_days(self):
        if self.kind == "policy_exception":
            return 90
        return {"High": 183, "Medium": 366, "Low": 366}.get(self.band, 90)

    def clean(self):
        if self.expiry and self.start and (self.expiry - self.start).days > self.max_days():
            raise ValidationError({"expiry": f"Maximum duration for this {self.get_kind_display().lower()} is {self.max_days()} days."})
        if self.kind == "risk_acceptance" and self.band == "Critical":
            raise ValidationError("A Critical risk cannot be accepted. Treat it, and cover compensating controls with a policy exception.")

    def save(self, *args, **kwargs):
        if not self.ref:
            self.ref = next_ref(GovernanceException, "EXC-")
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.ref} {self.title}"


class ExceptionDecision(models.Model):
    exception = models.ForeignKey(GovernanceException, related_name="decisions", on_delete=models.CASCADE)
    decided_by = models.ForeignKey(USER, on_delete=models.CASCADE, related_name="+")
    decision = models.CharField(max_length=10, choices=[("approve", "Approve"), ("reject", "Reject")])
    note = models.TextField(blank=True)
    decided_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["decided_at"]
        constraints = [models.UniqueConstraint(fields=["exception", "decided_by"], name="os_excdecision_unique")]


# ---------------------------------------------------------------------------
# Supplier register (POL-015, REG-006)
# ---------------------------------------------------------------------------
class Supplier(models.Model):
    TIER = [("critical", "Critical"), ("high", "High"), ("standard", "Standard")]
    STATUS = [("proposed", "Proposed"), ("assessing", "Due diligence"), ("active", "Active"),
              ("suspended", "Suspended"), ("exited", "Exited")]
    CLASSIFICATION = [("public", "Public"), ("internal", "Internal"), ("confidential", "Confidential"), ("restricted", "Restricted")]
    ref = models.CharField(max_length=20, unique=True, blank=True)
    name = models.CharField(max_length=200)
    service = models.TextField()
    data_shared = models.TextField(blank=True)
    classification = models.CharField(max_length=16, choices=CLASSIFICATION, default="internal",
                                      help_text="Highest classification of company data the supplier receives.")
    tier = models.CharField(max_length=10, choices=TIER, default="standard")
    data_location = models.CharField(max_length=200, blank=True)
    personal_information = models.BooleanField(default=False, help_text="Supplier processes personal information.")
    products = models.CharField(max_length=200, blank=True, help_text="Products or functions that use the supplier.")
    assurance = models.TextField(blank=True, help_text="Independent assurance held, for example ISO/IEC 27001, SOC 2 Type II, PCI DSS.")
    assurance_expiry = models.DateField(null=True, blank=True)
    contract = models.TextField(blank=True, help_text="Contract, terms or DPA, and the terms mapping record.")
    breach_notification = models.BooleanField(default=False, help_text="Breach notification within 24 hours confirmed in the terms.")
    owner = models.ForeignKey(USER, null=True, blank=True, on_delete=models.SET_NULL, related_name="owned_suppliers")
    requested_by = models.ForeignKey(USER, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    status = models.CharField(max_length=12, choices=STATUS, default="proposed", db_index=True)
    last_review = models.DateField(null=True, blank=True)
    next_review = models.DateField(null=True, blank=True)
    website = models.CharField(max_length=300, blank=True)
    notes = models.TextField(blank=True)
    risks = models.ManyToManyField("orasec.RiskRegisterEntry", blank=True, related_name="suppliers")
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["ref"]

    def save(self, *args, **kwargs):
        if not self.ref:
            self.ref = next_ref(Supplier, "SUP-V-")
        super().save(*args, **kwargs)

    @property
    def review_overdue(self):
        return self.status == "active" and (not self.next_review or self.next_review < timezone.now().date())

    @property
    def approved_assessment(self):
        return self.assessments.filter(status__in=["approved", "approved_conditions"]).order_by("-assessed_on").first()

    def required_approvals(self):
        """POL-015: Critical suppliers need two people who are not the requester; others one."""
        return 2 if self.tier == "critical" else 1

    def __str__(self):
        return f"{self.ref} {self.name}"


class SupplierAssessment(models.Model):
    KIND = [("onboarding", "Onboarding due diligence"), ("annual", "Annual review"),
            ("triggered", "Triggered review"), ("offboarding", "Offboarding")]
    STATUS = [("draft", "Draft"), ("submitted", "Awaiting approval"), ("approved", "Approved"),
              ("approved_conditions", "Approved with conditions"), ("rejected", "Rejected")]
    RECOMMEND = [("approve", "Approve"), ("approve_conditions", "Approve with conditions"), ("reject", "Reject")]
    ref = models.CharField(max_length=20, unique=True, blank=True)
    supplier = models.ForeignKey(Supplier, related_name="assessments", on_delete=models.CASCADE)
    kind = models.CharField(max_length=16, choices=KIND, default="annual")
    assessed_by = models.ForeignKey(USER, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    assessed_on = models.DateField(default=datetime.date.today)
    # Due-diligence checklist (POL-015 section 4.3, FRM-008)
    assurance_ok = models.BooleanField(default=False, verbose_name="Current independent assurance reviewed (ISO 27001, SOC 2, PCI DSS)")
    data_location_ok = models.BooleanField(default=False, verbose_name="Data location meets the data location standard (STD-003)")
    breach_terms_ok = models.BooleanField(default=False, verbose_name="Breach notification and security terms in the contract")
    encryption_ok = models.BooleanField(default=False, verbose_name="Encryption in transit and at rest")
    access_ok = models.BooleanField(default=False, verbose_name="Least-privilege access, MFA and logging configured")
    subprocessors_ok = models.BooleanField(default=False, verbose_name="Sub-processors reviewed")
    incidents = models.TextField(blank=True, verbose_name="Incidents and news in the period")
    findings = models.TextField(blank=True)
    likelihood = models.PositiveSmallIntegerField(default=2, validators=LI, verbose_name="Supplier risk likelihood")
    impact = models.PositiveSmallIntegerField(default=3, validators=LI, verbose_name="Supplier risk impact")
    recommendation = models.CharField(max_length=20, choices=RECOMMEND, default="approve")
    conditions = models.TextField(blank=True)
    evidence = models.FileField(upload_to="grc/suppliers/%Y/", null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS, default="draft", db_index=True)
    submitted_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    created = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-assessed_on", "-id"]

    @property
    def score(self):
        return self.likelihood * self.impact

    @property
    def band(self):
        return risk_band(self.score)

    def save(self, *args, **kwargs):
        if not self.ref:
            self.ref = next_ref(SupplierAssessment, f"SA-{self.assessed_on:%Y}-")
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.ref} {self.supplier.name}"


class SupplierAssessmentDecision(models.Model):
    assessment = models.ForeignKey(SupplierAssessment, related_name="decisions", on_delete=models.CASCADE)
    decided_by = models.ForeignKey(USER, on_delete=models.CASCADE, related_name="+")
    decision = models.CharField(max_length=20, choices=SupplierAssessment.RECOMMEND)
    note = models.TextField(blank=True)
    decided_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["decided_at"]
        constraints = [models.UniqueConstraint(fields=["assessment", "decided_by"], name="os_sadecision_unique")]


# ---------------------------------------------------------------------------
# Opportunities (ISO/IEC 27001 clause 6.1.1)
# ---------------------------------------------------------------------------
class Opportunity(models.Model):
    STATUS = [("open", "Open"), ("in_progress", "In progress"), ("realised", "Realised"), ("dropped", "Dropped")]
    ref = models.CharField(max_length=20, unique=True, blank=True)
    title = models.CharField(max_length=300)
    benefit = models.TextField(blank=True)
    action = models.TextField(blank=True)
    owner = models.ForeignKey(USER, null=True, blank=True, on_delete=models.SET_NULL, related_name="owned_opportunities")
    status = models.CharField(max_length=16, choices=STATUS, default="open")
    review_date = models.DateField(null=True, blank=True)
    assessment = models.ForeignKey(RiskAssessment, null=True, blank=True, on_delete=models.SET_NULL, related_name="opportunities")
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["ref"]
        verbose_name_plural = "opportunities"

    def save(self, *args, **kwargs):
        if not self.ref:
            self.ref = next_ref(Opportunity, "OPP-")
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.ref} {self.title}"



# ---------------------------------------------------------------------------
# Information security objectives (ISO/IEC 27001 clause 6.2, FWK-001 section 3)
# ---------------------------------------------------------------------------
class SecurityObjective(models.Model):
    MEASURE = [("critical_overdue", "Critical and known-exploited findings past SLA (automatic)"),
               ("sla_compliance", "Findings closed within SLA (automatic)"),
               ("endpoint_coverage", "Wazuh coverage and FileVault evidence (automatic)"),
               ("evidence", "Latest evidence record (automatic)"),
               ("manual", "Manual")]
    STATUS = [("met", "Met"), ("on_track", "On track"), ("off_track", "Off track"),
              ("not_measured", "Not measured"), ("not_applicable", "Not applicable yet")]
    ref = models.CharField(max_length=10, unique=True)
    title = models.CharField(max_length=200)
    target = models.TextField()
    owner = models.ForeignKey(USER, null=True, blank=True, on_delete=models.SET_NULL, related_name="owned_objectives")
    plan = models.TextField(blank=True, help_text="What will be done and with what resources.")
    due_date = models.DateField(null=True, blank=True, help_text="When the target should be met.")
    measure = models.CharField(max_length=20, choices=MEASURE, default="evidence")
    evidence_prefix = models.CharField(max_length=120, blank=True,
                                       help_text="For evidence measures: evidence titles starting with this text count, e.g. 'Restore test'.")
    evidence_max_days = models.PositiveIntegerField(default=365, help_text="Evidence older than this does not count.")
    applicable = models.BooleanField(default=True)
    manual_met = models.BooleanField(default=False, help_text="For manual measures only.")
    status = models.CharField(max_length=16, choices=STATUS, default="not_measured", db_index=True)
    current_value = models.CharField(max_length=300, blank=True)
    last_measured = models.DateTimeField(null=True, blank=True)
    notes = models.TextField(blank=True)
    updated = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["ref"]

    def __str__(self):
        return f"{self.ref} {self.title}"

    @property
    def open_actions(self):
        return sum(1 for a in self.actions.all() if a.status == "open")


class ObjectiveAction(models.Model):
    STATUS = [("open", "Open"), ("done", "Done"), ("dropped", "Dropped")]
    objective = models.ForeignKey(SecurityObjective, related_name="actions", on_delete=models.CASCADE)
    title = models.CharField(max_length=300)
    owner = models.ForeignKey(USER, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    due_date = models.DateField(null=True, blank=True)
    status = models.CharField(max_length=10, choices=STATUS, default="open")
    done_by = models.ForeignKey(USER, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    done_at = models.DateTimeField(null=True, blank=True)
    note = models.TextField(blank=True)

    class Meta:
        ordering = ["status", "due_date", "id"]

    @property
    def overdue(self):
        return self.status == "open" and self.due_date and self.due_date < timezone.now().date()


# ---------------------------------------------------------------------------
# Change register (ISO/IEC 27001 clause 6.3 and A.8.32; FWK-001 8.4, PRC-003)
# ---------------------------------------------------------------------------
def _add_business_days(start, days):
    d = start
    while days > 0:
        d += datetime.timedelta(days=1)
        if d.weekday() < 5:
            days -= 1
    return d


class ChangeRequest(models.Model):
    """One record for every ISMS change and every IT change: raised, approved, done, then reviewed."""
    CATEGORY = [("isms", "ISMS (scope, policies, roles, risk method, objectives)"),
                ("network", "Firewall and network"),
                ("hosting", "Hosting and cloud (AWS, Cloudflare, DNS)"),
                ("infrastructure", "Servers and infrastructure"),
                ("application", "Application release"),
                ("security_tool", "Security and monitoring tools"),
                ("access", "Access and identity"),
                ("supplier", "Supplier"),
                ("other", "Other IT change")]
    TYPE = [("normal", "Normal"), ("standard", "Standard (pre-approved type)"),
            ("emergency", "Emergency"), ("retrospective", "Recorded after the change")]
    RISK = [("low", "Low"), ("medium", "Medium"), ("high", "High")]
    STATUS = [("submitted", "Awaiting approval"), ("approved", "Approved"), ("rejected", "Rejected"),
              ("implemented", "Done — awaiting review"), ("closed", "Reviewed and closed"), ("cancelled", "Cancelled")]
    RESULT = [("successful", "Successful"), ("issues", "Successful with issues"), ("failed", "Failed"),
              ("rolled_back", "Rolled back")]
    #: Emergency changes need written approval within 2 business days (PRC-003 6.5); changes recorded afterwards within 5.
    APPROVAL_DAYS = {"emergency": 2, "retrospective": 5}

    ref = models.CharField(max_length=20, unique=True, blank=True)
    category = models.CharField(max_length=20, choices=CATEGORY, default="infrastructure", db_index=True)
    change_type = models.CharField("Type", max_length=16, choices=TYPE, default="normal")
    title = models.CharField(max_length=300)
    reason = models.TextField("Why", help_text="What is changing and why.")
    impact = models.TextField("Consequences and what is affected",
                              help_text="What could go wrong, new risks, and which systems, documents, controls or customers are affected.")
    resources = models.TextField("People, time and cost", blank=True)
    plan = models.TextField("Plan, test and rollback", blank=True,
                            help_text="Steps, how it will be tested or checked, and how to undo it.")
    risk_level = models.CharField(max_length=8, choices=RISK, default="low")
    systems = models.CharField(max_length=300, blank=True, help_text="For example: app server, AWS, Cloudflare WAF, POL-008.")
    link = models.URLField(max_length=500, blank=True, help_text="Pull request, release or ticket, if any.")
    owner = models.ForeignKey(USER, null=True, blank=True, on_delete=models.SET_NULL, related_name="owned_changes")
    planned_date = models.DateField(null=True, blank=True)
    requested_by = models.ForeignKey(USER, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    requested_at = models.DateTimeField(default=timezone.now)
    status = models.CharField(max_length=16, choices=STATUS, default="submitted", db_index=True)
    approved_by = models.ForeignKey(USER, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    approved_at = models.DateTimeField(null=True, blank=True)
    approval_note = models.TextField(blank=True)
    implemented_by = models.ForeignKey(USER, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    implemented_at = models.DateTimeField(null=True, blank=True)
    implementation_note = models.TextField(blank=True)
    reviewed_by = models.ForeignKey(USER, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    reviewed_at = models.DateTimeField(null=True, blank=True)
    review_result = models.CharField(max_length=16, choices=RESULT, blank=True)
    review_note = models.TextField(blank=True)
    imported = models.BooleanField(default=False, help_text="Imported from the old Change Log (REG-010), recorded before "
                                   "the Change Register existed; the approval rules did not apply then.")
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-requested_at"]

    def save(self, *args, **kwargs):
        if not self.ref:
            self.ref = next_ref(ChangeRequest, f"CHG-{self.requested_at.year}-")
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.ref} {self.title}"

    @property
    def can_go_ahead_unapproved(self):
        """Emergency and after-the-fact records may be marked done before approval."""
        return self.change_type in self.APPROVAL_DAYS

    @property
    def approval_due(self):
        """Date by which an emergency or after-the-fact change must be approved."""
        if self.approved_by_id or not self.can_go_ahead_unapproved or not self.implemented_at:
            return None
        return _add_business_days(timezone.localtime(self.implemented_at).date(), self.APPROVAL_DAYS[self.change_type])

    @property
    def approval_overdue(self):
        due = self.approval_due
        return bool(due and due < timezone.now().date())

    @property
    def review_overdue(self):
        return bool(self.status == "implemented" and self.implemented_at
                    and self.implemented_at < timezone.now() - datetime.timedelta(days=14))


# ---------------------------------------------------------------------------
# Nonconformities and corrective actions (ISO/IEC 27001 clause 10.2)
# ---------------------------------------------------------------------------
class Nonconformity(models.Model):
    SOURCE = [("audit", "Internal or external audit"), ("incident", "Security incident"), ("check", "Failed automatic check"),
              ("review", "Management review"), ("other", "Other")]
    STATUS = [("open", "Open"), ("action", "Corrective action in progress"), ("verify", "Awaiting effectiveness check"),
              ("closed", "Closed"), ("dropped", "Not a nonconformity")]
    ref = models.CharField(max_length=20, unique=True, blank=True)
    title = models.CharField(max_length=300)
    source = models.CharField(max_length=16, choices=SOURCE, default="audit")
    control = models.CharField(max_length=40, blank=True, help_text="Clause or control, e.g. A.8.8")
    description = models.TextField(blank=True, help_text="What went wrong")
    correction = models.TextField(blank=True, help_text="Immediate fix")
    cause = models.TextField(blank=True, help_text="Root cause")
    corrective_action = models.TextField(blank=True, help_text="Action so it does not happen again")
    owner = models.ForeignKey(USER, null=True, blank=True, on_delete=models.SET_NULL, related_name="owned_nonconformities")
    due_date = models.DateField(null=True, blank=True)
    status = models.CharField(max_length=16, choices=STATUS, default="open", db_index=True)
    effectiveness = models.TextField(blank=True, help_text="How the fix was checked and the result")
    verified_by = models.ForeignKey(USER, null=True, blank=True, on_delete=models.SET_NULL, related_name="verified_nonconformities")
    raised = models.DateField(default=timezone.localdate)
    closed_date = models.DateField(null=True, blank=True)
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-ref"]

    def clean(self):
        if self.status == "closed":
            if not (self.cause.strip() and self.corrective_action.strip() and self.effectiveness.strip() and self.verified_by_id):
                raise ValidationError("To close: record the cause, corrective action, effectiveness check and who verified it.")
            if self.verified_by_id and self.verified_by_id == self.owner_id:
                raise ValidationError("The effectiveness check must be done by someone other than the action owner.")

    def save(self, *args, **kwargs):
        if not self.ref:
            self.ref = next_ref(Nonconformity, "NC-")
        if self.status == "closed" and not self.closed_date:
            self.closed_date = timezone.localdate()
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.ref} {self.title}"


# ---------------------------------------------------------------------------
# Policy tool (ISMS) two-way sync state
# ---------------------------------------------------------------------------
class IsmsLink(models.Model):
    """One OraSec record linked to one record in the policy tool, with the field values last agreed by both sides."""
    entity = models.CharField(max_length=32, db_index=True)
    orasec_id = models.IntegerField()
    isms_id = models.IntegerField()
    snapshot = models.JSONField(default=dict, blank=True)
    synced_at = models.DateTimeField(null=True, blank=True)
    archived = models.BooleanField(default=False)

    class Meta:
        unique_together = [("entity", "orasec_id"), ("entity", "isms_id")]


class IsmsConflict(models.Model):
    KIND = [("field", "Same field changed on both sides"), ("decision", "Decision made in the policy tool")]
    entity = models.CharField(max_length=32)
    orasec_id = models.IntegerField(null=True, blank=True)
    isms_id = models.IntegerField(null=True, blank=True)
    label = models.CharField(max_length=300, blank=True)
    field = models.CharField(max_length=64)
    kind = models.CharField(max_length=16, choices=KIND, default="field")
    orasec_value = models.TextField(blank=True)
    isms_value = models.TextField(blank=True)
    created = models.DateTimeField(auto_now_add=True)
    resolved = models.BooleanField(default=False, db_index=True)
    resolution = models.CharField(max_length=16, blank=True)
    resolved_by = models.ForeignKey(USER, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    resolved_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created"]


class IsmsSyncRun(models.Model):
    KIND = [("event", "Event"), ("full", "Full reconciliation"), ("push", "Push one record")]
    kind = models.CharField(max_length=8, choices=KIND)
    started = models.DateTimeField(auto_now_add=True)
    finished = models.DateTimeField(null=True, blank=True)
    ok = models.BooleanField(default=False)
    stats = models.JSONField(default=dict, blank=True)
    error = models.TextField(blank=True)

    class Meta:
        ordering = ["-started"]


# ---------------------------------------------------------------------------
# Leavers and movers: return of assets (A.5.11), removal of access (A.5.18, A.6.5) -- PRC-001 / FRM-002
# ---------------------------------------------------------------------------
LEAVER_STEPS = [
    ("devices", "Company devices returned (laptop, phone, security keys) and checked"),
    ("data", "Company data on returned devices kept or securely wiped (FRM-013 if disposed)"),
    ("accounts", "Accounts disabled: e-mail, GitHub, cloud providers, OraSec, policy tool, product admin consoles"),
    ("credentials", "Shared credentials and vault items the person knew rotated"),
    ("sessions", "Sessions and tokens revoked (OraSec phone app, WhatsApp groups, personal-device mail)"),
    ("assets", "Assets they owned or jointly owned moved to a new owner"),
    ("records", "Confidentiality undertaking reminded; leaver noted in the training and access registers"),
]


class LeaverRecord(models.Model):
    KIND = [("leaver", "Leaver"), ("mover", "Mover (role change)")]
    STATUS = [("open", "Open"), ("signed_off", "Signed off"), ("cancelled", "Cancelled")]
    ref = models.CharField(max_length=20, unique=True, blank=True)
    person = models.ForeignKey(USER, on_delete=models.PROTECT, related_name="leaver_records")
    kind = models.CharField(max_length=10, choices=KIND, default="leaver")
    leaving_date = models.DateField(default=timezone.localdate)
    due_date = models.DateField(null=True, blank=True, help_text="Checklist complete by (default 5 business days)")
    reason = models.TextField(blank=True)
    started_by = models.ForeignKey(USER, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    started_automatically = models.BooleanField(default=False)
    steps = models.JSONField(default=list, blank=True)
    assets = models.JSONField(default=list, blank=True, help_text="Assets owned or jointly owned when the record started")
    status = models.CharField(max_length=12, choices=STATUS, default="open", db_index=True)
    signed_off_by = models.ForeignKey(USER, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    signed_off_at = models.DateTimeField(null=True, blank=True)
    note = models.TextField(blank=True)
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-ref"]

    def save(self, *args, **kwargs):
        if not self.ref:
            self.ref = next_ref(LeaverRecord, "LVR-")
        if not self.steps:
            self.steps = [{"key": k, "label": l, "done": False, "by": "", "at": "", "note": ""} for k, l in LEAVER_STEPS]
        if not self.due_date:
            d, n = self.leaving_date, 0
            while n < 5:
                d += datetime.timedelta(days=1)
                if d.weekday() < 5:
                    n += 1
            self.due_date = d
        super().save(*args, **kwargs)

    @property
    def done_count(self):
        return sum(1 for s in self.steps if s.get("done"))

    @property
    def complete(self):
        return bool(self.steps) and all(s.get("done") for s in self.steps)

    @property
    def overdue(self):
        return self.status == "open" and self.due_date and self.due_date < timezone.localdate()

    def __str__(self):
        return f"{self.ref} {self.person}"

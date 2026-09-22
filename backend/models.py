from sqlalchemy import Column, Float, Integer, String, DateTime, ForeignKey, Table, UniqueConstraint, Boolean, Text, Index, text
from sqlalchemy.orm import relationship
from datetime import datetime

try:
    from database import Base
except ImportError:
    from backend.database import Base


# ---------------------------------------------------------------------------
# Association table for Risk <-> Control many-to-many relationship
# ---------------------------------------------------------------------------
risk_controls = Table(
    "risk_controls",
    Base.metadata,
    Column("risk_id", Integer, ForeignKey("risks.id", ondelete="CASCADE"), primary_key=True),
    Column("control_id", Integer, ForeignKey("controls.id", ondelete="CASCADE"), primary_key=True),
)


class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String, nullable=True)
    ip_address = Column(String, unique=True, nullable=False)
    mac_address = Column(String, nullable=True)
    operating_system = Column(String, nullable=True)
    open_ports = Column(String(1000), nullable=True)
    status = Column(String, default="Active")
    risk_score = Column(Integer, default=0)
    risk_level = Column(String, default="Low")
    last_seen = Column(DateTime, default=datetime.utcnow)

    # Phase 2: Asset Intelligence
    criticality = Column(String, nullable=True, default=None)      # Low, Medium, High, Critical
    environment = Column(String, nullable=True, default=None)  # Production, Development, Testing
    exposure = Column(String, nullable=True, default=None)       # Internal, DMZ, External
    owner = Column(String, nullable=True)
    business_function = Column(String, nullable=True)

    risks = relationship("Risk", backref="asset", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", backref="asset", cascade="all, delete-orphan")


class Risk(Base):
    __tablename__ = "risks"

    id = Column(Integer, primary_key=True, index=True)

    asset_id = Column(ForeignKey("assets.id"), nullable=False)

    title = Column(String, nullable=False)
    description = Column(String(1000), nullable=True)

    likelihood = Column(String, default="Medium")
    impact = Column(String, default="Medium")

    risk_score = Column(Integer, default=0)
    risk_level = Column(String, default="Medium")

    # Phase 2: Numerical scores and Inherent Risk
    likelihood_score = Column(Integer, default=2)
    impact_score = Column(Integer, default=2)
    inherent_risk_score = Column(Integer, default=4)
    inherent_risk_level = Column(String, default="Medium")

    # Phase 2: Residual Risk
    residual_likelihood = Column(Integer, default=2)
    residual_impact = Column(Integer, default=2)
    residual_risk_score = Column(Integer, default=4)
    residual_risk_level = Column(String, default="Medium")

    # Phase 2: Risk Management & Ownership
    treatment = Column(String, default="Mitigate")
    status = Column(String, default="Open")
    risk_owner = Column(String, nullable=True)
    due_date = Column(DateTime, nullable=True)

    compliance_framework = Column(String, nullable=True)
    compliance_control = Column(String, nullable=True)
    recommendation = Column(String(1000), nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow
    )

    # Phase 6C: Human Governance Review
    review_status = Column(String(32), default="Pending Review", nullable=False, index=True)

    controls = relationship("Control", secondary=risk_controls, back_populates="risks")
    ai_analyses = relationship("AIRiskAnalysis", back_populates="risk", cascade="all, delete-orphan")
    reviews = relationship("RiskReview", back_populates="risk", cascade="all, delete-orphan")



class Control(Base):
    __tablename__ = "controls"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    description = Column(String(1000), nullable=True)
    category = Column(String, nullable=True)     # Preventive, Detective, Corrective, Technical, Administrative
    framework = Column(String, nullable=True)    # NIST CSF, ISO 27001, CIS Controls
    effectiveness = Column(String, default="Medium")  # Low, Medium, High
    status = Column(String, default="Implemented")     # Implemented, Planned, Under Review
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow
    )

    risks = relationship("Risk", secondary=risk_controls, back_populates="controls")
    compliance_mappings = relationship("ControlComplianceMapping", back_populates="control", cascade="all, delete-orphan")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)

    asset_id = Column(
        ForeignKey("assets.id"),
        nullable=False
    )

    port = Column(Integer, nullable=True)

    service = Column(String, nullable=True)
    product = Column(String, nullable=True)
    version = Column(String, nullable=True)

    title = Column(String, nullable=False)

    severity = Column(String, default="Medium")

    description = Column(
        String(1000),
        nullable=True
    )

    cve = Column(String, nullable=True)

    cvss_score = Column(Float, nullable=True)

    cvss_version = Column(
        String,
        nullable=True
    )

    cve_confidence = Column(
        String,
        default="Unknown"
    )

    cve_candidate_count = Column(
        Integer,
        default=0
    )

    status = Column(
        String,
        default="Open"
    )

    discovered_at = Column(
        DateTime,
        default=datetime.utcnow
    )
    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow
    )


# ---------------------------------------------------------------------------
# Phase 3: Compliance Frameworks & Requirements Mapping
# ---------------------------------------------------------------------------

class ComplianceFramework(Base):
    __tablename__ = "compliance_frameworks"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    version = Column(String, nullable=False)
    description = Column(String(1000), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    requirements = relationship("ComplianceRequirement", back_populates="framework", cascade="all, delete-orphan")


class ComplianceRequirement(Base):
    __tablename__ = "compliance_requirements"

    id = Column(Integer, primary_key=True, index=True)
    framework_id = Column(ForeignKey("compliance_frameworks.id", ondelete="CASCADE"), nullable=False)
    requirement_id = Column(String, nullable=False)
    title = Column(String, nullable=False)
    description = Column(String(2000), nullable=True)
    function = Column(String, nullable=True)
    category = Column(String, nullable=True)
    subcategory = Column(String, nullable=True)
    status = Column(String, default="Not Assessed")
    notes = Column(String(2000), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow
    )

    framework = relationship("ComplianceFramework", back_populates="requirements")
    control_mappings = relationship("ControlComplianceMapping", back_populates="requirement", cascade="all, delete-orphan")


class ControlComplianceMapping(Base):
    __tablename__ = "control_compliance_mappings"
    __table_args__ = (
        UniqueConstraint("control_id", "requirement_id", name="uq_control_requirement"),
    )

    id = Column(Integer, primary_key=True, index=True)
    control_id = Column(ForeignKey("controls.id", ondelete="CASCADE"), nullable=False)
    requirement_id = Column(ForeignKey("compliance_requirements.id", ondelete="CASCADE"), nullable=False)
    mapping_strength = Column(String, default="Direct")  # Direct, Supporting
    notes = Column(String(1000), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    control = relationship("Control", back_populates="compliance_mappings")
    requirement = relationship("ComplianceRequirement", back_populates="control_mappings")


# ---------------------------------------------------------------------------
# Phase 4: AI-Assisted Security & Risk Intelligence
# ---------------------------------------------------------------------------

class AIRiskAnalysis(Base):
    __tablename__ = "ai_risk_analyses"

    id = Column(Integer, primary_key=True, index=True)
    risk_id = Column(ForeignKey("risks.id", ondelete="CASCADE"), nullable=False)
    priority = Column(String, nullable=False)
    simple_explanation = Column(String(2000), nullable=False)
    why_it_matters = Column(String(2000), nullable=False)
    severity_explanation = Column(String(2000), nullable=False)
    risk_factors = Column(String(2000), nullable=True)             # JSON list
    potential_business_impact = Column(String(2000), nullable=True) # JSON list
    recommendation = Column(String(2000), nullable=True)            # JSON list
    remediation_steps = Column(String(3000), nullable=True)         # JSON dict (immediate, permanent, validation)
    recommended_controls = Column(String(2000), nullable=True)      # JSON list of dicts (name, reason)
    confidence = Column(Float, nullable=False)
    human_review_required = Column(Boolean, default=True)
    human_review_reasons = Column(String(1000), nullable=True)     # JSON list
    model_name = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    risk = relationship("Risk", back_populates="ai_analyses")


# ---------------------------------------------------------------------------
# Phase 6C: Human Review & Risk Sign-off
# ---------------------------------------------------------------------------

class RiskReview(Base):
    __tablename__ = "risk_reviews"
    __table_args__ = (
        Index(
            "uq_risk_reviews_one_current",
            "risk_id",
            unique=True,
            postgresql_where=text("is_current = true"),
            sqlite_where=text("is_current = 1"),
        ),
    )

    id = Column(Integer, primary_key=True, index=True)
    risk_id = Column(ForeignKey("risks.id", ondelete="CASCADE"), nullable=False, index=True)

    # Attributed human reviewer/operator (metadata headers, not IAM/auth)
    reviewer_name = Column(String(128), nullable=False, index=True)
    reviewer_role = Column(String(64), nullable=False)

    # Governance decision & agreed treatment
    decision = Column(String(32), nullable=False, index=True)        # APPROVED, REJECTED, CHANGES_REQUESTED
    agreed_treatment = Column(String(32), nullable=False)            # Mitigate, Accept, Transfer, Avoid
    comments = Column(Text, nullable=False)                          # Mandatory justification / rationale

    # AI Advisory Consideration Acknowledgement
    ai_analysis_acknowledged = Column(Boolean, default=False, nullable=False)
    ai_analysis_id = Column(ForeignKey("ai_risk_analyses.id", ondelete="SET NULL"), nullable=True)

    # Immutable Technical & GRC Baseline Snapshot at Time of Sign-off
    snapshot_inherent_score = Column(Integer, nullable=False)
    snapshot_inherent_level = Column(String(32), nullable=False)
    snapshot_residual_score = Column(Integer, nullable=False)
    snapshot_residual_level = Column(String(32), nullable=False)
    snapshot_asset_criticality = Column(String(32), nullable=True)
    snapshot_asset_exposure = Column(String(32), nullable=True)
    snapshot_cvss_score = Column(Float, nullable=True)               # Human-readable scalar CVSS
    snapshot_control_ids = Column(String(500), nullable=True)        # Sorted comma-separated control IDs: "1,4,7"
    snapshot_vulnerability_hash = Column(String(64), nullable=False, index=True)  # Authoritative SHA-256 over correlated vuln findings
    snapshot_hash = Column(String(64), nullable=False, index=True)   # SHA-256 over complete canonical snapshot

    # Versioning & Single-Active State
    is_current = Column(Boolean, default=True, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    risk = relationship("Risk", back_populates="reviews")
    ai_analysis = relationship("AIRiskAnalysis")



# ---------------------------------------------------------------------------
# Phase 5: Continuous Network Monitoring, Scan Automation & Asset Drift
# ---------------------------------------------------------------------------

class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id = Column(Integer, primary_key=True, index=True)
    target = Column(String(100), nullable=False)
    scan_type = Column(String(50), nullable=False)  # single_host, subnet_discovery, scheduled_sweep
    status = Column(String(30), default="Queued", nullable=False, index=True)  # Queued, Running, Completed, Failed, Cancelled
    progress_percent = Column(Integer, default=0, nullable=False)
    discovered_assets_count = Column(Integer, default=0)
    discovered_vulns_count = Column(Integer, default=0)
    error_message = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)

    drift_events = relationship("DriftEvent", back_populates="scan_job", cascade="all, delete-orphan")


class ScanSchedule(Base):
    __tablename__ = "scan_schedules"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    target = Column(String(100), nullable=False)
    interval_minutes = Column(Integer, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False, index=True)
    last_run_at = Column(DateTime, nullable=True)
    next_run_at = Column(DateTime, nullable=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )


class DriftEvent(Base):
    __tablename__ = "drift_events"

    id = Column(Integer, primary_key=True, index=True)
    scan_job_id = Column(ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id = Column(ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True)
    event_type = Column(String(50), nullable=False)  # NEW_ASSET, PORT_OPENED, PORT_CLOSED, CVE_DETECTED, FINDING_RESOLVED
    title = Column(String(200), nullable=False)
    description = Column(String(2000), nullable=True)
    severity = Column(String(30), default="Low", nullable=False)  # Low, Medium, High, Critical
    detected_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    scan_job = relationship("ScanJob", back_populates="drift_events")
    asset = relationship("Asset", backref="drift_events")


# ---------------------------------------------------------------------------
# Phase 6A: Governance, Evidence & Tamper-Evident Audit Trail
# ---------------------------------------------------------------------------

evidence_risks = Table(
    "evidence_risks",
    Base.metadata,
    Column("evidence_id", Integer, ForeignKey("evidence_records.id", ondelete="CASCADE"), primary_key=True),
    Column("risk_id", Integer, ForeignKey("risks.id", ondelete="CASCADE"), primary_key=True),
)

evidence_controls = Table(
    "evidence_controls",
    Base.metadata,
    Column("evidence_id", Integer, ForeignKey("evidence_records.id", ondelete="CASCADE"), primary_key=True),
    Column("control_id", Integer, ForeignKey("controls.id", ondelete="CASCADE"), primary_key=True),
)

evidence_requirements = Table(
    "evidence_requirements",
    Base.metadata,
    Column("evidence_id", Integer, ForeignKey("evidence_records.id", ondelete="CASCADE"), primary_key=True),
    Column("requirement_id", Integer, ForeignKey("compliance_requirements.id", ondelete="CASCADE"), primary_key=True),
)


class EvidenceRecord(Base):
    __tablename__ = "evidence_records"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(200), nullable=False)
    description = Column(String(2000), nullable=True)
    evidence_type = Column(String(50), nullable=False)  # SCAN_OUTPUT, CONFIG_EXPORT, POLICY_REF, MANUAL_OBSERVATION, AUDIT_EXPORT
    source_system = Column(String(100), default="AI-GRC Platform", nullable=False)
    collector = Column(String(100), default="Security Analyst", nullable=False)
    collected_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    content_text = Column(Text, nullable=True)          # Raw text snippet or observation (capped at 50 KB)
    reference_url = Column(String(500), nullable=True)  # Artifact path or URL reference
    checksum_sha256 = Column(String(64), nullable=True) # Tamper-evident SHA-256 hex digest

    asset_id = Column(ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True)
    scan_job_id = Column(ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True, index=True)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    asset = relationship("Asset", backref="evidence_records")
    scan_job = relationship("ScanJob", backref="evidence_records")
    risks = relationship("Risk", secondary=evidence_risks, backref="evidence_records")
    controls = relationship("Control", secondary=evidence_controls, backref="evidence_records")
    requirements = relationship("ComplianceRequirement", secondary=evidence_requirements, backref="evidence_records")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    source = Column(String(30), nullable=False, index=True)      # USER, SYSTEM, SCANNER, SCHEDULER, AI, API
    actor = Column(String(100), nullable=False, index=True)      # Attribution: username, service name, or role
    ip_address = Column(String(50), nullable=True)               # Client IP address or 127.0.0.1
    action = Column(String(50), nullable=False, index=True)      # CREATE, UPDATE, DELETE, STATUS_CHANGE, ASSIGN, DETACH, DISPATCH, COMPLETE, CANCEL, DRIFT_DETECTED, AI_ANALYSIS
    entity_type = Column(String(50), nullable=False, index=True) # Risk, Asset, Control, ComplianceRequirement, ScanJob, EvidenceRecord
    entity_id = Column(Integer, nullable=True, index=True)
    entity_name = Column(String(200), nullable=True)
    old_values = Column(Text, nullable=True)                     # JSON string
    new_values = Column(Text, nullable=True)                     # JSON string
    description = Column(String(1000), nullable=True)
    integrity_hash = Column(String(64), nullable=True, index=True)  # Deterministic SHA-256 over canonical immutable event fields
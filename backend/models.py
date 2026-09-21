from sqlalchemy import Column, Float, Integer, String, DateTime, ForeignKey, Table
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
    criticality = Column(String, default="Medium")      # Low, Medium, High, Critical
    environment = Column(String, default="Production")  # Production, Development, Testing
    exposure = Column(String, default="Internal")       # Internal, DMZ, External
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

    controls = relationship("Control", secondary=risk_controls, back_populates="risks")


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
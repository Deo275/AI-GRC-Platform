from sqlalchemy import Column, Float, Integer, String, DateTime, ForeignKey
from datetime import datetime

from database import Base


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

    treatment = Column(String, default="Mitigate")
    status = Column(String, default="Open")

    compliance_framework = Column(String, nullable=True)
    compliance_control = Column(String, nullable=True)
    recommendation = Column(String(1000), nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow
    )

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)

    asset_id = Column(
        ForeignKey("assets.id"),
        nullable=False
    )

    port = Column(Integer, nullable=True)

    service = Column(String, nullable=True)

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
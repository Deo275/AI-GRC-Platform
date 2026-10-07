from fastapi import FastAPI, Query, HTTPException, Path, Body, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from datetime import datetime, timedelta
from typing import Any, Optional, Dict, List, Tuple
import sys
import os
import ipaddress
import logging
import time
import threading
from dotenv import load_dotenv

logger = logging.getLogger("ai_grc.backend")

_backend_env = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
_should_override = not bool(os.environ.get("GEMINI_API_KEY", "").strip())
if os.path.isfile(_backend_env):
    load_dotenv(dotenv_path=_backend_env, override=_should_override)
else:
    load_dotenv(override=False)

try:
    from database import engine, Base, SessionLocal
    import models
except ImportError:
    from backend.database import engine, Base, SessionLocal
    import backend.models as models

sys.path.append(
    os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..")
    )
)

from scanner.nmap_scanner import scan_host, discover_hosts
from scanner.risk_engine import calculate_risk
from scanner.vulnerability_scanner import identify_vulnerabilities
from scanner.grc_engine import (
    criticality_to_impact,
    calculate_likelihood,
    calculate_inherent_risk,
    calculate_residual_risk,
    calculate_risk_level,
)
try:
    from ai import analyze_risk, get_latest_risk_analysis, AIProviderError
except ImportError:
    from backend.ai import analyze_risk, get_latest_risk_analysis, AIProviderError

try:
    from monitoring import (
        validate_target_network,
        ScanWorkerPool,
        MonitoringScheduler,
    )
except ImportError:
    from backend.monitoring import (
        validate_target_network,
        ScanWorkerPool,
        MonitoringScheduler,
    )

try:
    from governance import (
        log_audit_event,
        format_audit_log,
        create_evidence_record,
        format_evidence,
        delete_evidence_record,
        submit_risk_review,
        get_or_evaluate_risk_reviews,
        format_risk_review,
        evaluate_review_staleness,
    )
except ImportError:
    from backend.governance import (
        log_audit_event,
        format_audit_log,
        create_evidence_record,
        format_evidence,
        delete_evidence_record,
        submit_risk_review,
        get_or_evaluate_risk_reviews,
        format_risk_review,
        evaluate_review_staleness,
    )

try:
    from reporting import (
        generate_report,
        REPORT_GENERATORS,
    )
except ImportError:
    from backend.reporting import (
        generate_report,
        REPORT_GENERATORS,
    )



# ---------------------------------------------------------------------------
# Pydantic Schemas for Request Validation
# ---------------------------------------------------------------------------

class AssetUpdate(BaseModel):
    criticality: str | None = None
    environment: str | None = None
    exposure: str | None = None
    owner: str | None = None
    business_function: str | None = None


class RiskUpdate(BaseModel):
    treatment: str | None = None
    risk_owner: str | None = None
    due_date: datetime | None = None
    status: str | None = None


class ControlCreate(BaseModel):
    name: str
    description: str | None = None
    category: str | None = "Preventive"
    framework: str | None = "NIST CSF"
    effectiveness: str | None = "Medium"
    status: str | None = "Implemented"


class ControlUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    category: str | None = None
    framework: str | None = None
    effectiveness: str | None = None
    status: str | None = None


class RequirementUpdate(BaseModel):
    status: str | None = None
    notes: str | None = None


class MappingCreate(BaseModel):
    control_id: int
    requirement_id: int
    mapping_strength: str | None = "Direct"
    notes: str | None = None


# Phase 5: Monitoring Schemas
class ScanJobCreate(BaseModel):
    target: str
    scan_type: str = "subnet_discovery"


class ScanScheduleCreate(BaseModel):
    name: str
    target: str
    interval_minutes: int = 60


class ScanScheduleUpdate(BaseModel):
    name: str | None = None
    target: str | None = None
    interval_minutes: int | None = None
    is_active: bool | None = None


# Phase 6A: Evidence Schemas
class EvidenceCreate(BaseModel):
    title: str
    evidence_type: str
    description: str | None = None
    content_text: str | None = None
    reference_url: str | None = None
    source_system: str | None = "AI-GRC Platform"
    collector: str | None = None
    collected_at: datetime | None = None
    asset_id: int | None = None
    scan_job_id: int | None = None
    risk_ids: list[int] | None = None
    control_ids: list[int] | None = None
    requirement_ids: list[int] | None = None


class RiskReviewCreate(BaseModel):
    decision: str = Field(..., description="APPROVED, REJECTED, or CHANGES_REQUESTED")
    agreed_treatment: str = Field(..., description="Mitigate, Accept, Transfer, or Avoid")
    comments: str = Field(..., min_length=5, description="Mandatory justification comments")
    ai_analysis_acknowledged: bool = Field(False, description="Acknowledgement that AI advisory intelligence was reviewed")
    reviewer_name: Optional[str] = Field(None, description="Optional override; defaults to X-Operator-Name")
    reviewer_role: Optional[str] = Field(None, description="Optional override; defaults to X-Operator-Role")


def get_operator_identity(request: Request = None) -> tuple[str, str]:
    """Extract attributed human reviewer/operator metadata from request headers.

    DISCLAIMER: X-Operator-Name and X-Operator-Role provide attribution metadata only
    and do not constitute authentication or authorization.
    """
    if not request:
        return "Security Analyst", "Operator"
    actor = request.headers.get("X-Operator-Name", "Security Analyst").strip() or "Security Analyst"
    role = request.headers.get("X-Operator-Role", "Operator").strip() or "Operator"
    return actor, role



# ---------------------------------------------------------------------------
# Helper formatting functions
# ---------------------------------------------------------------------------

def format_asset(asset: models.Asset) -> dict:
    return {
        "id": asset.id,
        "ip_address": asset.ip_address,
        "hostname": asset.hostname,
        "mac_address": asset.mac_address,
        "operating_system": asset.operating_system,
        "open_ports": asset.open_ports,
        "status": asset.status,
        "risk_score": asset.risk_score,
        "risk_level": asset.risk_level,
        "last_seen": asset.last_seen,
        "criticality": asset.criticality or "Medium",
        "environment": asset.environment or "Production",
        "exposure": asset.exposure or "Internal",
        "owner": asset.owner,
        "business_function": asset.business_function,
    }


def format_risk(risk: models.Risk) -> dict:
    return {
        "id": risk.id,
        "asset_id": risk.asset_id,
        "title": risk.title,
        "description": risk.description,
        "likelihood": risk.likelihood,
        "impact": risk.impact,
        "risk_score": risk.risk_score,
        "risk_level": risk.risk_level,
        "likelihood_score": risk.likelihood_score,
        "impact_score": risk.impact_score,
        "inherent_risk_score": risk.inherent_risk_score,
        "inherent_risk_level": risk.inherent_risk_level,
        "residual_likelihood": risk.residual_likelihood,
        "residual_impact": risk.residual_impact,
        "residual_risk_score": risk.residual_risk_score,
        "residual_risk_level": risk.residual_risk_level,
        "treatment": risk.treatment,
        "status": risk.status,
        "review_status": getattr(risk, "review_status", "Pending Review"),
        "risk_owner": risk.risk_owner,
        "due_date": risk.due_date,
        "compliance_framework": risk.compliance_framework,
        "compliance_control": risk.compliance_control,
        "recommendation": risk.recommendation,
        "controls": [
            {
                "id": c.id,
                "name": c.name,
                "category": c.category,
                "framework": c.framework,
                "effectiveness": c.effectiveness,
                "status": c.status,
            }
            for c in risk.controls
        ],
        "created_at": risk.created_at,
        "updated_at": risk.updated_at,
    }


def format_control(control: models.Control) -> dict:
    return {
        "id": control.id,
        "name": control.name,
        "description": control.description,
        "category": control.category,
        "framework": control.framework,
        "effectiveness": control.effectiveness,
        "status": control.status,
        "risk_count": len(control.risks),
        "created_at": control.created_at,
        "updated_at": control.updated_at,
    }


def format_framework(fw: models.ComplianceFramework) -> dict:
    return {
        "id": fw.id,
        "name": fw.name,
        "version": fw.version,
        "description": fw.description,
        "requirement_count": len(fw.requirements),
        "created_at": fw.created_at,
    }


def format_requirement(req: models.ComplianceRequirement) -> dict:
    return {
        "id": req.id,
        "framework_id": req.framework_id,
        "framework_name": req.framework.name if req.framework else None,
        "framework_version": req.framework.version if req.framework else None,
        "requirement_id": req.requirement_id,
        "title": req.title,
        "description": req.description,
        "function": req.function,
        "category": req.category,
        "subcategory": req.subcategory,
        "status": req.status or "Not Assessed",
        "notes": req.notes,
        "mapped_controls": [
            {
                "id": m.control.id,
                "name": m.control.name,
                "category": m.control.category,
                "effectiveness": m.control.effectiveness,
                "status": m.control.status,
                "mapping_strength": m.mapping_strength,
                "notes": m.notes,
            }
            for m in req.control_mappings if m.control
        ],
        "created_at": req.created_at,
        "updated_at": req.updated_at,
    }


def format_mapping(m: models.ControlComplianceMapping) -> dict:
    return {
        "id": m.id,
        "control_id": m.control_id,
        "control_name": m.control.name if m.control else None,
        "requirement_id": m.requirement_id,
        "requirement_code": m.requirement.requirement_id if m.requirement else None,
        "requirement_title": m.requirement.title if m.requirement else None,
        "framework_name": m.requirement.framework.name if m.requirement and m.requirement.framework else None,
        "mapping_strength": m.mapping_strength,
        "notes": m.notes,
        "created_at": m.created_at,
    }


def format_scan_job(job: models.ScanJob) -> dict:
    return {
        "id": job.id,
        "target": job.target,
        "scan_type": job.scan_type,
        "status": job.status,
        "progress_percent": job.progress_percent,
        "discovered_assets_count": job.discovered_assets_count,
        "discovered_vulns_count": job.discovered_vulns_count,
        "error_message": job.error_message,
        "created_at": job.created_at,
        "started_at": job.started_at,
        "completed_at": job.completed_at,
    }


def format_scan_schedule(sched: models.ScanSchedule) -> dict:
    return {
        "id": sched.id,
        "name": sched.name,
        "target": sched.target,
        "interval_minutes": sched.interval_minutes,
        "is_active": sched.is_active,
        "last_run_at": sched.last_run_at,
        "next_run_at": sched.next_run_at,
        "created_at": sched.created_at,
        "updated_at": sched.updated_at,
    }


def format_drift_event(ev: models.DriftEvent) -> dict:
    return {
        "id": ev.id,
        "scan_job_id": ev.scan_job_id,
        "asset_id": ev.asset_id,
        "event_type": ev.event_type,
        "title": ev.title,
        "description": ev.description,
        "severity": ev.severity,
        "detected_at": ev.detected_at,
    }


def recalculate_asset_risks(asset: models.Asset):
    """Recalculate inherent and residual risk scores for all risks belonging to an asset."""
    impact = criticality_to_impact(asset.criticality)
    for risk in asset.risks:
        likelihood = calculate_likelihood(
            severity_str=risk.likelihood,
            exposure=asset.exposure,
            fallback_likelihood=risk.likelihood
        )
        inh = calculate_inherent_risk(likelihood, impact)
        res = calculate_residual_risk(likelihood, impact, risk.controls)

        risk.likelihood_score = inh["likelihood_score"]
        risk.impact_score = inh["impact_score"]
        risk.inherent_risk_score = inh["inherent_risk_score"]
        risk.inherent_risk_level = inh["inherent_risk_level"]
        risk.residual_likelihood = res["residual_likelihood"]
        risk.residual_impact = res["residual_impact"]
        risk.residual_risk_score = res["residual_risk_score"]
        risk.residual_risk_level = res["residual_risk_level"]
        risk.updated_at = datetime.utcnow()



app = FastAPI(title="AI-GRC Platform")

DEFAULT_CORS_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]

_raw_cors = os.getenv("CORS_ALLOWED_ORIGINS", "").strip()
if _raw_cors:
    parsed_origins = [o.strip() for o in _raw_cors.split(",") if o.strip()]
    # Safely reject wildcard if present when allow_credentials=True
    filtered_origins = [o for o in parsed_origins if o != "*"]
    cors_allowed_origins = filtered_origins if filtered_origins else DEFAULT_CORS_ORIGINS
else:
    cors_allowed_origins = DEFAULT_CORS_ORIGINS

CORS_ALLOWED_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_allowed_origins,
    allow_credentials=True,
    allow_methods=CORS_ALLOWED_METHODS,
    allow_headers=["*"],
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    # Conditional HSTS: Never emit during normal HTTP development;
    # only emit when ENABLE_HSTS is explicitly true AND the request is over HTTPS
    enable_hsts = os.getenv("ENABLE_HSTS", "false").strip().lower() in ("true", "1")
    if enable_hsts and request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    return response

Base.metadata.create_all(bind=engine)

# ---------------------------------------------------------------------------
# Phase 5: Continuous Monitoring Single-Process Worker Pool & Scheduler
# NOTE: Single FastAPI process architecture only. Multi-worker deployments
# (e.g. gunicorn -w 4) are not supported with this in-process scheduler.
# ---------------------------------------------------------------------------
scan_worker_pool = ScanWorkerPool(max_workers=3)
monitoring_scheduler = MonitoringScheduler(worker_pool=scan_worker_pool, poll_interval_seconds=30)


@app.on_event("startup")
def on_startup():
    monitoring_scheduler.start()


@app.on_event("shutdown")
def on_shutdown():
    monitoring_scheduler.stop()
    scan_worker_pool.shutdown(wait=False)


@app.get("/")
def home():
    return {
        "message": "AI-GRC Platform Backend is Running",
        "database": "Connected Successfully"
    }


@app.post("/scan")
def scan_network(
    target: str = Query("192.168.127.1")
    ):

    try:
        # Reuse existing target validation logic already used by the monitoring scanner
        validated_target = validate_target_network(target)
        ip = ipaddress.ip_address(validated_target)

        # Standalone scanner explicitly permits only private RFC 1918 internal targets.
        # Explicitly reject loopback (127.0.0.0/8) and link-local (169.254.0.0/16).
        if ip.is_loopback or ip in ipaddress.ip_network("127.0.0.0/8"):
            raise HTTPException(
                status_code=400,
                detail="Loopback addresses (127.0.0.0/8) are not permitted for scanning."
            )
        if ip.is_link_local or ip in ipaddress.ip_network("169.254.0.0/16"):
            raise HTTPException(
                status_code=400,
                detail="Link-local addresses (169.254.0.0/16) are not permitted for scanning."
            )
    except HTTPException:
        raise
    except ValueError as err:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid scan target: {str(err)}"
        )

    # Run Nmap scan
    try:
        result = scan_host(str(ip))
    except RuntimeError as err:
        logger.error(f"Nmap host scan failed for target {ip}: {err}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="Network scan execution failed to complete."
        )
    except Exception as err:
        logger.error(f"Unexpected scan error for target {ip}: {err}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="Network scan encountered an unexpected execution error."
        )

    # Calculate security risk
    risk_result = calculate_risk(
        result["open_ports"]
    )

    vulnerability_result = identify_vulnerabilities(
        result["open_ports"]
    )

    # Convert ports into a readable string
    port_data = ", ".join(
        f"{item['port']}/{item['service']}"
        for item in result["open_ports"]
    )

    # Connect to PostgreSQL
    db = SessionLocal()

    try:

        # Check whether this IP already exists
        asset = db.query(models.Asset).filter(
            models.Asset.ip_address == target
        ).first()

        if asset:

            # Update existing asset
            asset.hostname = result["hostname"]
            asset.mac_address = result["mac_address"]
            asset.operating_system = result["operating_system"]
            asset.open_ports = port_data
            asset.status = "Active"
            asset.risk_score = risk_result["risk_score"]
            asset.risk_level = risk_result["risk_level"]
            asset.last_seen = models.datetime.utcnow()

        else:

            # Create new asset
            asset = models.Asset(
                ip_address=target,
                hostname=result["hostname"],
                mac_address=result["mac_address"],
                operating_system=result["operating_system"],
                open_ports=port_data,
                status="Active",
                risk_score=risk_result["risk_score"],
                risk_level=risk_result["risk_level"],
                criticality="Medium",
                environment="Production",
                exposure="Internal",
                owner=None,
                business_function=None
            )

            db.add(asset)
            db.flush()

        # ------------------------------------------------
        # CREATE / UPDATE GRC RISK REGISTER ENTRIES
        # ------------------------------------------------

        current_finding_titles = set(risk_result["findings"])

        for finding in risk_result["findings"]:

            # Default risk rating
            likelihood = "High"
            impact = "High"
            risk_score = 9
            risk_level = "Critical"

            # -----------------------------------------
            # COMPLIANCE MAPPING
            # -----------------------------------------

            compliance_framework = "NIST CSF"

            if "SMB" in finding:
                compliance_control = "PR.AC-4"
                recommendation = (
                    "Restrict unauthorized network access "
                    "and secure SMB services."
                )

            elif "NetBIOS" in finding:
                compliance_control = "PR.AC-4"
                recommendation = (
                    "Disable unnecessary NetBIOS services "
                    "and restrict network exposure."
                )

            elif "RPC" in finding:
                compliance_control = "PR.AC-4"
                recommendation = (
                    "Restrict Microsoft RPC access using "
                    "firewall rules and network segmentation."
                )

            elif "PostgreSQL" in finding:
                compliance_control = "PR.AC-4"
                recommendation = (
                    "Restrict database access to authorized "
                    "hosts and networks."
                )

            elif "VMware" in finding:
                compliance_control = "PR.AC-4"
                recommendation = (
                    "Restrict VMware management services "
                    "to authorized systems."
                )

            else:
                compliance_control = "PR.IP-1"
                recommendation = (
                    "Review the exposed service and apply "
                    "appropriate security controls."
                )

            # Check if this risk already exists for this asset
            existing_risk = db.query(models.Risk).filter(
                models.Risk.asset_id == asset.id,
                models.Risk.title == finding
            ).first()

            # Correlate with vulnerability findings for CVSS/severity
            matched_vuln = None
            for v in vulnerability_result:
                v_title = v.get("title", "").lower()
                if v_title and (v_title in finding.lower() or any(w.lower() in v_title for w in finding.split()[:2])):
                    matched_vuln = v
                    break

            cvss_val = matched_vuln.get("cvss_score") if matched_vuln else None
            sev_val = matched_vuln.get("severity") if matched_vuln else None

            impact_score = criticality_to_impact(asset.criticality)
            likelihood_score = calculate_likelihood(
                severity_str=sev_val,
                cvss_score=cvss_val,
                exposure=asset.exposure,
                fallback_likelihood=likelihood
            )

            inh = calculate_inherent_risk(likelihood_score, impact_score)
            controls = existing_risk.controls if existing_risk else []
            res = calculate_residual_risk(likelihood_score, impact_score, controls)

            if existing_risk:
                # Update scanner-derived fields
                existing_risk.likelihood = likelihood
                existing_risk.impact = impact
                existing_risk.risk_score = risk_score
                existing_risk.risk_level = risk_level

                existing_risk.likelihood_score = inh["likelihood_score"]
                existing_risk.impact_score = inh["impact_score"]
                existing_risk.inherent_risk_score = inh["inherent_risk_score"]
                existing_risk.inherent_risk_level = inh["inherent_risk_level"]

                existing_risk.residual_likelihood = res["residual_likelihood"]
                existing_risk.residual_impact = res["residual_impact"]
                existing_risk.residual_risk_score = res["residual_risk_score"]
                existing_risk.residual_risk_level = res["residual_risk_level"]

                existing_risk.compliance_framework = compliance_framework
                existing_risk.compliance_control = compliance_control
                existing_risk.recommendation = recommendation
                existing_risk.updated_at = models.datetime.utcnow()

                # If a previously Resolved risk reappears: reopen it
                if existing_risk.status == "Resolved":
                    existing_risk.status = "Open"

                # treatment, risk_owner, due_date and non-Resolved status are preserved
            else:
                # Create risk record
                risk = models.Risk(
                    asset_id=asset.id,
                    title=finding,
                    description=f"Security finding detected on asset {target}.",
                    likelihood=likelihood,
                    impact=impact,
                    risk_score=risk_score,
                    risk_level=risk_level,
                    likelihood_score=inh["likelihood_score"],
                    impact_score=inh["impact_score"],
                    inherent_risk_score=inh["inherent_risk_score"],
                    inherent_risk_level=inh["inherent_risk_level"],
                    residual_likelihood=res["residual_likelihood"],
                    residual_impact=res["residual_impact"],
                    residual_risk_score=res["residual_risk_score"],
                    residual_risk_level=res["residual_risk_level"],
                    treatment="Mitigate",
                    status="Open",
                    risk_owner=None,
                    due_date=None,
                    compliance_framework=compliance_framework,
                    compliance_control=compliance_control,
                    recommendation=recommendation,
                    created_at=models.datetime.utcnow(),
                    updated_at=models.datetime.utcnow()
                )

                db.add(risk)

        # Mark absent risks for this asset as Resolved
        existing_asset_risks = db.query(models.Risk).filter(
            models.Risk.asset_id == asset.id
        ).all()

        for r in existing_asset_risks:
            if r.title not in current_finding_titles and r.status != "Resolved":
                r.status = "Resolved"
                r.updated_at = models.datetime.utcnow()

        # ------------------------------------------------
        # SAVE / UPDATE VULNERABILITIES & LIFECYCLE
        # ------------------------------------------------
        current_vuln_keys = set()

        for vulnerability in vulnerability_result:
            vuln_port = vulnerability.get("port")
            vuln_title = vulnerability.get("title")
            current_vuln_keys.add((vuln_port, vuln_title))

            existing_vulnerability = db.query(
                models.Vulnerability
            ).filter(
                models.Vulnerability.asset_id == asset.id,
                models.Vulnerability.port == vuln_port,
                models.Vulnerability.title == vuln_title
            ).first()

            if existing_vulnerability:
                # Update existing vulnerability
                existing_vulnerability.service = (
                    vulnerability.get("service")
                )
                existing_vulnerability.product = (
                    vulnerability.get("product")
                )
                existing_vulnerability.version = (
                    vulnerability.get("version")
                )
                existing_vulnerability.severity = (
                    vulnerability.get("severity")
                )
                existing_vulnerability.description = (
                    vulnerability.get("description")
                )
                existing_vulnerability.cve = (
                    vulnerability.get("cve")
                )
                existing_vulnerability.cvss_score = (
                    vulnerability.get("cvss_score")
                )
                existing_vulnerability.cvss_version = (
                    vulnerability.get("cvss_version")
                )
                existing_vulnerability.cve_confidence = (
                    vulnerability.get("cve_confidence")
                )
                existing_vulnerability.cve_candidate_count = (
                    vulnerability.get("cve_candidate_count", 0)
                )
                existing_vulnerability.status = "Open"
                existing_vulnerability.updated_at = models.datetime.utcnow()

            else:
                vulnerability_record = models.Vulnerability(
                    asset_id=asset.id,
                    port=vuln_port,
                    service=vulnerability.get("service"),
                    product=vulnerability.get("product"),
                    version=vulnerability.get("version"),
                    title=vuln_title,
                    severity=vulnerability.get("severity"),
                    description=vulnerability.get("description"),
                    cve=vulnerability.get("cve"),
                    cvss_score=vulnerability.get("cvss_score"),
                    cvss_version=vulnerability.get("cvss_version"),
                    cve_confidence=vulnerability.get("cve_confidence"),
                    cve_candidate_count=vulnerability.get("cve_candidate_count", 0),
                    status="Open",
                    discovered_at=models.datetime.utcnow(),
                    updated_at=models.datetime.utcnow()
                )

                db.add(vulnerability_record)

        # Mark absent vulnerabilities for this asset as Resolved
        existing_asset_vulns = db.query(models.Vulnerability).filter(
            models.Vulnerability.asset_id == asset.id
        ).all()

        for v in existing_asset_vulns:
            if (v.port, v.title) not in current_vuln_keys and v.status != "Resolved":
                v.status = "Resolved"
                v.updated_at = models.datetime.utcnow()

        # Save everything once
        db.commit()
        db.refresh(asset)

        # Get risks belonging to this asset
        risks = db.query(models.Risk).filter(
            models.Risk.asset_id == asset.id
        ).all()

        return {
            "message": "Network scan completed and GRC risks registered",
            "asset_id": asset.id,
            "ip_address": asset.ip_address,
            "open_ports": asset.open_ports,
            "risk_score": asset.risk_score,
            "risk_level": asset.risk_level,
            "findings": risk_result["findings"],
            "vulnerabilities": vulnerability_result,
            "risk_register_count": len(risks)
        }

    finally:
        db.close()

# ------------------------------------------------
# DISCOVER NETWORK ASSETS
# ------------------------------------------------

@app.post("/discover")
def discover_network(
    network: str = Query("192.168.127.0/24")
):

    if not isinstance(network, str) or "/" not in network:
        raise HTTPException(
            status_code=400,
            detail="Invalid CIDR format. Subnet mask prefix required (e.g. 192.168.127.0/24)."
        )

    try:
        net = ipaddress.ip_network(network, strict=False)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Invalid network CIDR notation."
        )

    if net.version != 4:
        raise HTTPException(
            status_code=400,
            detail="Only IPv4 networks are supported for discovery."
        )

    if not net.is_private:
        raise HTTPException(
            status_code=400,
            detail="Discovery is only permitted on private networks (RFC 1918)."
        )

    if net.prefixlen < 24:
        raise HTTPException(
            status_code=400,
            detail="Network size too large. Maximum allowed size is /24."
        )

    # Discover active hosts
    try:
        hosts = discover_hosts(network)
    except RuntimeError as err:
        logger.error(f"Host discovery failed for network {network}: {err}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="Network host discovery failed to complete."
        )

    db = SessionLocal()

    discovered_assets = []

    try:

        for host in hosts:

            # Run detailed scan
            try:
                result = scan_host(host)
            except RuntimeError:
                continue

            # Calculate risk
            risk_result = calculate_risk(
                result["open_ports"]
            )

            # Convert ports into readable string
            port_data = ", ".join(
                f'{item["port"]}/{item["service"]}'
                for item in result["open_ports"]
            )

            # Check if asset already exists
            asset = db.query(models.Asset).filter(
                models.Asset.ip_address == host
            ).first()

            if asset:

                # Update existing asset
                asset.hostname = result["hostname"]
                asset.mac_address = result["mac_address"]
                asset.operating_system = result["operating_system"]
                asset.open_ports = port_data
                asset.status = "Active"
                asset.risk_score = risk_result["risk_score"]
                asset.risk_level = risk_result["risk_level"]
                asset.last_seen = models.datetime.utcnow()

            else:

                # Create new asset
                asset = models.Asset(
                    ip_address=host,
                    hostname=result["hostname"],
                    mac_address=result["mac_address"],
                    operating_system=result["operating_system"],
                    open_ports=port_data,
                    status="Active",
                    risk_score=risk_result["risk_score"],
                    risk_level=risk_result["risk_level"],
                    criticality="Medium",
                    environment="Production",
                    exposure="Internal",
                    owner=None,
                    business_function=None
                )

                db.add(asset)

            discovered_assets.append({
                "ip_address": host,
                "hostname": result["hostname"],
                "mac_address": result["mac_address"],
                "operating_system": result["operating_system"],
                "open_ports": port_data,
                "risk_score": risk_result["risk_score"],
                "risk_level": risk_result["risk_level"],
                "criticality": asset.criticality or "Medium",
                "environment": asset.environment or "Production",
                "exposure": asset.exposure or "Internal",
                "owner": asset.owner,
                "business_function": asset.business_function,
            })

        # Save all discovered assets
        db.commit()

        return {
            "message": "Network discovery completed",
            "network": network,
            "hosts_found": len(discovered_assets),
            "assets": discovered_assets
        }

    finally:
        db.close()


# ---------------------------------------------------------------------------
# ASSET INVENTORY & ASSET INTELLIGENCE ENDPOINTS
# ---------------------------------------------------------------------------

@app.get("/assets")
def get_assets():
    db = SessionLocal()
    try:
        assets = db.query(models.Asset).order_by(models.Asset.id).all()
        return {
            "count": len(assets),
            "assets": [format_asset(asset) for asset in assets]
        }
    finally:
        db.close()


@app.get("/assets/{asset_id}")
def get_asset(asset_id: int = Path(..., description="The ID of the asset")):
    db = SessionLocal()
    try:
        asset = db.query(models.Asset).filter(models.Asset.id == asset_id).first()
        if not asset:
            raise HTTPException(status_code=404, detail=f"Asset with ID {asset_id} not found")
        return format_asset(asset)
    finally:
        db.close()


@app.patch("/assets/{asset_id}")
def update_asset(
    asset_id: int = Path(..., description="The ID of the asset"),
    payload: AssetUpdate = Body(...),
    request: Request = None,
):
    db = SessionLocal()
    try:
        asset = db.query(models.Asset).filter(models.Asset.id == asset_id).first()
        if not asset:
            raise HTTPException(status_code=404, detail=f"Asset with ID {asset_id} not found")

        old_state = {
            "criticality": asset.criticality,
            "environment": asset.environment,
            "exposure": asset.exposure,
            "owner": asset.owner,
            "business_function": asset.business_function,
        }

        criticality_changed = False
        exposure_changed = False

        if payload.criticality is not None:
            valid_criticalities = {"low": "Low", "medium": "Medium", "high": "High", "critical": "Critical"}
            norm_crit = valid_criticalities.get(payload.criticality.strip().lower())
            if not norm_crit:
                raise HTTPException(status_code=400, detail="Invalid criticality. Allowed values: Low, Medium, High, Critical")
            if asset.criticality != norm_crit:
                asset.criticality = norm_crit
                criticality_changed = True

        if payload.environment is not None:
            valid_envs = {"production": "Production", "development": "Development", "testing": "Testing"}
            norm_env = valid_envs.get(payload.environment.strip().lower())
            if not norm_env:
                raise HTTPException(status_code=400, detail="Invalid environment. Allowed values: Production, Development, Testing")
            asset.environment = norm_env

        if payload.exposure is not None:
            valid_exposures = {"internal": "Internal", "dmz": "DMZ", "external": "External"}
            norm_exp = valid_exposures.get(payload.exposure.strip().lower())
            if not norm_exp:
                raise HTTPException(status_code=400, detail="Invalid exposure. Allowed values: Internal, DMZ, External")
            if asset.exposure != norm_exp:
                asset.exposure = norm_exp
                exposure_changed = True

        if payload.owner is not None:
            asset.owner = payload.owner.strip() if payload.owner.strip() else None

        if payload.business_function is not None:
            asset.business_function = payload.business_function.strip() if payload.business_function.strip() else None

        # When criticality or exposure changes, recalculate risk ratings for all associated risks
        if criticality_changed or exposure_changed:
            recalculate_asset_risks(asset)

        db.commit()
        db.refresh(asset)

        actor, _ = get_operator_identity(request)
        log_audit_event(
            db=db,
            source="USER",
            actor=actor,
            action="UPDATE",
            entity_type="Asset",
            entity_id=asset.id,
            entity_name=asset.ip_address,
            old_values=old_state,
            new_values={
                "criticality": asset.criticality,
                "environment": asset.environment,
                "exposure": asset.exposure,
                "owner": asset.owner,
                "business_function": asset.business_function,
            },
            description=f"Updated asset {asset.ip_address} intelligence metadata",
            ip_address=request.client.host if request and request.client else None,
            commit=True,
        )

        return {
            "message": "Asset metadata updated successfully",
            "asset": format_asset(asset)
        }
    finally:
        db.close()


# ---------------------------------------------------------------------------
# RISK REGISTER ENDPOINTS
# ---------------------------------------------------------------------------

@app.get("/risks")
def get_risks():
    db = SessionLocal()
    try:
        risks = db.query(models.Risk).order_by(models.Risk.id).all()
        return {
            "count": len(risks),
            "risks": [format_risk(risk) for risk in risks]
        }
    finally:
        db.close()


@app.get("/risks/{risk_id}")
def get_risk(risk_id: int = Path(..., description="The ID of the risk")):
    db = SessionLocal()
    try:
        risk = db.query(models.Risk).filter(models.Risk.id == risk_id).first()
        if not risk:
            raise HTTPException(status_code=404, detail=f"Risk with ID {risk_id} not found")
        return format_risk(risk)
    finally:
        db.close()


@app.patch("/risks/{risk_id}")
def update_risk(
    risk_id: int = Path(..., description="The ID of the risk"),
    payload: RiskUpdate = Body(...),
    request: Request = None,
):
    db = SessionLocal()
    try:
        risk = db.query(models.Risk).filter(models.Risk.id == risk_id).first()
        if not risk:
            raise HTTPException(status_code=404, detail=f"Risk with ID {risk_id} not found")

        old_state = {
            "treatment": risk.treatment,
            "status": risk.status,
            "risk_owner": risk.risk_owner,
            "due_date": risk.due_date.isoformat() if risk.due_date else None,
        }

        if payload.treatment is not None:
            valid_treatments = {"mitigate": "Mitigate", "accept": "Accept", "transfer": "Transfer", "avoid": "Avoid"}
            norm_treat = valid_treatments.get(payload.treatment.strip().lower())
            if not norm_treat:
                raise HTTPException(status_code=400, detail="Invalid treatment. Allowed values: Mitigate, Accept, Transfer, Avoid")
            risk.treatment = norm_treat

        if payload.status is not None:
            valid_statuses = {"open": "Open", "resolved": "Resolved", "accepted": "Accepted", "under review": "Under Review"}
            norm_stat = valid_statuses.get(payload.status.strip().lower())
            if not norm_stat:
                raise HTTPException(status_code=400, detail="Invalid status. Allowed values: Open, Resolved, Accepted, Under Review")
            risk.status = norm_stat

        if payload.risk_owner is not None:
            risk.risk_owner = payload.risk_owner.strip() if payload.risk_owner.strip() else None

        if payload.due_date is not None:
            risk.due_date = payload.due_date

        risk.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(risk)

        actor, _ = get_operator_identity(request)
        log_audit_event(
            db=db,
            source="USER",
            actor=actor,
            action="UPDATE",
            entity_type="Risk",
            entity_id=risk.id,
            entity_name=risk.title,
            old_values=old_state,
            new_values={
                "treatment": risk.treatment,
                "status": risk.status,
                "risk_owner": risk.risk_owner,
                "due_date": risk.due_date.isoformat() if risk.due_date else None,
            },
            description=f"Updated risk #{risk.id} '{risk.title}' management attributes",
            ip_address=request.client.host if request and request.client else None,
            commit=True,
        )

        return {
            "message": "Risk management fields updated successfully",
            "risk": format_risk(risk)
        }
    finally:
        db.close()


# ---------------------------------------------------------------------------
# SECURITY CONTROLS ENDPOINTS
# ---------------------------------------------------------------------------

@app.get("/controls")
def get_controls():
    db = SessionLocal()
    try:
        controls = db.query(models.Control).order_by(models.Control.id).all()
        return {
            "count": len(controls),
            "controls": [format_control(c) for c in controls]
        }
    finally:
        db.close()


@app.post("/controls")
def create_control(
    payload: ControlCreate = Body(...),
    request: Request = None,
):
    db = SessionLocal()
    try:
        existing = db.query(models.Control).filter(models.Control.name.ilike(payload.name.strip())).first()
        if existing:
            raise HTTPException(status_code=400, detail=f"Control with name '{payload.name}' already exists")

        valid_eff = {"low": "Low", "medium": "Medium", "high": "High"}
        eff = valid_eff.get((payload.effectiveness or "Medium").strip().lower(), "Medium")

        valid_stat = {"implemented": "Implemented", "planned": "Planned", "under review": "Under Review"}
        stat = valid_stat.get((payload.status or "Implemented").strip().lower(), "Implemented")

        control = models.Control(
            name=payload.name.strip(),
            description=payload.description.strip() if payload.description else None,
            category=payload.category.strip() if payload.category else "Preventive",
            framework=payload.framework.strip() if payload.framework else "NIST CSF",
            effectiveness=eff,
            status=stat,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        db.add(control)
        db.commit()
        db.refresh(control)

        actor, _ = get_operator_identity(request)
        log_audit_event(
            db=db,
            source="USER",
            actor=actor,
            action="CREATE",
            entity_type="Control",
            entity_id=control.id,
            entity_name=control.name,
            new_values=format_control(control),
            description=f"Created security control '{control.name}'",
            ip_address=request.client.host if request and request.client else None,
            commit=True,
        )

        return {
            "message": "Control created successfully",
            "control": format_control(control)
        }
    finally:
        db.close()


@app.get("/controls/{control_id}")
def get_control(control_id: int = Path(..., description="The ID of the control")):
    db = SessionLocal()
    try:
        control = db.query(models.Control).filter(models.Control.id == control_id).first()
        if not control:
            raise HTTPException(status_code=404, detail=f"Control with ID {control_id} not found")
        return format_control(control)
    finally:
        db.close()


@app.patch("/controls/{control_id}")
def update_control(
    control_id: int = Path(..., description="The ID of the control"),
    payload: ControlUpdate = Body(...),
    request: Request = None,
):
    db = SessionLocal()
    try:
        control = db.query(models.Control).filter(models.Control.id == control_id).first()
        if not control:
            raise HTTPException(status_code=404, detail=f"Control with ID {control_id} not found")

        old_state = format_control(control)
        eff_changed = False
        if payload.name is not None:
            control.name = payload.name.strip()
        if payload.description is not None:
            control.description = payload.description.strip() if payload.description else None
        if payload.category is not None:
            control.category = payload.category.strip()
        if payload.framework is not None:
            control.framework = payload.framework.strip()

        if payload.effectiveness is not None:
            valid_eff = {"low": "Low", "medium": "Medium", "high": "High"}
            norm_eff = valid_eff.get(payload.effectiveness.strip().lower())
            if not norm_eff:
                raise HTTPException(status_code=400, detail="Invalid effectiveness. Allowed: Low, Medium, High")
            if control.effectiveness != norm_eff:
                control.effectiveness = norm_eff
                eff_changed = True

        if payload.status is not None:
            valid_stat = {"implemented": "Implemented", "planned": "Planned", "under review": "Under Review"}
            norm_stat = valid_stat.get(payload.status.strip().lower())
            if not norm_stat:
                raise HTTPException(status_code=400, detail="Invalid status. Allowed: Implemented, Planned, Under Review")
            if control.status != norm_stat:
                control.status = norm_stat
                eff_changed = True

        control.updated_at = datetime.utcnow()

        # If effectiveness or status changed, recompute residual risk for all associated risks
        if eff_changed:
            for r in control.risks:
                res = calculate_residual_risk(r.likelihood_score, r.impact_score, r.controls)
                r.residual_likelihood = res["residual_likelihood"]
                r.residual_impact = res["residual_impact"]
                r.residual_risk_score = res["residual_risk_score"]
                r.residual_risk_level = res["residual_risk_level"]
                r.updated_at = datetime.utcnow()

        db.commit()
        db.refresh(control)

        actor, _ = get_operator_identity(request)
        log_audit_event(
            db=db,
            source="USER",
            actor=actor,
            action="UPDATE",
            entity_type="Control",
            entity_id=control.id,
            entity_name=control.name,
            old_values=old_state,
            new_values=format_control(control),
            description=f"Updated security control '{control.name}'",
            ip_address=request.client.host if request and request.client else None,
            commit=True,
        )

        return {
            "message": "Control updated successfully",
            "control": format_control(control)
        }
    finally:
        db.close()


@app.delete("/controls/{control_id}")
def delete_control(
    control_id: int = Path(..., description="The ID of the control"),
    request: Request = None,
):
    db = SessionLocal()
    try:
        control = db.query(models.Control).filter(models.Control.id == control_id).first()
        if not control:
            raise HTTPException(status_code=404, detail=f"Control with ID {control_id} not found")

        old_state = format_control(control)
        control_name = control.name
        affected_risks = list(control.risks)
        db.delete(control)
        db.commit()

        # Recalculate residual risks for previously associated risks
        for r in affected_risks:
            db.refresh(r)
            res = calculate_residual_risk(r.likelihood_score, r.impact_score, r.controls)
            r.residual_likelihood = res["residual_likelihood"]
            r.residual_impact = res["residual_impact"]
            r.residual_risk_score = res["residual_risk_score"]
            r.residual_risk_level = res["residual_risk_level"]
            r.updated_at = datetime.utcnow()

        db.commit()

        actor, _ = get_operator_identity(request)
        log_audit_event(
            db=db,
            source="USER",
            actor=actor,
            action="DELETE",
            entity_type="Control",
            entity_id=control_id,
            entity_name=control_name,
            old_values=old_state,
            description=f"Deleted security control '{control_name}'",
            ip_address=request.client.host if request and request.client else None,
            commit=True,
        )

        return {"message": f"Control {control_id} deleted successfully"}
    finally:
        db.close()


@app.post("/risks/{risk_id}/controls/{control_id}")
def assign_control_to_risk(
    risk_id: int = Path(..., description="The ID of the risk"),
    control_id: int = Path(..., description="The ID of the control"),
    request: Request = None,
):
    db = SessionLocal()
    try:
        risk = db.query(models.Risk).filter(models.Risk.id == risk_id).first()
        if not risk:
            raise HTTPException(status_code=404, detail=f"Risk with ID {risk_id} not found")
        control = db.query(models.Control).filter(models.Control.id == control_id).first()
        if not control:
            raise HTTPException(status_code=404, detail=f"Control with ID {control_id} not found")

        if control not in risk.controls:
            risk.controls.append(control)

        # Recalculate residual risk
        res = calculate_residual_risk(risk.likelihood_score, risk.impact_score, risk.controls)
        risk.residual_likelihood = res["residual_likelihood"]
        risk.residual_impact = res["residual_impact"]
        risk.residual_risk_score = res["residual_risk_score"]
        risk.residual_risk_level = res["residual_risk_level"]
        risk.updated_at = datetime.utcnow()

        db.commit()
        db.refresh(risk)

        actor, _ = get_operator_identity(request)
        log_audit_event(
            db=db,
            source="USER",
            actor=actor,
            action="ASSIGN",
            entity_type="Risk",
            entity_id=risk.id,
            entity_name=risk.title,
            new_values={
                "assigned_control_id": control.id,
                "control_name": control.name,
                "residual_risk_score": risk.residual_risk_score,
                "residual_risk_level": risk.residual_risk_level,
            },
            description=f"Assigned control '{control.name}' to risk #{risk.id}",
            ip_address=request.client.host if request and request.client else None,
            commit=True,
        )

        return {
            "message": f"Control '{control.name}' assigned to risk {risk_id}",
            "risk": format_risk(risk)
        }
    finally:
        db.close()


@app.delete("/risks/{risk_id}/controls/{control_id}")
def detach_control_from_risk(
    risk_id: int = Path(..., description="The ID of the risk"),
    control_id: int = Path(..., description="The ID of the control"),
    request: Request = None,
):
    db = SessionLocal()
    try:
        risk = db.query(models.Risk).filter(models.Risk.id == risk_id).first()
        if not risk:
            raise HTTPException(status_code=404, detail=f"Risk with ID {risk_id} not found")
        control = db.query(models.Control).filter(models.Control.id == control_id).first()
        if not control:
            raise HTTPException(status_code=404, detail=f"Control with ID {control_id} not found")

        if control in risk.controls:
            risk.controls.remove(control)

        # Recalculate residual risk
        res = calculate_residual_risk(risk.likelihood_score, risk.impact_score, risk.controls)
        risk.residual_likelihood = res["residual_likelihood"]
        risk.residual_impact = res["residual_impact"]
        risk.residual_risk_score = res["residual_risk_score"]
        risk.residual_risk_level = res["residual_risk_level"]
        risk.updated_at = datetime.utcnow()

        db.commit()
        db.refresh(risk)

        actor, _ = get_operator_identity(request)
        log_audit_event(
            db=db,
            source="USER",
            actor=actor,
            action="DETACH",
            entity_type="Risk",
            entity_id=risk.id,
            entity_name=risk.title,
            old_values={
                "detached_control_id": control.id,
                "control_name": control.name,
                "residual_risk_score": risk.residual_risk_score,
                "residual_risk_level": risk.residual_risk_level,
            },
            description=f"Detached control '{control.name}' from risk #{risk.id}",
            ip_address=request.client.host if request and request.client else None,
            commit=True,
        )

        return {
            "message": f"Control '{control.name}' detached from risk {risk_id}",
            "risk": format_risk(risk)
        }
    finally:
        db.close()


# ---------------------------------------------------------------------------
# GET VULNERABILITY FINDINGS
# ---------------------------------------------------------------------------

@app.get("/vulnerabilities")
def get_vulnerabilities():
    db = SessionLocal()

    try:
        vulnerabilities = db.query(
            models.Vulnerability
        ).order_by(
            models.Vulnerability.id
        ).all()

        return {
            "count": len(vulnerabilities),
            "vulnerabilities": [
                {
                    "id": vulnerability.id,
                    "asset_id": vulnerability.asset_id,
                    "port": vulnerability.port,
                    "service": vulnerability.service,
                    "product": vulnerability.product,
                    "version": vulnerability.version,
                    "title": vulnerability.title,
                    "severity": vulnerability.severity,
                    "description": vulnerability.description,
                    "cve": vulnerability.cve,
                    "cvss_score": vulnerability.cvss_score,
                    "cvss_version": vulnerability.cvss_version,
                    "cve_confidence": vulnerability.cve_confidence,
                    "cve_candidate_count": vulnerability.cve_candidate_count,
                    "status": vulnerability.status,
                    "discovered_at": vulnerability.discovered_at,
                    "updated_at": vulnerability.updated_at
                }
                for vulnerability in vulnerabilities
            ]
        }

    finally:
        db.close()


# ---------------------------------------------------------------------------
# PHASE 3: COMPLIANCE FRAMEWORKS, REQUIREMENTS & MAPPINGS ENDPOINTS
# ---------------------------------------------------------------------------

@app.get("/compliance/frameworks")
def get_compliance_frameworks():
    """Retrieve all supported compliance frameworks."""
    db = SessionLocal()
    try:
        frameworks = db.query(models.ComplianceFramework).order_by(models.ComplianceFramework.id).all()
        return {
            "count": len(frameworks),
            "frameworks": [format_framework(fw) for fw in frameworks]
        }
    finally:
        db.close()


@app.get("/compliance/requirements")
def get_compliance_requirements(
    framework: str | None = Query(None, description="Filter by framework name (e.g. 'NIST CSF', 'ISO/IEC 27001') or ID"),
    status: str | None = Query(None, description="Filter by assessment status"),
    function: str | None = Query(None, description="Filter by function/theme (e.g. 'Protect', 'Technological')"),
    category: str | None = Query(None, description="Filter by category")
):
    """Retrieve compliance requirements with optional filtering by framework, status, function, or category."""
    db = SessionLocal()
    try:
        query = db.query(models.ComplianceRequirement)

        if framework:
            if framework.strip().isdigit():
                query = query.filter(models.ComplianceRequirement.framework_id == int(framework.strip()))
            else:
                query = query.join(models.ComplianceFramework).filter(
                    models.ComplianceFramework.name.ilike(f"%{framework.strip()}%")
                )

        if status:
            query = query.filter(models.ComplianceRequirement.status.ilike(status.strip()))

        if function:
            query = query.filter(models.ComplianceRequirement.function.ilike(f"%{function.strip()}%"))

        if category:
            query = query.filter(models.ComplianceRequirement.category.ilike(f"%{category.strip()}%"))

        requirements = query.order_by(models.ComplianceRequirement.id).all()
        return {
            "count": len(requirements),
            "requirements": [format_requirement(r) for r in requirements]
        }
    finally:
        db.close()


@app.get("/compliance/mappings")
def get_compliance_mappings():
    """Retrieve all control-to-compliance requirement mappings."""
    db = SessionLocal()
    try:
        mappings = db.query(models.ControlComplianceMapping).order_by(models.ControlComplianceMapping.id).all()
        return {
            "count": len(mappings),
            "mappings": [format_mapping(m) for m in mappings]
        }
    finally:
        db.close()


@app.get("/compliance/summary")
def get_compliance_summary():
    """Calculate implementation coverage metrics per compliance framework."""
    db = SessionLocal()
    try:
        frameworks = db.query(models.ComplianceFramework).order_by(models.ComplianceFramework.id).all()
        summary = []

        for fw in frameworks:
            total = len(fw.requirements)
            implemented = sum(1 for r in fw.requirements if r.status == "Implemented")
            partially_implemented = sum(1 for r in fw.requirements if r.status == "Partially Implemented")
            not_implemented = sum(1 for r in fw.requirements if r.status == "Not Implemented")
            not_assessed = sum(1 for r in fw.requirements if (r.status == "Not Assessed" or not r.status))
            not_applicable = sum(1 for r in fw.requirements if r.status == "Not Applicable")

            applicable_count = total - not_applicable
            if applicable_count > 0:
                coverage_score = ((implemented + 0.5 * partially_implemented) / applicable_count) * 100
                coverage_percentage = round(coverage_score, 1)
            else:
                coverage_percentage = 0.0

            summary.append({
                "framework_id": fw.id,
                "framework_name": fw.name,
                "framework_version": fw.version,
                "total_requirements": total,
                "implemented": implemented,
                "partially_implemented": partially_implemented,
                "not_implemented": not_implemented,
                "not_assessed": not_assessed,
                "not_applicable": not_applicable,
                "implementation_coverage": coverage_percentage,
                "metric_label": "Implementation Coverage"
            })

        return {
            "summary": summary,
            "note": (
                "Implementation Coverage is an internal GRC tracking metric for reviewed supported requirements "
                "and does not constitute formal certification or compliance."
            )
        }
    finally:
        db.close()


@app.patch("/compliance/requirements/{requirement_id}")
def update_compliance_requirement(
    requirement_id: int = Path(..., description="The ID of the compliance requirement"),
    payload: RequirementUpdate = Body(...),
    request: Request = None,
):
    """Update requirement compliance status and auditor/review notes."""
    db = SessionLocal()
    try:
        req = db.query(models.ComplianceRequirement).filter(
            models.ComplianceRequirement.id == requirement_id
        ).first()

        if not req:
            raise HTTPException(status_code=404, detail=f"Compliance requirement with ID {requirement_id} not found")

        old_state = {"status": req.status, "notes": req.notes}

        if payload.status is not None:
            valid_statuses = {
                "not assessed": "Not Assessed",
                "not implemented": "Not Implemented",
                "partially implemented": "Partially Implemented",
                "implemented": "Implemented",
                "not applicable": "Not Applicable"
            }
            norm_status = valid_statuses.get(payload.status.strip().lower())
            if not norm_status:
                raise HTTPException(
                    status_code=400,
                    detail="Invalid status. Allowed values: Not Assessed, Not Implemented, Partially Implemented, Implemented, Not Applicable"
                )
            req.status = norm_status

        if payload.notes is not None:
            req.notes = payload.notes.strip() if payload.notes.strip() else None

        req.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(req)

        actor, _ = get_operator_identity(request)
        log_audit_event(
            db=db,
            source="USER",
            actor=actor,
            action="UPDATE",
            entity_type="ComplianceRequirement",
            entity_id=req.id,
            entity_name=f"{req.requirement_id}: {req.title}",
            old_values=old_state,
            new_values={"status": req.status, "notes": req.notes},
            description=f"Updated compliance requirement {req.requirement_id} status to '{req.status}'",
            ip_address=request.client.host if request and request.client else None,
            commit=True,
        )

        return {
            "message": "Compliance requirement updated successfully",
            "requirement": format_requirement(req)
        }
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Phase 4: AI-Assisted Security & Risk Intelligence Endpoints
# ---------------------------------------------------------------------------

class AIRateLimiter:
    """Lightweight in-memory sliding-window rate limiter for AI analysis endpoints.

    DISCLAIMER: This is an operational abuse-control layer to prevent quota exhaustion
    and resource starvation; it does not constitute authentication or authorization.
    """
    def __init__(self, max_requests: int = 5, window_seconds: int = 60, max_tracked_clients: int = 1000):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.max_tracked_clients = max_tracked_clients
        self._history: Dict[str, List[float]] = {}
        self._lock = threading.Lock()
        self._last_cleanup = time.time()

    def check_rate_limit(self, client_key: str) -> Tuple[bool, int]:
        now = time.time()
        with self._lock:
            # Clean expired entries periodically or when tracking map gets large
            if now - self._last_cleanup > 60 or len(self._history) > self.max_tracked_clients:
                self._cleanup(now)

            timestamps = self._history.get(client_key, [])
            cutoff = now - self.window_seconds
            timestamps = [t for t in timestamps if t > cutoff]

            if len(timestamps) >= self.max_requests:
                earliest = timestamps[0]
                retry_after = max(1, int(self.window_seconds - (now - earliest)))
                self._history[client_key] = timestamps
                return False, retry_after

            timestamps.append(now)
            self._history[client_key] = timestamps
            return True, 0

    def _cleanup(self, now: float):
        cutoff = now - self.window_seconds
        keys_to_remove = []
        for k, ts in list(self._history.items()):
            valid = [t for t in ts if t > cutoff]
            if not valid:
                keys_to_remove.append(k)
            else:
                self._history[k] = valid
        for k in keys_to_remove:
            self._history.pop(k, None)
        self._last_cleanup = now


ai_rate_limiter = AIRateLimiter(max_requests=5, window_seconds=60)


def get_ai_client_identity(request: Request = None) -> str:
    """Derive client identity for operational rate limiting of AI requests.

    Prefers operator metadata headers; falls back to client IP address.
    """
    if not request:
        return "system:default"
    actor = request.headers.get("X-Operator-Name", "").strip() if request.headers else ""
    role = request.headers.get("X-Operator-Role", "").strip() if request.headers else ""
    if actor or role:
        return f"operator:{actor or 'Unknown'}:{role or 'Unknown'}"
    if request.client and request.client.host:
        return f"ip:{request.client.host}"
    return "ip:unknown"


@app.post("/risks/{risk_id}/analyze")
def trigger_ai_risk_analysis(
    risk_id: int = Path(..., description="The ID of the risk to analyze with AI intelligence"),
    force_refresh: bool = Query(False, description="Perform new analysis even if a fresh unchanged analysis exists"),
    request: Request = None,
):
    """Analyze a security finding/risk using AI-assisted security intelligence.

    Extracts normalized context, invokes the configured AI intelligence provider,
    persists the auditable analysis record, and returns structured intelligence.

    Operational protections:
    - In-memory rate limiting (max 5 requests/minute per client identity).
    - Freshness reuse: Reuses existing unchanged analysis within 60 minutes unless force_refresh=True.
    - CRITICAL INVARIANT: Official rule-based risk scores remain strictly immutable.
    """
    # 1. Operational rate limiting check
    client_identity = get_ai_client_identity(request)
    allowed, retry_after = ai_rate_limiter.check_rate_limit(client_identity)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"AI analysis rate limit exceeded (maximum 5 requests per minute). Please retry after {retry_after} seconds.",
            headers={"Retry-After": str(retry_after)},
        )

    db = SessionLocal()
    try:
        risk = db.query(models.Risk).filter(models.Risk.id == risk_id).first()
        if not risk:
            raise HTTPException(status_code=404, detail=f"Risk with ID {risk_id} not found")

        try:
            analysis_data = analyze_risk(risk_id=risk_id, db=db, force_refresh=force_refresh)
        except AIProviderError as e:
            logger.error(f"AI security intelligence provider error for risk #{risk_id}: {e}", exc_info=True)
            raise HTTPException(
                status_code=503,
                detail="AI security intelligence service is temporarily unavailable. Please try again later."
            )

        db.refresh(risk)

        is_reused = bool(analysis_data.get("is_reused", False))
        actor, _ = get_operator_identity(request)
        log_audit_event(
            db=db,
            source="AI",
            actor=actor,
            action="AI_ANALYSIS_REUSE" if is_reused else "AI_ANALYSIS_RUN",
            entity_type="Risk",
            entity_id=risk_id,
            entity_name=risk.title,
            new_values={
                "model_name": analysis_data.get("model_name"),
                "priority": analysis_data.get("priority"),
                "confidence": analysis_data.get("confidence"),
                "human_review_required": analysis_data.get("human_review_required"),
                "is_reused": is_reused,
            },
            description=(
                f"Retrieved fresh cached AI risk intelligence for risk #{risk_id}"
                if is_reused
                else f"Generated AI risk intelligence analysis for risk #{risk_id} using {analysis_data.get('model_name')}"
            ),
            ip_address=request.client.host if request and request.client else None,
            commit=True,
        )

        return {
            "message": (
                "AI security intelligence analysis retrieved from cache"
                if is_reused
                else "AI security intelligence analysis generated successfully"
            ),
            "risk_id": risk_id,
            "reused": is_reused,
            "official_risk_scores": {
                "inherent_risk_score": risk.inherent_risk_score,
                "inherent_risk_level": risk.inherent_risk_level,
                "residual_risk_score": risk.residual_risk_score,
                "residual_risk_level": risk.residual_risk_level,
                "likelihood": risk.likelihood,
                "impact": risk.impact,
                "status": risk.status,
                "treatment": risk.treatment,
            },
            "analysis": analysis_data,
            "disclaimer": (
                "AI output is supplementary intelligence for technical and non-technical decision support. "
                "The rule-based GRC risk engine remains the authoritative source for official risk scores."
            ),
        }
    finally:
        db.close()


@app.get("/risks/{risk_id}/analysis")
def get_risk_ai_analysis(
    risk_id: int = Path(..., description="The ID of the risk")
):
    """Retrieve the latest auditable AI security intelligence analysis for a risk."""
    db = SessionLocal()
    try:
        risk = db.query(models.Risk).filter(models.Risk.id == risk_id).first()
        if not risk:
            raise HTTPException(status_code=404, detail=f"Risk with ID {risk_id} not found")

        analysis_data = get_latest_risk_analysis(risk_id=risk_id, db=db)
        if not analysis_data:
            raise HTTPException(
                status_code=404,
                detail=f"No AI security intelligence analysis found for risk ID {risk_id}. Run POST /risks/{risk_id}/analyze first."
            )

        return {
            "risk_id": risk_id,
            "official_risk_scores": {
                "inherent_risk_score": risk.inherent_risk_score,
                "inherent_risk_level": risk.inherent_risk_level,
                "residual_risk_score": risk.residual_risk_score,
                "residual_risk_level": risk.residual_risk_level,
                "status": risk.status,
                "treatment": risk.treatment,
            },
            "analysis": analysis_data,
        }
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Phase 5: Continuous Network Monitoring & Drift Detection Endpoints
# ---------------------------------------------------------------------------

@app.post("/monitoring/jobs", status_code=202)
def create_monitoring_job(
    payload: ScanJobCreate = Body(...),
    request: Request = None,
):
    """Submit an asynchronous network scan job (single host or RFC 1918 /24 subnet).

    Validates target bounds, creates ScanJob with status Queued, and submits to bounded worker pool.
    """
    try:
        validated_target = validate_target_network(payload.target)
    except ValueError as err:
        raise HTTPException(status_code=400, detail=str(err))

    valid_scan_types = ("single_host", "subnet_discovery", "scheduled_sweep")
    if payload.scan_type not in valid_scan_types:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid scan_type '{payload.scan_type}'. Must be one of: {', '.join(valid_scan_types)}",
        )

    # Queue bounds protection: Reject submission early if worker pool is at capacity
    if not scan_worker_pool.can_accept_job():
        raise HTTPException(
            status_code=429,
            detail=(
                f"Scan queue is at maximum capacity ({scan_worker_pool.max_pending_jobs} "
                f"pending/active jobs). Please wait for running scans to complete."
            ),
        )

    db = SessionLocal()
    try:
        job = models.ScanJob(
            target=validated_target,
            scan_type=payload.scan_type,
            status="Queued",
            progress_percent=0,
        )
        db.add(job)
        db.commit()
        db.refresh(job)

        submitted = scan_worker_pool.submit_scan_job(job.id)
        if not submitted:
            job.status = "Failed"
            job.error_message = "Scan queue limit reached. Job rejected."
            job.completed_at = datetime.utcnow()
            db.commit()
            raise HTTPException(
                status_code=429,
                detail=(
                    f"Scan queue is at maximum capacity ({scan_worker_pool.max_pending_jobs} "
                    f"pending/active jobs). Please wait for running scans to complete."
                ),
            )

        actor, _ = get_operator_identity(request)
        log_audit_event(
            db=db,
            source="SCANNER",
            actor=actor,
            action="DISPATCH",
            entity_type="ScanJob",
            entity_id=job.id,
            entity_name=job.target,
            new_values={"id": job.id, "target": job.target, "scan_type": job.scan_type},
            description=f"Dispatched background scan job #{job.id} on target {job.target}",
            ip_address=request.client.host if request and request.client else None,
            commit=True,
        )

        return format_scan_job(job)
    finally:
        db.close()


@app.get("/monitoring/jobs")
def list_monitoring_jobs(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    status: str | None = Query(None),
):
    """List recent scan jobs with optional status filtering and pagination."""
    db = SessionLocal()
    try:
        query = db.query(models.ScanJob)
        if status:
            query = query.filter(models.ScanJob.status == status)

        total = query.count()
        jobs = query.order_by(models.ScanJob.created_at.desc(), models.ScanJob.id.desc()).offset(offset).limit(limit).all()

        return {
            "jobs": [format_scan_job(j) for j in jobs],
            "total": total,
        }
    finally:
        db.close()


@app.get("/monitoring/jobs/{job_id}")
def get_monitoring_job(
    job_id: int = Path(..., description="The ID of the scan job")
):
    """Retrieve execution status, metrics, and progress for a specific scan job."""
    db = SessionLocal()
    try:
        job = db.query(models.ScanJob).filter(models.ScanJob.id == job_id).first()
        if not job:
            raise HTTPException(status_code=404, detail=f"ScanJob with ID {job_id} not found")
        return format_scan_job(job)
    finally:
        db.close()


@app.post("/monitoring/jobs/{job_id}/cancel")
def cancel_monitoring_job(
    job_id: int = Path(..., description="The ID of the scan job to cancel"),
    request: Request = None,
):
    """Request cooperative cancellation of a queued or running scan job.

    Terminates active Nmap subprocess if running and marks job Cancelled once verified.
    """
    db = SessionLocal()
    try:
        job = db.query(models.ScanJob).filter(models.ScanJob.id == job_id).first()
        if not job:
            raise HTTPException(status_code=404, detail=f"ScanJob with ID {job_id} not found")

        if job.status in ("Completed", "Failed", "Cancelled"):
            raise HTTPException(
                status_code=400,
                detail=f"Cannot cancel job with terminal status '{job.status}'",
            )

        scan_worker_pool.cancel_scan_job(job_id)

        actor, _ = get_operator_identity(request)
        log_audit_event(
            db=db,
            source="SCANNER",
            actor=actor,
            action="CANCEL",
            entity_type="ScanJob",
            entity_id=job_id,
            entity_name=job.target,
            description=f"Requested cancellation of scan job #{job_id}",
            ip_address=request.client.host if request and request.client else None,
            commit=True,
        )

        return {
            "message": "Scan job cancellation requested",
            "job_id": job_id,
        }
    finally:
        db.close()


@app.get("/monitoring/schedules")
def list_monitoring_schedules():
    """List all configured continuous monitoring scan schedules."""
    db = SessionLocal()
    try:
        schedules = db.query(models.ScanSchedule).order_by(models.ScanSchedule.created_at.desc()).all()
        return {
            "schedules": [format_scan_schedule(s) for s in schedules],
            "total": len(schedules),
        }
    finally:
        db.close()


@app.post("/monitoring/schedules", status_code=201)
def create_monitoring_schedule(
    payload: ScanScheduleCreate = Body(...)
):
    """Create a new automated continuous monitoring scan schedule.

    Target must be valid RFC 1918 (max /24), and interval must be at least 15 minutes.
    """
    try:
        validated_target = validate_target_network(payload.target)
    except ValueError as err:
        raise HTTPException(status_code=400, detail=str(err))

    if payload.interval_minutes < 15:
        raise HTTPException(
            status_code=400,
            detail="Minimum schedule interval is 15 minutes",
        )

    db = SessionLocal()
    try:
        now = datetime.utcnow()
        sched = models.ScanSchedule(
            name=payload.name.strip(),
            target=validated_target,
            interval_minutes=payload.interval_minutes,
            is_active=True,
            next_run_at=now + timedelta(minutes=payload.interval_minutes),
        )
        db.add(sched)
        db.commit()
        db.refresh(sched)
        return format_scan_schedule(sched)
    finally:
        db.close()


@app.get("/monitoring/schedules/{schedule_id}")
def get_monitoring_schedule(
    schedule_id: int = Path(..., description="The ID of the scan schedule to retrieve")
):
    """Retrieve details for a specific continuous monitoring scan schedule."""
    db = SessionLocal()
    try:
        sched = db.query(models.ScanSchedule).filter(models.ScanSchedule.id == schedule_id).first()
        if not sched:
            raise HTTPException(status_code=404, detail=f"ScanSchedule with ID {schedule_id} not found")
        return format_scan_schedule(sched)
    finally:
        db.close()


@app.patch("/monitoring/schedules/{schedule_id}")
def update_monitoring_schedule(
    schedule_id: int = Path(..., description="The ID of the scan schedule to update"),
    payload: ScanScheduleUpdate = Body(...),
):
    """Update name, target, interval, or active state of an existing scan schedule."""
    db = SessionLocal()
    try:
        sched = db.query(models.ScanSchedule).filter(models.ScanSchedule.id == schedule_id).first()
        if not sched:
            raise HTTPException(status_code=404, detail=f"ScanSchedule with ID {schedule_id} not found")

        if payload.name is not None:
            sched.name = payload.name.strip()

        if payload.target is not None:
            try:
                sched.target = validate_target_network(payload.target)
            except ValueError as err:
                raise HTTPException(status_code=400, detail=str(err))

        if payload.interval_minutes is not None:
            if payload.interval_minutes < 15:
                raise HTTPException(status_code=400, detail="Minimum schedule interval is 15 minutes")
            sched.interval_minutes = payload.interval_minutes
            # Recalculate next run relative to now if active
            if sched.is_active:
                sched.next_run_at = datetime.utcnow() + timedelta(minutes=payload.interval_minutes)

        if payload.is_active is not None:
            sched.is_active = payload.is_active
            if sched.is_active and not sched.next_run_at:
                sched.next_run_at = datetime.utcnow() + timedelta(minutes=sched.interval_minutes)

        sched.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(sched)
        return format_scan_schedule(sched)
    finally:
        db.close()


@app.delete("/monitoring/schedules/{schedule_id}")
def delete_monitoring_schedule(
    schedule_id: int = Path(..., description="The ID of the scan schedule to delete")
):
    """Delete an automated continuous monitoring schedule."""
    db = SessionLocal()
    try:
        sched = db.query(models.ScanSchedule).filter(models.ScanSchedule.id == schedule_id).first()
        if not sched:
            raise HTTPException(status_code=404, detail=f"ScanSchedule with ID {schedule_id} not found")

        db.delete(sched)
        db.commit()
        return {"message": f"ScanSchedule with ID {schedule_id} deleted successfully"}
    finally:
        db.close()


@app.get("/monitoring/drift")
def list_drift_events(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    severity: str | None = Query(None),
    event_type: str | None = Query(None),
    asset_id: int | None = Query(None),
):
    """Query network attack surface drift events feed, sorted newest first."""
    db = SessionLocal()
    try:
        query = db.query(models.DriftEvent)

        if severity:
            query = query.filter(models.DriftEvent.severity == severity.strip())
        if event_type:
            query = query.filter(models.DriftEvent.event_type == event_type.strip())
        if asset_id:
            query = query.filter(models.DriftEvent.asset_id == asset_id)

        total = query.count()
        events = query.order_by(models.DriftEvent.detected_at.desc(), models.DriftEvent.id.desc()).offset(offset).limit(limit).all()

        return {
            "events": [format_drift_event(e) for e in events],
            "total": total,
        }
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Phase 6A: Governance, Evidence Catalog & Tamper-Evident Audit Trail Endpoints
# ---------------------------------------------------------------------------

@app.get("/audit-logs")
def list_audit_logs(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    source: str | None = Query(None),
    actor: str | None = Query(None),
    action: str | None = Query(None),
    entity_type: str | None = Query(None),
    entity_id: int | None = Query(None),
):
    """Query append-only governance audit trail with multi-attribute filtering.

    STRICT GUARANTEE: AuditLog is append-only through the API. No UPDATE or DELETE endpoints exist.
    """
    db = SessionLocal()
    try:
        query = db.query(models.AuditLog)

        if source:
            query = query.filter(models.AuditLog.source == source.strip().upper())
        if actor:
            query = query.filter(models.AuditLog.actor.ilike(f"%{actor.strip()}%"))
        if action:
            query = query.filter(models.AuditLog.action == action.strip().upper())
        if entity_type:
            query = query.filter(models.AuditLog.entity_type == entity_type.strip())
        if entity_id is not None:
            query = query.filter(models.AuditLog.entity_id == entity_id)

        total = query.count()
        logs = (
            query.order_by(models.AuditLog.timestamp.desc(), models.AuditLog.id.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return {
            "logs": [format_audit_log(l) for l in logs],
            "total": total,
        }
    finally:
        db.close()


@app.get("/audit-logs/{log_id}")
def get_audit_log(
    log_id: int = Path(..., description="The ID of the audit log record")
):
    """Retrieve full details for a specific audit log record including state diffs."""
    db = SessionLocal()
    try:
        log = db.query(models.AuditLog).filter(models.AuditLog.id == log_id).first()
        if not log:
            raise HTTPException(status_code=404, detail=f"AuditLog with ID {log_id} not found")
        return format_audit_log(log)
    finally:
        db.close()


@app.get("/evidence")
def list_evidence(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    evidence_type: str | None = Query(None),
    asset_id: int | None = Query(None),
    scan_job_id: int | None = Query(None),
    risk_id: int | None = Query(None),
    control_id: int | None = Query(None),
    requirement_id: int | None = Query(None),
):
    """Retrieve evidence records with filtering by technical or governance linkages."""
    db = SessionLocal()
    try:
        query = db.query(models.EvidenceRecord)

        if evidence_type:
            query = query.filter(models.EvidenceRecord.evidence_type == evidence_type.strip())
        if asset_id is not None:
            query = query.filter(models.EvidenceRecord.asset_id == asset_id)
        if scan_job_id is not None:
            query = query.filter(models.EvidenceRecord.scan_job_id == scan_job_id)
        if risk_id is not None:
            query = query.filter(models.EvidenceRecord.risks.any(models.Risk.id == risk_id))
        if control_id is not None:
            query = query.filter(models.EvidenceRecord.controls.any(models.Control.id == control_id))
        if requirement_id is not None:
            query = query.filter(
                models.EvidenceRecord.requirements.any(models.ComplianceRequirement.id == requirement_id)
            )

        total = query.count()
        records = (
            query.order_by(models.EvidenceRecord.collected_at.desc(), models.EvidenceRecord.id.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return {
            "evidence": [format_evidence(r) for r in records],
            "total": total,
        }
    finally:
        db.close()


@app.post("/evidence", status_code=201)
def create_evidence(
    request: Request,
    payload: EvidenceCreate = Body(...),
):
    """Register a new tamper-evident evidence artifact with M2M governance linkages."""
    actor, _ = get_operator_identity(request)
    ip_addr = request.client.host if request.client else None

    db = SessionLocal()
    try:
        record = create_evidence_record(
            db=db,
            title=payload.title,
            evidence_type=payload.evidence_type,
            description=payload.description,
            content_text=payload.content_text,
            reference_url=payload.reference_url,
            source_system=payload.source_system or "AI-GRC Platform",
            collector=payload.collector or actor,
            collected_at=payload.collected_at,
            asset_id=payload.asset_id,
            scan_job_id=payload.scan_job_id,
            risk_ids=payload.risk_ids,
            control_ids=payload.control_ids,
            requirement_ids=payload.requirement_ids,
            actor=actor,
            ip_address=ip_addr,
        )
        return format_evidence(record)
    except ValueError as err:
        raise HTTPException(status_code=400, detail=str(err))
    finally:
        db.close()


@app.get("/evidence/{evidence_id}")
def get_evidence_detail(
    evidence_id: int = Path(..., description="The ID of the evidence record")
):
    """Retrieve full details of an evidence record including SHA-256 and linkages."""
    db = SessionLocal()
    try:
        record = db.query(models.EvidenceRecord).filter(models.EvidenceRecord.id == evidence_id).first()
        if not record:
            raise HTTPException(status_code=404, detail=f"EvidenceRecord with ID {evidence_id} not found")
        return format_evidence(record)
    finally:
        db.close()


@app.delete("/evidence/{evidence_id}")
def delete_evidence(
    request: Request,
    evidence_id: int = Path(..., description="The ID of the evidence record to delete"),
):
    """Delete an evidence record and emit a corresponding audit log."""
    actor, _ = get_operator_identity(request)
    ip_addr = request.client.host if request.client else None

    db = SessionLocal()
    try:
        record = db.query(models.EvidenceRecord).filter(models.EvidenceRecord.id == evidence_id).first()
        if not record:
            raise HTTPException(status_code=404, detail=f"EvidenceRecord with ID {evidence_id} not found")

        success = delete_evidence_record(
            db=db,
            evidence_id=evidence_id,
            actor=actor,
            ip_address=ip_addr,
        )
        if not success:
            raise HTTPException(
                status_code=500,
                detail=f"Failed to atomically delete evidence record #{evidence_id}: audit log recording failed.",
            )
        return {"message": f"Evidence record #{evidence_id} deleted successfully"}
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Phase 6B: Reporting & Multi-Format Export Endpoints
# ---------------------------------------------------------------------------

def _handle_report_response(
    report_type: str,
    format_type: str,
    db: Any,
    request: Request,
    filters: Optional[dict] = None,
) -> Response:
    actor, _ = get_operator_identity(request)
    ip_addr = request.client.host if request.client else None

    try:
        content, media_type, filename = generate_report(
            report_type=report_type,
            format_type=format_type,
            db=db,
            operator=actor,
            filters=filters,
        )

        # Emit tamper-evident audit event for report generation
        log_audit_event(
            db=db,
            source="API",
            actor=actor,
            action="EXPORT",
            entity_type="Report",
            entity_name=report_type,
            description=f"Exported '{report_type}' report in '{format_type.upper()}' format",
            ip_address=ip_addr,
            commit=True,
        )

        headers = {
            "Content-Disposition": f'attachment; filename="{filename}"',
        }
        return Response(content=content, media_type=media_type, headers=headers)
    except ValueError as err:
        raise HTTPException(status_code=400, detail=str(err))


@app.get("/reports/executive-summary")
def get_executive_summary_report(
    request: Request,
    format: str = Query("json", description="Export format: json, csv, or html"),
    risk_level: Optional[str] = Query(None, description="Filter by residual risk level: Low, Medium, High, Critical"),
):
    """Generate executive risk and posture summary in JSON, CSV, or HTML format."""
    db = SessionLocal()
    try:
        filters = {}
        if risk_level:
            filters["risk_level"] = risk_level
        return _handle_report_response("executive_summary", format, db, request, filters)
    finally:
        db.close()


@app.get("/reports/technical-vulnerabilities")
def get_technical_vulnerabilities_report(
    request: Request,
    format: str = Query("json", description="Export format: json, csv, or html"),
    asset_id: Optional[int] = Query(None, description="Filter by asset ID"),
    severity: Optional[str] = Query(None, description="Filter by severity: Low, Medium, High, Critical"),
    status: Optional[str] = Query(None, description="Filter by status: Open, Resolved"),
):
    """Generate technical vulnerability & attack surface inventory in JSON, CSV, or HTML format."""
    db = SessionLocal()
    try:
        filters = {}
        if asset_id:
            filters["asset_id"] = asset_id
        if severity:
            filters["severity"] = severity
        if status:
            filters["status"] = status
        return _handle_report_response("technical_vulnerabilities", format, db, request, filters)
    finally:
        db.close()


@app.get("/reports/compliance-gap")
def get_compliance_gap_report(
    request: Request,
    format: str = Query("json", description="Export format: json, csv, or html"),
    framework_id: Optional[int] = Query(None, description="Filter by framework ID"),
    status: Optional[str] = Query(None, description="Filter by requirement status"),
):
    """Generate compliance framework readiness and gap analysis in JSON, CSV, or HTML format."""
    db = SessionLocal()
    try:
        filters = {}
        if framework_id:
            filters["framework_id"] = framework_id
        if status:
            filters["status"] = status
        return _handle_report_response("compliance_gap", format, db, request, filters)
    finally:
        db.close()


@app.get("/reports/risk-register")
def get_risk_register_report(
    request: Request,
    format: str = Query("json", description="Export format: json, csv, or html"),
    status: Optional[str] = Query(None, description="Filter by status: Open, Mitigated, Accepted, Closed"),
    treatment: Optional[str] = Query(None, description="Filter by treatment: Mitigate, Accept, Transfer, Avoid"),
    owner: Optional[str] = Query(None, description="Filter by risk owner"),
):
    """Generate complete enterprise risk register in JSON, CSV, or HTML format."""
    db = SessionLocal()
    try:
        filters = {}
        if status:
            filters["status"] = status
        if treatment:
            filters["treatment"] = treatment
        if owner:
            filters["owner"] = owner
        return _handle_report_response("risk_register", format, db, request, filters)
    finally:
        db.close()


@app.get("/reports/audit-trail")
def get_governance_audit_report(
    request: Request,
    format: str = Query("json", description="Export format: json, csv, or html"),
    source: Optional[str] = Query(None, description="Filter by source: USER, SYSTEM, SCANNER, SCHEDULER, AI, API"),
    actor: Optional[str] = Query(None, description="Filter by actor name"),
    start_time: Optional[datetime] = Query(None, description="Filter by start timestamp"),
    end_time: Optional[datetime] = Query(None, description="Filter by end timestamp"),
):
    """Generate governance audit trail and evidence report in JSON, CSV, or HTML format."""
    db = SessionLocal()
    try:
        filters = {}
        if source:
            filters["source"] = source
        if actor:
            filters["actor"] = actor
        if start_time:
            filters["start_time"] = start_time
        if end_time:
            filters["end_time"] = end_time
        return _handle_report_response("governance_audit", format, db, request, filters)
    finally:
        db.close()


@app.get("/reports/{report_type}")
def get_generic_report(
    request: Request,
    report_type: str = Path(..., description="One of: executive_summary, technical_vulnerabilities, compliance_gap, risk_register, governance_audit"),
    format: str = Query("json", description="Export format: json, csv, or html"),
):
    """Unified report export endpoint supporting JSON, CSV, and HTML formats."""
    db = SessionLocal()
    try:
        return _handle_report_response(report_type, format, db, request, filters=None)
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Phase 6C: Human Review & Risk Sign-off Endpoints
# ---------------------------------------------------------------------------

@app.post("/risks/{risk_id}/reviews", status_code=201)
def create_risk_review(
    request: Request,
    risk_id: int = Path(..., description="The ID of the risk being reviewed"),
    payload: RiskReviewCreate = Body(...),
):
    """Submit formal human governance sign-off and treatment review for a risk.

    Guarantees:
    - AI output is advisory decision support only; human reviewer explicitly decides.
    - Exactly one active review per risk enforced at the database level.
    - Attributed reviewer metadata captured from headers (X-Operator-Name, X-Operator-Role).
    - Material treatment overrides and review submissions are permanently audited.
    """
    actor, role = get_operator_identity(request)
    reviewer_name = payload.reviewer_name or actor
    reviewer_role = payload.reviewer_role or role
    ip_addr = request.client.host if request.client else None

    db = SessionLocal()
    try:
        review = submit_risk_review(
            db=db,
            risk_id=risk_id,
            decision=payload.decision,
            agreed_treatment=payload.agreed_treatment,
            comments=payload.comments,
            ai_analysis_acknowledged=payload.ai_analysis_acknowledged,
            reviewer_name=reviewer_name,
            reviewer_role=reviewer_role,
            ip_address=ip_addr,
        )
        return format_risk_review(review, is_stale=False, stale_reasons=[])
    except ValueError as err:
        raise HTTPException(status_code=400, detail=str(err))
    except Exception as err:
        logger.error(f"Failed to submit risk review for risk #{risk_id}: {err}", exc_info=True)
        err_msg = str(err).lower()
        if "unique" in err_msg or "integrityerror" in err_msg:
            raise HTTPException(
                status_code=409,
                detail="A concurrent review submission conflicted with this request. Please refresh and retry."
            )
        raise HTTPException(
            status_code=500,
            detail="Failed to submit risk review due to an internal server error."
        )
    finally:
        db.close()


@app.get("/risks/{risk_id}/reviews")
def list_risk_reviews(
    risk_id: int = Path(..., description="The ID of the risk"),
):
    """Retrieve review history for a risk, dynamically evaluating staleness in real-time.

    Guarantees:
    - Historical reviews remain queryable in chronological order.
    - Evaluates material technical changes (CVSS, drift, exposure) dynamically on read.
    - Deduplication: Emits RISK_REVIEW_STALE audit event ONLY upon actual state transition.
    """
    db = SessionLocal()
    try:
        current_rev, all_revs, is_stale, stale_reasons = get_or_evaluate_risk_reviews(db=db, risk_id=risk_id)
        risk = db.query(models.Risk).filter(models.Risk.id == risk_id).first()
        if not risk:
            raise HTTPException(status_code=404, detail=f"Risk with ID {risk_id} not found")

        return {
            "risk_id": risk_id,
            "review_status": risk.review_status,
            "is_stale": is_stale,
            "stale_reasons": stale_reasons,
            "current_review": format_risk_review(current_rev, is_stale, stale_reasons) if current_rev else None,
            "history": [format_risk_review(r) for r in all_revs],
        }
    except ValueError as err:
        raise HTTPException(status_code=404, detail=str(err))
    finally:
        db.close()


@app.get("/governance/reviews/pending")
def list_pending_risk_reviews(
    review_status: Optional[str] = Query(None, description="Filter by review status: Pending Review, Stale, Changes Requested, Under Review, Approved, Rejected"),
    asset_id: Optional[int] = Query(None, description="Filter by asset ID"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    """Query risks requiring human governance review or re-evaluation.

    Defaults to risks needing attention ('Pending Review', 'Stale', 'Changes Requested').
    """
    db = SessionLocal()
    try:
        query = db.query(models.Risk)
        if review_status:
            query = query.filter(models.Risk.review_status == review_status.strip())
        else:
            query = query.filter(models.Risk.review_status.in_(["Pending Review", "Stale", "Changes Requested"]))

        if asset_id:
            query = query.filter(models.Risk.asset_id == asset_id)

        total = query.count()
        risks = query.order_by(models.Risk.residual_risk_score.desc(), models.Risk.id.asc()).offset(offset).limit(limit).all()

        results = []
        for r in risks:
            current_rev = (
                db.query(models.RiskReview)
                .filter(models.RiskReview.risk_id == r.id, models.RiskReview.is_current == True)
                .first()
            )
            results.append({
                "risk": format_risk(r),
                "review_status": r.review_status,
                "current_review": format_risk_review(current_rev) if current_rev else None,
            })

        return {
            "risks": results,
            "total": total,
            "limit": limit,
            "offset": offset,
        }
    finally:
        db.close()


@app.post("/governance/reviews/evaluate-stale")
def evaluate_stale_reviews_batch(
    risk_id: Optional[int] = Query(None, description="Optional target risk ID"),
    asset_id: Optional[int] = Query(None, description="Optional target asset ID"),
):
    """On-demand bulk reconciliation to evaluate and update stale review statuses.

    Emits RISK_REVIEW_STALE audit events only on actual Approved -> Stale transitions.
    """
    db = SessionLocal()
    try:
        query = db.query(models.Risk).filter(models.Risk.review_status == "Approved")
        if risk_id:
            query = query.filter(models.Risk.id == risk_id)
        if asset_id:
            query = query.filter(models.Risk.asset_id == asset_id)

        approved_risks = query.all()
        newly_stale_count = 0
        stale_details = []

        for r in approved_risks:
            current_rev = (
                db.query(models.RiskReview)
                .filter(models.RiskReview.risk_id == r.id, models.RiskReview.is_current == True)
                .first()
            )
            if current_rev:
                is_stale, reasons = evaluate_review_staleness(db, r, current_rev)
                if is_stale:
                    r.review_status = "Stale"
                    r.updated_at = datetime.utcnow()
                    newly_stale_count += 1
                    stale_details.append({
                        "risk_id": r.id,
                        "risk_title": r.title,
                        "reasons": reasons,
                    })
                    log_audit_event(
                        db=db,
                        source="SYSTEM",
                        actor="governance_engine",
                        action="RISK_REVIEW_STALE",
                        entity_type="Risk",
                        entity_id=r.id,
                        entity_name=r.title,
                        new_values={"stale_reasons": reasons, "review_id": current_rev.id},
                        description=f"Batch evaluation marked risk #{r.id} review #{current_rev.id} stale: {'; '.join(reasons)}",
                        commit=False,
                    )

        if newly_stale_count > 0:
            db.commit()

        return {
            "evaluated_count": len(approved_risks),
            "newly_stale_count": newly_stale_count,
            "stale_risks": stale_details,
        }
    finally:
        db.close()

from fastapi import FastAPI, Query, HTTPException, Path, Body
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from datetime import datetime
import sys
import os
import ipaddress
from dotenv import load_dotenv

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

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

Base.metadata.create_all(bind=engine)


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
        ip = ipaddress.ip_address(target)

        if ip.version != 4:
            raise HTTPException(
                status_code=400,
                detail="Only IPv4 addresses are supported for single-host scans."
            )

    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Invalid target. Enter a single IPv4 address."
        )

    # Run Nmap scan
    try:
        result = scan_host(target)
    except RuntimeError as err:
        raise HTTPException(
            status_code=500,
            detail=f"Nmap scan failed: {str(err)}"
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
        raise HTTPException(
            status_code=500,
            detail=f"Nmap discovery failed: {str(err)}"
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
    payload: AssetUpdate = Body(...)
):
    db = SessionLocal()
    try:
        asset = db.query(models.Asset).filter(models.Asset.id == asset_id).first()
        if not asset:
            raise HTTPException(status_code=404, detail=f"Asset with ID {asset_id} not found")

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
    payload: RiskUpdate = Body(...)
):
    db = SessionLocal()
    try:
        risk = db.query(models.Risk).filter(models.Risk.id == risk_id).first()
        if not risk:
            raise HTTPException(status_code=404, detail=f"Risk with ID {risk_id} not found")

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
def create_control(payload: ControlCreate = Body(...)):
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
    payload: ControlUpdate = Body(...)
):
    db = SessionLocal()
    try:
        control = db.query(models.Control).filter(models.Control.id == control_id).first()
        if not control:
            raise HTTPException(status_code=404, detail=f"Control with ID {control_id} not found")

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
        return {
            "message": "Control updated successfully",
            "control": format_control(control)
        }
    finally:
        db.close()


@app.delete("/controls/{control_id}")
def delete_control(control_id: int = Path(..., description="The ID of the control")):
    db = SessionLocal()
    try:
        control = db.query(models.Control).filter(models.Control.id == control_id).first()
        if not control:
            raise HTTPException(status_code=404, detail=f"Control with ID {control_id} not found")

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
        return {"message": f"Control {control_id} deleted successfully"}
    finally:
        db.close()


@app.post("/risks/{risk_id}/controls/{control_id}")
def assign_control_to_risk(
    risk_id: int = Path(..., description="The ID of the risk"),
    control_id: int = Path(..., description="The ID of the control")
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
        return {
            "message": f"Control '{control.name}' assigned to risk {risk_id}",
            "risk": format_risk(risk)
        }
    finally:
        db.close()


@app.delete("/risks/{risk_id}/controls/{control_id}")
def detach_control_from_risk(
    risk_id: int = Path(..., description="The ID of the risk"),
    control_id: int = Path(..., description="The ID of the control")
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
    payload: RequirementUpdate = Body(...)
):
    """Update requirement compliance status and auditor/review notes."""
    db = SessionLocal()
    try:
        req = db.query(models.ComplianceRequirement).filter(
            models.ComplianceRequirement.id == requirement_id
        ).first()

        if not req:
            raise HTTPException(status_code=404, detail=f"Compliance requirement with ID {requirement_id} not found")

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
        return {
            "message": "Compliance requirement updated successfully",
            "requirement": format_requirement(req)
        }
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Phase 4: AI-Assisted Security & Risk Intelligence Endpoints
# ---------------------------------------------------------------------------

@app.post("/risks/{risk_id}/analyze")
def trigger_ai_risk_analysis(
    risk_id: int = Path(..., description="The ID of the risk to analyze with AI intelligence")
):
    """Analyze a security finding/risk using AI-assisted security intelligence.

    Extracts normalized context, invokes the configured AI intelligence provider,
    persists the auditable analysis record, and returns structured intelligence.

    CRITICAL INVARIANT: Official rule-based risk scores remain strictly immutable.
    """
    db = SessionLocal()
    try:
        risk = db.query(models.Risk).filter(models.Risk.id == risk_id).first()
        if not risk:
            raise HTTPException(status_code=404, detail=f"Risk with ID {risk_id} not found")

        try:
            analysis_data = analyze_risk(risk_id=risk_id, db=db)
        except AIProviderError as e:
            raise HTTPException(
                status_code=503,
                detail=f"AI security intelligence provider is currently unavailable: {str(e)}"
            )

        db.refresh(risk)

        return {
            "message": "AI security intelligence analysis generated successfully",
            "risk_id": risk_id,
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

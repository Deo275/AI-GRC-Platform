from fastapi import FastAPI, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
try:
    from database import engine, Base, SessionLocal
    import models
except ImportError:
    from backend.database import engine, Base, SessionLocal
    import backend.models as models
import sys
import os
import ipaddress

sys.path.append(
    os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..")
    )
)

from scanner.nmap_scanner import scan_host, discover_hosts
from scanner.risk_engine import calculate_risk
from scanner.vulnerability_scanner import identify_vulnerabilities


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
                risk_level=risk_result["risk_level"]
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

            if existing_risk:
                # Update scanner-derived fields
                existing_risk.likelihood = likelihood
                existing_risk.impact = impact
                existing_risk.risk_score = risk_score
                existing_risk.risk_level = risk_level
                existing_risk.compliance_framework = compliance_framework
                existing_risk.compliance_control = compliance_control
                existing_risk.recommendation = recommendation
                existing_risk.updated_at = models.datetime.utcnow()

                # If a previously Resolved risk reappears: reopen it
                if existing_risk.status == "Resolved":
                    existing_risk.status = "Open"

                # treatment and non-Resolved status are preserved
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
                    treatment="Mitigate",
                    status="Open",
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
                    risk_level=risk_result["risk_level"]
                )

                db.add(asset)

            discovered_assets.append({
                "ip_address": host,
                "hostname": result["hostname"],
                "mac_address": result["mac_address"],
                "operating_system": result["operating_system"],
                "open_ports": port_data,
                "risk_score": risk_result["risk_score"],
                "risk_level": risk_result["risk_level"]
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

# ------------------------------------------------
# GET ASSET INVENTORY
# ------------------------------------------------

@app.get("/assets")
def get_assets():

    db = SessionLocal()

    try:

        assets = db.query(models.Asset).order_by(
            models.Asset.id
        ).all()

        return {
            "count": len(assets),
            "assets": [
                {
                    "id": asset.id,
                    "ip_address": asset.ip_address,
                    "hostname": asset.hostname,
                    "mac_address": asset.mac_address,
                    "operating_system": asset.operating_system,
                    "open_ports": asset.open_ports,
                    "status": asset.status,
                    "risk_score": asset.risk_score,
                    "risk_level": asset.risk_level,
                    "last_seen": asset.last_seen
                }
                for asset in assets
            ]
        }

    finally:
        db.close()


# ------------------------------------------------
# GET RISK REGISTER
# ------------------------------------------------

@app.get("/risks")
def get_risks():

    db = SessionLocal()

    try:

        risks = db.query(models.Risk).order_by(
            models.Risk.id
        ).all()

        return {
            "count": len(risks),
            "risks": [
                {
                    "id": risk.id,
                    "asset_id": risk.asset_id,
                    "title": risk.title,
                    "description": risk.description,
                    "likelihood": risk.likelihood,
                    "impact": risk.impact,
                    "risk_score": risk.risk_score,
                    "risk_level": risk.risk_level,
                    "treatment": risk.treatment,
                    "status": risk.status,
                    "compliance_framework": risk.compliance_framework,
                    "compliance_control": risk.compliance_control,
                    "recommendation": risk.recommendation,
                    "created_at": risk.created_at,
                    "updated_at": risk.updated_at
                }
                for risk in risks
            ]
        }

    finally:
        db.close()


# ------------------------------------------------
# GET VULNERABILITY FINDINGS
# ------------------------------------------------

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
from fastapi import FastAPI, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from database import engine, Base, SessionLocal
import models
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
    result = scan_host(target)

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
        # CREATE GRC RISK REGISTER ENTRIES
        # ------------------------------------------------

        for finding in risk_result["findings"]:

            # Check if this risk already exists for this asset
            existing_risk = db.query(models.Risk).filter(
                models.Risk.asset_id == asset.id,
                models.Risk.title == finding
            ).first()

            if existing_risk:
                continue

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
                recommendation=recommendation
            )

            db.add(risk)

        # SAVE VULNERABILITIES
        for vulnerability in vulnerability_result:

            existing_vulnerability = db.query(
                models.Vulnerability
            ).filter(
                models.Vulnerability.asset_id == asset.id,
                models.Vulnerability.port == vulnerability["port"],
                models.Vulnerability.title == vulnerability["title"]
            ).first()

            if existing_vulnerability:

                # Update existing vulnerability
                existing_vulnerability.service = (
                    vulnerability["service"]
                )

                existing_vulnerability.severity = (
                    vulnerability["severity"]
                )

                existing_vulnerability.description = (
                    vulnerability["description"]
                )

                existing_vulnerability.cve = (
                    vulnerability["cve"]
                )

                existing_vulnerability.cvss_score = (
                    vulnerability["cvss_score"]
                )

                existing_vulnerability.cvss_version = (
                    vulnerability["cvss_version"]
                )

                existing_vulnerability.cve_confidence = (
                    vulnerability["cve_confidence"]
                )

                existing_vulnerability.cve_candidate_count = (
                    vulnerability["cve_candidate_count"]
                )

                continue

            vulnerability_record = models.Vulnerability(
                asset_id=asset.id,
                port=vulnerability["port"],
                service=vulnerability["service"],
                title=vulnerability["title"],
                severity=vulnerability["severity"],
                description=vulnerability["description"],
                cve=vulnerability["cve"],
                cvss_score=vulnerability["cvss_score"],
                cvss_version=vulnerability["cvss_version"],
                cve_confidence=vulnerability["cve_confidence"],
                cve_candidate_count=vulnerability["cve_candidate_count"],
                status="Open"
            )

            db.add(vulnerability_record)

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

    # Discover active hosts
    hosts = discover_hosts(network)

    db = SessionLocal()

    discovered_assets = []

    try:

        for host in hosts:

            # Run detailed scan
            result = scan_host(host)

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
                    "title": vulnerability.title,
                    "severity": vulnerability.severity,
                    "description": vulnerability.description,
                    "cve": vulnerability.cve,
                    "cvss_score": vulnerability.cvss_score,
                    "cvss_version": vulnerability.cvss_version,
                    "cve_confidence": vulnerability.cve_confidence,
                    "cve_candidate_count": vulnerability.cve_candidate_count,
                    "status": vulnerability.status,
                    "discovered_at": vulnerability.discovered_at
                }
                for vulnerability in vulnerabilities
            ]
        }

    finally:
        db.close()
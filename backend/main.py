from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from database import engine, Base, SessionLocal
import models
import sys
import os

sys.path.append(
    os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..")
    )
)

from scanner.nmap_scanner import scan_host
from scanner.risk_engine import calculate_risk


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
def scan_network():

    target = "192.168.127.1"

    # Run Nmap scan
    result = scan_host(target)

    # Calculate security risk
    risk_result = calculate_risk(
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
            asset.open_ports = port_data
            asset.status = "Active"
            asset.risk_score = risk_result["risk_score"]
            asset.risk_level = risk_result["risk_level"]
            asset.last_seen = models.datetime.utcnow()

        else:

            # Create new asset
            asset = models.Asset(
                ip_address=target,
                hostname="Windows Host",
                operating_system="Windows",
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

        # Save everything
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
            "risk_register_count": len(risks)
        }

    finally:
        db.close()
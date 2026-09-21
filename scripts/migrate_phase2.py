"""Phase 2 Database Migration Script.

Performs safe, non-destructive schema migration on the live PostgreSQL database:
1. Adds asset intelligence columns to `assets` table.
2. Adds numerical risk, inherent risk, residual risk, and risk management columns to `risks`.
3. Creates `controls` table.
4. Creates `risk_controls` association table.
5. Seeds initial catalog of 9 standard controls.
6. Synchronizes existing risk records with calculated inherent/residual risk scores.
"""

import os
import sys
from pathlib import Path

# Ensure project root and backend are in sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(BASE_DIR / "backend"))

import database
import models
from scanner.grc_engine import (
    criticality_to_impact,
    calculate_inherent_risk,
    calculate_residual_risk,
)
from sqlalchemy import text, inspect

INITIAL_CONTROLS = [
    {
        "name": "Firewall",
        "description": "Network packet filtering to restrict unauthorized inbound and outbound traffic.",
        "category": "Preventive",
        "framework": "NIST CSF (PR.AC-4)",
        "effectiveness": "High",
        "status": "Implemented"
    },
    {
        "name": "Access Control",
        "description": "Role-based access control and principle of least privilege for network services.",
        "category": "Preventive",
        "framework": "NIST CSF (PR.AC-1)",
        "effectiveness": "High",
        "status": "Implemented"
    },
    {
        "name": "Patch Management",
        "description": "Regular vulnerability scanning and timely deployment of security patches.",
        "category": "Corrective",
        "framework": "NIST CSF (PR.IP-12)",
        "effectiveness": "Medium",
        "status": "Implemented"
    },
    {
        "name": "Network Segmentation",
        "description": "Isolating database and management services into restricted network VLANs.",
        "category": "Preventive",
        "framework": "NIST CSF (PR.AC-5)",
        "effectiveness": "High",
        "status": "Implemented"
    },
    {
        "name": "Multi-Factor Authentication (MFA)",
        "description": "Requiring multiple authentication factors for remote management and administrative access.",
        "category": "Preventive",
        "framework": "NIST CSF (PR.AC-7)",
        "effectiveness": "High",
        "status": "Implemented"
    },
    {
        "name": "Encryption (TLS/SSL)",
        "description": "Enforcing TLS cryptographic protocols for data in transit across database and service connections.",
        "category": "Preventive",
        "framework": "NIST CSF (PR.DS-2)",
        "effectiveness": "High",
        "status": "Implemented"
    },
    {
        "name": "Logging & Monitoring",
        "description": "Centralized audit logging and automated alerts for anomalous access attempts.",
        "category": "Detective",
        "framework": "NIST CSF (DE.AE-3)",
        "effectiveness": "Medium",
        "status": "Implemented"
    },
    {
        "name": "Automated Backups",
        "description": "Periodic encrypted data backups with regular restoration verification.",
        "category": "Corrective",
        "framework": "NIST CSF (PR.IP-4)",
        "effectiveness": "Medium",
        "status": "Implemented"
    },
    {
        "name": "Endpoint Protection",
        "description": "Anti-malware and host-based intrusion prevention on managed systems.",
        "category": "Preventive",
        "framework": "NIST CSF (PR.PT-1)",
        "effectiveness": "High",
        "status": "Implemented"
    }
]


def run_migration():
    engine = database.engine
    print("Beginning Phase 2 database migration...")

    with engine.connect() as conn:
        # 1. Add Asset Intelligence columns
        print("Migrating 'assets' table columns...")
        conn.execute(text("ALTER TABLE assets ADD COLUMN IF NOT EXISTS criticality VARCHAR DEFAULT 'Medium';"))
        conn.execute(text("ALTER TABLE assets ADD COLUMN IF NOT EXISTS environment VARCHAR DEFAULT 'Production';"))
        conn.execute(text("ALTER TABLE assets ADD COLUMN IF NOT EXISTS exposure VARCHAR DEFAULT 'Internal';"))
        conn.execute(text("ALTER TABLE assets ADD COLUMN IF NOT EXISTS owner VARCHAR;"))
        conn.execute(text("ALTER TABLE assets ADD COLUMN IF NOT EXISTS business_function VARCHAR;"))
        conn.execute(text("UPDATE assets SET criticality = 'Medium' WHERE criticality IS NULL;"))
        conn.execute(text("UPDATE assets SET environment = 'Production' WHERE environment IS NULL;"))
        conn.execute(text("UPDATE assets SET exposure = 'Internal' WHERE exposure IS NULL;"))

        # 2. Add Risk Model columns
        print("Migrating 'risks' table columns...")
        conn.execute(text("ALTER TABLE risks ADD COLUMN IF NOT EXISTS likelihood_score INTEGER DEFAULT 2;"))
        conn.execute(text("ALTER TABLE risks ADD COLUMN IF NOT EXISTS impact_score INTEGER DEFAULT 2;"))
        conn.execute(text("ALTER TABLE risks ADD COLUMN IF NOT EXISTS inherent_risk_score INTEGER DEFAULT 4;"))
        conn.execute(text("ALTER TABLE risks ADD COLUMN IF NOT EXISTS inherent_risk_level VARCHAR DEFAULT 'Medium';"))
        conn.execute(text("ALTER TABLE risks ADD COLUMN IF NOT EXISTS residual_likelihood INTEGER DEFAULT 2;"))
        conn.execute(text("ALTER TABLE risks ADD COLUMN IF NOT EXISTS residual_impact INTEGER DEFAULT 2;"))
        conn.execute(text("ALTER TABLE risks ADD COLUMN IF NOT EXISTS residual_risk_score INTEGER DEFAULT 4;"))
        conn.execute(text("ALTER TABLE risks ADD COLUMN IF NOT EXISTS residual_risk_level VARCHAR DEFAULT 'Medium';"))
        conn.execute(text("ALTER TABLE risks ADD COLUMN IF NOT EXISTS risk_owner VARCHAR;"))
        conn.execute(text("ALTER TABLE risks ADD COLUMN IF NOT EXISTS due_date TIMESTAMP;"))

        # 3. Create 'controls' table
        print("Creating 'controls' table...")
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS controls (
                id SERIAL PRIMARY KEY,
                name VARCHAR NOT NULL,
                description VARCHAR(1000),
                category VARCHAR,
                framework VARCHAR,
                effectiveness VARCHAR DEFAULT 'Medium',
                status VARCHAR DEFAULT 'Implemented',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """))

        # 4. Create 'risk_controls' association table
        print("Creating 'risk_controls' association table...")
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS risk_controls (
                risk_id INTEGER NOT NULL REFERENCES risks(id) ON DELETE CASCADE,
                control_id INTEGER NOT NULL REFERENCES controls(id) ON DELETE CASCADE,
                PRIMARY KEY (risk_id, control_id)
            );
        """))

        conn.commit()
        print("Schema altered successfully.")

    # 5. Seed Controls Catalog
    db = database.SessionLocal()
    try:
        print("Checking/seeding controls catalog...")
        for c_data in INITIAL_CONTROLS:
            existing = db.query(models.Control).filter(models.Control.name == c_data["name"]).first()
            if not existing:
                ctrl = models.Control(**c_data)
                db.add(ctrl)
        db.commit()
        ctrl_count = db.query(models.Control).count()
        print(f"Total controls in catalog: {ctrl_count}")

        # 6. Recalculate inherent and residual risks for existing risks
        print("Recalculating scores for existing risks...")
        risks = db.query(models.Risk).all()
        for r in risks:
            asset = db.query(models.Asset).filter(models.Asset.id == r.asset_id).first()
            crit = asset.criticality if asset else "Medium"
            impact = criticality_to_impact(crit)
            # Default likelihood for existing High findings is 3, else 2
            likelihood = 3 if r.likelihood == "High" else (4 if r.likelihood == "Critical" else 2)

            inh = calculate_inherent_risk(likelihood, impact)
            res = calculate_residual_risk(likelihood, impact, r.controls)

            r.likelihood_score = inh["likelihood_score"]
            r.impact_score = inh["impact_score"]
            r.inherent_risk_score = inh["inherent_risk_score"]
            r.inherent_risk_level = inh["inherent_risk_level"]
            r.residual_likelihood = res["residual_likelihood"]
            r.residual_impact = res["residual_impact"]
            r.residual_risk_score = res["residual_risk_score"]
            r.residual_risk_level = res["residual_risk_level"]

        db.commit()
        print(f"Updated {len(risks)} risk records with Inherent & Residual risk scores.")

        # Verification check
        asset_count = db.query(models.Asset).count()
        risk_count = db.query(models.Risk).count()
        vuln_count = db.query(models.Vulnerability).count()
        print(f"Verification: Assets={asset_count}, Risks={risk_count}, Vulns={vuln_count}, Controls={ctrl_count}")

    finally:
        db.close()

    print("Phase 2 migration complete!")


if __name__ == "__main__":
    run_migration()

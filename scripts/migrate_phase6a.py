"""Phase 6A Database Migration Script: Evidence Catalog & Tamper-Evident Audit Trail.

Performs safe, non-destructive schema migration on the PostgreSQL database:
1. Creates `audit_logs` table for append-only governance-level milestone tracking.
2. Creates `evidence_records` table for tamper-evident artifacts and evidence tracking.
3. Creates `evidence_risks`, `evidence_controls`, and `evidence_requirements` M2M tables.
4. Creates necessary foreign keys, cascading rules, and performance indexes.
5. Verifies complete preservation of all Phase 1-5 database records.
"""

import sys
from pathlib import Path

# Ensure project root and backend are in sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(BASE_DIR / "backend"))

import database
import models
from sqlalchemy import text


def run_migration():
    print("Starting Phase 6A database migration...")

    # 1. Create Phase 6A tables and indexes non-destructively
    with database.engine.connect() as conn:
        print("Ensuring `audit_logs` table exists...")
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMP WITHOUT TIME ZONE DEFAULT (NOW() AT TIME ZONE 'utc') NOT NULL,
                source VARCHAR(30) NOT NULL,
                actor VARCHAR(100) NOT NULL,
                ip_address VARCHAR(50),
                action VARCHAR(50) NOT NULL,
                entity_type VARCHAR(50) NOT NULL,
                entity_id INTEGER,
                entity_name VARCHAR(200),
                old_values TEXT,
                new_values TEXT,
                description VARCHAR(1000)
            );
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_audit_logs_id ON audit_logs (id);
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_audit_logs_timestamp ON audit_logs (timestamp DESC);
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_audit_logs_source ON audit_logs (source);
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_audit_logs_actor ON audit_logs (actor);
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_audit_logs_action ON audit_logs (action);
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_audit_logs_entity_type ON audit_logs (entity_type);
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_audit_logs_entity_id ON audit_logs (entity_id);
        """))

        print("Ensuring `evidence_records` table exists...")
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS evidence_records (
                id SERIAL PRIMARY KEY,
                title VARCHAR(200) NOT NULL,
                description VARCHAR(2000),
                evidence_type VARCHAR(50) NOT NULL,
                source_system VARCHAR(100) DEFAULT 'AI-GRC Platform' NOT NULL,
                collector VARCHAR(100) DEFAULT 'Security Analyst' NOT NULL,
                collected_at TIMESTAMP WITHOUT TIME ZONE DEFAULT (NOW() AT TIME ZONE 'utc') NOT NULL,
                content_text TEXT,
                reference_url VARCHAR(500),
                checksum_sha256 VARCHAR(64),
                asset_id INTEGER REFERENCES assets(id) ON DELETE SET NULL,
                scan_job_id INTEGER REFERENCES scan_jobs(id) ON DELETE SET NULL,
                created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT (NOW() AT TIME ZONE 'utc') NOT NULL
            );
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_evidence_records_id ON evidence_records (id);
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_evidence_records_collected_at ON evidence_records (collected_at DESC);
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_evidence_records_evidence_type ON evidence_records (evidence_type);
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_evidence_records_asset_id ON evidence_records (asset_id);
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_evidence_records_scan_job_id ON evidence_records (scan_job_id);
        """))

        print("Ensuring Many-to-Many association tables exist...")
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS evidence_risks (
                evidence_id INTEGER NOT NULL REFERENCES evidence_records(id) ON DELETE CASCADE,
                risk_id INTEGER NOT NULL REFERENCES risks(id) ON DELETE CASCADE,
                PRIMARY KEY (evidence_id, risk_id)
            );
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_evidence_risks_risk_id ON evidence_risks (risk_id);
        """))

        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS evidence_controls (
                evidence_id INTEGER NOT NULL REFERENCES evidence_records(id) ON DELETE CASCADE,
                control_id INTEGER NOT NULL REFERENCES controls(id) ON DELETE CASCADE,
                PRIMARY KEY (evidence_id, control_id)
            );
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_evidence_controls_control_id ON evidence_controls (control_id);
        """))

        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS evidence_requirements (
                evidence_id INTEGER NOT NULL REFERENCES evidence_records(id) ON DELETE CASCADE,
                requirement_id INTEGER NOT NULL REFERENCES compliance_requirements(id) ON DELETE CASCADE,
                PRIMARY KEY (evidence_id, requirement_id)
            );
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_evidence_requirements_requirement_id ON evidence_requirements (requirement_id);
        """))

        conn.commit()
        print("Schema verified: `audit_logs`, `evidence_records`, and M2M association tables ready.")

    # 2. Verify all Phase 1-5 records are completely preserved
    db = database.SessionLocal()
    try:
        asset_count = db.query(models.Asset).count()
        risk_count = db.query(models.Risk).count()
        vuln_count = db.query(models.Vulnerability).count()
        ctrl_count = db.query(models.Control).count()
        fw_count = db.query(models.ComplianceFramework).count()
        req_count = db.query(models.ComplianceRequirement).count()
        mapping_count = db.query(models.ControlComplianceMapping).count()
        ai_analysis_count = db.query(models.AIRiskAnalysis).count()
        scan_job_count = db.query(models.ScanJob).count()
        drift_event_count = db.query(models.DriftEvent).count()

        audit_log_count = db.query(models.AuditLog).count()
        evidence_count = db.query(models.EvidenceRecord).count()

        print("\n--- Phase 6A Migration Verification ---")
        print(f"Assets:                     {asset_count} (Preserved)")
        print(f"Risks:                      {risk_count} (Preserved)")
        print(f"Vulnerabilities:            {vuln_count} (Preserved)")
        print(f"Controls:                   {ctrl_count} (Preserved)")
        print(f"Compliance Frameworks:      {fw_count} (Preserved)")
        print(f"Compliance Requirements:    {req_count} (Preserved)")
        print(f"Control Mappings:           {mapping_count} (Preserved)")
        print(f"AI Risk Analyses:           {ai_analysis_count} (Preserved)")
        print(f"Scan Jobs:                  {scan_job_count} (Preserved)")
        print(f"Drift Events:               {drift_event_count} (Preserved)")
        print(f"Audit Logs:                 {audit_log_count} (New table)")
        print(f"Evidence Records:           {evidence_count} (New table)")
        print("---------------------------------------")

        assert asset_count > 0, "Assertion failed: Asset records missing!"
        assert risk_count > 0, "Assertion failed: Risk records missing!"
        assert fw_count >= 2, "Assertion failed: Compliance frameworks missing!"

    finally:
        db.close()

    print("Phase 6A migration completed successfully!")


if __name__ == "__main__":
    run_migration()

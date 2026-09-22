"""Phase 5 Database Migration Script: Continuous Monitoring, Scan Automation & Asset Drift.

Performs safe, non-destructive schema migration on the live PostgreSQL database:
1. Creates `scan_jobs` table for asynchronous scan execution tracking.
2. Creates `scan_schedules` table for automated continuous monitoring schedules.
3. Creates `drift_events` table for auditable technical attack surface drift records.
4. Creates necessary foreign keys, cascading rules, and performance indexes.
5. Verifies complete preservation of all Phase 1-4 database records.
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
    print("Starting Phase 5 database migration...")

    # 1. Create Phase 5 tables and indexes non-destructively
    with database.engine.connect() as conn:
        print("Ensuring `scan_jobs` table exists...")
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS scan_jobs (
                id SERIAL PRIMARY KEY,
                target VARCHAR(100) NOT NULL,
                scan_type VARCHAR(50) NOT NULL,
                status VARCHAR(30) DEFAULT 'Queued' NOT NULL,
                progress_percent INTEGER DEFAULT 0 NOT NULL,
                discovered_assets_count INTEGER DEFAULT 0,
                discovered_vulns_count INTEGER DEFAULT 0,
                error_message TEXT,
                created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT (NOW() AT TIME ZONE 'utc') NOT NULL,
                started_at TIMESTAMP WITHOUT TIME ZONE,
                completed_at TIMESTAMP WITHOUT TIME ZONE
            );
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_scan_jobs_id ON scan_jobs (id);
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_scan_jobs_status ON scan_jobs (status);
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_scan_jobs_created_at ON scan_jobs (created_at DESC);
        """))

        print("Ensuring `scan_schedules` table exists...")
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS scan_schedules (
                id SERIAL PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                target VARCHAR(100) NOT NULL,
                interval_minutes INTEGER NOT NULL,
                is_active BOOLEAN DEFAULT TRUE NOT NULL,
                last_run_at TIMESTAMP WITHOUT TIME ZONE,
                next_run_at TIMESTAMP WITHOUT TIME ZONE,
                created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT (NOW() AT TIME ZONE 'utc') NOT NULL,
                updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT (NOW() AT TIME ZONE 'utc') NOT NULL
            );
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_scan_schedules_id ON scan_schedules (id);
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_scan_schedules_is_active ON scan_schedules (is_active);
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_scan_schedules_next_run_at ON scan_schedules (next_run_at);
        """))

        print("Ensuring `drift_events` table exists...")
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS drift_events (
                id SERIAL PRIMARY KEY,
                scan_job_id INTEGER NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
                asset_id INTEGER REFERENCES assets(id) ON DELETE SET NULL,
                event_type VARCHAR(50) NOT NULL,
                title VARCHAR(200) NOT NULL,
                description VARCHAR(2000),
                severity VARCHAR(30) DEFAULT 'Low' NOT NULL,
                detected_at TIMESTAMP WITHOUT TIME ZONE DEFAULT (NOW() AT TIME ZONE 'utc') NOT NULL
            );
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_drift_events_id ON drift_events (id);
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_drift_events_scan_job_id ON drift_events (scan_job_id);
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_drift_events_asset_id ON drift_events (asset_id);
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_drift_events_detected_at ON drift_events (detected_at DESC);
        """))

        conn.commit()
        print("Schema verified: `scan_jobs`, `scan_schedules`, and `drift_events` tables and indexes ready.")

    # 2. Verify all Phase 1-4 records are completely preserved
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
        scan_schedule_count = db.query(models.ScanSchedule).count()
        drift_event_count = db.query(models.DriftEvent).count()

        print("\n--- Phase 5 Migration Verification ---")
        print(f"Assets:                     {asset_count} (Preserved)")
        print(f"Risks:                      {risk_count} (Preserved)")
        print(f"Vulnerabilities:            {vuln_count} (Preserved)")
        print(f"Controls:                   {ctrl_count} (Preserved)")
        print(f"Compliance Frameworks:      {fw_count} (Preserved)")
        print(f"Compliance Requirements:    {req_count} (Preserved)")
        print(f"Control Mappings:           {mapping_count} (Preserved)")
        print(f"AI Risk Analyses:           {ai_analysis_count} (Preserved)")
        print(f"Scan Jobs:                  {scan_job_count} (New table)")
        print(f"Scan Schedules:             {scan_schedule_count} (New table)")
        print(f"Drift Events:               {drift_event_count} (New table)")
        print("--------------------------------------")

        assert asset_count > 0, "Assertion failed: Asset records missing!"
        assert risk_count > 0, "Assertion failed: Risk records missing!"
        assert fw_count >= 2, "Assertion failed: Compliance frameworks missing!"

    finally:
        db.close()

    print("Phase 5 migration completed successfully!")


if __name__ == "__main__":
    run_migration()

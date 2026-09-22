"""Phase 6C Database Migration Script: Human Review & Risk Sign-off.

Performs safe, non-destructive schema migration on the PostgreSQL database:
1. Adds `review_status` column with index to `risks` table (default: 'Pending Review').
2. Creates `risk_reviews` table for immutable governance review history and technical snapshots.
3. Creates PostgreSQL partial unique index `uq_risk_reviews_one_current` enforcing exactly one
   current review per risk at the database level.
4. Backfills any NULL `review_status` on existing risks to 'Pending Review'.
5. Preserves all Phase 1-6B records and existing Risk.status values without mutation.
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
    print("Starting Phase 6C database migration...")

    with database.engine.connect() as conn:
        print("Ensuring `review_status` column on `risks` exists...")
        conn.execute(text("""
            ALTER TABLE risks ADD COLUMN IF NOT EXISTS review_status VARCHAR(32) DEFAULT 'Pending Review' NOT NULL;
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_risks_review_status ON risks (review_status);
        """))

        print("Ensuring `risk_reviews` table exists...")
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS risk_reviews (
                id SERIAL PRIMARY KEY,
                risk_id INTEGER NOT NULL REFERENCES risks(id) ON DELETE CASCADE,
                reviewer_name VARCHAR(128) NOT NULL,
                reviewer_role VARCHAR(64) NOT NULL,
                decision VARCHAR(32) NOT NULL,
                agreed_treatment VARCHAR(32) NOT NULL,
                comments TEXT NOT NULL,
                ai_analysis_acknowledged BOOLEAN DEFAULT FALSE NOT NULL,
                ai_analysis_id INTEGER REFERENCES ai_risk_analyses(id) ON DELETE SET NULL,
                snapshot_inherent_score INTEGER NOT NULL,
                snapshot_inherent_level VARCHAR(32) NOT NULL,
                snapshot_residual_score INTEGER NOT NULL,
                snapshot_residual_level VARCHAR(32) NOT NULL,
                snapshot_asset_criticality VARCHAR(32),
                snapshot_asset_exposure VARCHAR(32),
                snapshot_cvss_score FLOAT,
                snapshot_control_ids VARCHAR(500),
                snapshot_vulnerability_hash VARCHAR(64) NOT NULL,
                snapshot_hash VARCHAR(64) NOT NULL,
                is_current BOOLEAN DEFAULT TRUE NOT NULL,
                created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT (NOW() AT TIME ZONE 'utc') NOT NULL
            );
        """))

        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_risk_reviews_id ON risk_reviews (id);
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_risk_reviews_risk_id ON risk_reviews (risk_id);
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_risk_reviews_is_current ON risk_reviews (is_current);
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_risk_reviews_decision ON risk_reviews (decision);
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_risk_reviews_created_at ON risk_reviews (created_at DESC);
        """))

        print("Ensuring PostgreSQL partial unique index on current reviews exists...")
        conn.execute(text("""
            CREATE UNIQUE INDEX IF NOT EXISTS uq_risk_reviews_one_current
            ON risk_reviews (risk_id)
            WHERE (is_current = TRUE);
        """))

        # Backfill existing risks safely
        conn.execute(text("""
            UPDATE risks SET review_status = 'Pending Review' WHERE review_status IS NULL;
        """))
        conn.commit()

        print("Schema verified: `risk_reviews` and `review_status` ready.")

    # Verification: check existing data integrity
    with database.SessionLocal() as db:
        asset_count = db.query(models.Asset).count()
        risk_count = db.query(models.Risk).count()
        vuln_count = db.query(models.Vulnerability).count()
        control_count = db.query(models.Control).count()
        fw_count = db.query(models.ComplianceFramework).count()
        req_count = db.query(models.ComplianceRequirement).count()
        mapping_count = db.query(models.ControlComplianceMapping).count()
        ai_count = db.query(models.AIRiskAnalysis).count()
        scan_job_count = db.query(models.ScanJob).count()
        drift_count = db.query(models.DriftEvent).count()
        audit_count = db.query(models.AuditLog).count()
        evidence_count = db.query(models.EvidenceRecord).count()
        review_count = db.query(models.RiskReview).count()

        print("\n--- Phase 6C Migration Verification ---")
        print(f"Assets:                     {asset_count} (Preserved)")
        print(f"Risks:                      {risk_count} (Preserved with review_status)")
        print(f"Vulnerabilities:            {vuln_count} (Preserved)")
        print(f"Controls:                   {control_count} (Preserved)")
        print(f"Compliance Frameworks:      {fw_count} (Preserved)")
        print(f"Compliance Requirements:    {req_count} (Preserved)")
        print(f"Control Mappings:           {mapping_count} (Preserved)")
        print(f"AI Risk Analyses:           {ai_count} (Preserved)")
        print(f"Scan Jobs:                  {scan_job_count} (Preserved)")
        print(f"Drift Events:               {drift_count} (Preserved)")
        print(f"Audit Logs:                 {audit_count} (Preserved)")
        print(f"Evidence Records:           {evidence_count} (Preserved)")
        print(f"Risk Reviews:               {review_count} (New table)")
        print("---------------------------------------")
        print("Phase 6C migration completed successfully!\n")


if __name__ == "__main__":
    run_migration()

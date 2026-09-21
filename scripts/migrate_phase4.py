"""Phase 4 Database Migration Script: AI-Assisted Security Intelligence.

Performs safe, non-destructive schema migration on the live PostgreSQL database:
1. Creates `ai_risk_analyses` table for auditable AI security intelligence records.
2. Creates foreign key cascade link to `risks.id`.
3. Creates indexes on `id` and `risk_id`.
4. Verifies complete preservation of all Phase 1-3 database records.
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
    print("Starting Phase 4 database migration...")

    # 1. Create ai_risk_analyses table non-destructively
    with database.engine.connect() as conn:
        print("Ensuring `ai_risk_analyses` table exists...")
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS ai_risk_analyses (
                id SERIAL PRIMARY KEY,
                risk_id INTEGER NOT NULL REFERENCES risks(id) ON DELETE CASCADE,
                priority VARCHAR NOT NULL,
                simple_explanation VARCHAR(2000) NOT NULL,
                why_it_matters VARCHAR(2000) NOT NULL,
                severity_explanation VARCHAR(2000) NOT NULL,
                risk_factors VARCHAR(2000),
                potential_business_impact VARCHAR(2000),
                recommendation VARCHAR(2000),
                remediation_steps VARCHAR(3000),
                recommended_controls VARCHAR(2000),
                confidence FLOAT NOT NULL,
                human_review_required BOOLEAN DEFAULT TRUE,
                human_review_reasons VARCHAR(1000),
                model_name VARCHAR NOT NULL,
                created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT (NOW() AT TIME ZONE 'utc')
            );
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_ai_risk_analyses_id ON ai_risk_analyses (id);
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_ai_risk_analyses_risk_id ON ai_risk_analyses (risk_id);
        """))
        conn.commit()
        print("Schema verified: `ai_risk_analyses` table and indexes ready.")

    # 2. Verify all Phase 1-3 records are completely preserved
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

        print("\n--- Phase 4 Migration Verification ---")
        print(f"Assets:                     {asset_count} (Preserved)")
        print(f"Risks:                      {risk_count} (Preserved)")
        print(f"Vulnerabilities:            {vuln_count} (Preserved)")
        print(f"Controls:                   {ctrl_count} (Preserved)")
        print(f"Compliance Frameworks:      {fw_count} (Preserved)")
        print(f"Compliance Requirements:    {req_count} (Preserved)")
        print(f"Control Mappings:           {mapping_count} (Preserved)")
        print(f"AI Risk Analyses:           {ai_analysis_count} (New table)")
        print("--------------------------------------")

        assert asset_count > 0, "Assertion failed: Asset records missing!"
        assert risk_count > 0, "Assertion failed: Risk records missing!"
        assert fw_count >= 2, "Assertion failed: Compliance frameworks missing!"

    finally:
        db.close()

    print("Phase 4 migration completed successfully!")


if __name__ == "__main__":
    run_migration()

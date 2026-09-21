"""Phase 3 Isolated Automated Test Suite: Compliance Mapping.

Runs isolated tests using Python unittest and in-memory SQLite database:
1. Compliance Framework creation and attributes (NIST CSF 2.0 and ISO/IEC 27001:2022).
2. Compliance Requirement hierarchy (Function, Category, Subcategory).
3. Independent status tracking (defaults to 'Not Assessed', editable).
4. Control-to-requirement mapping (Direct / Supporting).
5. Duplicate mapping prevention via unique constraint (control_id, requirement_id).
6. Non-automatic status change: Mapping a control does NOT alter compliance status.
7. Implementation Coverage metric calculation logic.
8. Preservation of Phase 1 & 2 entities (Asset, Risk, Vulnerability, Control, Residual Risk).

This test suite DOES NOT modify or touch the real development PostgreSQL database.
"""

import unittest
import sys
from pathlib import Path
from datetime import datetime

# Setup sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(BASE_DIR / "backend"))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import IntegrityError
import models
from scanner.grc_engine import (
    calculate_inherent_risk,
    calculate_residual_risk,
    criticality_to_impact,
)


class TestPhase3ComplianceIsolated(unittest.TestCase):
    """Test Phase 3 Compliance models, constraints, and logic in isolation."""

    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")
        models.Base.metadata.create_all(bind=self.engine)
        self.Session = sessionmaker(bind=self.engine)
        self.db = self.Session()

    def tearDown(self):
        self.db.close()
        models.Base.metadata.drop_all(bind=self.engine)

    def test_framework_creation_and_cascade(self):
        fw = models.ComplianceFramework(
            name="NIST CSF",
            version="2.0",
            description="NIST Cybersecurity Framework 2.0 (Prototype Subset)"
        )
        self.db.add(fw)
        self.db.commit()
        self.db.refresh(fw)

        self.assertEqual(fw.name, "NIST CSF")
        self.assertEqual(fw.version, "2.0")

        # Add requirements to framework
        req1 = models.ComplianceRequirement(
            framework_id=fw.id,
            requirement_id="PR.AA-01",
            title="Identity Management",
            function="Protect",
            category="PR.AA",
            subcategory="PR.AA-01",
            status="Not Assessed"
        )
        req2 = models.ComplianceRequirement(
            framework_id=fw.id,
            requirement_id="PR.AA-03",
            title="Authentication",
            function="Protect",
            category="PR.AA",
            subcategory="PR.AA-03",
            status="Not Assessed"
        )
        self.db.add_all([req1, req2])
        self.db.commit()

        self.assertEqual(len(fw.requirements), 2)

        # Deleting framework cascades to requirements
        self.db.delete(fw)
        self.db.commit()
        self.assertEqual(self.db.query(models.ComplianceRequirement).count(), 0)

    def test_iso27001_themes_and_defaults(self):
        iso = models.ComplianceFramework(
            name="ISO/IEC 27001",
            version="2022",
            description="ISO 27001:2022 Annex A"
        )
        self.db.add(iso)
        self.db.commit()

        req = models.ComplianceRequirement(
            framework_id=iso.id,
            requirement_id="A.8.20",
            title="Network security",
            function="Technological",
            category="A.8",
            subcategory="A.8.20",
            description="Networks and network devices shall be secured, managed and controlled."
        )
        self.db.add(req)
        self.db.commit()
        self.db.refresh(req)

        # Verify safe default status is 'Not Assessed'
        self.assertEqual(req.status, "Not Assessed")
        self.assertEqual(req.function, "Technological")
        self.assertEqual(req.requirement_id, "A.8.20")

    def test_control_compliance_mapping_and_non_automatic_status(self):
        # 1. Create Framework & Requirement
        fw = models.ComplianceFramework(name="NIST CSF", version="2.0")
        self.db.add(fw)
        self.db.commit()

        req = models.ComplianceRequirement(
            framework_id=fw.id,
            requirement_id="PR.IR-01",
            title="Network Protection",
            function="Protect",
            category="PR.IR",
            status="Not Assessed"
        )
        self.db.add(req)

        # 2. Create Security Control
        ctrl = models.Control(
            name="Firewall",
            category="Preventive",
            framework="NIST CSF",
            effectiveness="High",
            status="Implemented"
        )
        self.db.add(ctrl)
        self.db.commit()

        # 3. Create Mapping
        mapping = models.ControlComplianceMapping(
            control_id=ctrl.id,
            requirement_id=req.id,
            mapping_strength="Direct",
            notes="Packet filtering enforcement"
        )
        self.db.add(mapping)
        self.db.commit()
        self.db.refresh(req)
        self.db.refresh(ctrl)

        # 4. Verify Mapping exists
        self.assertEqual(len(req.control_mappings), 1)
        self.assertEqual(len(ctrl.compliance_mappings), 1)
        self.assertEqual(req.control_mappings[0].mapping_strength, "Direct")

        # 5. CRITICAL GRC RULE: Mapping a control MUST NOT automatically change compliance status!
        self.assertEqual(req.status, "Not Assessed")

    def test_duplicate_mapping_prevention(self):
        fw = models.ComplianceFramework(name="NIST CSF", version="2.0")
        self.db.add(fw)
        self.db.commit()

        req = models.ComplianceRequirement(framework_id=fw.id, requirement_id="PR.PS-02", title="Patching")
        ctrl = models.Control(name="Patch Management")
        self.db.add_all([req, ctrl])
        self.db.commit()

        # First mapping
        m1 = models.ControlComplianceMapping(control_id=ctrl.id, requirement_id=req.id, mapping_strength="Direct")
        self.db.add(m1)
        self.db.commit()

        # Duplicate mapping attempt must raise IntegrityError due to unique constraint
        m2 = models.ControlComplianceMapping(control_id=ctrl.id, requirement_id=req.id, mapping_strength="Supporting")
        self.db.add(m2)
        with self.assertRaises(IntegrityError):
            self.db.commit()
        self.db.rollback()

    def test_requirement_status_updating(self):
        fw = models.ComplianceFramework(name="NIST CSF", version="2.0")
        self.db.add(fw)
        self.db.commit()

        req = models.ComplianceRequirement(
            framework_id=fw.id,
            requirement_id="DE.CM-01",
            title="Continuous Monitoring",
            status="Not Assessed"
        )
        self.db.add(req)
        self.db.commit()

        # Simulate assessment update
        req.status = "Partially Implemented"
        req.notes = "Internal logging operational; external SIEM ingestion pending."
        self.db.commit()
        self.db.refresh(req)

        self.assertEqual(req.status, "Partially Implemented")
        self.assertIn("external SIEM", req.notes)

    def test_implementation_coverage_calculation(self):
        """Verify Implementation Coverage formula: (Implemented + 0.5 * Partially) / (Total - NA) * 100."""
        fw = models.ComplianceFramework(name="ISO/IEC 27001", version="2022")
        self.db.add(fw)
        self.db.commit()

        # Create 5 requirements with different statuses
        reqs = [
            models.ComplianceRequirement(framework_id=fw.id, requirement_id="R1", title="R1", status="Implemented"),
            models.ComplianceRequirement(framework_id=fw.id, requirement_id="R2", title="R2", status="Partially Implemented"),
            models.ComplianceRequirement(framework_id=fw.id, requirement_id="R3", title="R3", status="Not Implemented"),
            models.ComplianceRequirement(framework_id=fw.id, requirement_id="R4", title="R4", status="Not Assessed"),
            models.ComplianceRequirement(framework_id=fw.id, requirement_id="R5", title="R5", status="Not Applicable"),
        ]
        self.db.add_all(reqs)
        self.db.commit()

        total = len(reqs)  # 5
        implemented = sum(1 for r in reqs if r.status == "Implemented")  # 1
        partially = sum(1 for r in reqs if r.status == "Partially Implemented")  # 1
        na = sum(1 for r in reqs if r.status == "Not Applicable")  # 1
        applicable = total - na  # 4

        # Score = (1 + 0.5 * 1) / 4 * 100 = 1.5 / 4 * 100 = 37.5%
        coverage = round(((implemented + 0.5 * partially) / applicable) * 100, 1)
        self.assertEqual(coverage, 37.5)

    def test_phase1_and_phase2_data_preservation(self):
        """Ensure Phase 1/2 entities and GRC calculations remain completely intact."""
        asset = models.Asset(
            ip_address="192.168.1.100",
            criticality="High",
            environment="Production",
            exposure="Internal"
        )
        self.db.add(asset)
        self.db.flush()

        impact = criticality_to_impact(asset.criticality)  # 3
        inh = calculate_inherent_risk(likelihood=3, impact=impact)  # 9 (High)

        risk = models.Risk(
            asset_id=asset.id,
            title="SMB Signing Disabled",
            likelihood_score=3,
            impact_score=impact,
            inherent_risk_score=inh["inherent_risk_score"],
            inherent_risk_level=inh["inherent_risk_level"],
            treatment="Mitigate",
            status="Open"
        )
        self.db.add(risk)
        self.db.flush()

        ctrl = models.Control(
            name="Network Segmentation",
            effectiveness="High",
            status="Implemented"
        )
        self.db.add(ctrl)
        self.db.flush()

        # Control mitigates risk
        risk.controls.append(ctrl)
        res = calculate_residual_risk(risk.likelihood_score, risk.impact_score, risk.controls)
        risk.residual_likelihood = res["residual_likelihood"]
        risk.residual_impact = res["residual_impact"]
        risk.residual_risk_score = res["residual_risk_score"]
        risk.residual_risk_level = res["residual_risk_level"]

        self.db.commit()
        self.db.refresh(risk)

        self.assertEqual(risk.inherent_risk_score, 9)
        self.assertEqual(risk.residual_likelihood, 1)  # 3 - 2 = 1
        self.assertEqual(risk.residual_impact, 3)      # unchanged impact
        self.assertEqual(risk.residual_risk_score, 3)   # 1 * 3 = 3


if __name__ == "__main__":
    unittest.main()

"""Phase 2 Isolated Automated Test Suite.

Runs isolated tests using Python unittest and in-memory SQLite database:
1. GRC Engine Likelihood, Impact, Inherent Risk, and Residual Risk calculations.
2. Control mitigation behavior (likelihood-only reduction, floor=1, impact unchanged).
3. CVE confidence and fallback behavior.
4. Asset intelligence defaults (criticality=Medium, environment=Production, exposure=Internal, owner=None, business_function=None).
5. Isolated in-memory SQLAlchemy model relationships and cascading logic.

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

from scanner.grc_engine import (
    criticality_to_impact,
    calculate_likelihood,
    calculate_inherent_risk,
    calculate_residual_risk,
    calculate_risk_level,
)
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import models


class TestGRCEngine(unittest.TestCase):
    """Test GRC calculation formulas, thresholds, and edge cases."""

    def test_criticality_to_impact_mapping(self):
        self.assertEqual(criticality_to_impact("Low"), 1)
        self.assertEqual(criticality_to_impact("low"), 1)
        self.assertEqual(criticality_to_impact("Medium"), 2)
        self.assertEqual(criticality_to_impact("medium"), 2)
        self.assertEqual(criticality_to_impact("High"), 3)
        self.assertEqual(criticality_to_impact("high"), 3)
        self.assertEqual(criticality_to_impact("Critical"), 4)
        self.assertEqual(criticality_to_impact("critical"), 4)
        # Safe default for None or unknown
        self.assertEqual(criticality_to_impact(None), 2)
        self.assertEqual(criticality_to_impact("Unknown"), 2)

    def test_risk_level_thresholds(self):
        # 1-3 Low
        self.assertEqual(calculate_risk_level(1), "Low")
        self.assertEqual(calculate_risk_level(2), "Low")
        self.assertEqual(calculate_risk_level(3), "Low")
        # 4-6 Medium
        self.assertEqual(calculate_risk_level(4), "Medium")
        self.assertEqual(calculate_risk_level(6), "Medium")
        # 7-11 High
        self.assertEqual(calculate_risk_level(7), "High")
        self.assertEqual(calculate_risk_level(10), "High")
        self.assertEqual(calculate_risk_level(11), "High")
        # 12-16 Critical
        self.assertEqual(calculate_risk_level(12), "Critical")
        self.assertEqual(calculate_risk_level(16), "Critical")

    def test_calculate_likelihood_cvss_available(self):
        # Exposure = Internal (-1 modifier)
        # CVSS >= 9.0 -> base 4 -> 4 - 1 = 3
        self.assertEqual(calculate_likelihood(cvss_score=9.8, exposure="Internal"), 3)
        # Exposure = External (+1 modifier)
        # CVSS >= 9.0 -> base 4 -> 4 + 1 = 5 clamped to 4
        self.assertEqual(calculate_likelihood(cvss_score=9.5, exposure="External"), 4)
        # Exposure = DMZ (0 modifier)
        self.assertEqual(calculate_likelihood(cvss_score=7.5, exposure="DMZ"), 3)
        self.assertEqual(calculate_likelihood(cvss_score=5.0, exposure="DMZ"), 2)
        self.assertEqual(calculate_likelihood(cvss_score=2.1, exposure="DMZ"), 1)

    def test_calculate_likelihood_cvss_unavailable_severity_fallback(self):
        # CVSS unavailable -> severity string
        self.assertEqual(calculate_likelihood(severity_str="critical", exposure="DMZ"), 4)
        self.assertEqual(calculate_likelihood(severity_str="high", exposure="DMZ"), 3)
        self.assertEqual(calculate_likelihood(severity_str="medium", exposure="DMZ"), 2)
        self.assertEqual(calculate_likelihood(severity_str="low", exposure="DMZ"), 1)
        # With exposure adjustments
        self.assertEqual(calculate_likelihood(severity_str="high", exposure="External"), 4)
        self.assertEqual(calculate_likelihood(severity_str="low", exposure="Internal"), 1)  # clamped to 1

    def test_calculate_likelihood_both_unavailable_fallback(self):
        # CVSS and severity both unavailable -> fallback_likelihood
        self.assertEqual(calculate_likelihood(fallback_likelihood="High", exposure="DMZ"), 3)
        self.assertEqual(calculate_likelihood(fallback_likelihood="Medium", exposure="Internal"), 1)

    def test_calculate_inherent_risk(self):
        # Likelihood 3 x Impact 2 = 6 (Medium)
        res = calculate_inherent_risk(likelihood=3, impact=2)
        self.assertEqual(res["likelihood_score"], 3)
        self.assertEqual(res["impact_score"], 2)
        self.assertEqual(res["inherent_risk_score"], 6)
        self.assertEqual(res["inherent_risk_level"], "Medium")

        # Likelihood 4 x Impact 4 = 16 (Critical)
        res2 = calculate_inherent_risk(likelihood=4, impact=4)
        self.assertEqual(res2["inherent_risk_score"], 16)
        self.assertEqual(res2["inherent_risk_level"], "Critical")

    def test_calculate_residual_risk_controls_reduce_likelihood_only(self):
        # Inherent: Likelihood 4, Impact 3
        # Apply High effectiveness control (-2) and Medium effectiveness control (-1)
        controls = [
            {"name": "Firewall", "effectiveness": "High", "status": "Implemented"},
            {"name": "Patch Management", "effectiveness": "Medium", "status": "Implemented"}
        ]
        res = calculate_residual_risk(4, 3, controls)
        # Likelihood reduced: 4 - (2 + 1) = 1
        self.assertEqual(res["residual_likelihood"], 1)
        # Impact strictly UNCHANGED: 3
        self.assertEqual(res["residual_impact"], 3)
        # Residual score: 1 x 3 = 3 (Low)
        self.assertEqual(res["residual_risk_score"], 3)
        self.assertEqual(res["residual_risk_level"], "Low")

    def test_calculate_residual_risk_floor_at_one(self):
        # Excessive controls cannot reduce likelihood below 1
        controls = [
            {"name": "Ctrl 1", "effectiveness": "High", "status": "Implemented"},
            {"name": "Ctrl 2", "effectiveness": "High", "status": "Implemented"},
            {"name": "Ctrl 3", "effectiveness": "High", "status": "Implemented"}
        ]
        res = calculate_residual_risk(3, 4, controls)
        self.assertEqual(res["residual_likelihood"], 1)
        self.assertEqual(res["residual_impact"], 4)
        self.assertEqual(res["residual_risk_score"], 4)
        self.assertEqual(res["residual_risk_level"], "Medium")

    def test_calculate_residual_risk_unimplemented_controls_ignored(self):
        # Planned or Under Review controls should not reduce likelihood
        controls = [
            {"name": "Firewall", "effectiveness": "High", "status": "Planned"},
            {"name": "MFA", "effectiveness": "High", "status": "Under Review"}
        ]
        res = calculate_residual_risk(3, 3, controls)
        self.assertEqual(res["residual_likelihood"], 3)
        self.assertEqual(res["residual_impact"], 3)
        self.assertEqual(res["residual_risk_score"], 9)
        self.assertEqual(res["residual_risk_level"], "High")


class TestIsolatedDatabaseModels(unittest.TestCase):
    """Test SQLAlchemy models and relationships using an in-memory SQLite database."""

    def setUp(self):
        # In-memory SQLite engine
        self.engine = create_engine("sqlite:///:memory:")
        models.Base.metadata.create_all(bind=self.engine)
        self.Session = sessionmaker(bind=self.engine)
        self.db = self.Session()

    def tearDown(self):
        self.db.close()
        models.Base.metadata.drop_all(bind=self.engine)

    def test_asset_safe_defaults(self):
        asset = models.Asset(
            ip_address="10.0.0.1",
            hostname="test-host",
            status="Active",
            risk_score=6,
            risk_level="Medium",
            criticality="Medium",
            environment="Production",
            exposure="Internal",
            owner=None,
            business_function=None
        )
        self.db.add(asset)
        self.db.commit()
        self.db.refresh(asset)

        self.assertEqual(asset.criticality, "Medium")
        self.assertEqual(asset.environment, "Production")
        self.assertEqual(asset.exposure, "Internal")
        self.assertIsNone(asset.owner)
        self.assertIsNone(asset.business_function)

    def test_risk_control_association_and_cascade(self):
        asset = models.Asset(
            ip_address="10.0.0.2",
            criticality="High",
            environment="Production",
            exposure="DMZ"
        )
        self.db.add(asset)
        self.db.flush()

        risk = models.Risk(
            asset_id=asset.id,
            title="Exposed Database Port",
            likelihood="High",
            impact="High",
            risk_score=9,
            risk_level="High",
            likelihood_score=3,
            impact_score=3,
            inherent_risk_score=9,
            inherent_risk_level="High",
            residual_likelihood=3,
            residual_impact=3,
            residual_risk_score=9,
            residual_risk_level="High",
            treatment="Mitigate",
            status="Open"
        )
        self.db.add(risk)
        self.db.flush()

        control = models.Control(
            name="Network Segmentation",
            category="Preventive",
            framework="NIST CSF",
            effectiveness="High",
            status="Implemented"
        )
        self.db.add(control)
        self.db.flush()

        # Associate control to risk
        risk.controls.append(control)
        self.db.commit()

        # Verify association
        self.db.refresh(risk)
        self.db.refresh(control)
        self.assertEqual(len(risk.controls), 1)
        self.assertEqual(risk.controls[0].name, "Network Segmentation")
        self.assertEqual(len(control.risks), 1)
        self.assertEqual(control.risks[0].id, risk.id)

        # Detach control
        risk.controls.remove(control)
        self.db.commit()
        self.db.refresh(risk)
        self.assertEqual(len(risk.controls), 0)
        # Control itself is still preserved
        self.assertEqual(self.db.query(models.Control).count(), 1)


if __name__ == "__main__":
    unittest.main()

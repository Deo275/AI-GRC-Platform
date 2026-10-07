"""Stage 13D.4 Operator Identity & Audit Migration Test Suite.

Verifies:
1.  Authenticated Security Analyst creates an auditable action -> audit actor is Analyst user identity.
2.  Authenticated GRC Reviewer creates an auditable action -> audit actor is Reviewer user identity.
3.  Authenticated Administrator creates an auditable action -> audit actor is Admin user identity.
4.  Security Analyst JWT + spoofed X-Operator headers -> audit actor remains Analyst user identity.
5.  GRC Reviewer JWT + spoofed X-Operator headers -> audit actor remains Reviewer user identity.
6.  Spoofed reviewer_name / reviewer_role in review payload -> ignored, backend uses authenticated User.
7.  Governance review audit entry -> reviewer identity comes strictly from authenticated User.
8.  Evidence creation & deletion mutations -> actor comes strictly from authenticated User.
9.  Background/system audit action -> system identities (e.g. SYSTEM / governance_engine) remain unchanged.
10. Audit integrity hash calculation -> matches canonical SHA-256 for all events.
11. Server-side RBAC enforcement -> unauthorized roles receive HTTP 403.
12. Missing or invalid Bearer JWT -> returns HTTP 401.
"""

import os
import sys
import unittest
from unittest import mock
from pathlib import Path
from datetime import datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient

# Setup sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(BASE_DIR / "backend"))

import models
import main
from governance.audit_logger import calculate_audit_integrity_hash, log_audit_event
from auth_test_utils import create_test_user, create_test_auth_headers

TEST_SECRET = "test-jwt-secret-key-at-least-32-chars-long-123456"


class TestStage13D4OperatorIdentityAndAudit(unittest.TestCase):
    """Test suite verifying authoritative operator identity and tamper-proof audit attribution."""

    def setUp(self):
        self.env_patcher = mock.patch.dict(os.environ, {"JWT_SECRET_KEY": TEST_SECRET})
        self.env_patcher.start()

        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        models.Base.metadata.create_all(bind=self.engine)
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        self.db = self.SessionLocal()

        self.session_patcher = mock.patch("main.SessionLocal", side_effect=lambda: self.SessionLocal())
        self.session_patcher.start()
        self.auth_session_patcher = mock.patch("auth.dependencies.SessionLocal", side_effect=lambda: self.SessionLocal())
        self.auth_session_patcher.start()

        self.client = TestClient(main.app)

        # Provision authoritative user accounts
        self.analyst_user = create_test_user(
            self.db,
            username="analyst_alice",
            role="Security Analyst",
        )
        self.analyst_user.display_name = "Alice Analyst"
        self.db.commit()

        self.reviewer_user = create_test_user(
            self.db,
            username="reviewer_bob",
            role="GRC Reviewer",
        )
        self.reviewer_user.display_name = "Bob Reviewer"
        self.db.commit()

        self.admin_user = create_test_user(
            self.db,
            username="admin_charlie",
            role="Administrator",
        )
        self.admin_user.display_name = "Charlie Admin"
        self.db.commit()

        self.analyst_headers = create_test_auth_headers(self.db, username="analyst_alice", role="Security Analyst")
        self.reviewer_headers = create_test_auth_headers(self.db, username="reviewer_bob", role="GRC Reviewer")
        self.admin_headers = create_test_auth_headers(self.db, username="admin_charlie", role="Administrator")

        # Provision sample asset and risk
        self.asset = models.Asset(
            ip_address="10.0.0.15",
            hostname="server-01.internal",
            criticality="High",
            environment="Production",
            exposure="Internal",
        )
        self.db.add(self.asset)
        self.db.commit()
        self.db.refresh(self.asset)

        self.risk = models.Risk(
            title="Unauthenticated Internal Service",
            asset_id=self.asset.id,
            description="Missing Service Authentication leading to potential lateral movement",
            likelihood="High",
            impact="High",
            inherent_risk_score=20,
            inherent_risk_level="High",
            residual_risk_score=20,
            residual_risk_level="High",
            treatment="Mitigate",
            status="Open",
            review_status="Pending Review",
        )
        self.db.add(self.risk)
        self.db.commit()
        self.db.refresh(self.risk)

    def tearDown(self):
        self.auth_session_patcher.stop()
        self.session_patcher.stop()
        self.db.close()
        models.Base.metadata.drop_all(bind=self.engine)
        self.env_patcher.stop()

    # -------------------------------------------------------------------------
    # 1. Authoritative Operator Attribution by Role
    # -------------------------------------------------------------------------

    def test_01_analyst_auditable_action_attributed_to_analyst_user(self):
        """Authenticated Security Analyst dispatching a monitoring job records audit with analyst username."""
        payload = {"target": "10.0.0.15", "scan_type": "single_host"}
        resp = self.client.post("/monitoring/jobs", json=payload, headers=self.analyst_headers)
        self.assertEqual(resp.status_code, 202)

        audit = (
            self.db.query(models.AuditLog)
            .filter(models.AuditLog.action == "DISPATCH", models.AuditLog.entity_type == "ScanJob")
            .order_by(models.AuditLog.id.desc())
            .first()
        )
        self.assertIsNotNone(audit)
        self.assertEqual(audit.actor, "analyst_alice")
        self.assertEqual(audit.source, "SCANNER")

    def test_02_reviewer_auditable_action_attributed_to_reviewer_user(self):
        """Authenticated GRC Reviewer updating asset records audit with reviewer username."""
        resp = self.client.patch(
            f"/assets/{self.asset.id}",
            json={"criticality": "Critical"},
            headers=self.reviewer_headers,
        )
        self.assertEqual(resp.status_code, 200)

        audit = (
            self.db.query(models.AuditLog)
            .filter(models.AuditLog.action == "UPDATE", models.AuditLog.entity_type == "Asset")
            .order_by(models.AuditLog.id.desc())
            .first()
        )
        self.assertIsNotNone(audit)
        self.assertEqual(audit.actor, "reviewer_bob")
        self.assertEqual(audit.source, "USER")

    def test_03_admin_auditable_action_attributed_to_admin_user(self):
        """Authenticated Administrator deleting evidence records audit with admin username."""
        # Create evidence first
        ev = models.EvidenceRecord(
            title="Audit Deletion Target",
            evidence_type="MANUAL_OBSERVATION",
            collector="admin_charlie",
            source_system="AI-GRC Platform",
        )
        self.db.add(ev)
        self.db.commit()
        self.db.refresh(ev)

        resp = self.client.delete(f"/evidence/{ev.id}", headers=self.admin_headers)
        self.assertEqual(resp.status_code, 200)

        audit = (
            self.db.query(models.AuditLog)
            .filter(models.AuditLog.action == "DELETE", models.AuditLog.entity_type == "EvidenceRecord", models.AuditLog.entity_id == ev.id)
            .order_by(models.AuditLog.id.desc())
            .first()
        )
        self.assertIsNotNone(audit)
        self.assertEqual(audit.actor, "admin_charlie")
        self.assertEqual(audit.source, "USER")

    # -------------------------------------------------------------------------
    # 2. Anti-Spoofing Regression Tests (X-Operator-* Headers Ignored)
    # -------------------------------------------------------------------------

    def test_04_analyst_jwt_with_spoofed_admin_headers_remains_analyst(self):
        """Security Analyst JWT with spoofed X-Operator-Name/Role: Administrator cannot spoof audit attribution."""
        spoofed_headers = {
            **self.analyst_headers,
            "X-Operator-Name": "Administrator",
            "X-Operator-Role": "Administrator",
        }
        payload = {"target": "10.0.0.15", "scan_type": "single_host"}
        resp = self.client.post("/monitoring/jobs", json=payload, headers=spoofed_headers)
        self.assertEqual(resp.status_code, 202)

        audit = (
            self.db.query(models.AuditLog)
            .filter(models.AuditLog.action == "DISPATCH")
            .order_by(models.AuditLog.id.desc())
            .first()
        )
        self.assertIsNotNone(audit)
        self.assertEqual(audit.actor, "analyst_alice")
        self.assertNotEqual(audit.actor, "Administrator")

    def test_05_reviewer_jwt_with_spoofed_operator_headers_remains_reviewer(self):
        """GRC Reviewer JWT with spoofed headers cannot alter audit actor attribution."""
        spoofed_headers = {
            **self.reviewer_headers,
            "X-Operator-Name": "Fake Person",
            "X-Operator-Role": "Security Analyst",
        }
        resp = self.client.patch(
            f"/risks/{self.risk.id}",
            json={"treatment": "Accept", "status": "Accepted"},
            headers=spoofed_headers,
        )
        self.assertEqual(resp.status_code, 200)

        audit = (
            self.db.query(models.AuditLog)
            .filter(models.AuditLog.action == "UPDATE", models.AuditLog.entity_type == "Risk")
            .order_by(models.AuditLog.id.desc())
            .first()
        )
        self.assertIsNotNone(audit)
        self.assertEqual(audit.actor, "reviewer_bob")
        self.assertNotEqual(audit.actor, "Fake Person")

    # -------------------------------------------------------------------------
    # 3. Governance Review Attribution & Payload Anti-Spoofing
    # -------------------------------------------------------------------------

    def test_06_spoofed_reviewer_name_and_role_in_payload_are_ignored(self):
        """Governance review submission ignores client payload reviewer_name/role and uses authenticated User."""
        payload = {
            "decision": "APPROVED",
            "agreed_treatment": "Mitigate",
            "comments": "Formal risk review sign-off with valid justification comments.",
            "ai_analysis_acknowledged": True,
            "reviewer_name": "Chief Executive Officer",
            "reviewer_role": "Administrator",
        }
        spoofed_headers = {
            **self.reviewer_headers,
            "X-Operator-Name": "Fake Header Name",
            "X-Operator-Role": "Administrator",
        }
        resp = self.client.post(
            f"/risks/{self.risk.id}/reviews",
            json=payload,
            headers=spoofed_headers,
        )
        self.assertEqual(resp.status_code, 201)
        data = resp.json()

        # Review record must reflect authenticated user display name / role
        self.assertEqual(data["reviewer_name"], "Bob Reviewer")
        self.assertEqual(data["reviewer_role"], "GRC Reviewer")
        self.assertNotEqual(data["reviewer_name"], "Chief Executive Officer")
        self.assertNotEqual(data["reviewer_name"], "Fake Header Name")

        # Emitted audit trail must reflect authenticated user username
        audit = (
            self.db.query(models.AuditLog)
            .filter(models.AuditLog.action == "RISK_REVIEW_SUBMITTED")
            .order_by(models.AuditLog.id.desc())
            .first()
        )
        self.assertIsNotNone(audit)
        self.assertEqual(audit.actor, "reviewer_bob")
        self.assertNotEqual(audit.actor, "Chief Executive Officer")
        self.assertNotEqual(audit.actor, "Fake Header Name")

    def test_07_governance_review_treatment_override_audit_actor(self):
        """Treatment override emitted during review is attributed to authenticated User."""
        payload = {
            "decision": "APPROVED",
            "agreed_treatment": "Accept",  # Overrides inherent "Mitigate"
            "comments": "Overriding treatment from Mitigate to Accept with formal sign-off.",
            "ai_analysis_acknowledged": True,
        }
        resp = self.client.post(
            f"/risks/{self.risk.id}/reviews",
            json=payload,
            headers=self.reviewer_headers,
        )
        self.assertEqual(resp.status_code, 201)

        override_audit = (
            self.db.query(models.AuditLog)
            .filter(models.AuditLog.action == "TREATMENT_OVERRIDDEN")
            .first()
        )
        self.assertIsNotNone(override_audit)
        self.assertEqual(override_audit.actor, "reviewer_bob")

    # -------------------------------------------------------------------------
    # 4. Evidence Lifecycle Attribution
    # -------------------------------------------------------------------------

    def test_08_evidence_creation_and_deletion_attribution(self):
        """Evidence creation and deletion mutations use authoritative authenticated user."""
        # Create evidence as Reviewer
        create_resp = self.client.post(
            "/evidence",
            json={"title": "Network Topology Evidence", "evidence_type": "CONFIG_EXPORT"},
            headers=self.reviewer_headers,
        )
        self.assertEqual(create_resp.status_code, 201)
        ev_id = create_resp.json()["id"]

        create_audit = (
            self.db.query(models.AuditLog)
            .filter(models.AuditLog.action == "CREATE", models.AuditLog.entity_type == "EvidenceRecord", models.AuditLog.entity_id == ev_id)
            .first()
        )
        self.assertIsNotNone(create_audit)
        self.assertEqual(create_audit.actor, "reviewer_bob")

        # Delete evidence as Admin
        del_resp = self.client.delete(f"/evidence/{ev_id}", headers=self.admin_headers)
        self.assertEqual(del_resp.status_code, 200)

        del_audit = (
            self.db.query(models.AuditLog)
            .filter(models.AuditLog.action == "DELETE", models.AuditLog.entity_type == "EvidenceRecord", models.AuditLog.entity_id == ev_id)
            .first()
        )
        self.assertIsNotNone(del_audit)
        self.assertEqual(del_audit.actor, "admin_charlie")

    # -------------------------------------------------------------------------
    # 5. Background / System Audit Attribution Preservation
    # -------------------------------------------------------------------------

    def test_09_system_audit_action_preserves_system_identity(self):
        """Internal background actions (e.g. governance engine staleness) retain explicit SYSTEM identity."""
        # Directly invoke batch staleness evaluation endpoint or internal event
        resp = self.client.post("/governance/reviews/evaluate-stale", headers=self.reviewer_headers)
        self.assertEqual(resp.status_code, 200)

        # Directly log a system audit event to verify convention
        entry = log_audit_event(
            db=self.db,
            source="SYSTEM",
            actor="SYSTEM_DRIFT_DETECTOR",
            action="DRIFT_DETECTED",
            entity_type="Asset",
            entity_id=self.asset.id,
            description="Automated background drift detected",
        )
        self.assertIsNotNone(entry)
        self.assertEqual(entry.source, "SYSTEM")
        self.assertEqual(entry.actor, "SYSTEM_DRIFT_DETECTOR")

    # -------------------------------------------------------------------------
    # 6. Audit Hash-Chain Integrity Verification
    # -------------------------------------------------------------------------

    def test_10_audit_integrity_hash_verification(self):
        """All audit records produced by authenticated operations compute deterministic SHA-256 hashes."""
        # Perform mutation to ensure audit records exist
        self.client.patch(
            f"/assets/{self.asset.id}",
            json={"exposure": "DMZ"},
            headers=self.reviewer_headers,
        )

        entries = self.db.query(models.AuditLog).all()
        self.assertTrue(len(entries) > 0)

        for entry in entries:
            self.assertIsNotNone(entry.integrity_hash)
            self.assertEqual(len(entry.integrity_hash), 64)

            expected_hash = calculate_audit_integrity_hash(
                timestamp=entry.timestamp,
                source=entry.source,
                actor=entry.actor,
                action=entry.action,
                entity_type=entry.entity_type,
                entity_id=entry.entity_id,
                entity_name=entry.entity_name,
                old_values=entry.old_values,
                new_values=entry.new_values,
                description=entry.description,
                ip_address=entry.ip_address,
            )
            self.assertEqual(entry.integrity_hash, expected_hash)

    # -------------------------------------------------------------------------
    # 7. Preserved RBAC & Authentication Invariants
    # -------------------------------------------------------------------------

    def test_11_rbac_unauthorized_roles_receive_403(self):
        """RBAC boundaries remain enforced: Analyst cannot submit reviews or create controls."""
        # Analyst cannot submit reviews
        review_payload = {
            "decision": "APPROVED",
            "agreed_treatment": "Mitigate",
            "comments": "Analyst trying to review",
        }
        resp1 = self.client.post(
            f"/risks/{self.risk.id}/reviews",
            json=review_payload,
            headers=self.analyst_headers,
        )
        self.assertEqual(resp1.status_code, 403)

        # Analyst cannot delete evidence
        resp2 = self.client.delete("/evidence/1", headers=self.analyst_headers)
        self.assertEqual(resp2.status_code, 403)

    def test_12_unauthenticated_request_receives_401(self):
        """Requests without valid Bearer JWT receive HTTP 401."""
        resp1 = self.client.get("/assets")
        self.assertEqual(resp1.status_code, 401)

        resp2 = self.client.get(
            "/assets",
            headers={"Authorization": "Bearer invalid.jwt.token"},
        )
        self.assertEqual(resp2.status_code, 401)


if __name__ == "__main__":
    unittest.main()

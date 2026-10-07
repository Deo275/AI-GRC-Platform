"""Phase 6C Isolated Automated Test Suite: Human Review & Risk Sign-Off Workflow.

Comprehensive tests using Python unittest and in-memory SQLite:
1.  test_risk_review_model_fields_and_defaults
2.  test_partial_unique_index_enforces_single_current_review_at_db_level
3.  test_multiple_historical_inactive_reviews_allowed
4.  test_risk_review_status_defaults_to_pending_review
5.  test_preserves_existing_risk_status_values_without_mutation
6.  test_heuristic_vulnerability_correlation_matches_relevant_only
7.  test_heuristic_vulnerability_correlation_ignores_unrelated_on_same_asset
8.  test_deterministic_vulnerability_hash_and_snapshot_hash
9.  test_submit_approved_review_success_and_status_transition
10. test_submit_rejected_review_success
11. test_submit_changes_requested_review_success
12. test_submit_review_rejects_invalid_decision
13. test_submit_review_rejects_empty_or_short_comments
14. test_operator_attribution_metadata_headers
15. test_ai_acknowledgement_flag_semantics
16. test_historical_review_inactivation_on_new_review
17. test_treatment_override_updates_risk_and_emits_audit_event
18. test_treatment_override_rejects_invalid_treatment_value
19. test_stale_detection_on_inherent_score_change
20. test_stale_detection_on_residual_score_change
21. test_stale_detection_on_asset_criticality_change
22. test_stale_detection_on_asset_exposure_change
23. test_stale_detection_on_control_linkage_change
24. test_stale_detection_on_relevant_vulnerability_change
25. test_stale_detection_ignores_unrelated_vulnerability_change_on_same_asset
26. test_stale_detection_on_relevant_drift_event
27. test_stale_detection_ignores_unrelated_drift_event
28. test_stale_detection_ignores_non_material_risk_metadata_changes
29. test_stale_audit_event_deduplication_on_repeated_get_reviews
30. test_api_submit_and_get_risk_reviews
31. test_api_get_pending_reviews_queue_and_filters
32. test_api_bulk_evaluate_stale_endpoint

Zero external dependencies; does not require live PostgreSQL or network.
"""

import hashlib
import json
import unittest
from unittest import mock
from datetime import datetime, timedelta
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient

import sys
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(BASE_DIR / "backend"))

import models
from governance.review_manager import (
    get_relevant_vulnerabilities_for_risk,
    calculate_vulnerability_hash,
    calculate_review_snapshot_hash,
    evaluate_review_staleness,
    submit_risk_review,
    get_or_evaluate_risk_reviews,
    format_risk_review,
    VALID_DECISIONS,
    VALID_TREATMENTS,
)
from governance.audit_logger import log_audit_event
import main


class BasePhase6CIsolatedTestCase(unittest.TestCase):
    """Sets up an isolated in-memory SQLite database for each test."""

    def setUp(self):
        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        models.Base.metadata.create_all(bind=self.engine)
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        self.db = self.SessionLocal()

        # Seed foundational test asset
        self.asset = models.Asset(
            ip_address="10.0.0.5",
            hostname="db-primary.internal",
            criticality="High",
            environment="Production",
            exposure="Internal",
            owner="SecOps",
            business_function="Core Database",
        )
        self.db.add(self.asset)
        self.db.commit()
        self.db.refresh(self.asset)

        # Seed test control
        self.control = models.Control(
            name="TLS Enforcement",
            description="Enforce TLS 1.3 on PostgreSQL port 5432",
            category="Technical",
            framework="NIST CSF",
            effectiveness="High",
            status="Implemented",
        )
        self.db.add(self.control)
        self.db.commit()
        self.db.refresh(self.control)

        # Seed test risk
        self.risk = models.Risk(
            asset_id=self.asset.id,
            title="PostgreSQL Cleartext Traffic on Port 5432",
            description="Database service running on port 5432 allows unencrypted connections",
            likelihood="High",
            impact="High",
            likelihood_score=3,
            impact_score=3,
            inherent_risk_score=9,
            inherent_risk_level="High",
            residual_risk_score=6,
            residual_risk_level="Medium",
            treatment="Mitigate",
            status="Open",
            review_status="Pending Review",
            risk_owner="SecOps Lead",
        )
        self.db.add(self.risk)
        self.db.commit()
        self.db.refresh(self.risk)

        # Attach control to risk
        self.risk.controls.append(self.control)
        self.db.commit()

        # Seed relevant vulnerability (port 5432 postgresql)
        self.vuln_relevant = models.Vulnerability(
            asset_id=self.asset.id,
            cve="CVE-2023-5432",
            title="PostgreSQL Cleartext Auth Bypass",
            port=5432,
            service="postgresql",
            cvss_score=7.5,
            severity="High",
        )
        self.db.add(self.vuln_relevant)

        # Seed unrelated vulnerability on the same asset (port 22 ssh)
        self.vuln_unrelated = models.Vulnerability(
            asset_id=self.asset.id,
            cve="CVE-2023-2222",
            title="OpenSSH Weak MAC",
            port=22,
            service="ssh",
            cvss_score=5.0,
            severity="Medium",
        )
        self.db.add(self.vuln_unrelated)
        self.db.commit()
        self.db.refresh(self.vuln_relevant)
        self.db.refresh(self.vuln_unrelated)

    def tearDown(self):
        self.db.close()
        models.Base.metadata.drop_all(bind=self.engine)


class TestRiskReviewModelAndDatabaseConstraints(BasePhase6CIsolatedTestCase):
    """Unit tests verifying the database model, schema constraints, and partial unique index."""

    def test_risk_review_model_fields_and_defaults(self):
        review = models.RiskReview(
            risk_id=self.risk.id,
            reviewer_name="Alice SecOps",
            reviewer_role="Compliance Officer",
            decision="APPROVED",
            agreed_treatment="Mitigate",
            comments="Verified mitigating TLS controls and approved residual risk.",
            ai_analysis_acknowledged=True,
            snapshot_inherent_score=9,
            snapshot_inherent_level="High",
            snapshot_residual_score=6,
            snapshot_residual_level="Medium",
            snapshot_asset_criticality="High",
            snapshot_asset_exposure="Internal",
            snapshot_cvss_score=7.5,
            snapshot_control_ids=str(self.control.id),
            snapshot_vulnerability_hash="dummy_vuln_hash",
            snapshot_hash="dummy_snapshot_hash",
            is_current=True,
        )
        self.db.add(review)
        self.db.commit()
        self.db.refresh(review)

        self.assertIsNotNone(review.id)
        self.assertEqual(review.risk_id, self.risk.id)
        self.assertEqual(review.decision, "APPROVED")
        self.assertEqual(review.reviewer_name, "Alice SecOps")
        self.assertEqual(review.reviewer_role, "Compliance Officer")
        self.assertTrue(review.is_current)
        self.assertTrue(review.ai_analysis_acknowledged)
        self.assertIsNotNone(review.created_at)

    def test_partial_unique_index_enforces_single_current_review_at_db_level(self):
        """Database partial unique index must forbid two rows with is_current=True for the same risk_id."""
        review1 = models.RiskReview(
            risk_id=self.risk.id,
            reviewer_name="Reviewer One",
            reviewer_role="Security Lead",
            decision="APPROVED",
            agreed_treatment="Mitigate",
            comments="First active review.",
            snapshot_inherent_score=9,
            snapshot_inherent_level="High",
            snapshot_residual_score=6,
            snapshot_residual_level="Medium",
            snapshot_vulnerability_hash="hash1",
            snapshot_hash="snap1",
            is_current=True,
        )
        self.db.add(review1)
        self.db.commit()

        review2 = models.RiskReview(
            risk_id=self.risk.id,
            reviewer_name="Reviewer Two",
            reviewer_role="Security Lead",
            decision="APPROVED",
            agreed_treatment="Mitigate",
            comments="Second active review attempting collision.",
            snapshot_inherent_score=9,
            snapshot_inherent_level="High",
            snapshot_residual_score=6,
            snapshot_residual_level="Medium",
            snapshot_vulnerability_hash="hash2",
            snapshot_hash="snap2",
            is_current=True,
        )
        self.db.add(review2)
        with self.assertRaises(IntegrityError):
            self.db.commit()
        self.db.rollback()

    def test_multiple_historical_inactive_reviews_allowed(self):
        """Multiple reviews with is_current=False must succeed without collision."""
        for i in range(5):
            r = models.RiskReview(
                risk_id=self.risk.id,
                reviewer_name=f"Reviewer {i}",
                reviewer_role="Security Lead",
                decision="APPROVED",
                agreed_treatment="Mitigate",
                comments=f"Historical inactive review {i}",
                snapshot_inherent_score=9,
                snapshot_inherent_level="High",
                snapshot_residual_score=6,
                snapshot_residual_level="Medium",
                snapshot_vulnerability_hash=f"hash_{i}",
                snapshot_hash=f"snap_{i}",
                is_current=False,
            )
            self.db.add(r)
        self.db.commit()

        # Exactly 1 active review is still allowed
        active_r = models.RiskReview(
            risk_id=self.risk.id,
            reviewer_name="Active Reviewer",
            reviewer_role="Security Lead",
            decision="APPROVED",
            agreed_treatment="Mitigate",
            comments="Current active review",
            snapshot_inherent_score=9,
            snapshot_inherent_level="High",
            snapshot_residual_score=6,
            snapshot_residual_level="Medium",
            snapshot_vulnerability_hash="hash_active",
            snapshot_hash="snap_active",
            is_current=True,
        )
        self.db.add(active_r)
        self.db.commit()

        all_reviews = self.db.query(models.RiskReview).filter(models.RiskReview.risk_id == self.risk.id).all()
        self.assertEqual(len(all_reviews), 6)
        active_count = sum(1 for r in all_reviews if r.is_current)
        self.assertEqual(active_count, 1)

    def test_risk_review_status_defaults_to_pending_review(self):
        new_risk = models.Risk(
            asset_id=self.asset.id,
            title="New Risk Entry",
            description="Testing default review status",
            likelihood="Low",
            impact="Low",
            likelihood_score=1,
            impact_score=1,
            inherent_risk_score=1,
            inherent_risk_level="Low",
            residual_risk_score=1,
            residual_risk_level="Low",
            treatment="Accept",
        )
        self.db.add(new_risk)
        self.db.commit()
        self.db.refresh(new_risk)
        self.assertEqual(new_risk.review_status, "Pending Review")

    def test_preserves_existing_risk_status_values_without_mutation(self):
        """Existing Risk.status values ('Open', 'Resolved', 'Accepted', 'Under Review') must remain intact."""
        for status_val in ["Open", "Resolved", "Accepted", "Under Review"]:
            self.risk.status = status_val
            self.db.commit()
            self.db.refresh(self.risk)
            self.assertEqual(self.risk.status, status_val)


class TestVulnerabilityCorrelationAndSnapshotHashing(BasePhase6CIsolatedTestCase):
    """Tests narrow heuristic vulnerability correlation and deterministic snapshot SHA-256 hashes."""

    def test_heuristic_vulnerability_correlation_matches_relevant_only(self):
        matched = get_relevant_vulnerabilities_for_risk(self.risk, self.db)
        matched_cves = [v.cve for v in matched]
        self.assertIn("CVE-2023-5432", matched_cves)

    def test_heuristic_vulnerability_correlation_ignores_unrelated_on_same_asset(self):
        matched = get_relevant_vulnerabilities_for_risk(self.risk, self.db)
        matched_cves = [v.cve for v in matched]
        self.assertNotIn("CVE-2023-2222", matched_cves)

    def test_deterministic_vulnerability_hash_and_snapshot_hash(self):
        matched = get_relevant_vulnerabilities_for_risk(self.risk, self.db)
        v_hash_1 = calculate_vulnerability_hash(matched)
        v_hash_2 = calculate_vulnerability_hash(matched)
        self.assertEqual(v_hash_1, v_hash_2)
        self.assertEqual(len(v_hash_1), 64)

        # Snapshot hash must be 64-char hex string and deterministic
        s_hash_1 = calculate_review_snapshot_hash(
            inherent_score=self.risk.inherent_risk_score,
            residual_score=self.risk.residual_risk_score,
            criticality=self.asset.criticality,
            exposure=self.asset.exposure,
            cvss_score=self.vuln_relevant.cvss_score,
            control_ids=[self.control.id],
            vulnerability_hash=v_hash_1,
        )
        s_hash_2 = calculate_review_snapshot_hash(
            inherent_score=self.risk.inherent_risk_score,
            residual_score=self.risk.residual_risk_score,
            criticality=self.asset.criticality,
            exposure=self.asset.exposure,
            cvss_score=self.vuln_relevant.cvss_score,
            control_ids=[self.control.id],
            vulnerability_hash=v_hash_1,
        )
        self.assertEqual(s_hash_1, s_hash_2)
        self.assertEqual(len(s_hash_1), 64)


class TestReviewWorkflowService(BasePhase6CIsolatedTestCase):
    """Unit tests for submit_risk_review and state transitions."""

    def test_submit_approved_review_success_and_status_transition(self):
        review = submit_risk_review(
            db=self.db,
            risk_id=self.risk.id,
            decision="APPROVED",
            agreed_treatment="Mitigate",
            comments="Residual risk accepted with compensating controls.",
            ai_analysis_acknowledged=True,
            reviewer_name="SecLead Bob",
            reviewer_role="Security Lead",
        )
        self.assertIsNotNone(review.id)
        self.assertEqual(review.decision, "APPROVED")
        self.assertTrue(review.is_current)
        self.assertEqual(self.risk.review_status, "Approved")
        self.assertEqual(review.snapshot_inherent_score, 9)
        self.assertEqual(review.snapshot_residual_score, 6)
        self.assertEqual(review.snapshot_asset_criticality, "High")
        self.assertEqual(review.snapshot_asset_exposure, "Internal")
        self.assertIn(str(self.control.id), review.snapshot_control_ids)
        self.assertIsNotNone(review.snapshot_vulnerability_hash)
        self.assertIsNotNone(review.snapshot_hash)

        # Verify audit log was emitted
        audit = (
            self.db.query(models.AuditLog)
            .filter(models.AuditLog.action == "RISK_REVIEW_SUBMITTED", models.AuditLog.entity_id == review.id)
            .first()
        )
        self.assertIsNotNone(audit)
        self.assertEqual(audit.actor, "SecLead Bob")
        self.assertEqual(audit.source, "USER")

    def test_submit_rejected_review_success(self):
        review = submit_risk_review(
            db=self.db,
            risk_id=self.risk.id,
            decision="REJECTED",
            agreed_treatment="Mitigate",
            comments="Risk level is unacceptable without network airgap.",
            ai_analysis_acknowledged=False,
            reviewer_name="CISO Jane",
            reviewer_role="Chief Information Security Officer",
        )
        self.assertEqual(review.decision, "REJECTED")
        self.assertEqual(self.risk.review_status, "Rejected")

    def test_submit_changes_requested_review_success(self):
        review = submit_risk_review(
            db=self.db,
            risk_id=self.risk.id,
            decision="CHANGES_REQUESTED",
            agreed_treatment="Mitigate",
            comments="Please link additional detective monitoring control.",
            ai_analysis_acknowledged=True,
            reviewer_name="SecLead Bob",
            reviewer_role="Security Lead",
        )
        self.assertEqual(review.decision, "CHANGES_REQUESTED")
        self.assertEqual(self.risk.review_status, "Changes Requested")

    def test_submit_review_rejects_invalid_decision(self):
        with self.assertRaises(ValueError) as ctx:
            submit_risk_review(
                db=self.db,
                risk_id=self.risk.id,
                decision="ArbitrarySignoff",
                agreed_treatment="Mitigate",
                comments="Valid comments here.",
                reviewer_name="Bob",
                reviewer_role="Lead",
            )
        self.assertIn("Invalid decision", str(ctx.exception))

    def test_submit_review_rejects_empty_or_short_comments(self):
        with self.assertRaises(ValueError) as ctx:
            submit_risk_review(
                db=self.db,
                risk_id=self.risk.id,
                decision="APPROVED",
                agreed_treatment="Mitigate",
                comments="ok",  # Less than 5 characters
                reviewer_name="Bob",
                reviewer_role="Lead",
            )
        self.assertIn("at least 5 characters", str(ctx.exception))

    def test_operator_attribution_metadata_headers(self):
        """Attributed human reviewer metadata provides attribution only and does not constitute auth."""
        review = submit_risk_review(
            db=self.db,
            risk_id=self.risk.id,
            decision="APPROVED",
            agreed_treatment="Mitigate",
            comments="Governance audit sign-off complete.",
            reviewer_name="AuditSpecialist",
            reviewer_role="Senior Auditor",
        )
        self.assertEqual(review.reviewer_name, "AuditSpecialist")
        self.assertEqual(review.reviewer_role, "Senior Auditor")

    def test_ai_acknowledgement_flag_semantics(self):
        """ai_analysis_acknowledged indicates viewed/considered, not AI agreement or AI authorization."""
        review = submit_risk_review(
            db=self.db,
            risk_id=self.risk.id,
            decision="APPROVED",
            agreed_treatment="Mitigate",
            comments="AI suggestion was considered by human reviewer but human holds full authority.",
            ai_analysis_acknowledged=True,
            reviewer_name="Human Reviewer",
            reviewer_role="GRC Analyst",
        )
        self.assertTrue(review.ai_analysis_acknowledged)

    def test_historical_review_inactivation_on_new_review(self):
        review1 = submit_risk_review(
            db=self.db,
            risk_id=self.risk.id,
            decision="CHANGES_REQUESTED",
            agreed_treatment="Mitigate",
            comments="Initial review: changes needed.",
            reviewer_name="Reviewer A",
            reviewer_role="Analyst",
        )
        self.assertTrue(review1.is_current)
        self.assertEqual(self.risk.review_status, "Changes Requested")

        review2 = submit_risk_review(
            db=self.db,
            risk_id=self.risk.id,
            decision="APPROVED",
            agreed_treatment="Mitigate",
            comments="Updated review: all criteria satisfied.",
            reviewer_name="Reviewer B",
            reviewer_role="Lead",
        )
        self.db.refresh(review1)
        self.assertFalse(review1.is_current)
        self.assertTrue(review2.is_current)
        self.assertEqual(self.risk.review_status, "Approved")


class TestTreatmentOverrideAuditing(BasePhase6CIsolatedTestCase):
    """Tests human treatment overrides and audit trail emission."""

    def test_treatment_override_updates_risk_and_emits_audit_event(self):
        self.assertEqual(self.risk.treatment, "Mitigate")

        review = submit_risk_review(
            db=self.db,
            risk_id=self.risk.id,
            decision="APPROVED",
            agreed_treatment="Accept",  # Overriding from Mitigate to Accept
            comments="Executive exception approved: accept risk pending Q4 migration.",
            reviewer_name="CISO Sarah",
            reviewer_role="CISO",
        )

        self.assertEqual(self.risk.treatment, "Accept")
        self.assertEqual(review.agreed_treatment, "Accept")

        # Verify TREATMENT_OVERRIDDEN audit log
        audit = (
            self.db.query(models.AuditLog)
            .filter(models.AuditLog.action == "TREATMENT_OVERRIDDEN", models.AuditLog.entity_id == self.risk.id)
            .first()
        )
        self.assertIsNotNone(audit)
        self.assertEqual(audit.actor, "CISO Sarah")
        old_v = json.loads(audit.old_values)
        new_v = json.loads(audit.new_values)
        self.assertEqual(old_v.get("treatment"), "Mitigate")
        self.assertEqual(new_v.get("treatment"), "Accept")

    def test_treatment_override_rejects_invalid_treatment_value(self):
        with self.assertRaises(ValueError) as ctx:
            submit_risk_review(
                db=self.db,
                risk_id=self.risk.id,
                decision="APPROVED",
                agreed_treatment="InvalidValue",
                comments="Invalid treatment testing.",
                reviewer_name="CISO Sarah",
                reviewer_role="CISO",
            )
        self.assertIn("Invalid agreed_treatment", str(ctx.exception))


class TestStaleReviewDetectionAndDeduplication(BasePhase6CIsolatedTestCase):
    """Tests material-change stale detection logic and deduplication of stale audit events."""

    def setUp(self):
        super().setUp()
        self.review = submit_risk_review(
            db=self.db,
            risk_id=self.risk.id,
            decision="APPROVED",
            agreed_treatment="Mitigate",
            comments="Baseline approved state.",
            reviewer_name="Lead Reviewer",
            reviewer_role="Security Lead",
        )

    def test_stale_detection_on_inherent_score_change(self):
        is_stale, reasons = evaluate_review_staleness(self.db, self.risk, self.review)
        self.assertFalse(is_stale)

        # Change inherent score
        self.risk.inherent_risk_score = 12
        self.db.commit()

        is_stale, reasons = evaluate_review_staleness(self.db, self.risk, self.review)
        self.assertTrue(is_stale)
        self.assertTrue(any("Inherent risk score changed" in r for r in reasons))

    def test_stale_detection_on_residual_score_change(self):
        self.risk.residual_risk_score = 1
        self.db.commit()

        is_stale, reasons = evaluate_review_staleness(self.db, self.risk, self.review)
        self.assertTrue(is_stale)
        self.assertTrue(any("Residual risk score changed" in r for r in reasons))

    def test_stale_detection_on_asset_criticality_change(self):
        self.asset.criticality = "Critical"
        self.db.commit()

        is_stale, reasons = evaluate_review_staleness(self.db, self.risk, self.review)
        self.assertTrue(is_stale)
        self.assertTrue(any("Asset criticality changed" in r for r in reasons))

    def test_stale_detection_on_asset_exposure_change(self):
        self.asset.exposure = "External"
        self.db.commit()

        is_stale, reasons = evaluate_review_staleness(self.db, self.risk, self.review)
        self.assertTrue(is_stale)
        self.assertTrue(any("Asset exposure changed" in r for r in reasons))

    def test_stale_detection_on_control_linkage_change(self):
        # Detach existing control
        self.risk.controls.clear()
        self.db.commit()

        is_stale, reasons = evaluate_review_staleness(self.db, self.risk, self.review)
        self.assertTrue(is_stale)
        self.assertTrue(any("Mitigating controls changed" in r for r in reasons))

    def test_stale_detection_on_relevant_vulnerability_change(self):
        # Modifying relevant vulnerability CVSS
        self.vuln_relevant.cvss_score = 9.8
        self.db.commit()

        is_stale, reasons = evaluate_review_staleness(self.db, self.risk, self.review)
        self.assertTrue(is_stale)
        self.assertTrue(any("Relevant vulnerability findings" in r for r in reasons))

    def test_stale_detection_ignores_unrelated_vulnerability_change_on_same_asset(self):
        """Unrelated vulnerability on same asset must NOT cause review to become stale!"""
        self.vuln_unrelated.cvss_score = 9.0
        self.vuln_unrelated.title = "Critical SSH Remote Exploit"
        self.db.commit()

        is_stale, reasons = evaluate_review_staleness(self.db, self.risk, self.review)
        self.assertFalse(is_stale)
        self.assertEqual(len(reasons), 0)

    def test_stale_detection_on_relevant_drift_event(self):
        # Seed a scan job first
        job = models.ScanJob(target=self.asset.ip_address, scan_type="single_host", status="Completed")
        self.db.add(job)
        self.db.commit()

        # Seed a relevant drift event created AFTER review
        drift = models.DriftEvent(
            scan_job_id=job.id,
            asset_id=self.asset.id,
            event_type="PORT_OPENED",
            severity="High",
            title="Port 5432 opened",
            description="Port 5432 postgresql unexpectedly re-exposed",
            detected_at=datetime.utcnow() + timedelta(minutes=5),
        )
        self.db.add(drift)
        self.db.commit()

        is_stale, reasons = evaluate_review_staleness(self.db, self.risk, self.review)
        self.assertTrue(is_stale)
        self.assertTrue(any("network drift" in r.lower() for r in reasons))

    def test_stale_detection_ignores_unrelated_drift_event(self):
        # Seed a scan job first
        job = models.ScanJob(target=self.asset.ip_address, scan_type="single_host", status="Completed")
        self.db.add(job)
        self.db.commit()

        # Seed drift event on unrelated port (port 8080)
        drift = models.DriftEvent(
            scan_job_id=job.id,
            asset_id=self.asset.id,
            event_type="PORT_OPENED",
            severity="Low",
            title="Port 8080 opened",
            description="Developer test proxy opened on port 8080",
            detected_at=datetime.utcnow() + timedelta(minutes=5),
        )
        self.db.add(drift)
        self.db.commit()

        is_stale, reasons = evaluate_review_staleness(self.db, self.risk, self.review)
        self.assertFalse(is_stale)

    def test_stale_detection_ignores_non_material_risk_metadata_changes(self):
        # Description or owner change is not material
        self.risk.description = "Updated description for administrative clarity"
        self.risk.risk_owner = "New Custodian"
        self.db.commit()

        is_stale, reasons = evaluate_review_staleness(self.db, self.risk, self.review)
        self.assertFalse(is_stale)

    def test_stale_audit_event_deduplication_on_repeated_get_reviews(self):
        """Repeated GET /risks/{id}/reviews calls must produce exactly ONE stale-transition audit event!"""
        # Trigger material staleness
        self.asset.criticality = "Critical"
        self.db.commit()

        # Initial call transitions Approved -> Stale and emits 1 audit event
        current_rev, all_revs, is_stale, reasons = get_or_evaluate_risk_reviews(db=self.db, risk_id=self.risk.id)
        self.assertTrue(is_stale)
        self.assertEqual(self.risk.review_status, "Stale")

        stale_events_1 = (
            self.db.query(models.AuditLog)
            .filter(
                models.AuditLog.action == "RISK_REVIEW_STALE",
                models.AuditLog.entity_id == self.risk.id,
            )
            .all()
        )
        self.assertEqual(len(stale_events_1), 1)

        # Repeated calls encountering an already Stale review must NOT emit duplicate audit events
        for _ in range(5):
            get_or_evaluate_risk_reviews(db=self.db, risk_id=self.risk.id)
            self.assertEqual(self.risk.review_status, "Stale")

        stale_events_repeat = (
            self.db.query(models.AuditLog)
            .filter(
                models.AuditLog.action == "RISK_REVIEW_STALE",
                models.AuditLog.entity_id == self.risk.id,
            )
            .all()
        )
        self.assertEqual(len(stale_events_repeat), 1, "Expected exactly 1 audit event after repeated GET calls!")


class TestRiskReviewApiEndpoints(BasePhase6CIsolatedTestCase):
    """Integration tests for Phase 6C REST API endpoints."""

    def setUp(self):
        super().setUp()
        self.session_patcher = unittest.mock.patch("main.SessionLocal", side_effect=lambda: self.SessionLocal())
        self.session_patcher.start()
        self.auth_patcher = unittest.mock.patch("auth.dependencies.SessionLocal", side_effect=lambda: self.SessionLocal())
        self.auth_patcher.start()
        self.client = TestClient(main.app)
        from tests.auth_test_utils import create_test_auth_headers
        self.client.headers.update(create_test_auth_headers(self.db, role="Administrator"))

    def tearDown(self):
        self.session_patcher.stop()
        self.auth_patcher.stop()
        super().tearDown()

    def test_api_submit_and_get_risk_reviews(self):
        headers = {
            "X-Operator-Name": "AuditorDave",
            "X-Operator-Role": "GRC Auditor",
        }
        payload = {
            "decision": "APPROVED",
            "agreed_treatment": "Mitigate",
            "comments": "Audited and verified compliant with policy.",
            "ai_analysis_acknowledged": True,
        }
        resp = self.client.post(f"/risks/{self.risk.id}/reviews", json=payload, headers=headers)
        self.assertEqual(resp.status_code, 201)
        data = resp.json()
        self.assertEqual(data["decision"], "APPROVED")
        # Stage 13D.4: Reviewer identity is authoritatively derived from authenticated User session
        self.assertEqual(data["reviewer_name"], "Test Admin")
        self.assertEqual(data["reviewer_role"], "Administrator")
        self.assertTrue(data["is_current"])

        # GET reviews
        get_resp = self.client.get(f"/risks/{self.risk.id}/reviews")
        self.assertEqual(get_resp.status_code, 200)
        get_data = get_resp.json()
        self.assertEqual(get_data["review_status"], "Approved")
        self.assertEqual(len(get_data["history"]), 1)
        self.assertFalse(get_data["is_stale"])

    def test_api_get_pending_reviews_queue_and_filters(self):
        # Initially risk is "Pending Review"
        resp = self.client.get("/governance/reviews/pending")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("risks", data)
        self.assertGreaterEqual(data["total"], 1)

        risk_ids = [item["risk"]["id"] for item in data["risks"]]
        self.assertIn(self.risk.id, risk_ids)

        # Filter by review_status
        resp_filtered = self.client.get("/governance/reviews/pending?review_status=Approved")
        self.assertEqual(resp_filtered.status_code, 200)
        data_filtered = resp_filtered.json()
        self.assertEqual(data_filtered["total"], 0)

    def test_api_bulk_evaluate_stale_endpoint(self):
        # Approve review first
        submit_risk_review(
            db=self.db,
            risk_id=self.risk.id,
            decision="APPROVED",
            agreed_treatment="Mitigate",
            comments="Approved baseline.",
            reviewer_name="SecOps",
            reviewer_role="Lead",
        )
        self.assertEqual(self.risk.review_status, "Approved")

        # Material change: asset criticality
        self.asset.criticality = "Critical"
        self.db.commit()

        resp = self.client.post("/governance/reviews/evaluate-stale")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["evaluated_count"], 1)
        self.assertEqual(data["newly_stale_count"], 1)
        stale_ids = [item["risk_id"] for item in data["stale_risks"]]
        self.assertIn(self.risk.id, stale_ids)

        # Risk review_status should now be Stale in DB
        self.db.refresh(self.risk)
        self.assertEqual(self.risk.review_status, "Stale")


if __name__ == "__main__":
    unittest.main()

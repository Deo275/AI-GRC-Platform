"""Phase 6A Isolated Automated Test Suite: Evidence Catalog & Tamper-Evident Audit Trail.

Comprehensive tests using Python unittest and in-memory SQLite:
1.  test_audit_log_creation_and_fields
2.  test_sensitive_field_sanitization_in_audit_diffs
3.  test_format_audit_log_json_deserialization
4.  test_audit_logging_handles_database_errors_gracefully
5.  test_sha256_checksum_calculation
6.  test_evidence_creation_with_all_fields
7.  test_evidence_content_limit_50kb_rejection
8.  test_evidence_content_within_50kb_accepted
9.  test_evidence_m2m_linkages_risks_controls_requirements
10. test_evidence_asset_and_scan_job_linkage
11. test_evidence_invalid_foreign_keys_raise_error
12. test_evidence_creation_emits_audit_log
13. test_evidence_deletion_emits_audit_log
14. test_get_audit_logs_pagination_and_total
15. test_get_audit_logs_filtering_by_source_action_entity
16. test_get_audit_log_by_id_and_404
17. test_audit_log_append_only_no_patch_or_delete_allowed
18. test_post_evidence_api_success_and_201
19. test_post_evidence_api_rejects_oversized_content
20. test_post_evidence_api_rejects_invalid_fk
21. test_get_evidence_list_and_filters
22. test_get_evidence_by_id_and_404
23. test_delete_evidence_api_and_404
24. test_operator_identity_header_propagation
25. test_patch_asset_emits_audit_event
26. test_patch_risk_emits_audit_event
27. test_control_crud_emits_audit_events
28. test_control_assignment_and_detachment_emits_audit_events
29. test_patch_compliance_requirement_emits_audit_event

Zero external dependencies; does not require live PostgreSQL or network.
"""

import hashlib
import json
import unittest
from unittest import mock
from datetime import datetime
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient

import sys
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(BASE_DIR / "backend"))

import models
from governance.audit_logger import (
    log_audit_event,
    sanitize_sensitive_data,
    format_audit_log,
)
from governance.evidence_manager import (
    calculate_sha256,
    create_evidence_record,
    format_evidence,
    delete_evidence_record,
    MAX_CONTENT_BYTES,
)
import main


class BasePhase6IsolatedTestCase(unittest.TestCase):
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

        # Seed basic foundational test data
        self.asset = models.Asset(
            ip_address="192.168.1.10",
            hostname="test-host.local",
            criticality="High",
            environment="Production",
            exposure="Internal",
            owner="SecOps",
            business_function="Database",
        )
        self.db.add(self.asset)
        self.db.commit()
        self.db.refresh(self.asset)

        self.risk = models.Risk(
            asset_id=self.asset.id,
            title="Unencrypted Database Port",
            description="Port 5432 is exposed without TLS",
            likelihood="High",
            impact="Critical",
            likelihood_score=3,
            impact_score=3,
            inherent_risk_score=9,
            inherent_risk_level="High",
            residual_risk_score=9,
            residual_risk_level="High",
            treatment="Mitigate",
            status="Open",
            risk_owner="Alice",
        )
        self.db.add(self.risk)

        self.control = models.Control(
            name="Network Segmentation",
            description="Segment database network via VLAN",
            category="Preventive",
            framework="NIST CSF",
            effectiveness="High",
            status="Implemented",
        )
        self.db.add(self.control)

        self.framework = models.ComplianceFramework(
            name="NIST CSF",
            version="2.0",
            description="Cybersecurity Framework",
        )
        self.db.add(self.framework)
        self.db.commit()
        self.db.refresh(self.framework)

        self.requirement = models.ComplianceRequirement(
            framework_id=self.framework.id,
            requirement_id="PR.DS-01",
            title="Data-at-rest is protected",
            status="Partially Implemented",
        )
        self.db.add(self.requirement)

        self.scan_job = models.ScanJob(
            target="192.168.1.10",
            scan_type="single_host",
            status="Completed",
            progress_percent=100,
        )
        self.db.add(self.scan_job)
        self.db.commit()
        self.db.refresh(self.risk)
        self.db.refresh(self.control)
        self.db.refresh(self.requirement)
        self.db.refresh(self.scan_job)

    def tearDown(self):
        self.db.close()
        models.Base.metadata.drop_all(bind=self.engine)


class TestAuditLogger(BasePhase6IsolatedTestCase):
    """Unit tests for the centralized governance audit logger."""

    def test_audit_log_creation_and_fields(self):
        entry = log_audit_event(
            db=self.db,
            source="USER",
            actor="admin",
            action="UPDATE",
            entity_type="Asset",
            entity_id=self.asset.id,
            entity_name=self.asset.ip_address,
            old_values={"criticality": "Medium"},
            new_values={"criticality": "High"},
            description="Updated asset criticality",
            ip_address="127.0.0.1",
            commit=True,
        )
        self.assertIsNotNone(entry)
        self.assertEqual(entry.source, "USER")
        self.assertEqual(entry.actor, "admin")
        self.assertEqual(entry.action, "UPDATE")
        self.assertEqual(entry.entity_type, "Asset")
        self.assertEqual(entry.entity_id, self.asset.id)
        self.assertIn("Medium", entry.old_values)
        self.assertIn("High", entry.new_values)
        self.assertEqual(entry.ip_address, "127.0.0.1")

    def test_sensitive_field_sanitization_in_audit_diffs(self):
        leaky_data = {
            "api_key": "AIzaSySecret12345",
            "db_password": "SuperSecretPassword!",
            "token": "bearer_xyz_jwt",
            "safe_field": "public_info",
            "nested": {
                "private_key": "-----BEGIN PRIVATE KEY-----",
                "client_secret": "topsecret",
                "normal": 42,
            },
        }
        sanitized = sanitize_sensitive_data(leaky_data)
        self.assertEqual(sanitized["api_key"], "[REDACTED]")
        self.assertEqual(sanitized["db_password"], "[REDACTED]")
        self.assertEqual(sanitized["token"], "[REDACTED]")
        self.assertEqual(sanitized["safe_field"], "public_info")
        self.assertEqual(sanitized["nested"]["private_key"], "[REDACTED]")
        self.assertEqual(sanitized["nested"]["client_secret"], "[REDACTED]")
        self.assertEqual(sanitized["nested"]["normal"], 42)

        # Confirm audit logger stores the sanitized representation
        entry = log_audit_event(
            db=self.db,
            source="API",
            actor="system",
            action="CREATE",
            entity_type="Config",
            new_values=leaky_data,
        )
        self.assertNotIn("AIzaSySecret12345", entry.new_values)
        self.assertNotIn("SuperSecretPassword!", entry.new_values)
        self.assertIn("[REDACTED]", entry.new_values)

    def test_format_audit_log_json_deserialization(self):
        entry = log_audit_event(
            db=self.db,
            source="SYSTEM",
            actor="scanner_daemon",
            action="DISPATCH",
            entity_type="ScanJob",
            entity_id=1,
            new_values={"target": "10.0.0.1", "ports": [80, 443]},
        )
        formatted = format_audit_log(entry)
        self.assertIsInstance(formatted["new_values"], dict)
        self.assertEqual(formatted["new_values"]["target"], "10.0.0.1")
        self.assertEqual(formatted["new_values"]["ports"], [80, 443])

    def test_audit_logging_handles_database_errors_gracefully(self):
        # Database commit exception should be caught and return None without raising unhandled error
        faulty_session = mock.MagicMock()
        faulty_session.commit.side_effect = Exception("Simulated DB connection drop")
        res = log_audit_event(
            db=faulty_session,
            source="API",
            actor="test",
            action="TEST",
            entity_type="None",
            commit=True,
        )
        self.assertIsNone(res)


class TestEvidenceManager(BasePhase6IsolatedTestCase):
    """Unit tests for the Evidence Repository and SHA-256 calculation."""

    def test_sha256_checksum_calculation(self):
        sample = "Nmap scan output: 80/tcp open http Apache 2.4.41"
        expected_sha = hashlib.sha256(sample.encode("utf-8")).hexdigest()
        self.assertEqual(calculate_sha256(sample), expected_sha)
        self.assertIsNone(calculate_sha256(None))

    def test_evidence_creation_with_all_fields(self):
        record = create_evidence_record(
            db=self.db,
            title="Q3 Network Scan Report",
            evidence_type="SCAN_OUTPUT",
            description="Quarterly discovery scan results",
            content_text="PORT STATE SERVICE\n80/tcp open http",
            reference_url="s3://evidence/scan-q3.txt",
            source_system="Nmap",
            collector="Bob Auditor",
            asset_id=self.asset.id,
            scan_job_id=self.scan_job.id,
            risk_ids=[self.risk.id],
            control_ids=[self.control.id],
            requirement_ids=[self.requirement.id],
            actor="Bob Auditor",
        )
        self.assertIsNotNone(record.id)
        self.assertEqual(record.title, "Q3 Network Scan Report")
        self.assertEqual(record.evidence_type, "SCAN_OUTPUT")
        self.assertIsNotNone(record.checksum_sha256)
        self.assertEqual(record.asset_id, self.asset.id)
        self.assertEqual(record.scan_job_id, self.scan_job.id)

    def test_evidence_content_limit_50kb_rejection(self):
        oversized = "A" * (MAX_CONTENT_BYTES + 1)
        with self.assertRaises(ValueError) as ctx:
            create_evidence_record(
                db=self.db,
                title="Oversized Evidence",
                evidence_type="SCAN_OUTPUT",
                content_text=oversized,
            )
        self.assertIn("exceeds 50 KB limit", str(ctx.exception))

    def test_evidence_content_within_50kb_accepted(self):
        valid_size_content = "A" * MAX_CONTENT_BYTES
        record = create_evidence_record(
            db=self.db,
            title="50KB Evidence",
            evidence_type="CONFIG_EXPORT",
            content_text=valid_size_content,
        )
        self.assertIsNotNone(record.id)
        self.assertEqual(len(record.content_text), MAX_CONTENT_BYTES)

    def test_evidence_m2m_linkages_risks_controls_requirements(self):
        record = create_evidence_record(
            db=self.db,
            title="Multi-Link Evidence",
            evidence_type="POLICY_REF",
            risk_ids=[self.risk.id],
            control_ids=[self.control.id],
            requirement_ids=[self.requirement.id],
        )
        formatted = format_evidence(record)
        self.assertEqual(formatted["linked_risk_ids"], [self.risk.id])
        self.assertEqual(formatted["linked_control_ids"], [self.control.id])
        self.assertEqual(formatted["linked_requirement_ids"], [self.requirement.id])

        # Verify reverse relationships
        self.assertIn(record, self.risk.evidence_records)
        self.assertIn(record, self.control.evidence_records)
        self.assertIn(record, self.requirement.evidence_records)

    def test_evidence_asset_and_scan_job_linkage(self):
        record = create_evidence_record(
            db=self.db,
            title="Asset Scan Link",
            evidence_type="SCAN_OUTPUT",
            asset_id=self.asset.id,
            scan_job_id=self.scan_job.id,
        )
        self.assertEqual(record.asset.ip_address, "192.168.1.10")
        self.assertEqual(record.scan_job.target, "192.168.1.10")

    def test_evidence_invalid_foreign_keys_raise_error(self):
        with self.assertRaises(ValueError) as ctx:
            create_evidence_record(
                db=self.db,
                title="Bad Asset Link",
                evidence_type="SCAN_OUTPUT",
                asset_id=99999,
            )
        self.assertIn("Asset with ID 99999 does not exist", str(ctx.exception))

        with self.assertRaises(ValueError) as ctx:
            create_evidence_record(
                db=self.db,
                title="Bad Scan Link",
                evidence_type="SCAN_OUTPUT",
                scan_job_id=99999,
            )
        self.assertIn("ScanJob with ID 99999 does not exist", str(ctx.exception))

    def test_evidence_creation_emits_audit_log(self):
        record = create_evidence_record(
            db=self.db,
            title="Audited Evidence",
            evidence_type="MANUAL_OBSERVATION",
            actor="AuditorDave",
        )
        log = (
            self.db.query(models.AuditLog)
            .filter(
                models.AuditLog.entity_type == "EvidenceRecord",
                models.AuditLog.entity_id == record.id,
                models.AuditLog.action == "CREATE",
            )
            .first()
        )
        self.assertIsNotNone(log)
        self.assertEqual(log.actor, "AuditorDave")
        self.assertEqual(log.source, "USER")

    def test_evidence_deletion_emits_audit_log(self):
        record = create_evidence_record(
            db=self.db,
            title="Temporary Evidence",
            evidence_type="AUDIT_EXPORT",
        )
        evidence_id = record.id
        deleted = delete_evidence_record(self.db, evidence_id, actor="AuditorDave")
        self.assertTrue(deleted)

        # Verify record is deleted
        found = self.db.query(models.EvidenceRecord).filter(models.EvidenceRecord.id == evidence_id).first()
        self.assertIsNone(found)

        # Verify audit record
        log = (
            self.db.query(models.AuditLog)
            .filter(
                models.AuditLog.entity_type == "EvidenceRecord",
                models.AuditLog.entity_id == evidence_id,
                models.AuditLog.action == "DELETE",
            )
            .first()
        )
        self.assertIsNotNone(log)
        self.assertEqual(log.actor, "AuditorDave")


class TestGovernanceApiEndpoints(BasePhase6IsolatedTestCase):
    """Integration tests for the Phase 6A REST API endpoints."""

    def setUp(self):
        super().setUp()
        # Patch SessionLocal in main to use our in-memory SQLite session
        self.session_patcher = unittest.mock.patch("main.SessionLocal", side_effect=lambda: self.SessionLocal())
        self.session_patcher.start()
        self.client = TestClient(main.app)

    def tearDown(self):
        self.session_patcher.stop()
        super().tearDown()

    def test_get_audit_logs_pagination_and_total(self):
        # Create a few audit logs
        for i in range(5):
            log_audit_event(
                db=self.db,
                source="API",
                actor="test_user",
                action="TEST",
                entity_type="MockEntity",
                entity_id=i + 1,
            )

        resp = self.client.get("/audit-logs?limit=3&offset=0")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("logs", data)
        self.assertIn("total", data)
        self.assertGreaterEqual(data["total"], 5)
        self.assertEqual(len(data["logs"]), 3)

    def test_get_audit_logs_filtering_by_source_action_entity(self):
        log_audit_event(
            db=self.db,
            source="SCHEDULER",
            actor="daemon",
            action="DISPATCH",
            entity_type="ScanJob",
            entity_id=101,
        )
        resp = self.client.get("/audit-logs?source=SCHEDULER&action=DISPATCH&entity_type=ScanJob")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertGreaterEqual(data["total"], 1)
        self.assertEqual(data["logs"][0]["source"], "SCHEDULER")
        self.assertEqual(data["logs"][0]["action"], "DISPATCH")

    def test_get_audit_log_by_id_and_404(self):
        entry = log_audit_event(
            db=self.db,
            source="USER",
            actor="admin",
            action="CREATE",
            entity_type="Test",
        )
        resp = self.client.get(f"/audit-logs/{entry.id}")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["id"], entry.id)

        resp_404 = self.client.get("/audit-logs/99999")
        self.assertEqual(resp_404.status_code, 404)

    def test_audit_log_append_only_no_patch_or_delete_allowed(self):
        # Verify no mutate routes exist on /audit-logs
        resp_post = self.client.post("/audit-logs", json={"test": 1})
        self.assertIn(resp_post.status_code, (404, 405))

        resp_patch = self.client.patch("/audit-logs/1", json={"test": 1})
        self.assertIn(resp_patch.status_code, (404, 405))

        resp_delete = self.client.delete("/audit-logs/1")
        self.assertIn(resp_delete.status_code, (404, 405))

    def test_post_evidence_api_success_and_201(self):
        payload = {
            "title": "API Test Evidence",
            "evidence_type": "SCAN_OUTPUT",
            "description": "Evidence created via REST API",
            "content_text": "Port 443 open",
            "risk_ids": [self.risk.id],
            "control_ids": [self.control.id],
            "requirement_ids": [self.requirement.id],
            "asset_id": self.asset.id,
            "scan_job_id": self.scan_job.id,
        }
        resp = self.client.post(
            "/evidence",
            json=payload,
            headers={"X-Operator-Name": "AuditorAlice", "X-Operator-Role": "CISO"},
        )
        self.assertEqual(resp.status_code, 201)
        data = resp.json()
        self.assertEqual(data["title"], "API Test Evidence")
        self.assertIsNotNone(data["checksum_sha256"])
        self.assertEqual(data["collector"], "AuditorAlice")
        self.assertEqual(data["linked_risk_ids"], [self.risk.id])

    def test_post_evidence_api_rejects_oversized_content(self):
        payload = {
            "title": "Too Big",
            "evidence_type": "SCAN_OUTPUT",
            "content_text": "X" * (MAX_CONTENT_BYTES + 1),
        }
        resp = self.client.post("/evidence", json=payload)
        self.assertEqual(resp.status_code, 400)
        self.assertIn("exceeds 50 KB limit", resp.json()["detail"])

    def test_post_evidence_api_rejects_invalid_fk(self):
        payload = {
            "title": "Bad Asset",
            "evidence_type": "SCAN_OUTPUT",
            "asset_id": 99999,
        }
        resp = self.client.post("/evidence", json=payload)
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Asset with ID 99999 does not exist", resp.json()["detail"])

    def test_get_evidence_list_and_filters(self):
        self.client.post(
            "/evidence",
            json={"title": "Doc Evidence", "evidence_type": "POLICY_REF"},
        )
        resp = self.client.get("/evidence?evidence_type=POLICY_REF")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertGreaterEqual(data["total"], 1)
        self.assertEqual(data["evidence"][0]["evidence_type"], "POLICY_REF")

    def test_get_evidence_by_id_and_404(self):
        create_resp = self.client.post(
            "/evidence",
            json={"title": "Detail Evidence", "evidence_type": "MANUAL_OBSERVATION"},
        )
        evidence_id = create_resp.json()["id"]

        get_resp = self.client.get(f"/evidence/{evidence_id}")
        self.assertEqual(get_resp.status_code, 200)
        self.assertEqual(get_resp.json()["id"], evidence_id)

        resp_404 = self.client.get("/evidence/99999")
        self.assertEqual(resp_404.status_code, 404)

    def test_delete_evidence_api_and_404(self):
        create_resp = self.client.post(
            "/evidence",
            json={"title": "To Delete", "evidence_type": "CONFIG_EXPORT"},
        )
        evidence_id = create_resp.json()["id"]

        del_resp = self.client.delete(f"/evidence/{evidence_id}")
        self.assertEqual(del_resp.status_code, 200)

        # Deleting again returns 404
        del_again = self.client.delete(f"/evidence/{evidence_id}")
        self.assertEqual(del_again.status_code, 404)

    def test_operator_identity_header_propagation(self):
        resp = self.client.post(
            "/evidence",
            json={"title": "Header Test", "evidence_type": "POLICY_REF"},
            headers={"X-Operator-Name": "LeadAuditorX", "X-Operator-Role": "Auditor"},
        )
        self.assertEqual(resp.status_code, 201)
        evidence_id = resp.json()["id"]

        audit_entry = (
            self.db.query(models.AuditLog)
            .filter(models.AuditLog.entity_type == "EvidenceRecord", models.AuditLog.entity_id == evidence_id)
            .first()
        )
        self.assertIsNotNone(audit_entry)
        self.assertEqual(audit_entry.actor, "LeadAuditorX")


class TestGovernanceAuditInstrumentation(BasePhase6IsolatedTestCase):
    """Verify that existing Phase 1-5 mutation endpoints emit audit records."""

    def setUp(self):
        super().setUp()
        self.session_patcher = unittest.mock.patch("main.SessionLocal", side_effect=lambda: self.SessionLocal())
        self.session_patcher.start()
        self.client = TestClient(main.app)

    def tearDown(self):
        self.session_patcher.stop()
        super().tearDown()

    def test_patch_asset_emits_audit_event(self):
        resp = self.client.patch(
            f"/assets/{self.asset.id}",
            json={"criticality": "Critical", "exposure": "DMZ"},
            headers={"X-Operator-Name": "AssetManagerBob"},
        )
        self.assertEqual(resp.status_code, 200)

        log = (
            self.db.query(models.AuditLog)
            .filter(models.AuditLog.entity_type == "Asset", models.AuditLog.entity_id == self.asset.id)
            .order_by(models.AuditLog.id.desc())
            .first()
        )
        self.assertIsNotNone(log)
        self.assertEqual(log.actor, "AssetManagerBob")
        self.assertEqual(log.action, "UPDATE")

    def test_patch_risk_emits_audit_event(self):
        resp = self.client.patch(
            f"/risks/{self.risk.id}",
            json={"treatment": "Accept", "status": "Accepted"},
            headers={"X-Operator-Name": "RiskOfficerCarol"},
        )
        self.assertEqual(resp.status_code, 200)

        log = (
            self.db.query(models.AuditLog)
            .filter(models.AuditLog.entity_type == "Risk", models.AuditLog.entity_id == self.risk.id)
            .order_by(models.AuditLog.id.desc())
            .first()
        )
        self.assertIsNotNone(log)
        self.assertEqual(log.actor, "RiskOfficerCarol")
        self.assertEqual(log.action, "UPDATE")

    def test_control_crud_emits_audit_events(self):
        # Create control
        resp = self.client.post(
            "/controls",
            json={"name": "Audit Test Control", "category": "Detective"},
            headers={"X-Operator-Name": "SecOpsDan"},
        )
        self.assertEqual(resp.status_code, 200)
        ctrl_id = resp.json()["control"]["id"]

        create_log = (
            self.db.query(models.AuditLog)
            .filter(models.AuditLog.entity_type == "Control", models.AuditLog.entity_id == ctrl_id, models.AuditLog.action == "CREATE")
            .first()
        )
        self.assertIsNotNone(create_log)
        self.assertEqual(create_log.actor, "SecOpsDan")

        # Update control
        resp_up = self.client.patch(
            f"/controls/{ctrl_id}",
            json={"effectiveness": "High"},
            headers={"X-Operator-Name": "SecOpsDan"},
        )
        self.assertEqual(resp_up.status_code, 200)

        # Delete control
        resp_del = self.client.delete(
            f"/controls/{ctrl_id}",
            headers={"X-Operator-Name": "SecOpsDan"},
        )
        self.assertEqual(resp_del.status_code, 200)

        del_log = (
            self.db.query(models.AuditLog)
            .filter(models.AuditLog.entity_type == "Control", models.AuditLog.entity_id == ctrl_id, models.AuditLog.action == "DELETE")
            .first()
        )
        self.assertIsNotNone(del_log)

    def test_control_assignment_and_detachment_emits_audit_events(self):
        # Assign
        resp_assign = self.client.post(
            f"/risks/{self.risk.id}/controls/{self.control.id}",
            headers={"X-Operator-Name": "AssignerEve"},
        )
        self.assertEqual(resp_assign.status_code, 200)

        assign_log = (
            self.db.query(models.AuditLog)
            .filter(models.AuditLog.entity_type == "Risk", models.AuditLog.action == "ASSIGN")
            .first()
        )
        self.assertIsNotNone(assign_log)
        self.assertEqual(assign_log.actor, "AssignerEve")

        # Detach
        resp_detach = self.client.delete(
            f"/risks/{self.risk.id}/controls/{self.control.id}",
            headers={"X-Operator-Name": "AssignerEve"},
        )
        self.assertEqual(resp_detach.status_code, 200)

        detach_log = (
            self.db.query(models.AuditLog)
            .filter(models.AuditLog.entity_type == "Risk", models.AuditLog.action == "DETACH")
            .first()
        )
        self.assertIsNotNone(detach_log)

    def test_patch_compliance_requirement_emits_audit_event(self):
        resp = self.client.patch(
            f"/compliance/requirements/{self.requirement.id}",
            json={"status": "Implemented", "notes": "Verified in Q3 audit"},
            headers={"X-Operator-Name": "AuditorFrank"},
        )
        self.assertEqual(resp.status_code, 200)

        log = (
            self.db.query(models.AuditLog)
            .filter(models.AuditLog.entity_type == "ComplianceRequirement", models.AuditLog.entity_id == self.requirement.id)
            .first()
        )
        self.assertIsNotNone(log)
        self.assertEqual(log.actor, "AuditorFrank")
        self.assertEqual(log.action, "UPDATE")


if __name__ == "__main__":
    unittest.main()

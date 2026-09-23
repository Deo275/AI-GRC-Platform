"""Phase 6E Final Integration & End-to-End Verification Test Suite.

Verifies cross-phase integration across the entire AI-GRC Platform:
1.  Full lifecycle: Scan simulation -> Asset -> Vulnerability -> Risk -> AI Advisory -> Review -> Audit -> Report
2.  AI advisory isolation: Malicious/extreme AI recommendations do not mutate authoritative GRC scores or review status
3.  Human approval workflow: Approving with agreed treatment updates Risk.review_status while preserving Risk.status
4.  Review history retrieval: Superseded reviews remain archived and retrievable in review history
5.  Audit event generation: Review submission generates the expected tamper-evident audit record
6.  Stale review on drift: Vulnerability drift invalidates approved review to STALE and logs RISK_REVIEW_STALE
7.  Audit integrity verification: Deterministic SHA-256 integrity hash matches recomputed value from canonical fields
8.  CSV formula injection defense: Cells starting with =, +, -, @, \\t, \\r are safely prefixed with single quote
9.  Multi-format report generation: Reports generate successfully across JSON, CSV, and HTML formats
10. Authoritative vs AI separation in reports: Clear demarcation and disclaimers distinguish GRC scores from advisory AI
11. Compliance framework integration: Control-to-requirement mappings accurately integrate with GRC entities
12. Compliance state semantics: 'Not Assessed' and 'Not Applicable' statuses maintain strict evaluation semantics

Deterministic execution: Runs entirely in-memory with SQLite and mocked AI/network providers.
No external network, Nmap binary, or real API keys required.
"""

import json
import os
import sys
import unittest
from unittest import mock
from datetime import datetime
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient

# Setup sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(BASE_DIR / "backend"))

import models
from scanner.grc_engine import (
    calculate_inherent_risk,
    calculate_residual_risk,
    criticality_to_impact,
    calculate_likelihood,
    calculate_risk_level,
)
from ai.schemas import (
    NormalizedSecurityContext,
    AIAnalysisResult,
    RemediationSteps,
    RecommendedControl,
)
from ai.provider import AIProvider
from ai.risk_analyzer import analyze_risk
from governance.review_manager import (
    submit_risk_review,
    get_or_evaluate_risk_reviews,
    evaluate_review_staleness,
)
from governance.audit_logger import (
    log_audit_event,
    calculate_audit_integrity_hash,
)
from reporting.report_generator import (
    generate_report,
    generate_compliance_gap_data,
)
from reporting.csv_export import (
    sanitize_csv_cell,
)
from reporting.html_export import (
    build_html_report,
)
import main


class StubMockAIProvider(AIProvider):
    """Deterministic in-memory AI provider for end-to-end integration testing."""

    def __init__(self, override_result=None, model_name="integration-mock-ai"):
        self.model_name = model_name
        self.override_result = override_result
        self.fallback_enabled = False

    def analyze_finding(self, context: NormalizedSecurityContext) -> AIAnalysisResult:
        if self.override_result:
            return self.override_result

        return AIAnalysisResult(
            priority="High",
            simple_explanation=f"Simulated AI analysis for {context.risk_title} on port {context.port}.",
            why_it_matters="Exposure of network services increases lateral movement attack surface.",
            severity_explanation=f"Evaluated with context CVSS {context.cvss_score or 'N/A'}.",
            risk_factors=[
                f"Asset Environment: {context.asset_environment}",
                f"Asset Criticality: {context.asset_criticality}",
            ],
            potential_business_impact=[
                "Potential unauthenticated access to internal database records",
                "Service disruption if exploited by automated denial-of-service tool",
            ],
            recommendation=[
                "Restrict service to internal management VLAN",
                "Deploy firewall rule blocking external ingress",
            ],
            remediation=RemediationSteps(
                immediate_mitigation=[f"Block incoming traffic on port {context.port}"],
                permanent_remediation=["Configure service binding to 127.0.0.1 or internal private subnet"],
                validation=["Re-scan host to verify port is closed from untrusted networks"],
            ),
            recommended_controls=[
                RecommendedControl(name="Firewall Protection", reason="Network boundary access control"),
                RecommendedControl(name="Patch Management", reason="Regular security updates"),
            ],
            confidence=0.92,
            model_name=self.model_name,
            human_review_required=True,
        )


class TestPhase6EEndToEndIntegration(unittest.TestCase):
    """End-to-end integration test suite validating cross-phase interoperability."""

    def setUp(self):
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
        self.client = TestClient(main.app)

    def tearDown(self):
        self.session_patcher.stop()
        self.db.close()
        models.Base.metadata.drop_all(bind=self.engine)

    # 1. Full Lifecycle Integration Test
    def test_01_full_lifecycle_integration(self):
        """Verify unbroken chain: Scan simulation -> Asset -> Vuln -> Risk -> AI -> Review -> Audit -> Report."""
        # A. Asset registration (simulating scan discovery)
        asset = models.Asset(
            ip_address="192.168.1.100",
            hostname="app-prod-01.local",
            criticality="High",
            environment="Production",
            exposure="Internal",
            owner="Platform Team",
            business_function="Payment Gateway",
        )
        self.db.add(asset)
        self.db.commit()
        self.db.refresh(asset)

        # B. Vulnerability enrichment
        vuln = models.Vulnerability(
            asset_id=asset.id,
            title="PostgreSQL Remote Code Execution",
            severity="High",
            cve="CVE-2023-39417",
            cvss_score=8.8,
            port=5432,
            service="postgresql",
            description="Buffer overflow in PostgreSQL connection handler allows remote exploitation.",
        )
        self.db.add(vuln)
        self.db.commit()
        self.db.refresh(vuln)

        # C. Authoritative GRC risk calculation
        impact_val = criticality_to_impact(asset.criticality)  # 3
        likelihood_val = 3  # High likelihood based on CVSS 8.8
        inherent_data = calculate_inherent_risk(likelihood_val, impact_val)
        inherent_score = inherent_data["inherent_risk_score"]
        residual_data = calculate_residual_risk(likelihood_val, impact_val, controls=[])
        residual_score = residual_data["residual_risk_score"]

        risk = models.Risk(
            asset_id=asset.id,
            title="PostgreSQL Remote Code Execution Exposure",
            description="Exposed database port with high CVSS vulnerability",
            likelihood="High",
            impact="High",
            inherent_risk_score=inherent_score,
            inherent_risk_level=inherent_data["inherent_risk_level"],
            residual_risk_score=residual_score,
            residual_risk_level=residual_data["residual_risk_level"],
            status="Identified",
            review_status="Pending Review",
        )
        self.db.add(risk)
        self.db.commit()
        self.db.refresh(risk)

        self.assertEqual(risk.inherent_risk_score, 9)
        self.assertEqual(risk.review_status, "Pending Review")

        # D. AI advisory generation
        ai_provider = StubMockAIProvider()
        ai_result = analyze_risk(risk_id=risk.id, db=self.db, provider=ai_provider)
        self.assertIsNotNone(ai_result)
        self.assertEqual(ai_result["priority"], "High")

        # Verify AI record exists
        ai_rec = self.db.query(models.AIRiskAnalysis).filter(models.AIRiskAnalysis.risk_id == risk.id).first()
        self.assertIsNotNone(ai_rec)
        self.assertEqual(ai_rec.model_name, "integration-mock-ai")

        # E. Human review / sign-off
        review_obj = submit_risk_review(
            db=self.db,
            risk_id=risk.id,
            decision="APPROVED",
            agreed_treatment="Mitigate",
            comments="Approved mitigation plan: firewall rules to be applied by EOD.",
            reviewer_name="SecLead Alice",
            reviewer_role="Security Lead",
            ai_analysis_acknowledged=True,
        )
        self.assertEqual(review_obj.decision, "APPROVED")
        self.assertEqual(review_obj.is_current, True)

        self.db.refresh(risk)
        self.assertEqual(risk.review_status, "Approved")
        self.assertEqual(risk.treatment, "Mitigate")

        # F. Audit event verification
        audit_events = self.db.query(models.AuditLog).all()
        self.assertTrue(len(audit_events) >= 1)
        review_audit = next((e for e in audit_events if e.action == "RISK_REVIEW_SUBMITTED"), None)
        self.assertIsNotNone(review_audit)
        self.assertEqual(review_audit.actor, "SecLead Alice")
        self.assertTrue(len(review_audit.integrity_hash) == 64)

        # G. Report generation
        content_json, media_json, file_json = generate_report(
            report_type="executive_summary",
            format_type="json",
            db=self.db,
            operator="SecLead Alice",
        )
        self.assertEqual(media_json, "application/json")
        self.assertTrue(file_json.endswith(".json"))
        parsed = json.loads(content_json)
        self.assertIn("authoritative_data", parsed)
        self.assertIn("ai_advisory_data", parsed)

    # 2. AI Advisory Isolation Enforcement
    def test_02_ai_advisory_isolation_enforcement(self):
        """Simulate malicious/extreme AI recommendations; verify authoritative GRC values are strictly immutable."""
        asset = models.Asset(ip_address="10.0.1.20", hostname="web-dmz.local", criticality="Medium")
        self.db.add(asset)
        self.db.commit()

        risk = models.Risk(
            asset_id=asset.id,
            title="HTTP Cleartext Service",
            description="Web server listening on port 80",
            likelihood="Medium",
            impact="Medium",
            inherent_risk_score=4,
            inherent_risk_level="Medium",
            residual_risk_score=4,
            residual_risk_level="Medium",
            status="Identified",
            review_status="Pending Review",
        )
        self.db.add(risk)
        self.db.commit()
        self.db.refresh(risk)

        # Snapshot authoritative values
        orig_likelihood = risk.likelihood
        orig_impact = risk.impact
        orig_inherent = risk.inherent_risk_score
        orig_residual = risk.residual_risk_score
        orig_status = risk.status
        orig_review_status = risk.review_status

        # AI provider returns extreme advisory recommendation trying to force Critical
        malicious_ai_result = AIAnalysisResult(
            priority="Critical",
            simple_explanation="Malicious attempt to manipulate GRC score to 25.",
            why_it_matters="Attacker claims total network compromise.",
            severity_explanation="Extreme priority injected.",
            risk_factors=["Critical Vulnerability"],
            potential_business_impact=["Total System Destruction"],
            recommendation=["Shut down entire infrastructure immediately"],
            remediation=RemediationSteps(
                immediate_mitigation=["Sever all network cables"],
                permanent_remediation=["Decommission business"],
                validation=["Verify total outage"],
            ),
            recommended_controls=[RecommendedControl(name="ExtremeControl", reason="Forced mitigation")],
            confidence=0.99,
            model_name="malicious-injected-ai",
            human_review_required=True,
        )

        malicious_provider = StubMockAIProvider(override_result=malicious_ai_result)
        analyze_risk(risk_id=risk.id, db=self.db, provider=malicious_provider)

        self.db.refresh(risk)

        # Assert strict immutability of authoritative GRC fields
        self.assertEqual(risk.likelihood, orig_likelihood)
        self.assertEqual(risk.impact, orig_impact)
        self.assertEqual(risk.inherent_risk_score, orig_inherent)
        self.assertEqual(risk.residual_risk_score, orig_residual)
        self.assertEqual(risk.status, orig_status)
        self.assertEqual(risk.review_status, orig_review_status)

    # 3. Human Approval Workflow
    def test_03_human_approval_workflow(self):
        """Verify approving a risk sets review_status='Approved' while preserving Risk.status."""
        asset = models.Asset(ip_address="10.0.1.25", hostname="auth-srv.local", criticality="High")
        self.db.add(asset)
        self.db.commit()

        risk = models.Risk(
            asset_id=asset.id,
            title="LDAP Anonymous Bind",
            description="LDAP allows unauthenticated directory queries",
            likelihood="High",
            impact="High",
            inherent_risk_score=9,
            inherent_risk_level="High",
            residual_risk_score=9,
            residual_risk_level="High",
            status="Active Finding",
            review_status="Pending Review",
        )
        self.db.add(risk)
        self.db.commit()
        self.db.refresh(risk)

        review_obj = submit_risk_review(
            db=self.db,
            risk_id=risk.id,
            decision="APPROVED",
            agreed_treatment="Mitigate",
            comments="Approved: LDAP binding to require Kerberos authentication.",
            reviewer_name="SecAnalyst Bob",
            reviewer_role="Senior Analyst",
            ai_analysis_acknowledged=False,
        )

        self.db.refresh(risk)
        self.assertEqual(review_obj.decision, "APPROVED")
        self.assertEqual(risk.review_status, "Approved")
        self.assertEqual(risk.treatment, "Mitigate")
        # Existing Risk.status remains independent and untouched
        self.assertEqual(risk.status, "Active Finding")

    # 4. Review History Retrieval
    def test_04_review_history_retrieval(self):
        """Verify multiple reviews preserve historical trail and mark only latest as current."""
        asset = models.Asset(ip_address="10.0.2.10", hostname="api-gateway.local", criticality="Medium")
        self.db.add(asset)
        self.db.commit()

        risk = models.Risk(
            asset_id=asset.id,
            title="TLS 1.0 Enabled",
            description="Legacy cipher suites permitted",
            likelihood="Medium",
            impact="Medium",
            inherent_risk_score=4,
            inherent_risk_level="Medium",
            residual_risk_score=4,
            residual_risk_level="Medium",
            review_status="Pending Review",
        )
        self.db.add(risk)
        self.db.commit()
        self.db.refresh(risk)

        # Review 1: Changes Requested
        submit_risk_review(
            db=self.db,
            risk_id=risk.id,
            decision="CHANGES_REQUESTED",
            agreed_treatment="Mitigate",
            comments="Please provide updated cipher deprecation schedule.",
            reviewer_name="Auditor Carol",
            reviewer_role="GRC Lead",
        )

        # Review 2: Approved
        submit_risk_review(
            db=self.db,
            risk_id=risk.id,
            decision="APPROVED",
            agreed_treatment="Mitigate",
            comments="Schedule provided and verified.",
            reviewer_name="Auditor Carol",
            reviewer_role="GRC Lead",
        )

        current_review, history, is_stale, stale_reasons = get_or_evaluate_risk_reviews(db=self.db, risk_id=risk.id)
        self.assertIsNotNone(current_review)
        self.assertEqual(current_review.decision, "APPROVED")
        self.assertEqual(len(history), 2)

        # Historical review check
        historical = [r for r in history if not r.is_current]
        self.assertEqual(len(historical), 1)
        self.assertEqual(historical[0].decision, "CHANGES_REQUESTED")

    # 5. Audit Event Generation on Review Submission
    def test_05_audit_generation_on_review(self):
        """Verify review submission records an auditable RISK_REVIEW_SUBMITTED milestone."""
        asset = models.Asset(ip_address="10.0.3.5", hostname="dns-primary.local", criticality="High")
        self.db.add(asset)
        self.db.commit()

        risk = models.Risk(
            asset_id=asset.id,
            title="DNS Zone Transfer Allowed",
            description="AXFR permitted to arbitrary clients",
            likelihood="High",
            impact="High",
            inherent_risk_score=9,
            inherent_risk_level="High",
            residual_risk_score=9,
            residual_risk_level="High",
            review_status="Pending Review",
        )
        self.db.add(risk)
        self.db.commit()
        self.db.refresh(risk)

        submit_risk_review(
            db=self.db,
            risk_id=risk.id,
            decision="APPROVED",
            agreed_treatment="Mitigate",
            comments="Restricted AXFR to secondary DNS servers only.",
            reviewer_name="SecOps Dave",
            reviewer_role="Network Admin",
        )

        audit_entry = (
            self.db.query(models.AuditLog)
            .filter(models.AuditLog.action == "RISK_REVIEW_SUBMITTED")
            .first()
        )
        self.assertIsNotNone(audit_entry)
        self.assertEqual(audit_entry.actor, "SecOps Dave")
        self.assertEqual(audit_entry.source, "USER")
        self.assertIn("APPROVED", audit_entry.new_values)
        self.assertTrue(len(audit_entry.integrity_hash) == 64)

    # 6. Stale Review Invalidation on Vulnerability Drift
    def test_06_stale_review_on_vulnerability_drift(self):
        """Verify that relevant vulnerability drift marks approved review as STALE with an audit event."""
        asset = models.Asset(ip_address="10.0.4.1", hostname="db-cluster-01.local", criticality="High")
        self.db.add(asset)
        self.db.commit()

        vuln = models.Vulnerability(
            asset_id=asset.id,
            title="PostgreSQL Information Disclosure",
            severity="Medium",
            cve="CVE-2023-1001",
            cvss_score=5.5,
            port=5432,
            service="postgresql",
        )
        self.db.add(vuln)
        self.db.commit()

        risk = models.Risk(
            asset_id=asset.id,
            title="PostgreSQL Service Exposure",
            description="Exposed database service",
            likelihood="Medium",
            impact="High",
            inherent_risk_score=6,
            inherent_risk_level="Medium",
            residual_risk_score=6,
            residual_risk_level="Medium",
            review_status="Pending Review",
        )
        self.db.add(risk)
        self.db.commit()
        self.db.refresh(risk)

        # Approve review
        submit_risk_review(
            db=self.db,
            risk_id=risk.id,
            decision="APPROVED",
            agreed_treatment="Mitigate",
            comments="Baseline verified and approved.",
            reviewer_name="Auditor Eve",
            reviewer_role="Lead Auditor",
        )

        self.db.refresh(risk)
        self.assertEqual(risk.review_status, "Approved")

        # Simulate drift: Add a new critical vulnerability to the same service
        drift_vuln = models.Vulnerability(
            asset_id=asset.id,
            title="PostgreSQL Remote Arbitrary Code Execution",
            severity="Critical",
            cve="CVE-2024-9999",
            cvss_score=9.8,
            port=5432,
            service="postgresql",
        )
        self.db.add(drift_vuln)
        self.db.commit()

        # Query reviews dynamically via review manager which executes staleness check
        current_review, history, is_stale, stale_reasons = get_or_evaluate_risk_reviews(db=self.db, risk_id=risk.id)
        self.assertTrue(is_stale)
        self.assertTrue(len(stale_reasons) >= 1)

        self.db.refresh(risk)
        self.assertEqual(risk.review_status, "Stale")

        # Verify RISK_REVIEW_STALE audit log
        stale_audit = (
            self.db.query(models.AuditLog)
            .filter(
                models.AuditLog.action == "RISK_REVIEW_STALE",
                models.AuditLog.entity_id == risk.id,
            )
            .first()
        )
        self.assertIsNotNone(stale_audit)
        self.assertEqual(stale_audit.source, "SYSTEM")

    # 7. Audit Integrity Hash Verification
    def test_07_audit_integrity_hash_verification(self):
        """Verify that audit integrity hash can be deterministically recomputed from event fields."""
        log_audit_event(
            db=self.db,
            source="SYSTEM",
            actor="VerifierAgent",
            action="CONTROL_EFFECTIVENESS_VERIFIED",
            entity_type="Control",
            entity_id=42,
            entity_name="Firewall Rule 101",
            old_values={"effectiveness": "Low"},
            new_values={"effectiveness": "High"},
            description="Verified rule prevents unauthorized external ingress.",
            ip_address="127.0.0.1",
            commit=True,
        )

        entry = (
            self.db.query(models.AuditLog)
            .filter(
                models.AuditLog.action == "CONTROL_EFFECTIVENESS_VERIFIED",
                models.AuditLog.entity_id == 42,
            )
            .first()
        )
        self.assertIsNotNone(entry)
        stored_hash = entry.integrity_hash

        # Recompute hash using exact canonical function
        recomputed = calculate_audit_integrity_hash(
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

        self.assertEqual(stored_hash, recomputed)

    # 8. CSV Formula Injection Defense
    def test_08_csv_formula_injection_defense(self):
        """Verify malicious values starting with =, +, -, @, \\t, \\r are prefixed with single quote in CSV export."""
        malicious_cells = [
            "=CMD('calc')",
            "@SUM(1,1)",
            "-1+1",
            "+5-2",
            "\tTAB_INJECT",
            "\rRETURN_INJECT",
        ]

        for cell in malicious_cells:
            sanitized = sanitize_csv_cell(cell)
            self.assertTrue(
                sanitized.startswith("'"),
                f"Expected cell {cell!r} to be sanitized with leading single quote, got {sanitized!r}",
            )

        # Test in full CSV export pipeline
        asset = models.Asset(ip_address="10.0.5.5", hostname="vuln-host.local", criticality="Medium")
        self.db.add(asset)
        self.db.commit()

        risk = models.Risk(
            asset_id=asset.id,
            title="=HYPERLINK('http://attacker.com','Click Me')",
            description="@SUM(1,2,3) malicious formula in description",
            likelihood="Low",
            impact="Low",
            inherent_risk_score=1,
            inherent_risk_level="Low",
            residual_risk_score=1,
            residual_risk_level="Low",
        )
        self.db.add(risk)
        self.db.commit()

        content_csv, media_csv, filename_csv = generate_report(
            report_type="risk_register",
            format_type="csv",
            db=self.db,
            operator="SecurityTester",
        )

        self.assertIn("DISCLAIMER", content_csv)
        self.assertTrue(filename_csv.endswith(".csv"))
        # Ensure raw formula syntax is not present unquoted at start of fields
        self.assertNotIn("\n=HYPERLINK", content_csv)
        self.assertNotIn(",=HYPERLINK", content_csv)

    # 9. Multi-Format Report Generation
    def test_09_multi_format_report_generation(self):
        """Verify that risk register reports generate cleanly across JSON, CSV, and HTML."""
        asset = models.Asset(ip_address="10.0.6.1", hostname="app-node.local", criticality="Medium")
        self.db.add(asset)
        self.db.commit()

        risk = models.Risk(
            asset_id=asset.id,
            title="Unencrypted Management Interface",
            description="Telnet running on port 23",
            likelihood="Medium",
            impact="High",
            inherent_risk_score=6,
            inherent_risk_level="Medium",
            residual_risk_score=6,
            residual_risk_level="Medium",
            review_status="Approved",
        )
        self.db.add(risk)
        self.db.commit()

        # 1. JSON
        c_json, m_json, f_json = generate_report("risk_register", "json", self.db, "Tester")
        self.assertEqual(m_json, "application/json")
        self.assertTrue(f_json.endswith(".json"))
        parsed = json.loads(c_json)
        self.assertIn("authoritative_data", parsed)
        self.assertTrue(len(parsed["authoritative_data"]["records"]) >= 1)

        # 2. CSV
        c_csv, m_csv, f_csv = generate_report("risk_register", "csv", self.db, "Tester")
        self.assertEqual(m_csv, "text/csv; charset=utf-8")
        self.assertTrue(f_csv.endswith(".csv"))
        self.assertIn("Unencrypted Management Interface", c_csv)

        # 3. HTML
        c_html, m_html, f_html = generate_report("risk_register", "html", self.db, "Tester")
        self.assertEqual(m_html, "text/html; charset=utf-8")
        self.assertTrue(f_html.endswith(".html"))
        self.assertIn("<!DOCTYPE html>", c_html)
        self.assertIn("Unencrypted Management Interface", c_html)

    # 10. Authoritative vs AI Separation in Reports
    def test_10_authoritative_vs_ai_separation_in_reports(self):
        """Verify that reports clearly distinguish authoritative GRC data from AI advisory intelligence."""
        asset = models.Asset(ip_address="10.0.7.1", hostname="k8s-worker.local", criticality="High")
        self.db.add(asset)
        self.db.commit()

        risk = models.Risk(
            asset_id=asset.id,
            title="Kubelet Port Exposed",
            description="Kubelet API accessible without token auth",
            likelihood="High",
            impact="High",
            inherent_risk_score=9,
            inherent_risk_level="High",
            residual_risk_score=9,
            residual_risk_level="High",
        )
        self.db.add(risk)
        self.db.commit()
        self.db.refresh(risk)

        # Add AI analysis
        ai_provider = StubMockAIProvider()
        analyze_risk(risk_id=risk.id, db=self.db, provider=ai_provider)

        # Generate Executive Summary in JSON
        c_json, _, _ = generate_report("executive_summary", "json", self.db, "ComplianceReviewer")
        parsed = json.loads(c_json)

        self.assertIn("authoritative_data", parsed)
        self.assertIn("ai_advisory_data", parsed)
        self.assertIn("notice", parsed["ai_advisory_data"])
        self.assertIn("NON-AUTHORITATIVE", parsed["ai_advisory_data"]["notice"])

        # Generate HTML report and check for visible demarcation headers
        c_html, _, _ = generate_report("executive_summary", "html", self.db, "ComplianceReviewer")
        self.assertIn("[AUTHORITATIVE GRC DATA]", c_html)
        self.assertIn("NON-AUTHORITATIVE", c_html)

    # 11. Compliance Framework Integration
    def test_11_compliance_integration_with_controls(self):
        """Verify NIST CSF compliance structures integrate with controls and reports."""
        fw = models.ComplianceFramework(
            name="NIST CSF",
            version="2.0",
            description="National Institute of Standards and Technology CSF 2.0",
        )
        self.db.add(fw)
        self.db.commit()

        req = models.ComplianceRequirement(
            framework_id=fw.id,
            requirement_id="PR.AA-01",
            function="PROTECT",
            category="Identity Management (PR.AA)",
            subcategory="PR.AA-01",
            title="Identities and credentials are managed",
            description="Credentials are authenticated and revoked upon departure.",
            status="Not Assessed",
        )
        self.db.add(req)
        self.db.commit()

        control = models.Control(
            name="Central Identity Management",
            description="SSO and MFA via IdP",
            category="Technical",
            framework="NIST CSF",
            effectiveness="High",
            status="Implemented",
        )
        self.db.add(control)
        self.db.commit()

        mapping = models.ControlComplianceMapping(
            control_id=control.id,
            requirement_id=req.id,
            mapping_strength="Direct",
            notes="Maps IdP to PR.AA-01",
        )
        self.db.add(mapping)
        self.db.commit()

        gap_data = generate_compliance_gap_data(db=self.db, operator="ComplianceOfficer")
        self.assertIn("table_rows", gap_data)
        found_row = next((r for r in gap_data["table_rows"] if r[2] == "PR.AA-01"), None)
        self.assertIsNotNone(found_row)
        self.assertEqual(found_row[1], "NIST CSF")
        self.assertEqual(found_row[6], "Central Identity Management")

    # 12. Existing Data Semantics: Not Assessed & Not Applicable
    def test_12_compliance_not_assessed_not_applicable_semantics(self):
        """Verify 'Not Assessed' and 'Not Applicable' statuses maintain strict evaluation semantics."""
        fw = models.ComplianceFramework(
            name="ISO 27001",
            version="2022",
            description="ISO/IEC 27001:2022 ISMS",
        )
        self.db.add(fw)
        self.db.commit()

        # Req 1: Not Assessed (default)
        req_unassessed = models.ComplianceRequirement(
            framework_id=fw.id,
            requirement_id="A.5.1",
            function="Organizational",
            category="A.5",
            subcategory="A.5.1",
            title="Policies for information security",
            description="Policies defined and approved",
            status="Not Assessed",
        )
        # Req 2: Not Applicable
        req_na = models.ComplianceRequirement(
            framework_id=fw.id,
            requirement_id="A.7.4",
            function="Physical",
            category="A.7",
            subcategory="A.7.4",
            title="Physical security monitoring",
            description="Monitored by surveillance in server rooms",
            status="Not Applicable",
        )
        self.db.add_all([req_unassessed, req_na])
        self.db.commit()

        # Mapping a control to req_unassessed must NOT automatically mark it compliant/implemented
        ctrl = models.Control(
            name="Security Policy Document",
            description="Approved corporate ISMS policy",
            category="Administrative",
            framework="ISO 27001",
            effectiveness="Medium",
            status="Implemented",
        )
        self.db.add(ctrl)
        self.db.commit()

        map_link = models.ControlComplianceMapping(
            control_id=ctrl.id,
            requirement_id=req_unassessed.id,
            mapping_strength="Direct",
        )
        self.db.add(map_link)
        self.db.commit()

        self.db.refresh(req_unassessed)
        self.db.refresh(req_na)

        # Invariant: Requirement status remains 'Not Assessed' until explicit assessor determination
        self.assertEqual(req_unassessed.status, "Not Assessed")
        # Invariant: Requirement marked 'Not Applicable' preserves its designated exclusion state
        self.assertEqual(req_na.status, "Not Applicable")


if __name__ == "__main__":
    unittest.main()

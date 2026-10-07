"""Phase 6B Isolated Automated Test Suite: Reporting & Multi-Format Export Engine.

Tests cover:
1. CSV formula injection defense (OWASP CSV Injection).
2. Safe dataset size ceilings (rejection of oversized exports vs. silent truncation).
3. HTML XSS escaping and print stylesheet formatting.
4. Authoritative vs. AI-advisory data separation and disclaimer presence.
5. All 5 report types across JSON, CSV, and HTML formats.
6. API endpoint integration, content negotiation, and export audit event recording.

Zero external network or service dependencies; runs entirely in-memory with SQLite.
"""

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
from reporting.csv_export import (
    sanitize_csv_cell,
    build_csv_report,
    MAX_REPORT_ROWS,
    STANDARD_DISCLAIMER,
)
from reporting.html_export import (
    safe_escape,
    build_html_report,
)
from reporting.report_generator import (
    generate_report,
    generate_executive_summary_data,
    generate_technical_vulnerabilities_data,
    generate_compliance_gap_data,
    generate_risk_register_data,
    generate_governance_audit_data,
    REPORT_GENERATORS,
)
import main


class BasePhase6bIsolatedTestCase(unittest.TestCase):
    """Sets up an in-memory SQLite database populated with foundational GRC records."""

    def setUp(self):
        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        models.Base.metadata.create_all(bind=self.engine)
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        self.db = self.SessionLocal()

        # Seed representative foundational test data
        self.asset = models.Asset(
            ip_address="192.168.1.15",
            hostname="finance-db.local",
            criticality="Critical",
            environment="Production",
            exposure="Internal",
            owner="DataOps",
            business_function="Financial Ledger",
        )
        self.db.add(self.asset)
        self.db.commit()
        self.db.refresh(self.asset)

        self.vuln = models.Vulnerability(
            asset_id=self.asset.id,
            port=5432,
            service="postgresql",
            title="PostgreSQL Remote Code Execution",
            severity="High",
            cve="CVE-2023-39417",
            cvss_score=8.8,
            status="Open",
        )
        self.db.add(self.vuln)

        self.risk = models.Risk(
            asset_id=self.asset.id,
            title="Database Exposed to Unauthorized Network Segments",
            description="Port 5432 reachable from non-isolated VLANs",
            likelihood="High",
            impact="Critical",
            inherent_risk_score=16,
            inherent_risk_level="Critical",
            residual_risk_score=8,
            residual_risk_level="High",
            treatment="Mitigate",
            status="Open",
            risk_owner="SecOps Lead",
        )
        self.db.add(self.risk)
        self.db.commit()
        self.db.refresh(self.risk)

        self.control = models.Control(
            name="VLAN Isolation & Stateful Firewall Rule",
            description="Restrict inbound access to port 5432 to application tier only",
            category="Preventive",
            effectiveness="High",
            status="Implemented",
        )
        self.control.risks.append(self.risk)
        self.db.add(self.control)

        self.framework = models.ComplianceFramework(
            name="NIST CSF",
            version="2.0",
            description="National Institute of Standards and Technology Cybersecurity Framework",
        )
        self.db.add(self.framework)
        self.db.commit()
        self.db.refresh(self.framework)

        self.requirement = models.ComplianceRequirement(
            framework_id=self.framework.id,
            requirement_id="PR.AC-05",
            title="Network integrity is protected",
            function="Protect",
            category="Access Control",
            status="Implemented",
        )
        self.db.add(self.requirement)
        self.db.commit()
        self.db.refresh(self.requirement)

        self.mapping = models.ControlComplianceMapping(
            control_id=self.control.id,
            requirement_id=self.requirement.id,
            mapping_strength="Direct",
        )
        self.db.add(self.mapping)

        self.ai_analysis = models.AIRiskAnalysis(
            risk_id=self.risk.id,
            priority="High",
            simple_explanation="Critical database port open to unauthorized segments.",
            why_it_matters="Attacker could access financial records or execute arbitrary code.",
            severity_explanation="CVSS 8.8 vulnerability on production crown jewel.",
            recommendation=json.dumps(["Enforce network ACLs immediately", "Upgrade PostgreSQL package"]),
            confidence=0.95,
            model_name="gemini-1.5-flash",
        )
        self.db.add(self.ai_analysis)

        self.audit_log = models.AuditLog(
            source="USER",
            actor="compliance_officer",
            action="UPDATE",
            entity_type="Risk",
            entity_id=self.risk.id,
            entity_name=self.risk.title,
            description="Updated residual risk after compensating control verification",
            integrity_hash="a"*64,
            ip_address="10.0.0.5",
        )
        self.db.add(self.audit_log)
        self.db.commit()

    def tearDown(self):
        self.db.close()
        models.Base.metadata.drop_all(bind=self.engine)


class TestCsvExport(unittest.TestCase):
    """Unit tests for CSV export generation and formula injection defenses."""

    def test_sanitize_csv_cell_dangerous_formula_prefixes(self):
        # Formulas starting with =, +, -, @, \t, \r must be prepended with a single quote
        self.assertEqual(sanitize_csv_cell("=cmd|' /C calc'!A0"), "'=cmd|' /C calc'!A0")
        self.assertEqual(sanitize_csv_cell("=SUM(A1:A10)"), "'=SUM(A1:A10)")
        self.assertEqual(sanitize_csv_cell("+12345"), "'+12345")
        self.assertEqual(sanitize_csv_cell("-12345"), "'-12345")
        self.assertEqual(sanitize_csv_cell("@SUM(A1)"), "'@SUM(A1)")
        self.assertEqual(sanitize_csv_cell("\tTabPrefix"), "'\tTabPrefix")
        self.assertEqual(sanitize_csv_cell("\rReturnPrefix"), "'\rReturnPrefix")

    def test_sanitize_csv_cell_safe_values_preserved(self):
        # Benign values must remain unquoted
        self.assertEqual(sanitize_csv_cell("Normal String"), "Normal String")
        self.assertEqual(sanitize_csv_cell("CVE-2023-39417"), "CVE-2023-39417")
        self.assertEqual(sanitize_csv_cell(42), 42)
        self.assertEqual(sanitize_csv_cell(8.8), 8.8)
        self.assertEqual(sanitize_csv_cell(True), True)
        self.assertEqual(sanitize_csv_cell(None), "")

    def test_build_csv_report_structure_and_bom(self):
        headers = ["Risk ID", "Title", "Severity"]
        rows = [
            [1, "=Malicious Formula", "High"],
            [2, "Safe Risk Title", "Medium"],
        ]
        csv_text = build_csv_report(
            headers=headers,
            rows=rows,
            title="Test Risk Report",
            disclaimer="TEST DISCLAIMER",
        )

        # Must start with UTF-8 BOM
        self.assertTrue(csv_text.startswith("\ufeff"))
        # Must include metadata comments
        self.assertIn("# REPORT: Test Risk Report", csv_text)
        self.assertIn("# TOTAL_ROWS: 2", csv_text)
        self.assertIn("# TEST DISCLAIMER", csv_text)
        # Must include headers
        self.assertIn("Risk ID,Title,Severity", csv_text)
        # Must neutralize formula injection
        self.assertIn("1,'=Malicious Formula,High", csv_text)
        self.assertIn("2,Safe Risk Title,Medium", csv_text)

    def test_build_csv_report_rejects_oversized_dataset(self):
        headers = ["Col1"]
        # Create dataset exceeding MAX_REPORT_ROWS (10,000)
        oversized_rows = [[i] for i in range(MAX_REPORT_ROWS + 1)]
        with self.assertRaises(ValueError) as ctx:
            build_csv_report(
                headers=headers,
                rows=oversized_rows,
                title="Massive Export",
            )
        self.assertIn("exceeding the maximum supported export limit", str(ctx.exception))
        self.assertIn("10000", str(ctx.exception))


class TestHtmlExport(unittest.TestCase):
    """Unit tests for HTML export formatting, stored XSS protection, and print styling."""

    def test_html_export_xss_sanitization(self):
        malicious_title = "<script>alert('XSS Title')</script>"
        malicious_cell = "<img src=x onerror=alert('XSS Cell')>"
        malicious_adv = "'; alert('XSS Advisory'); //"

        html_text = build_html_report(
            title=malicious_title,
            subtitle="Testing XSS Protections",
            summary_cards=[{"label": "Card", "value": "10"}],
            table_headers=["Col1", "Col2"],
            table_rows=[[1, malicious_cell]],
            ai_advisories=[{
                "title": "Advisory",
                "priority": "High",
                "simple_explanation": malicious_adv,
            }],
        )

        # Raw tags must NOT exist
        self.assertNotIn("<script>alert('XSS Title')</script>", html_text)
        self.assertNotIn("<img src=x", html_text)
        # Properly escaped representations must be present
        self.assertIn("&lt;script&gt;alert(&#x27;XSS Title&#x27;)&lt;/script&gt;", html_text)
        self.assertIn("&lt;img src=x onerror=alert(&#x27;XSS Cell&#x27;)&gt;", html_text)

    def test_html_export_print_media_css(self):
        html_text = build_html_report(
            title="Executive Report",
            subtitle="Subtitle",
            summary_cards=[],
            table_headers=["A"],
            table_rows=[["B"]],
        )
        self.assertIn("@media print", html_text)
        self.assertIn("page-break-inside: avoid;", html_text)

    def test_html_export_disclaimer_and_badges(self):
        html_text = build_html_report(
            title="Executive Report",
            subtitle="Subtitle",
            summary_cards=[],
            table_headers=["A"],
            table_rows=[["B"]],
            ai_advisories=[{
                "title": "Adv",
                "priority": "Low",
                "simple_explanation": "Advisory text",
            }],
        )
        self.assertIn("[AUTHORITATIVE GRC DATA]", html_text)
        self.assertIn("[AI-ASSISTED ADVISORY — NON-AUTHORITATIVE]", html_text)
        self.assertIn("DISCLAIMER:", html_text)
        self.assertIn("does not constitute formal legal counsel", html_text)

    def test_html_export_rejects_oversized_dataset(self):
        oversized_rows = [[i] for i in range(MAX_REPORT_ROWS + 1)]
        with self.assertRaises(ValueError) as ctx:
            build_html_report(
                title="Massive Report",
                subtitle="Sub",
                summary_cards=[],
                table_headers=["Col"],
                table_rows=oversized_rows,
            )
        self.assertIn("exceeding the maximum supported export limit", str(ctx.exception))


class TestReportGenerators(BasePhase6bIsolatedTestCase):
    """Unit tests for the 5 report data assembly generators."""

    def test_executive_summary_data(self):
        data = generate_executive_summary_data(self.db, operator="auditor_jane")
        self.assertEqual(data["title"], "Executive Risk & Posture Summary")
        self.assertGreaterEqual(len(data["summary_cards"]), 4)
        self.assertIn("Risk ID", data["table_headers"])
        self.assertEqual(len(data["table_rows"]), 1)
        self.assertEqual(data["table_rows"][0][2], "Database Exposed to Unauthorized Network Segments")
        # Confirms AI advisories are extracted
        self.assertIsNotNone(data["ai_advisories"])
        self.assertEqual(len(data["ai_advisories"]), 1)

    def test_technical_vulnerabilities_data(self):
        data = generate_technical_vulnerabilities_data(self.db, operator="sec_eng")
        self.assertEqual(data["title"], "Technical Vulnerability & Attack Surface Report")
        self.assertIn("CVE ID", data["table_headers"])
        self.assertEqual(len(data["table_rows"]), 1)
        row = data["table_rows"][0]
        # Assert accurate CVE terminology & CVSS score
        self.assertEqual(row[5], "CVE-2023-39417")
        self.assertEqual(row[6], 8.8)
        self.assertEqual(row[7], "High")

    def test_compliance_gap_data(self):
        data = generate_compliance_gap_data(self.db, operator="grc_analyst")
        self.assertEqual(data["title"], "Compliance Readiness & Gap Analysis Report")
        self.assertIn("Framework", data["table_headers"])
        self.assertIn("Mapped Controls", data["table_headers"])
        self.assertEqual(len(data["table_rows"]), 1)
        row = data["table_rows"][0]
        self.assertEqual(row[1], "NIST CSF")
        self.assertEqual(row[2], "PR.AC-05")
        self.assertIn("VLAN Isolation", row[6])
        # Verifies disclaimer explicitly states non-certification
        self.assertIn("not constitute formal legal counsel", data["metadata"]["disclaimer"])

    def test_risk_register_data(self):
        data = generate_risk_register_data(self.db, operator="risk_mgr")
        self.assertEqual(data["title"], "Enterprise Risk Register Report")
        self.assertIn("Inherent Score", data["table_headers"])
        self.assertIn("Residual Score", data["table_headers"])
        row = data["table_rows"][0]
        self.assertEqual(row[3], 16)  # Inherent score
        self.assertEqual(row[5], 8)   # Residual score
        self.assertEqual(row[7], "Mitigate")

    def test_governance_audit_data(self):
        data = generate_governance_audit_data(self.db, operator="compliance_officer")
        self.assertEqual(data["title"], "Governance Audit Trail & Evidence Report")
        self.assertIn("Integrity Hash (SHA-256)", data["table_headers"])
        row = data["table_rows"][0]
        self.assertEqual(row[2], "USER")
        self.assertEqual(row[3], "compliance_officer")
        self.assertEqual(row[9], "a"*64)

    def test_generate_report_dispatcher_all_formats(self):
        # 1. JSON
        content_json, media_json, file_json = generate_report("executive_summary", "json", self.db, "admin")
        self.assertEqual(media_json, "application/json")
        self.assertTrue(file_json.endswith(".json"))
        parsed = json.loads(content_json)
        self.assertIn("metadata", parsed)
        self.assertIn("authoritative_data", parsed)
        self.assertIn("ai_advisory_data", parsed)

        # 2. CSV
        content_csv, media_csv, file_csv = generate_report("technical_vulnerabilities", "csv", self.db, "admin")
        self.assertEqual(media_csv, "text/csv; charset=utf-8")
        self.assertTrue(file_csv.endswith(".csv"))
        self.assertIn("CVE-2023-39417", content_csv)

        # 3. HTML
        content_html, media_html, file_html = generate_report("compliance_gap", "html", self.db, "admin")
        self.assertEqual(media_html, "text/html; charset=utf-8")
        self.assertTrue(file_html.endswith(".html"))
        self.assertIn("<!DOCTYPE html>", content_html)
        self.assertIn("NIST CSF", content_html)

    def test_generate_report_invalid_inputs(self):
        with self.assertRaises(ValueError):
            generate_report("invalid_report", "json", self.db)
        with self.assertRaises(ValueError):
            generate_report("executive_summary", "pdf_unsupported", self.db)


class TestReportingApiEndpoints(BasePhase6bIsolatedTestCase):
    """Integration tests for Phase 6B REST API report export routes."""

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

    def test_api_executive_summary_json(self):
        resp = self.client.get("/reports/executive-summary?format=json")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers["content-type"], "application/json")
        self.assertIn("attachment; filename=", resp.headers["content-disposition"])
        data = resp.json()
        self.assertIn("authoritative_data", data)
        self.assertIn("ai_advisory_data", data)

    def test_api_technical_vulnerabilities_csv(self):
        resp = self.client.get("/reports/technical-vulnerabilities?format=csv")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("text/csv", resp.headers["content-type"])
        self.assertIn("CVE-2023-39417", resp.text)

    def test_api_compliance_gap_html(self):
        resp = self.client.get("/reports/compliance-gap?format=html")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("text/html", resp.headers["content-type"])
        self.assertIn("[AUTHORITATIVE GRC DATA]", resp.text)
        self.assertIn("NIST CSF", resp.text)

    def test_api_risk_register_export(self):
        resp = self.client.get("/reports/risk-register?format=json")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["metadata"]["report_type"], "risk_register")

    def test_api_audit_trail_export(self):
        resp = self.client.get("/reports/audit-trail?format=csv")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("compliance_officer", resp.text)

    def test_api_generic_endpoint_route(self):
        resp = self.client.get("/reports/executive_summary?format=html")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("Executive Risk &amp; Posture Summary", resp.text)

    def test_api_invalid_format_returns_400(self):
        resp = self.client.get("/reports/executive-summary?format=docx")
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Unsupported format", resp.json()["detail"])

    def test_api_invalid_report_type_returns_400(self):
        resp = self.client.get("/reports/non_existent_report?format=json")
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Unsupported report type", resp.json()["detail"])

    def test_api_export_records_audit_event(self):
        # Trigger export
        resp = self.client.get(
            "/reports/risk-register?format=csv",
            headers={"X-Operator-Name": "AuditorBob"},
        )
        self.assertEqual(resp.status_code, 200)

        # Verify an EXPORT audit log entry was recorded
        audit_entry = (
            self.db.query(models.AuditLog)
            .filter(
                models.AuditLog.action == "EXPORT",
                models.AuditLog.entity_name == "risk_register",
            )
            .order_by(models.AuditLog.id.desc())
            .first()
        )
        self.assertIsNotNone(audit_entry)
        self.assertEqual(audit_entry.actor, "AuditorBob")
        self.assertIn("CSV", audit_entry.description)

    def test_api_oversized_export_rejection(self):
        # Verify that when query exceeds MAX_REPORT_ROWS, an HTTP 400 with a clear message is returned
        with mock.patch("reporting.report_generator._validate_row_limit") as mock_val:
            mock_val.side_effect = ValueError(
                "Query for report 'Executive Summary' returned 10001 records, exceeding the maximum supported export limit of 10000 rows."
            )
            resp = self.client.get("/reports/executive-summary?format=json")
            self.assertEqual(resp.status_code, 400)
            self.assertIn("exceeding the maximum supported export limit", resp.json()["detail"])


if __name__ == "__main__":
    unittest.main()

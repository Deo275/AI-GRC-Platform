import unittest
import os
from unittest.mock import patch, MagicMock

from scanner.openvas_scanner import (
    get_openvas_config,
    get_openvas_status,
    parse_openvas_xml_report,
    execute_openvas_scan,
)
from backend.reporting.pdf_export import PDFCanvas, build_pdf_report
from backend.reporting.report_generator import generate_report, REPORT_GENERATORS


class TestOpenVASScanner(unittest.TestCase):
    @patch.dict(os.environ, {
        "OPENVAS_HOST": "",
        "OPENVAS_PORT": "9390",
        "OPENVAS_USER": "",
        "OPENVAS_PASSWORD": "",
        "OPENVAS_SOCKET": "",
    }, clear=True)
    def test_openvas_unconfigured_status(self):
        status = get_openvas_status()
        self.assertEqual(status["status"], "Not Configured")
        self.assertFalse(status["available"])
        self.assertFalse(status["configured"])
        self.assertIn("OPENVAS_HOST", status["message"])
        self.assertIn("supported_features", status)
        self.assertIn("Greenbone Management Protocol (GMP)", status["supported_features"])

    @patch.dict(os.environ, {
        "OPENVAS_HOST": "127.0.0.1",
        "OPENVAS_PORT": "9390",
        "OPENVAS_USER": "admin",
        "OPENVAS_PASSWORD": "dummy_password",
        "OPENVAS_SOCKET": "",
    }, clear=True)
    def test_openvas_configured_connection_probe_failure(self):
        # 127.0.0.1:9390 should fail to connect when no daemon is running
        status = get_openvas_status()
        self.assertTrue(status["configured"])
        self.assertFalse(status["available"])
        self.assertIn(status["status"], ("Unreachable", "Connection Error"))
        self.assertIn("unreachable", status["message"].lower())

    @patch("socket.socket")
    def test_openvas_configured_and_connected(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_socket_cls.return_value = mock_sock

        with patch.dict(os.environ, {
            "OPENVAS_HOST": "openvas.internal",
            "OPENVAS_PORT": "9390",
            "OPENVAS_USER": "admin",
            "OPENVAS_PASSWORD": "secret_password",
            "OPENVAS_SOCKET": "",
        }, clear=True):
            status = get_openvas_status()
            self.assertEqual(status["status"], "Connected")
            self.assertTrue(status["available"])
            self.assertEqual(status["host"], "openvas.internal")
            self.assertEqual(status["port"], 9390)
            self.assertEqual(status["user"], "admin")

    def test_parse_openvas_xml_report(self):
        sample_xml = """<?xml version="1.0" encoding="UTF-8"?>
        <report id="rep-001">
            <results>
                <result id="res-1">
                    <name>Apache Log4j Remote Code Execution</name>
                    <host>192.168.1.105</host>
                    <port>8080/tcp</port>
                    <nvt oid="1.3.6.1.4.1.25623.1.0.12345">
                        <cve>CVE-2021-44228, CVE-2021-45046</cve>
                        <cvss_base>10.0</cvss_base>
                        <solution>Upgrade log4j to version 2.17.1 or newer.</solution>
                    </nvt>
                    <threat>High</threat>
                    <severity>10.0</severity>
                    <qod>
                        <value>95</value>
                        <type>remote_vul</type>
                    </qod>
                    <description>Apache Log4j2 JNDI features do not protect against attacker controlled LDAP.</description>
                </result>
                <result id="res-2">
                    <name>SSH Weak MAC Algorithms Supported</name>
                    <host>192.168.1.105</host>
                    <port>22/tcp</port>
                    <nvt oid="1.3.6.1.4.1.25623.1.0.54321">
                        <cve>NOCVE</cve>
                        <cvss_base>4.3</cvss_base>
                        <solution>Disable MD5 and 96-bit MAC algorithms in sshd_config.</solution>
                    </nvt>
                    <threat>Medium</threat>
                    <severity>4.3</severity>
                    <qod>
                        <value>60</value>
                        <type>remote_analysis</type>
                    </qod>
                    <description>The remote SSH server supports weak message authentication codes.</description>
                </result>
                <result id="res-3">
                    <name>Open Port Detection</name>
                    <host>192.168.1.105</host>
                    <port>80/tcp</port>
                    <nvt oid="1.3.6.1.4.1.25623.1.0.11111">
                        <cvss_base>0.0</cvss_base>
                    </nvt>
                    <threat>Log</threat>
                    <severity>0.0</severity>
                    <qod>
                        <value>100</value>
                        <type>remote_banner</type>
                    </qod>
                    <description>HTTP server detected listening on port 80.</description>
                </result>
            </results>
        </report>
        """
        findings = parse_openvas_xml_report(sample_xml, target_ip="192.168.1.105")
        self.assertEqual(len(findings), 3)

        f1 = findings[0]
        self.assertEqual(f1["cve"], "CVE-2021-44228")
        self.assertEqual(f1["cvss_score"], 10.0)
        self.assertEqual(f1["finding_type"], "confirmed_vulnerability")
        self.assertEqual(f1["cve_confidence"], "Confirmed")
        self.assertEqual(f1["port"], 8080)
        self.assertEqual(f1["service"], "tcp")
        self.assertIn("Upgrade log4j", f1["remediation"])

        f2 = findings[1]
        self.assertEqual(f2["finding_type"], "potential_finding")
        self.assertIsNone(f2["cve"])
        self.assertEqual(f2["cvss_score"], 4.3)

        f3 = findings[2]
        self.assertEqual(f3["finding_type"], "service_exposure")
        self.assertEqual(f3["cvss_score"], 0.0)

    @patch.dict(os.environ, {
        "OPENVAS_HOST": "",
        "OPENVAS_USER": "",
        "OPENVAS_PASSWORD": "",
        "OPENVAS_SOCKET": "",
    }, clear=True)
    def test_openvas_scan_execution_unconfigured_error(self):
        with self.assertRaises(RuntimeError) as ctx:
            execute_openvas_scan("192.168.1.10")
        self.assertIn("cannot be performed", str(ctx.exception).lower())


class TestPDFExport(unittest.TestCase):
    def test_pdf_document_primitive_rendering(self):
        pdf_bytes = build_pdf_report(
            title="Test Executive Summary",
            subtitle="Automated Verification Report",
            summary_cards=[
                {"label": "Total Assets", "value": "12", "color": "accent"},
                {"label": "Critical Risks", "value": "2", "color": "danger"},
            ],
            table_headers=["Target IP", "Hostname", "Risk Score", "Status"],
            table_rows=[
                ["192.168.1.10", "gateway.local", "7.5", "High Risk"],
                ["192.168.1.20", "db01.corp", "2.1", "Compliant"],
            ],
            ai_advisories=[
                {
                    "title": "Advisory 1",
                    "source": "AI Recommendation Engine",
                    "details": "Rotate credentials on database host.",
                }
            ],
            generated_by="test-operator",
        )
        self.assertTrue(pdf_bytes.startswith(b"%PDF-1.4"))
        self.assertTrue(pdf_bytes.endswith(b"%%EOF\n"))
        self.assertGreater(len(pdf_bytes), 1500)

    def test_report_generator_pdf_export_all_suites(self):
        mock_db = MagicMock()
        mock_db.query.return_value.all.return_value = []
        mock_db.query.return_value.filter.return_value.all.return_value = []
        mock_db.query.return_value.count.return_value = 0

        for r_type in REPORT_GENERATORS.keys():
            content, mime_type, filename = generate_report(
                report_type=r_type,
                format_type="pdf",
                db=mock_db,
                operator="test_operator",
            )
            self.assertIsInstance(content, bytes)
            self.assertEqual(mime_type, "application/pdf")
            self.assertTrue(filename.endswith(".pdf"))
            self.assertTrue(content.startswith(b"%PDF-1.4"), f"Header invalid for {r_type}")
            self.assertTrue(content.endswith(b"%%EOF\n"), f"EOF invalid for {r_type}")
            self.assertGreater(len(content), 1000)


if __name__ == "__main__":
    unittest.main()

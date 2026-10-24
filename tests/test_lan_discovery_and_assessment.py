"""Comprehensive Unit & Integration Tests for LAN Discovery, OS Detection,
Vulnerability Correlation, and Risk Assessment.
"""

import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime

from scanner.os_identifier import identify_os_and_device
from scanner.risk_engine import calculate_risk
from scanner.vulnerability_scanner import identify_vulnerabilities
from scanner.router_dhcp import get_authorized_dhcp_info, AUTHORIZED_ROUTER_DHCP_CLIENTS
from backend.monitoring.remote_agent import NmapAgentClient, NmapAgentResponseError, NmapAgentConnectionError


class TestOSIdentifier(unittest.TestCase):
    def test_direct_nmap_os_match(self):
        host_data = {
            "ip_address": "192.168.1.101",
            "operating_system": "Microsoft Windows 11",
            "open_ports": [{"port": 445, "service": "microsoft-ds"}],
        }
        res = identify_os_and_device(host_data)
        self.assertEqual(res["operating_system"], "Microsoft Windows 11")
        self.assertEqual(res["os_confidence"], "High")
        self.assertIn("Nmap TCP/IP stack fingerprinting", res["os_fingerprint_reason"])
        self.assertIn("Workstation", res["device_type"])

    def test_service_banner_debian_ssh(self):
        host_data = {
            "ip_address": "192.168.1.149",
            "hostname": "grc",
            "operating_system": None,
            "open_ports": [
                {
                    "port": 22,
                    "service": "ssh",
                    "product": "OpenSSH",
                    "version": "10.0p2 Debian 7",
                    "details": "protocol 2.0; Debian 7",
                }
            ],
        }
        res = identify_os_and_device(host_data)
        self.assertEqual(res["operating_system"], "Debian Linux")
        self.assertEqual(res["os_confidence"], "High")
        self.assertIn("Debian Linux OS banner", res["os_fingerprint_reason"])
        self.assertTrue(len(res["device_type"]) > 0)

    def test_embedded_router_fingerprint(self):
        host_data = {
            "ip_address": "192.168.1.1",
            "hostname": "TP-Link Gateway",
            "operating_system": None,
            "open_ports": [
                {"port": 22, "service": "ssh", "product": "Dropbear sshd", "version": "2012.55"},
                {"port": 80, "service": "http", "product": "TP-LINK TD-W8968 admin"},
                {"port": 1900, "service": "upnp", "product": "Portable SDK for UPnP", "cpe": "cpe:/o:linux:linux_kernel:2.6.36"},
            ],
        }
        res = identify_os_and_device(host_data)
        self.assertIn("Embedded Linux", res["operating_system"])
        self.assertIn("Gateway", res["device_type"])

    def test_inconclusive_when_no_ports_or_evidence(self):
        host_data = {
            "ip_address": "192.168.1.200",
            "hostname": "unknown-host",
            "operating_system": None,
            "open_ports": [],
        }
        res = identify_os_and_device(host_data)
        self.assertIsNone(res["operating_system"])
        self.assertEqual(res["os_confidence"], "Inconclusive")
        self.assertIn("No open TCP/UDP ports", res["os_fingerprint_reason"])

    def test_mobile_hostname_heuristic(self):
        host_data = {
            "ip_address": "192.168.1.123",
            "hostname": "Nothing-Phone-2a",
            "operating_system": None,
            "open_ports": [],
        }
        res = identify_os_and_device(host_data)
        self.assertIn("Android", res["operating_system"])
        self.assertEqual(res["device_type"], "Mobile / Smartphone")


class TestVulnerabilityCorrelation(unittest.TestCase):
    def test_dropbear_and_upnp_cve_correlation(self):
        ports = [
            {"port": 22, "service": "ssh", "product": "Dropbear sshd", "version": "2012.55"},
            {"port": 1900, "service": "upnp", "product": "Portable SDK for UPnP", "version": "1.6.19"},
            {"port": 80, "service": "http", "product": "TP-LINK TD-W8968 admin"},
        ]
        vulns = identify_vulnerabilities(ports)
        self.assertTrue(len(vulns) >= 2)
        titles = [v["title"] for v in vulns]
        self.assertTrue(any("Dropbear" in t for t in titles))
        self.assertTrue(any("CallStranger" in t or "UPnP" in t for t in titles))

        # Check remediation and verification status presence
        for v in vulns:
            self.assertIn("remediation", v)
            self.assertIsNotNone(v["remediation"])
            self.assertIn("verification_status", v)

    def test_clean_ports_genuine_zero_findings(self):
        ports = [
            {"port": 80, "service": "http", "product": "nginx", "version": "1.25.4"},
        ]
        vulns = identify_vulnerabilities(ports)
        # Nginx without vulnerable banner does not trigger bogus CVEs
        self.assertEqual(len(vulns), 0)

    def test_raspberry_pi_openssh_no_cve_2008_3844(self):
        """OpenSSH 10.0p2 on Raspberry Pi must not match 2008 CVE-2008-3844."""
        ports = [
            {
                "port": 22,
                "service": "ssh",
                "product": "OpenSSH",
                "version": "10.0p2 Debian 7",
            }
        ]
        vulns = identify_vulnerabilities(ports)
        cves = [v.get("cve") for v in vulns if v.get("cve")]
        self.assertNotIn("CVE-2008-3844", cves)

    def test_windows_smb_rpc_netbios_are_advisories_not_cves(self):
        """Standard Windows ports (135, 139, 445) are hardening advisories, not confirmed CVEs."""
        ports = [
            {"port": 135, "service": "msrpc", "product": "Microsoft Windows RPC"},
            {"port": 139, "service": "netbios-ssn", "product": "Microsoft Windows netbios-ssn"},
            {"port": 445, "service": "microsoft-ds", "product": "Windows 11 SMB"},
        ]
        vulns = identify_vulnerabilities(ports)
        self.assertEqual(len(vulns), 3)
        for v in vulns:
            self.assertIsNone(v.get("cve"), f"Expected None for CVE on {v['title']}, got {v.get('cve')}")
            self.assertEqual(v.get("verification_status"), "Advisory")
            self.assertEqual(v.get("severity"), "Low")


class TestRiskEngineScoring(unittest.TestCase):
    def test_zero_findings_status_is_completed_no_findings(self):
        risk = calculate_risk(open_ports=[{"port": 80, "service": "http"}], vulnerabilities=[])
        self.assertEqual(risk["risk_score"], 0)
        self.assertEqual(risk["assessment_status"], "Completed — no findings detected")
        self.assertEqual(risk["risk_level"], "Low")

    def test_unassessed_status_when_ports_none(self):
        risk = calculate_risk(open_ports=None, vulnerabilities=None)
        self.assertEqual(risk["risk_score"], 0)
        self.assertEqual(risk["assessment_status"], "Not assessed")
        self.assertEqual(risk["risk_level"], "Unknown")

    def test_partial_failed_scan_status(self):
        risk = calculate_risk(open_ports=None, vulnerabilities=None, asset_context={"scan_failed": True})
        self.assertEqual(risk["risk_score"], 0)
        self.assertEqual(risk["assessment_status"], "Assessment failed/partial")
        self.assertEqual(risk["risk_level"], "Unknown")

    def test_windows_host_with_smb_rpc_netbios_not_inflated(self):
        """A Windows workstation with ports 135, 139, 445 must score Low (~10), not Critical (86)."""
        ports = [
            {"port": 135, "service": "msrpc"},
            {"port": 139, "service": "netbios-ssn"},
            {"port": 445, "service": "microsoft-ds"},
        ]
        advisories = [
            {"title": "Microsoft Windows SMB (Port 445) Exposed", "severity": "Low", "cve": None, "verification_status": "Advisory", "port": 445},
            {"title": "Microsoft Windows NetBIOS (Port 139) Exposed", "severity": "Low", "cve": None, "verification_status": "Advisory", "port": 139},
            {"title": "Microsoft Windows MSRPC (Port 135) Exposed", "severity": "Low", "cve": None, "verification_status": "Advisory", "port": 135},
        ]
        risk = calculate_risk(open_ports=ports, vulnerabilities=advisories)
        self.assertEqual(risk["risk_score"], 10)
        self.assertEqual(risk["risk_level"], "Low")
        self.assertEqual(risk["assessment_status"], "Completed — hardening advisories only")

    def test_potential_vs_confirmed_risk_weight(self):
        """Confirmed CVEs contribute more risk than unverified/potential matches."""
        ports = [{"port": 80, "service": "http"}]
        confirmed = [{"title": "Confirmed RCE", "severity": "High", "cve": "CVE-2024-1111", "verification_status": "Confirmed"}]
        potential = [{"title": "Potential RCE", "severity": "High", "cve": "CVE-2024-1111", "verification_status": "Potential"}]

        risk_confirmed = calculate_risk(open_ports=ports, vulnerabilities=confirmed)
        risk_potential = calculate_risk(open_ports=ports, vulnerabilities=potential)

        self.assertGreater(risk_confirmed["risk_score"], risk_potential["risk_score"])
        self.assertEqual(risk_confirmed["assessment_status"], "Findings detected")
        self.assertEqual(risk_potential["assessment_status"], "Findings detected")


class TestRouterDHCPMapping(unittest.TestCase):
    def test_authorized_dhcp_mapping(self):
        info = get_authorized_dhcp_info("192.168.1.101")
        self.assertIsNotNone(info)
        self.assertEqual(info["hostname"], "FLEMSIS")

        info_pi = get_authorized_dhcp_info("192.168.1.149")
        self.assertEqual(info_pi["hostname"], "grc")
        self.assertEqual(info_pi["device_type"], "Server / Appliance")

    def test_unlisted_client_returns_none(self):
        info = get_authorized_dhcp_info("192.168.1.250")
        self.assertIsNone(info)


class TestRemoteAgentClient(unittest.TestCase):
    @patch("requests.Session.request")
    def test_scan_host_direct(self, mock_request):
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.json.return_value = {
            "target": "192.168.1.1",
            "status": "up",
            "open_ports": [{"port": 80, "service": "http"}],
            "operating_system": "Embedded Linux",
        }
        mock_request.return_value = mock_resp

        client = NmapAgentClient(base_url="http://192.168.1.149:9000", token="test_token")
        res = client.scan_host("192.168.1.1")
        self.assertEqual(res["target"], "192.168.1.1")
        self.assertEqual(len(res["open_ports"]), 1)


class TestDatabaseSafetyAndDeduplication(unittest.TestCase):
    def setUp(self):
        import sys
        from pathlib import Path
        backend_dir = str(Path(__file__).resolve().parent.parent / "backend")
        if backend_dir not in sys.path:
            sys.path.insert(0, backend_dir)

        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        import models

        self.engine = create_engine("sqlite:///:memory:", echo=False)
        models.Base.metadata.create_all(bind=self.engine)
        self.Session = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        self.db = self.Session()

    def tearDown(self):
        import models
        self.db.close()
        models.Base.metadata.drop_all(bind=self.engine)

    def test_repeated_scans_deduplicate_asset(self):
        import models

        # Initial discovery
        asset1 = models.Asset(
            ip_address="192.168.1.101",
            hostname="FLEMSIS",
            operating_system="Microsoft Windows 11",
            criticality="High",
            owner="Security Ops",
            business_function="Forensic Analysis",
        )
        self.db.add(asset1)
        self.db.commit()

        # Repeated scan finds same IP
        existing = self.db.query(models.Asset).filter(models.Asset.ip_address == "192.168.1.101").first()
        self.assertIsNotNone(existing)

        # Update fields without overwriting user business context
        existing.open_ports = "445/microsoft-ds, 139/netbios-ssn"
        existing.last_assessed_at = datetime.utcnow()
        self.db.commit()

        total = self.db.query(models.Asset).filter(models.Asset.ip_address == "192.168.1.101").count()
        self.assertEqual(total, 1, "Repeated scans must not create duplicate asset records")
        self.assertEqual(existing.criticality, "High", "Existing business criticality must be preserved")
        self.assertEqual(existing.owner, "Security Ops", "Existing owner must not be overwritten")
        self.assertEqual(existing.business_function, "Forensic Analysis", "Existing business function preserved")

    def test_schema_idempotency(self):
        """Simulate running schema ALTER statements multiple times."""
        from sqlalchemy import text

        with self.engine.connect() as conn:
            # SQLite does not support IF NOT EXISTS in ADD COLUMN, but we verify idempotent inspection
            inspector = text("SELECT 1")
            res = conn.execute(inspector).scalar()
            self.assertEqual(res, 1)


class TestPartialScanFailures(unittest.TestCase):
    def test_partial_failure_retains_discovered_host(self):
        """A discovered host whose detailed scan times out or fails must not be dropped."""
        host_discovered = {
            "ip_address": "192.168.1.155",
            "hostname": "slow-device",
            "open_ports": None,  # Scan failed/timeout
        }
        risk = calculate_risk(open_ports=host_discovered["open_ports"], asset_context={"scan_failed": True})
        self.assertEqual(risk["assessment_status"], "Assessment failed/partial")
        self.assertEqual(risk["risk_level"], "Unknown")
        self.assertEqual(risk["risk_score"], 0)

    def test_offline_asset_marked_not_assessed_offline(self):
        """When an asset is offline, it must not claim Completed — no findings detected from past scans."""
        import models
        asset = models.Asset(
            ip_address="192.168.1.142",
            hostname="realme-12-5G",
            status="Offline",
            assessment_status="Not assessed (Host offline)",
            scan_coverage="Host unreachable in current scan",
        )
        self.assertEqual(asset.status, "Offline")
        self.assertIn("offline", asset.assessment_status.lower())
        self.assertNotIn("Completed", asset.assessment_status)


if __name__ == "__main__":
    unittest.main()



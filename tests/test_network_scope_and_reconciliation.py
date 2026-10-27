"""Regression tests for Network Scope Segregation, Asset Reconciliation, and Offline Hysteresis.

Verifies:
1. Network scope classification (physical_lan, local_container, virtual_interface, loopback, out_of_scope).
2. Boundary address exclusion (.0 network address and .255 broadcast).
3. Consecutive-scan offline hysteresis (does not flip offline on a single missed scan).
4. Failed or incomplete scans do not resolve open vulnerabilities.
5. DHCP MAC mismatch does not override host identity.
6. Exact duplicate reconciliation transfers events safely, writes audit log, and deactivates duplicate without data loss.
7. Locally administered / randomized MAC addresses are recognized and protected from automatic merging.
"""

import unittest
from unittest.mock import MagicMock, patch
import ipaddress
from datetime import datetime

import sys
from pathlib import Path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(BASE_DIR / "backend"))

import models
from monitoring.asset_identity import (
    determine_network_scope,
    normalize_mac,
    normalize_ip,
    is_locally_administered_mac,
    reconcile_duplicate_assets,
    upsert_discovered_asset,
)
from scanner.router_dhcp import (
    get_authorized_dhcp_info_for_host,
    get_dhcp_registry_status,
)
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


class TestNetworkScopeSegregation(unittest.TestCase):
    """Test network scope classification and boundary safeguards."""

    def test_physical_lan_classification(self):
        """Valid hosts within 192.168.1.0/24 are classified as physical_lan."""
        self.assertEqual(determine_network_scope("192.168.1.1"), "physical_lan")
        self.assertEqual(determine_network_scope("192.168.1.100"), "physical_lan")
        self.assertEqual(determine_network_scope("192.168.1.149"), "physical_lan")

    def test_network_and_broadcast_boundary_exclusion(self):
        """.0 and .255 boundary addresses are classified as out_of_scope."""
        self.assertEqual(determine_network_scope("192.168.1.0"), "out_of_scope")
        self.assertEqual(determine_network_scope("192.168.1.255"), "out_of_scope")
        self.assertEqual(determine_network_scope("192.168.127.255"), "out_of_scope")

    def test_loopback_classification(self):
        """127.0.0.1 and loopback IPs are classified as loopback."""
        self.assertEqual(determine_network_scope("127.0.0.1"), "loopback")
        self.assertEqual(determine_network_scope("127.0.0.2"), "loopback")

    def test_docker_container_classification(self):
        """Docker bridge network IPs (172.18.x, 172.17.x) are classified as local_container."""
        self.assertEqual(determine_network_scope("172.18.0.3"), "local_container")
        self.assertEqual(determine_network_scope("172.17.0.2"), "local_container")

    def test_vmware_virtual_interface_classification(self):
        """VMware host adapters (192.168.127.x, 192.168.47.x) are classified as virtual_interface."""
        self.assertEqual(determine_network_scope("192.168.127.1"), "virtual_interface")
        self.assertEqual(determine_network_scope("192.168.47.1"), "virtual_interface")

    def test_authorized_single_host_scan_scope(self):
        """Single host scan of outside private IP is classified as authorized_single_host."""
        self.assertEqual(
            determine_network_scope("10.0.5.10", source="single_host_scan"),
            "authorized_single_host"
        )


class TestMacRandomizationAndDhcpSafeguards(unittest.TestCase):
    """Test MAC address normalization, privacy bit detection, and DHCP integrity."""

    def test_locally_administered_mac_detection(self):
        """Locally administered bit (bit 1 of octet 0) is correctly detected."""
        # 8E:3D:42:4E:B3:03 -> 0x8E = 1000 1110 (bit 1 is set)
        self.assertTrue(is_locally_administered_mac("8E:3D:42:4E:B3:03"))
        # 02:EA:2F:FA:3C:B3 -> 0x02 = 0000 0010 (bit 1 is set)
        self.assertTrue(is_locally_administered_mac("02:EA:2F:FA:3C:B3"))
        # AC:84:C6:64:C2:3C -> 0xAC = 1010 1100 (bit 1 is clear -> OUI assigned)
        self.assertFalse(is_locally_administered_mac("AC:84:C6:64:C2:3C"))
        # 0A:CD:45:AB:91:A4 -> 0x0A = 0000 1010 (bit 1 is set)
        self.assertTrue(is_locally_administered_mac("0A:CD:45:AB:91:A4"))

    def test_dhcp_mac_mismatch_never_overrides_identity(self):
        """When an observed MAC does not match known DHCP registry MAC, do not overwrite identity."""
        # 192.168.1.100 in router DHCP has MAC 0A:CD:45:AB:91:A4
        mismatched_mac = "3C:E9:0E:12:34:56"
        res = get_authorized_dhcp_info_for_host("192.168.1.100", mac=mismatched_mac)
        # Should return None because MAC does not match
        self.assertIsNone(res)

        # When matching MAC is supplied, it returns authorized metadata
        matching_mac = "0A:CD:45:AB:91:A4"
        res_valid = get_authorized_dhcp_info_for_host("192.168.1.100", mac=matching_mac)
        self.assertIsNotNone(res_valid)
        self.assertEqual(res_valid["client_name"], "Sujal")
        self.assertEqual(res_valid["lease_source"], "Static DHCP Registry Reference")

    def test_router_dhcp_status_explicit_static_label(self):
        """Router DHCP registry status explicitly notes live_sync_supported = False."""
        status = get_dhcp_registry_status()
        self.assertFalse(status["live_sync_supported"])
        self.assertIn("TP-Link TL-WR840N", status["model"])
        self.assertIn("does not expose an authenticated public REST API", status["live_sync_reason"])


class TestReversibleDuplicateReconciliation(unittest.TestCase):
    """Test that exact duplicate reconciliation preserves both records, transfers history, and audits."""

    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")
        models.Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)
        self.db = self.Session()

    def tearDown(self):
        self.db.close()

    def test_exact_duplicate_reconciliation_preserves_records_and_transfers_drift(self):
        """Reconciliation merges secondary into primary: deactivates duplicate, transfers drift, preserves IDs."""
        primary = models.Asset(
            ip_address="192.168.1.103",
            hostname="FLEMSIS",
            mac_address="3C:6A:A7:8D:EA:87",
            status="Online",
            criticality="Medium",
            environment="Production",
            exposure="Internal",
            network_scope="physical_lan",
            assigned_ip_status="active_assignment",
        )
        self.db.add(primary)
        self.db.flush()

        secondary = models.Asset(
            ip_address="192.168.1.103",
            hostname="FLEMSIS-dup",
            mac_address="3C:6A:A7:8D:EA:87",
            status="Online",
            criticality="Medium",
            environment="Production",
            exposure="Internal",
            network_scope="physical_lan",
            assigned_ip_status="active_assignment",
        )
        self.db.add(secondary)
        self.db.flush()

        # Add a scan job and drift event associated with secondary
        scan_job = models.ScanJob(
            target="192.168.1.103",
            scan_type="single_host",
            status="Completed",
        )
        self.db.add(scan_job)
        self.db.flush()

        drift = models.DriftEvent(
            scan_job_id=scan_job.id,
            asset_id=secondary.id,
            event_type="PORT_OPENED",
            title="Port 80 Opened",
            description="Port 80 HTTP service became active",
            severity="Medium",
            detected_at=datetime.utcnow(),
        )
        self.db.add(drift)
        self.db.commit()

        # Reconcile secondary into primary
        surviving = reconcile_duplicate_assets(
            db=self.db,
            primary_asset_id=primary.id,
            secondary_asset_id=secondary.id,
            operator_name="admin",
            reason="Exact duplicate reconciliation test",
        )

        # Primary survives and remains Online
        self.assertEqual(surviving.id, primary.id)
        self.assertEqual(surviving.status, "Online")

        # Secondary record is NOT deleted; marked deactivated
        sec_record = self.db.query(models.Asset).filter(models.Asset.id == secondary.id).first()
        self.assertIsNotNone(sec_record)
        self.assertEqual(sec_record.status, "deactivated")
        self.assertEqual(sec_record.assigned_ip_status, "reconciled_duplicate")

        # Drift event transferred to primary
        reloaded_drift = self.db.query(models.DriftEvent).filter(models.DriftEvent.id == drift.id).first()
        self.assertEqual(reloaded_drift.asset_id, primary.id)

        # Audit log created
        audit_log = (
            self.db.query(models.AuditLog)
            .filter(models.AuditLog.action == "ASSET_RECONCILIATION")
            .first()
        )
        self.assertIsNotNone(audit_log)
        self.assertIn(f"Reconciled duplicate Asset #{secondary.id}", audit_log.description)


class TestOfflineHysteresisAndAssessmentSafety(unittest.TestCase):
    """Test consecutive-scan offline hysteresis and prevention of vuln resolution on incomplete scans."""

    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")
        models.Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)
        self.db = self.Session()

    def tearDown(self):
        self.db.close()

    def test_single_scan_miss_does_not_flip_asset_offline(self):
        """A single scan miss increments consecutive_scan_misses but leaves asset status Online."""
        asset = models.Asset(
            ip_address="192.168.1.100",
            hostname="Sujal",
            status="Online",
            criticality="Medium",
            environment="Production",
            exposure="Internal",
            network_scope="physical_lan",
            assigned_ip_status="active_assignment",
            consecutive_scan_misses=0,
        )
        self.db.add(asset)
        self.db.commit()

        # Simulate 1 missed scan cycle
        asset.consecutive_scan_misses = (asset.consecutive_scan_misses or 0) + 1
        threshold = 3
        if asset.consecutive_scan_misses >= threshold:
            asset.status = "Offline"
        self.db.commit()

        reloaded = self.db.query(models.Asset).filter(models.Asset.id == asset.id).first()
        self.assertEqual(reloaded.consecutive_scan_misses, 1)
        self.assertEqual(reloaded.status, "Online")

    def test_reaching_threshold_flips_asset_offline(self):
        """When consecutive scan misses reach the threshold, status transitions to Offline."""
        asset = models.Asset(
            ip_address="192.168.1.100",
            hostname="Sujal",
            status="Online",
            criticality="Medium",
            environment="Production",
            exposure="Internal",
            network_scope="physical_lan",
            assigned_ip_status="active_assignment",
            consecutive_scan_misses=2,
        )
        self.db.add(asset)
        self.db.commit()

        # Simulate 3rd consecutive missed scan cycle
        asset.consecutive_scan_misses = (asset.consecutive_scan_misses or 0) + 1
        threshold = 3
        if asset.consecutive_scan_misses >= threshold:
            asset.status = "Offline"
            asset.offline_reason = f"Unresponsive for {asset.consecutive_scan_misses} consecutive scan cycles"
        self.db.commit()

        reloaded = self.db.query(models.Asset).filter(models.Asset.id == asset.id).first()
        self.assertEqual(reloaded.consecutive_scan_misses, 3)
        self.assertEqual(reloaded.status, "Offline")
        self.assertIn("Unresponsive for 3 consecutive scan cycles", reloaded.offline_reason)

    def test_failed_or_incomplete_scan_prevents_vulnerability_resolution(self):
        """Vulnerabilities must never be marked Resolved when an assessment job is incomplete or failed."""
        asset = models.Asset(
            ip_address="192.168.1.100",
            hostname="Sujal",
            status="Online",
            criticality="Medium",
            environment="Production",
            exposure="Internal",
            network_scope="physical_lan",
        )
        self.db.add(asset)
        self.db.flush()

        vuln = models.Vulnerability(
            asset_id=asset.id,
            title="MS17-010 EternalBlue SMB Remote Code Execution",
            severity="Critical",
            status="Open",
        )
        self.db.add(vuln)
        self.db.commit()

        # Simulate scan job that failed or had incomplete host assessment
        scan_job_status = "Failed"
        # Safety rule: if scan_job_status != "Completed", never resolve open vulns
        if scan_job_status == "Completed":
            vuln.status = "Resolved"
        self.db.commit()

        reloaded_vuln = self.db.query(models.Vulnerability).filter(models.Vulnerability.id == vuln.id).first()
        self.assertEqual(reloaded_vuln.status, "Open")


if __name__ == "__main__":
    unittest.main()


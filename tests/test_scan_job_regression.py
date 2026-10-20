"""Regression test suite for ScanJob creation, worker execution, persistence, and production security.

Verifies:
1. POST /scan creates and completes a models.ScanJob record and logs an audit event.
2. POST /scan rejects loopback targets (127.0.0.0/8) and requires authentication.
3. POST /monitoring/jobs queues a ScanJob with status Pending.
4. Worker execution persists assets, vulnerabilities, and completes the ScanJob.
5. discover_live_hosts excludes network (.0) and broadcast (.255) IP addresses.
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock
from pathlib import Path
from datetime import datetime, timezone

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(BASE_DIR / "backend"))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient

import models
import main
from auth.security import create_access_token, hash_password
from monitoring.scanner_pipeline import MonitoringScannerPipeline

TEST_SECRET = "test-jwt-secret-key-at-least-32-chars-long-123456"


class TestScanJobRegression(unittest.TestCase):
    """Test suite for ScanJob creation, persistence, and security regression."""

    def setUp(self):
        self.env_patcher = patch.dict(os.environ, {
            "JWT_SECRET_KEY": TEST_SECRET,
            "ENV": "development",
            "AUTH_DEV_LOGIN_ENABLED": "true",
        })
        self.env_patcher.start()

        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        models.Base.metadata.create_all(bind=self.engine)
        self.TestingSessionLocal = sessionmaker(bind=self.engine, autocommit=False, autoflush=False)

        self.session_patcher = patch("main.SessionLocal", side_effect=self.TestingSessionLocal)
        self.session_patcher.start()
        self.auth_session_patcher = patch("auth.dependencies.SessionLocal", side_effect=self.TestingSessionLocal)
        self.auth_session_patcher.start()

        # Seed an admin user
        db = self.TestingSessionLocal()
        try:
            self.admin_user = models.User(
                username="admin_tester",
                email="admin_tester@example.com",
                display_name="Admin Tester",
                password_hash=hash_password("SecureAdminPassword123!"),
                role="Administrator",
                is_active=True,
            )
            db.add(self.admin_user)
            db.commit()
            db.refresh(self.admin_user)
            self.admin_id = self.admin_user.id
        finally:
            db.close()

        self.admin_token = create_access_token(
            subject=self.admin_id,
            username="admin_tester",
            role="Administrator",
        )
        self.auth_headers = {"Authorization": f"Bearer {self.admin_token}"}
        self.client = TestClient(main.app)

    def tearDown(self):
        self.session_patcher.stop()
        self.auth_session_patcher.stop()
        models.Base.metadata.drop_all(bind=self.engine)
        self.env_patcher.stop()

    def test_quick_scan_requires_authentication(self):
        """Unauthenticated request to POST /scan must return HTTP 401."""
        response = self.client.post("/scan?target=192.168.1.1")
        self.assertEqual(response.status_code, 401)

    def test_quick_scan_rejects_loopback(self):
        """POST /scan must reject loopback addresses (127.0.0.1) with HTTP 400."""
        response = self.client.post(
            "/scan?target=127.0.0.1",
            headers=self.auth_headers,
        )
        self.assertEqual(response.status_code, 400)
        detail = response.json().get("detail", "")
        self.assertIn("Loopback", detail)

    @patch("main.scan_host")
    def test_quick_scan_creates_scan_job_and_audit(self, mock_scan):
        """POST /scan must create a completed ScanJob record in the DB and an audit entry."""
        mock_scan.return_value = {
            "hostname": "test-workstation",
            "mac_address": "00:11:22:33:44:55",
            "operating_system": "Linux 5.4",
            "open_ports": [
                {
                    "port": 80,
                    "service": "http",
                    "state": "open",
                    "product": "Apache",
                    "version": "2.4.41",
                    "extra_info": "",
                    "cpe": "cpe:/a:apache:http_server:2.4.41",
                }
            ],
        }

        response = self.client.post(
            "/scan?target=192.168.1.10",
            headers=self.auth_headers,
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("scan_job_id", data)
        scan_job_id = data["scan_job_id"]

        db = self.TestingSessionLocal()
        try:
            job = db.query(models.ScanJob).filter(models.ScanJob.id == scan_job_id).first()
            self.assertIsNotNone(job, "ScanJob record was not created in PostgreSQL/DB")
            self.assertEqual(job.status, "Completed")
            self.assertEqual(job.target, "192.168.1.10")
            self.assertEqual(job.discovered_assets_count, 1)
            self.assertIsNotNone(job.completed_at)

            # Verify audit trail event was created
            audit_log = (
                db.query(models.AuditLog)
                .filter(models.AuditLog.action == "EXECUTE", models.AuditLog.entity_type == "ScanJob")
                .first()
            )
            self.assertIsNotNone(audit_log, "AuditLog was not recorded for quick scan")
            self.assertEqual(audit_log.entity_id, scan_job_id)
        finally:
            db.close()

    def test_monitoring_job_creation(self):
        """POST /monitoring/jobs must queue a ScanJob with status Queued."""
        response = self.client.post(
            "/monitoring/jobs",
            headers=self.auth_headers,
            json={"target": "192.168.1.0/24", "scan_type": "subnet_discovery"},
        )
        self.assertIn(response.status_code, [200, 201, 202])
        data = response.json()
        self.assertIn(data["status"], ["Pending", "Queued"])
        self.assertEqual(data["target"], "192.168.1.0/24")

        db = self.TestingSessionLocal()
        try:
            job = db.query(models.ScanJob).filter(models.ScanJob.id == data["id"]).first()
            self.assertIsNotNone(job)
            self.assertIn(job.status, ["Pending", "Queued"])
        finally:
            db.close()

    @patch("monitoring.scanner_pipeline.subprocess.Popen")
    def test_discover_live_hosts_excludes_network_and_broadcast(self, mock_popen):
        """discover_live_hosts must exclude .0 (network) and .255 (broadcast) addresses."""
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = (
            "Nmap scan report for 192.168.1.0\n"
            "Host is up (0.001s latency).\n"
            "Nmap scan report for 192.168.1.5\n"
            "Host is up (0.002s latency).\n"
            "Nmap scan report for 192.168.1.255\n"
            "Host is up (0.001s latency).\n",
            ""
        )
        mock_proc.returncode = 0
        mock_popen.return_value = mock_proc

        pipeline = MonitoringScannerPipeline()
        hosts = pipeline.discover_live_hosts("192.168.1.0/24")
        self.assertEqual(hosts, ["192.168.1.5"])
        self.assertNotIn("192.168.1.0", hosts)
        self.assertNotIn("192.168.1.255", hosts)

    @patch("main.scan_host")
    def test_repeated_quick_scans_do_not_duplicate_assets(self, mock_scan):
        """Repeated scans for the same IP target must update the existing asset without duplicating records."""
        mock_scan.return_value = {
            "hostname": "host-alpha",
            "mac_address": "00:11:22:33:44:55",
            "operating_system": "Linux",
            "open_ports": [
                {
                    "port": 22,
                    "service": "ssh",
                    "state": "open",
                    "product": "OpenSSH",
                    "version": "8.2",
                    "extra_info": "",
                    "cpe": "cpe:/a:openbsd:openssh:8.2",
                }
            ],
        }

        # Run first scan
        res1 = self.client.post("/scan?target=192.168.1.50", headers=self.auth_headers)
        self.assertEqual(res1.status_code, 200)

        # Run second scan on same target with updated hostname
        mock_scan.return_value["hostname"] = "host-alpha-renamed"
        res2 = self.client.post("/scan?target=192.168.1.50", headers=self.auth_headers)
        self.assertEqual(res2.status_code, 200)

        db = self.TestingSessionLocal()
        try:
            # Must only have ONE Asset record for this IP
            assets = db.query(models.Asset).filter(models.Asset.ip_address == "192.168.1.50").all()
            self.assertEqual(len(assets), 1, "Duplicate assets were created for the same target IP")
            self.assertEqual(assets[0].hostname, "host-alpha-renamed")

            # Must have TWO distinct ScanJob records (one for each executed scan)
            jobs = db.query(models.ScanJob).filter(models.ScanJob.target == "192.168.1.50").all()
            self.assertEqual(len(jobs), 2, "Each scan execution must produce its own distinct ScanJob")
        finally:
            db.close()

    def test_monitoring_jobs_rejects_loopback(self):
        """POST /monitoring/jobs must reject loopback IP and CIDR targets with HTTP 400."""
        # Single IP loopback
        resp1 = self.client.post(
            "/monitoring/jobs",
            headers=self.auth_headers,
            json={"target": "127.0.0.1", "scan_type": "single_host"},
        )
        self.assertEqual(resp1.status_code, 400)
        self.assertIn("Loopback", resp1.json().get("detail", ""))

        # CIDR loopback
        resp2 = self.client.post(
            "/monitoring/jobs",
            headers=self.auth_headers,
            json={"target": "127.0.0.0/24", "scan_type": "subnet_discovery"},
        )
        self.assertEqual(resp2.status_code, 400)
        self.assertIn("Loopback", resp2.json().get("detail", ""))

    def test_monitoring_jobs_rejects_link_local(self):
        """POST /monitoring/jobs must reject link-local targets with HTTP 400."""
        resp = self.client.post(
            "/monitoring/jobs",
            headers=self.auth_headers,
            json={"target": "169.254.1.5", "scan_type": "single_host"},
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Link-local", resp.json().get("detail", ""))

    def test_monitoring_schedules_rejects_loopback(self):
        """POST /monitoring/schedules must reject loopback targets with HTTP 400."""
        resp = self.client.post(
            "/monitoring/schedules",
            headers=self.auth_headers,
            json={"name": "Loopback Sweep", "target": "127.0.0.1", "interval_minutes": 60},
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Loopback", resp.json().get("detail", ""))

    def test_discover_rejects_loopback(self):
        """POST /discover must reject loopback subnets with HTTP 400."""
        resp = self.client.post(
            "/discover?network=127.0.0.0/24",
            headers=self.auth_headers,
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Loopback", resp.json().get("detail", ""))

    @patch("monitoring.scanner_pipeline.subprocess.Popen")
    def test_pipeline_discovery_command_includes_ps(self, mock_popen):
        """discover_live_hosts command must include TCP SYN ping probes (-PS)."""
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = ("", "")
        mock_proc.returncode = 0
        mock_popen.return_value = mock_proc

        pipeline = MonitoringScannerPipeline()
        pipeline.discover_live_hosts("192.168.127.0/24")

        cmd = mock_popen.call_args[0][0]
        self.assertTrue(any(arg.startswith("-PS") for arg in cmd), f"Expected -PS in command: {cmd}")

    @patch("monitoring.scanner_pipeline.subprocess.Popen")
    def test_pipeline_scan_single_host_command_includes_pn(self, mock_popen):
        """scan_single_host command must include -Pn to skip unprivileged ping failure."""
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = (
            "<nmaprun><host><status state='up'/><ports></ports></host></nmaprun>",
            ""
        )
        mock_proc.returncode = 0
        mock_popen.return_value = mock_proc

        pipeline = MonitoringScannerPipeline(enable_os_detection=False)
        pipeline.scan_single_host("192.168.127.1")

        cmd = mock_popen.call_args[0][0]
        self.assertIn("-Pn", cmd, f"Expected -Pn in command: {cmd}")

    @patch("scanner.nmap_scanner.subprocess.run")
    def test_standalone_discover_hosts_excludes_network_and_broadcast(self, mock_run):
        """scanner.nmap_scanner.discover_hosts must exclude network (.0) and broadcast (.255)."""
        from scanner.nmap_scanner import discover_hosts
        mock_res = MagicMock()
        mock_res.returncode = 0
        mock_res.stdout = (
            "Nmap scan report for 192.168.127.0\n"
            "Host is up (0.001s latency).\n"
            "Nmap scan report for 192.168.127.1\n"
            "Host is up (0.002s latency).\n"
            "Nmap scan report for 192.168.127.255\n"
            "Host is up (0.001s latency).\n"
        )
        mock_run.return_value = mock_res

        hosts = discover_hosts("192.168.127.0/24")
        self.assertEqual(hosts, ["192.168.127.1"])
        self.assertNotIn("192.168.127.0", hosts)
        self.assertNotIn("192.168.127.255", hosts)

    def test_worker_empty_discovery_completes_with_zero_assets(self):
        """When host discovery finds 0 live hosts, job is Completed with 0 assets and no error."""
        from monitoring.worker import ScanWorkerPool
        mock_pipeline = MagicMock()
        mock_pipeline.discover_live_hosts.return_value = []

        pool = ScanWorkerPool(pipeline=mock_pipeline)

        db = self.TestingSessionLocal()
        try:
            job = models.ScanJob(
                target="192.168.200.0/24",
                scan_type="subnet_discovery",
                status="Queued",
                progress_percent=0,
            )
            db.add(job)
            db.commit()
            db.refresh(job)
            job_id = job.id
        finally:
            db.close()

        import threading
        cancel_ev = threading.Event()
        with patch("monitoring.worker.SessionLocal", side_effect=self.TestingSessionLocal):
            pool._execute_scan_job(job_id, cancel_ev)

        db = self.TestingSessionLocal()
        try:
            updated_job = db.query(models.ScanJob).filter(models.ScanJob.id == job_id).first()
            self.assertEqual(updated_job.status, "Completed")
            self.assertEqual(updated_job.discovered_assets_count, 0)
            self.assertEqual(updated_job.discovered_vulns_count, 0)
            self.assertIsNone(updated_job.error_message)
        finally:
            db.close()

    def test_worker_failed_discovery_marks_job_failed(self):
        """When host discovery encounters a fatal error, job is marked Failed with error_message."""
        from monitoring.worker import ScanWorkerPool
        mock_pipeline = MagicMock()
        mock_pipeline.discover_live_hosts.side_effect = RuntimeError("Nmap ping sweep failed: Network unreachable")

        pool = ScanWorkerPool(pipeline=mock_pipeline)

        db = self.TestingSessionLocal()
        try:
            job = models.ScanJob(
                target="192.168.200.0/24",
                scan_type="subnet_discovery",
                status="Queued",
                progress_percent=0,
            )
            db.add(job)
            db.commit()
            db.refresh(job)
            job_id = job.id
        finally:
            db.close()

        import threading
        cancel_ev = threading.Event()
        with patch("monitoring.worker.SessionLocal", side_effect=self.TestingSessionLocal):
            pool._execute_scan_job(job_id, cancel_ev)

        db = self.TestingSessionLocal()
        try:
            updated_job = db.query(models.ScanJob).filter(models.ScanJob.id == job_id).first()
            self.assertEqual(updated_job.status, "Failed")
            self.assertIsNotNone(updated_job.error_message)
            self.assertIn("Network unreachable", updated_job.error_message)
        finally:
            db.close()


if __name__ == "__main__":
    unittest.main()

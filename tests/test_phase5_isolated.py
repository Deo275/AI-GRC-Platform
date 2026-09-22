"""Phase 5 Isolated Automated Test Suite: Continuous Network Monitoring Core.

Tests the backend monitoring core using Python unittest and in-memory SQLite:
1.  test_target_validation_rfc1918_valid_ips
2.  test_target_validation_rfc1918_valid_cidrs
3.  test_target_validation_rejects_public_ips
4.  test_target_validation_rejects_wide_subnets (/16, /8)
5.  test_target_validation_rejects_malformed_inputs
6.  test_pipeline_default_os_detection_disabled
7.  test_pipeline_os_detection_enabled_flag
8.  test_worker_max_concurrency_and_queueing (max 3 concurrent, excess remain Queued)
9.  test_worker_job_lifecycle_success (Queued -> Running -> Completed)
10. test_worker_job_lifecycle_failure (Queued -> Running -> Failed)
11. test_worker_cooperative_cancellation_terminates_subprocess
12. test_worker_db_session_isolation_and_cleanup
13. test_worker_new_asset_remains_unclassified
14. test_drift_baseline_strictly_from_last_completed_scan
15. test_drift_failed_or_cancelled_scan_never_becomes_baseline
16. test_drift_initial_scan_establishes_baseline
17. test_drift_detection_new_asset_event
18. test_drift_detection_port_opened_event
19. test_drift_detection_port_closed_event
20. test_drift_detection_cve_detected_event
21. test_drift_detection_finding_resolved_event
22. test_drift_events_contain_scan_job_id_and_asset_id
23. test_scheduler_interval_and_next_run_calculation
24. test_scheduler_skips_inactive_schedules
25. test_scheduler_prevents_duplicate_active_jobs_for_same_target
26. test_grc_recalculation_invoked_on_new_findings

This test suite does NOT require real Nmap execution or live PostgreSQL.
"""

import time
import threading
import unittest
from unittest.mock import patch, MagicMock
from pathlib import Path
from datetime import datetime, timedelta

from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import sessionmaker

import sys
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(BASE_DIR / "backend"))

import models
from monitoring.scanner_pipeline import validate_target_network, MonitoringScannerPipeline
from monitoring.drift_detector import (
    DriftDetector,
    AssetSnapshot,
    ScanSnapshot,
    normalize_ip,
    normalize_port_identity,
    normalize_service_identity,
)
from monitoring.worker import ScanWorkerPool, recalculate_asset_grc_risks
from monitoring.scheduler import MonitoringScheduler


class TestPhase5MonitoringCore(unittest.TestCase):
    """Isolated unit tests for Phase 5 continuous monitoring core."""

    def setUp(self):
        """Set up an isolated in-memory SQLite database for each test."""
        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        models.Base.metadata.create_all(bind=self.engine)
        self.SessionLocal = sessionmaker(bind=self.engine, autocommit=False, autoflush=False)
        self.db = self.SessionLocal()

    def tearDown(self):
        self.db.close()
        models.Base.metadata.drop_all(bind=self.engine)

    # -----------------------------------------------------------------------
    # 1. Target Validation & RFC 1918 Tests
    # -----------------------------------------------------------------------

    def test_target_validation_rfc1918_valid_ips(self):
        """Test 1: Valid RFC 1918 private IPs and loopback are normalized correctly."""
        self.assertEqual(validate_target_network("192.168.1.1"), "192.168.1.1")
        self.assertEqual(validate_target_network("10.0.5.24"), "10.0.5.24")
        self.assertEqual(validate_target_network("172.16.0.10"), "172.16.0.10")
        self.assertEqual(validate_target_network("127.0.0.1"), "127.0.0.1")

    def test_target_validation_rfc1918_valid_cidrs(self):
        """Test 2: Valid private CIDRs with prefix >= 24 are accepted."""
        self.assertEqual(validate_target_network("192.168.1.0/24"), "192.168.1.0/24")
        self.assertEqual(validate_target_network("10.50.0.0/24"), "10.50.0.0/24")
        self.assertEqual(validate_target_network("172.16.10.0/28"), "172.16.10.0/28")

    def test_target_validation_rejects_public_ips(self):
        """Test 3: Public IP addresses are strictly rejected."""
        with self.assertRaises(ValueError) as ctx:
            validate_target_network("8.8.8.8")
        self.assertIn("not an allowed RFC 1918", str(ctx.exception))

        with self.assertRaises(ValueError):
            validate_target_network("1.1.1.1")

    def test_target_validation_rejects_wide_subnets(self):
        """Test 4: Subnets wider than /24 (e.g. /16, /8) are rejected."""
        with self.assertRaises(ValueError) as ctx:
            validate_target_network("192.168.0.0/16")
        self.assertIn("Maximum allowed subnet size is /24", str(ctx.exception))

        with self.assertRaises(ValueError):
            validate_target_network("10.0.0.0/8")

    def test_target_validation_rejects_malformed_inputs(self):
        """Test 5: Malformed, non-IP strings, and empty inputs are rejected."""
        with self.assertRaises(ValueError):
            validate_target_network("")
        with self.assertRaises(ValueError):
            validate_target_network("not-a-valid-ip")
        with self.assertRaises(ValueError):
            validate_target_network("999.999.999.999")

    # -----------------------------------------------------------------------
    # 2. Scanner Pipeline Tests
    # -----------------------------------------------------------------------

    def test_pipeline_default_os_detection_disabled(self):
        """Test 6: OS detection (-O) is disabled by default in Stage 2 commands."""
        pipeline = MonitoringScannerPipeline(enable_os_detection=False)
        self.assertFalse(pipeline.enable_os_detection)

        with patch("subprocess.Popen") as mock_popen:
            mock_proc = MagicMock()
            mock_proc.communicate.return_value = ("<nmaprun></nmaprun>", "")
            mock_proc.returncode = 0
            mock_popen.return_value = mock_proc

            pipeline.scan_single_host("192.168.1.10")

            call_args = mock_popen.call_args[0][0]
            self.assertIn("--top-ports", call_args)
            self.assertIn("100", call_args)
            self.assertIn("-sV", call_args)
            self.assertNotIn("-O", call_args)

    def test_pipeline_os_detection_enabled_flag(self):
        """Test 7: When enable_os_detection=True, -O is appended to Stage 2 command."""
        pipeline = MonitoringScannerPipeline(enable_os_detection=True)
        self.assertTrue(pipeline.enable_os_detection)

        with patch("subprocess.Popen") as mock_popen:
            mock_proc = MagicMock()
            mock_proc.communicate.return_value = ("<nmaprun></nmaprun>", "")
            mock_proc.returncode = 0
            mock_popen.return_value = mock_proc

            pipeline.scan_single_host("192.168.1.10")

            call_args = mock_popen.call_args[0][0]
            self.assertIn("-O", call_args)

    # -----------------------------------------------------------------------
    # 3. Worker Concurrency, Lifecycle & Cancellation Tests
    # -----------------------------------------------------------------------

    @patch("monitoring.worker.SessionLocal")
    def test_worker_job_lifecycle_success(self, mock_session_cls):
        """Test 8: Successful scan job progresses Queued -> Running -> Completed."""
        mock_session_cls.return_value = self.db

    def test_worker_max_concurrency_and_queueing(self):
        """Test 8: Worker executes at most 3 jobs concurrently; excess jobs wait in queue."""
        active_count = 0
        max_active = 0
        lock = threading.Lock()
        started_event = threading.Event()
        release_event = threading.Event()

        worker_pool = ScanWorkerPool(max_workers=3)

        def mock_execute(job_id, cancel_event):
            nonlocal active_count, max_active
            with lock:
                active_count += 1
                if active_count > max_active:
                    max_active = active_count
            if active_count >= 3:
                started_event.set()
            release_event.wait(timeout=2.0)
            with lock:
                active_count -= 1

        worker_pool._execute_scan_job = mock_execute

        for i in range(5):
            worker_pool.submit_scan_job(i + 1)

        started_event.wait(timeout=2.0)
        with lock:
            self.assertLessEqual(active_count, 3, "Concurrent executions must not exceed max_workers=3")
        release_event.set()
        worker_pool.shutdown(wait=True)
        self.assertLessEqual(max_active, 3)

    @patch("monitoring.worker.SessionLocal")
    def test_worker_job_lifecycle_success(self, mock_session_cls):
        """Test 9: Successful scan job progresses Queued -> Running -> Completed."""
        mock_session_cls.side_effect = self.SessionLocal

        job = models.ScanJob(target="192.168.1.1", scan_type="single_host", status="Queued")
        self.db.add(job)
        self.db.commit()
        job_id = job.id

        mock_pipeline = MagicMock()
        mock_pipeline.discover_live_hosts.return_value = ["192.168.1.1"]
        mock_pipeline.scan_single_host.return_value = {
            "ip_address": "192.168.1.1",
            "hostname": "gateway.local",
            "open_ports": [{"port": 80, "protocol": "tcp", "service": "http"}],
            "vulnerabilities": [],
            "risk_result": {"findings": [], "risk_score": 0, "risk_level": "Low"},
        }

        worker_pool = ScanWorkerPool(max_workers=3, pipeline=mock_pipeline)
        cancel_event = unittest.mock.MagicMock()
        cancel_event.is_set.return_value = False

        worker_pool._execute_scan_job(job_id, cancel_event)

        session = self.SessionLocal()
        try:
            updated_job = session.query(models.ScanJob).filter_by(id=job_id).first()
            self.assertEqual(updated_job.status, "Completed")
            self.assertEqual(updated_job.progress_percent, 100)
            self.assertIsNotNone(updated_job.started_at)
            self.assertIsNotNone(updated_job.completed_at)
            self.assertEqual(updated_job.discovered_assets_count, 1)
        finally:
            session.close()

    @patch("monitoring.worker.SessionLocal")
    def test_worker_job_lifecycle_failure(self, mock_session_cls):
        """Test 10: Exception in scan job transitions to status Failed with error message."""
        mock_session_cls.side_effect = self.SessionLocal

        job = models.ScanJob(target="192.168.1.1", scan_type="single_host", status="Queued")
        self.db.add(job)
        self.db.commit()
        job_id = job.id

        mock_pipeline = MagicMock()
        mock_pipeline.discover_live_hosts.side_effect = RuntimeError("Nmap binary unavailable")

        worker_pool = ScanWorkerPool(max_workers=3, pipeline=mock_pipeline)
        cancel_event = unittest.mock.MagicMock()
        cancel_event.is_set.return_value = False

        worker_pool._execute_scan_job(job_id, cancel_event)

        session = self.SessionLocal()
        try:
            updated_job = session.query(models.ScanJob).filter_by(id=job_id).first()
            self.assertEqual(updated_job.status, "Failed")
            self.assertIn("Nmap binary unavailable", updated_job.error_message)
        finally:
            session.close()

    @patch("monitoring.worker.SessionLocal")
    def test_worker_cooperative_cancellation_terminates_subprocess(self, mock_session_cls):
        """Test 11: Cancellation terminates active subprocess before setting Cancelled status."""
        mock_session_cls.side_effect = self.SessionLocal

        job = models.ScanJob(target="192.168.1.1", scan_type="single_host", status="Running")
        self.db.add(job)
        self.db.commit()
        job_id = job.id

        mock_proc = MagicMock()
        mock_proc.poll.return_value = None

        worker_pool = ScanWorkerPool(max_workers=3)
        with worker_pool._lock:
            worker_pool._active_processes[job_id] = mock_proc
            worker_pool._cancel_events[job_id] = unittest.mock.MagicMock()

        success = worker_pool.cancel_scan_job(job_id)
        self.assertTrue(success)

        # Verify process termination was called
        mock_proc.terminate.assert_called_once()
        mock_proc.wait.assert_called_once()

        session = self.SessionLocal()
        try:
            updated_job = session.query(models.ScanJob).filter_by(id=job_id).first()
            self.assertEqual(updated_job.status, "Cancelled")
        finally:
            session.close()

    @patch("monitoring.worker.SessionLocal")
    def test_worker_new_asset_remains_unclassified(self, mock_session_cls):
        """Test 12: Discovered new assets have criticality=None, owner=None (unclassified)."""
        mock_session_cls.side_effect = self.SessionLocal

        job = models.ScanJob(target="192.168.1.50", scan_type="single_host", status="Queued")
        self.db.add(job)
        self.db.commit()
        job_id = job.id

        mock_pipeline = MagicMock()
        mock_pipeline.discover_live_hosts.return_value = ["192.168.1.50"]
        mock_pipeline.scan_single_host.return_value = {
            "ip_address": "192.168.1.50",
            "hostname": "new-server",
            "open_ports": [{"port": 80, "protocol": "tcp", "service": "http"}],
            "vulnerabilities": [],
            "risk_result": {"findings": [], "risk_score": 0, "risk_level": "Low"},
        }

        worker_pool = ScanWorkerPool(max_workers=3, pipeline=mock_pipeline)
        cancel_event = unittest.mock.MagicMock()
        cancel_event.is_set.return_value = False

        worker_pool._execute_scan_job(job_id, cancel_event)

        session = self.SessionLocal()
        try:
            asset = session.query(models.Asset).filter_by(ip_address="192.168.1.50").first()
            self.assertIsNotNone(asset)
            self.assertIsNone(asset.criticality, "New asset must NOT have assumed Medium criticality")
            self.assertIsNone(asset.owner, "New asset must NOT have assumed owner")
            self.assertIsNone(asset.environment, "New asset must NOT have assumed environment")
            self.assertIsNone(asset.exposure, "New asset must NOT have assumed exposure")
        finally:
            session.close()

    # -----------------------------------------------------------------------
    # 4. Drift Baseline & Detection Tests
    # -----------------------------------------------------------------------

    def test_drift_baseline_strictly_from_last_completed_scan(self):
        """Test 12: Only scans with status='Completed' are chosen as drift baseline."""
        target = "192.168.1.0/24"

        # Scan 1: Completed
        job1 = models.ScanJob(
            target=target,
            scan_type="subnet_discovery",
            status="Completed",
            completed_at=datetime.utcnow() - timedelta(hours=2),
        )
        # Scan 2: Failed
        job2 = models.ScanJob(
            target=target,
            scan_type="subnet_discovery",
            status="Failed",
            completed_at=datetime.utcnow() - timedelta(hours=1),
        )
        # Scan 3: Cancelled
        job3 = models.ScanJob(
            target=target,
            scan_type="subnet_discovery",
            status="Cancelled",
            completed_at=datetime.utcnow() - timedelta(minutes=30),
        )
        self.db.add_all([job1, job2, job3])
        self.db.commit()

        baseline = DriftDetector.get_baseline_snapshot(self.db, target)
        self.assertIsNotNone(baseline)
        self.assertEqual(baseline.scan_job_id, job1.id, "Failed and Cancelled scans must not be baseline")

    def test_drift_initial_scan_establishes_baseline(self):
        """Test 13: When no prior completed scan exists, get_baseline_snapshot returns None."""
        target = "192.168.1.0/24"
        baseline = DriftDetector.get_baseline_snapshot(self.db, target)
        self.assertIsNone(baseline)

    def test_drift_detection_new_asset_event(self):
        """Test 14: NEW_ASSET drift event is emitted when an IP was not in baseline."""
        curr = ScanSnapshot(
            target="192.168.1.0/24",
            scan_job_id=2,
            assets={
                "192.168.1.10": AssetSnapshot(ip_address="192.168.1.10"),
                "192.168.1.20": AssetSnapshot(ip_address="192.168.1.20"),
            },
        )
        baseline = ScanSnapshot(
            target="192.168.1.0/24",
            scan_job_id=1,
            assets={
                "192.168.1.10": AssetSnapshot(ip_address="192.168.1.10"),
            },
        )

        events = DriftDetector.detect_drift(baseline, curr, scan_job_id=2)
        event_types = [e["event_type"] for e in events]
        self.assertIn("NEW_ASSET", event_types)

        new_asset_ev = next(e for e in events if e["event_type"] == "NEW_ASSET")
        self.assertIn("192.168.1.20", new_asset_ev["title"])
        self.assertEqual(new_asset_ev["scan_job_id"], 2)

    def test_drift_detection_port_opened_event(self):
        """Test 15: PORT_OPENED event is emitted with High severity for port 445."""
        baseline = ScanSnapshot(
            target="192.168.1.10",
            scan_job_id=1,
            assets={
                "192.168.1.10": AssetSnapshot(
                    ip_address="192.168.1.10",
                    open_ports={(80, "tcp")},
                    services={(80, "tcp"): "http"},
                ),
            },
        )
        curr = ScanSnapshot(
            target="192.168.1.10",
            scan_job_id=2,
            assets={
                "192.168.1.10": AssetSnapshot(
                    ip_address="192.168.1.10",
                    open_ports={(80, "tcp"), (445, "tcp")},
                    services={(80, "tcp"): "http", (445, "tcp"): "microsoft-ds"},
                ),
            },
        )

        events = DriftDetector.detect_drift(baseline, curr, scan_job_id=2)
        event_types = [e["event_type"] for e in events]
        self.assertIn("PORT_OPENED", event_types)

        port_ev = next(e for e in events if e["event_type"] == "PORT_OPENED")
        self.assertIn("445/tcp", port_ev["title"])
        self.assertEqual(port_ev["severity"], "High")

    def test_drift_detection_port_closed_event(self):
        """Test 16: PORT_CLOSED event is emitted when port disappears from host."""
        baseline = ScanSnapshot(
            target="192.168.1.10",
            scan_job_id=1,
            assets={
                "192.168.1.10": AssetSnapshot(
                    ip_address="192.168.1.10",
                    open_ports={(80, "tcp"), (139, "tcp")},
                    services={(80, "tcp"): "http", (139, "tcp"): "netbios-ssn"},
                ),
            },
        )
        curr = ScanSnapshot(
            target="192.168.1.10",
            scan_job_id=2,
            assets={
                "192.168.1.10": AssetSnapshot(
                    ip_address="192.168.1.10",
                    open_ports={(80, "tcp")},
                    services={(80, "tcp"): "http"},
                ),
            },
        )

        events = DriftDetector.detect_drift(baseline, curr, scan_job_id=2)
        event_types = [e["event_type"] for e in events]
        self.assertIn("PORT_CLOSED", event_types)

        port_ev = next(e for e in events if e["event_type"] == "PORT_CLOSED")
        self.assertIn("139/tcp", port_ev["title"])
        self.assertEqual(port_ev["severity"], "Low")

    def test_drift_detection_cve_detected_event(self):
        """Test 17: CVE_DETECTED event is emitted for newly confirmed vulnerability."""
        baseline = ScanSnapshot(
            target="192.168.1.10",
            scan_job_id=1,
            assets={"192.168.1.10": AssetSnapshot(ip_address="192.168.1.10")},
        )
        curr = ScanSnapshot(
            target="192.168.1.10",
            scan_job_id=2,
            assets={
                "192.168.1.10": AssetSnapshot(
                    ip_address="192.168.1.10",
                    vulnerabilities={
                        "SMB Service Exposed": {
                            "title": "SMB Service Exposed",
                            "port": 445,
                            "cve": "CVE-2020-0796",
                            "cvss_score": 10.0,
                            "severity": "Critical",
                        }
                    },
                )
            },
        )

        events = DriftDetector.detect_drift(baseline, curr, scan_job_id=2)
        event_types = [e["event_type"] for e in events]
        self.assertIn("CVE_DETECTED", event_types)

        cve_ev = next(e for e in events if e["event_type"] == "CVE_DETECTED")
        self.assertIn("CVE-2020-0796", cve_ev["title"])
        self.assertEqual(cve_ev["severity"], "Critical")

    def test_drift_detection_finding_resolved_event(self):
        """Test 18: FINDING_RESOLVED event is emitted when prior finding is absent."""
        baseline = ScanSnapshot(
            target="192.168.1.10",
            scan_job_id=1,
            assets={
                "192.168.1.10": AssetSnapshot(
                    ip_address="192.168.1.10",
                    vulnerabilities={
                        "NetBIOS Exposed": {
                            "title": "NetBIOS Exposed",
                            "port": 139,
                            "cve": None,
                            "cvss_score": None,
                            "severity": "Medium",
                        }
                    },
                )
            },
        )
        curr = ScanSnapshot(
            target="192.168.1.10",
            scan_job_id=2,
            assets={"192.168.1.10": AssetSnapshot(ip_address="192.168.1.10")},
        )

        events = DriftDetector.detect_drift(baseline, curr, scan_job_id=2)
        event_types = [e["event_type"] for e in events]
        self.assertIn("FINDING_RESOLVED", event_types)

        res_ev = next(e for e in events if e["event_type"] == "FINDING_RESOLVED")
        self.assertIn("NetBIOS Exposed", res_ev["title"])

    def test_drift_events_contain_scan_job_id_and_asset_id(self):
        """Test 19: All emitted drift events strictly contain scan_job_id and asset_id."""
        baseline = ScanSnapshot(
            target="192.168.1.10",
            scan_job_id=5,
            assets={"192.168.1.10": AssetSnapshot(ip_address="192.168.1.10")},
        )
        curr = ScanSnapshot(
            target="192.168.1.10",
            scan_job_id=6,
            assets={
                "192.168.1.10": AssetSnapshot(
                    ip_address="192.168.1.10",
                    open_ports={(22, "tcp")},
                    services={(22, "tcp"): "ssh"},
                )
            },
        )

        events = DriftDetector.detect_drift(
            baseline,
            curr,
            scan_job_id=6,
            asset_id_map={"192.168.1.10": 42},
        )
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["scan_job_id"], 6)
        self.assertEqual(events[0]["asset_id"], 42)

    # -----------------------------------------------------------------------
    # 5. Scheduler Tests
    # -----------------------------------------------------------------------

    @patch("monitoring.scheduler.SessionLocal")
    def test_scheduler_interval_and_next_run_calculation(self, mock_session_cls):
        """Test 20: Scheduler evaluates due schedule and calculates next_run_at."""
        mock_session_cls.side_effect = self.SessionLocal

        sched = models.ScanSchedule(
            name="Daily Subnet",
            target="192.168.1.0/24",
            interval_minutes=60,
            is_active=True,
            next_run_at=datetime.utcnow() - timedelta(minutes=1),
        )
        self.db.add(sched)
        self.db.commit()
        sched_id = sched.id

        mock_worker = MagicMock()
        scheduler = MonitoringScheduler(worker_pool=mock_worker, poll_interval_seconds=1)

        scheduler.evaluate_due_schedules()

        mock_worker.submit_scan_job.assert_called_once()
        session = self.SessionLocal()
        try:
            updated_sched = session.query(models.ScanSchedule).filter_by(id=sched_id).first()
            self.assertIsNotNone(updated_sched.last_run_at)
            self.assertGreater(updated_sched.next_run_at, datetime.utcnow())
        finally:
            session.close()

    @patch("monitoring.scheduler.SessionLocal")
    def test_scheduler_skips_inactive_schedules(self, mock_session_cls):
        """Test 21: Inactive schedules (is_active=False) are ignored by the scheduler."""
        mock_session_cls.side_effect = self.SessionLocal

        sched = models.ScanSchedule(
            name="Paused Sweep",
            target="192.168.1.0/24",
            interval_minutes=60,
            is_active=False,
            next_run_at=datetime.utcnow() - timedelta(minutes=1),
        )
        self.db.add(sched)
        self.db.commit()

        mock_worker = MagicMock()
        scheduler = MonitoringScheduler(worker_pool=mock_worker, poll_interval_seconds=1)

        scheduler.evaluate_due_schedules()

        mock_worker.submit_scan_job.assert_not_called()

    @patch("monitoring.scheduler.SessionLocal")
    def test_scheduler_prevents_duplicate_active_jobs_for_same_target(self, mock_session_cls):
        """Test 22: Scheduler skips queuing if target already has a Queued or Running job."""
        mock_session_cls.side_effect = self.SessionLocal

        # Active job already running for target
        active_job = models.ScanJob(target="192.168.1.0/24", scan_type="scheduled_sweep", status="Running")
        self.db.add(active_job)

        sched = models.ScanSchedule(
            name="Subnet Sweep",
            target="192.168.1.0/24",
            interval_minutes=60,
            is_active=True,
            next_run_at=datetime.utcnow() - timedelta(minutes=5),
        )
        self.db.add(sched)
        self.db.commit()
        sched_id = sched.id

        mock_worker = MagicMock()
        scheduler = MonitoringScheduler(worker_pool=mock_worker, poll_interval_seconds=1)

        scheduler.evaluate_due_schedules()

        mock_worker.submit_scan_job.assert_not_called()
        session = self.SessionLocal()
        try:
            updated_sched = session.query(models.ScanSchedule).filter_by(id=sched_id).first()
            # Verify next_run_at was bumped to avoid spinning
            self.assertGreater(updated_sched.next_run_at, datetime.utcnow())
        finally:
            session.close()

    # -----------------------------------------------------------------------
    # 6. GRC Recalculation Integration Test
    # -----------------------------------------------------------------------

    def test_grc_recalculation_invoked_on_new_findings(self):
        """Test 23: recalculate_asset_grc_risks deterministically updates inherent risk."""
        asset = models.Asset(
            ip_address="192.168.1.100",
            criticality="High",  # Impact = 3
            exposure="Internal",  # Likelihood modifier = -1
        )
        risk = models.Risk(
            title="SMB Exposed",
            likelihood="High",  # Base 3, internal modifier -> 2
            impact="Medium",
        )
        asset.risks.append(risk)

        recalculate_asset_grc_risks(asset)

        # Inherent score = likelihood (2) x impact (3) = 6
        self.assertEqual(risk.likelihood_score, 2)
        self.assertEqual(risk.impact_score, 3)
        self.assertEqual(risk.inherent_risk_score, 6)
        self.assertEqual(risk.inherent_risk_level, "Medium")


class TestPhase5MonitoringAPI(unittest.TestCase):
    """Integration tests for Phase 5 /monitoring REST API endpoints in backend/main.py."""

    def setUp(self):
        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        models.Base.metadata.create_all(bind=self.engine)
        self.TestingSessionLocal = sessionmaker(bind=self.engine, autocommit=False, autoflush=False)

        # Patch SessionLocal and worker pool in main
        from main import app, scan_worker_pool
        self.app = app
        self.scan_worker_pool = scan_worker_pool

        self.session_patcher = patch("main.SessionLocal", side_effect=self.TestingSessionLocal)
        self.session_patcher.start()

        # Patch worker execution so real scans aren't run
        self.submit_patcher = patch.object(self.scan_worker_pool, "submit_scan_job")
        self.mock_submit = self.submit_patcher.start()

        from fastapi.testclient import TestClient
        self.client = TestClient(self.app)

    def tearDown(self):
        self.submit_patcher.stop()
        self.session_patcher.stop()
        models.Base.metadata.drop_all(bind=self.engine)

    def test_api_post_job_returns_202(self):
        """Test API 1: POST /monitoring/jobs with valid RFC 1918 target returns 202 Accepted."""
        resp = self.client.post("/monitoring/jobs", json={
            "target": "192.168.1.0/24",
            "scan_type": "subnet_discovery",
        })
        self.assertEqual(resp.status_code, 202)
        data = resp.json()
        self.assertEqual(data["target"], "192.168.1.0/24")
        self.assertEqual(data["scan_type"], "subnet_discovery")
        self.assertEqual(data["status"], "Queued")
        self.mock_submit.assert_called_once_with(data["id"])

    def test_api_post_job_rejects_invalid_target(self):
        """Test API 2: POST /monitoring/jobs rejects malformed targets with HTTP 400."""
        resp = self.client.post("/monitoring/jobs", json={
            "target": "not-an-ip",
            "scan_type": "subnet_discovery",
        })
        self.assertEqual(resp.status_code, 400)

    def test_api_post_job_rejects_public_ip(self):
        """Test API 3: POST /monitoring/jobs rejects public IP addresses with HTTP 400."""
        resp = self.client.post("/monitoring/jobs", json={
            "target": "8.8.8.8",
            "scan_type": "single_host",
        })
        self.assertEqual(resp.status_code, 400)
        self.assertIn("RFC 1918", resp.json()["detail"])

    def test_api_post_job_rejects_wide_network(self):
        """Test API 4: POST /monitoring/jobs rejects subnets wider than /24 with HTTP 400."""
        resp = self.client.post("/monitoring/jobs", json={
            "target": "10.0.0.0/16",
            "scan_type": "subnet_discovery",
        })
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Maximum allowed subnet size is /24", resp.json()["detail"])

    def test_api_post_job_rejects_invalid_scan_type(self):
        """Test API 5: POST /monitoring/jobs rejects unapproved scan_type with HTTP 400."""
        resp = self.client.post("/monitoring/jobs", json={
            "target": "192.168.1.1",
            "scan_type": "aggressive_exploit",
        })
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Invalid scan_type", resp.json()["detail"])

    def test_api_get_jobs_returns_created_job_and_pagination(self):
        """Test API 6: GET /monitoring/jobs lists recent jobs with pagination and status filter."""
        # Create 2 jobs in DB
        db = self.TestingSessionLocal()
        j1 = models.ScanJob(target="192.168.1.1", scan_type="single_host", status="Queued")
        j2 = models.ScanJob(target="192.168.1.2", scan_type="single_host", status="Completed")
        db.add_all([j1, j2])
        db.commit()
        db.close()

        resp = self.client.get("/monitoring/jobs?limit=10&offset=0")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["total"], 2)
        self.assertEqual(len(data["jobs"]), 2)

        # Filter by status
        resp_filtered = self.client.get("/monitoring/jobs?status=Completed")
        self.assertEqual(resp_filtered.status_code, 200)
        filtered_data = resp_filtered.json()
        self.assertEqual(filtered_data["total"], 1)
        self.assertEqual(filtered_data["jobs"][0]["status"], "Completed")

    def test_api_get_job_by_id_returns_details(self):
        """Test API 7: GET /monitoring/jobs/{id} returns job state and metrics."""
        db = self.TestingSessionLocal()
        job = models.ScanJob(
            target="192.168.1.10",
            scan_type="single_host",
            status="Running",
            progress_percent=45,
            discovered_assets_count=1,
            discovered_vulns_count=3,
        )
        db.add(job)
        db.commit()
        job_id = job.id
        db.close()

        resp = self.client.get(f"/monitoring/jobs/{job_id}")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["id"], job_id)
        self.assertEqual(data["status"], "Running")
        self.assertEqual(data["progress_percent"], 45)
        self.assertEqual(data["discovered_assets_count"], 1)
        self.assertEqual(data["discovered_vulns_count"], 3)

    def test_api_get_job_by_id_nonexistent_returns_404(self):
        """Test API 8: GET /monitoring/jobs/{id} for non-existent ID returns 404."""
        resp = self.client.get("/monitoring/jobs/99999")
        self.assertEqual(resp.status_code, 404)

    def test_api_cancel_job_requests_cooperative_cancellation(self):
        """Test API 9: POST /monitoring/jobs/{id}/cancel requests cooperative cancellation."""
        db = self.TestingSessionLocal()
        job = models.ScanJob(target="192.168.1.10", scan_type="single_host", status="Running")
        db.add(job)
        db.commit()
        job_id = job.id
        db.close()

        with patch.object(self.scan_worker_pool, "cancel_scan_job") as mock_cancel:
            resp = self.client.post(f"/monitoring/jobs/{job_id}/cancel")
            self.assertEqual(resp.status_code, 200)
            mock_cancel.assert_called_once_with(job_id)

    def test_api_cancel_job_already_terminal_returns_400(self):
        """Test API 10: Cannot cancel job with terminal status (Completed/Failed/Cancelled)."""
        db = self.TestingSessionLocal()
        job = models.ScanJob(target="192.168.1.10", scan_type="single_host", status="Completed")
        db.add(job)
        db.commit()
        job_id = job.id
        db.close()

        resp = self.client.post(f"/monitoring/jobs/{job_id}/cancel")
        self.assertEqual(resp.status_code, 400)
        self.assertIn("terminal status", resp.json()["detail"])

    def test_api_cancel_job_nonexistent_returns_404(self):
        """Test API: POST /monitoring/jobs/{id}/cancel returns 404 for nonexistent job."""
        resp = self.client.post("/monitoring/jobs/99999/cancel")
        self.assertEqual(resp.status_code, 404)

    def test_api_post_schedule_creates_schedule_and_calculates_next_run_at(self):
        """Test API 11: POST /monitoring/schedules creates schedule with next_run_at."""
        resp = self.client.post("/monitoring/schedules", json={
            "name": "Hourly Subnet Sweep",
            "target": "192.168.1.0/24",
            "interval_minutes": 60,
        })
        self.assertEqual(resp.status_code, 201)
        data = resp.json()
        self.assertEqual(data["name"], "Hourly Subnet Sweep")
        self.assertEqual(data["interval_minutes"], 60)
        self.assertTrue(data["is_active"])
        self.assertIsNotNone(data["next_run_at"])

    def test_api_post_schedule_rejects_interval_under_15(self):
        """Test API 12: POST /monitoring/schedules rejects interval < 15 minutes with HTTP 400."""
        resp = self.client.post("/monitoring/schedules", json={
            "name": "Rapid Sweep",
            "target": "192.168.1.0/24",
            "interval_minutes": 5,
        })
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Minimum schedule interval is 15 minutes", resp.json()["detail"])

    def test_api_post_schedule_validates_target(self):
        """Test API 13: POST /monitoring/schedules rejects public target with HTTP 400."""
        resp = self.client.post("/monitoring/schedules", json={
            "name": "Public Sweep",
            "target": "8.8.8.8",
            "interval_minutes": 60,
        })
        self.assertEqual(resp.status_code, 400)

    def test_api_get_schedules_returns_schedules(self):
        """Test API 14: GET /monitoring/schedules returns list of configured schedules."""
        db = self.TestingSessionLocal()
        s1 = models.ScanSchedule(name="S1", target="192.168.1.0/24", interval_minutes=60)
        s2 = models.ScanSchedule(name="S2", target="10.0.0.0/24", interval_minutes=120)
        db.add_all([s1, s2])
        db.commit()
        db.close()

        resp = self.client.get("/monitoring/schedules")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["total"], 2)
        self.assertEqual(len(data["schedules"]), 2)

    def test_api_patch_schedule_updates_fields(self):
        """Test API 15: PATCH /monitoring/schedules/{id} updates interval and active status."""
        db = self.TestingSessionLocal()
        s = models.ScanSchedule(name="Old Name", target="192.168.1.0/24", interval_minutes=60, is_active=True)
        db.add(s)
        db.commit()
        sid = s.id
        db.close()

        resp = self.client.patch(f"/monitoring/schedules/{sid}", json={
            "name": "New Name",
            "interval_minutes": 120,
            "is_active": False,
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["name"], "New Name")
        self.assertEqual(data["interval_minutes"], 120)
        self.assertFalse(data["is_active"])

    def test_api_patch_schedule_revalidates_target_and_interval(self):
        """Test API 16: PATCH revalidates changed target and interval bounds."""
        db = self.TestingSessionLocal()
        s = models.ScanSchedule(name="Sweep", target="192.168.1.0/24", interval_minutes=60)
        db.add(s)
        db.commit()
        sid = s.id
        db.close()

        # Revalidate interval < 15
        resp1 = self.client.patch(f"/monitoring/schedules/{sid}", json={"interval_minutes": 2})
        self.assertEqual(resp1.status_code, 400)

        # Revalidate public target
        resp2 = self.client.patch(f"/monitoring/schedules/{sid}", json={"target": "8.8.8.8"})
        self.assertEqual(resp2.status_code, 400)

    def test_api_delete_schedule_works(self):
        """Test API 17: DELETE /monitoring/schedules/{id} deletes the schedule."""
        db = self.TestingSessionLocal()
        s = models.ScanSchedule(name="To Delete", target="192.168.1.0/24", interval_minutes=60)
        db.add(s)
        db.commit()
        sid = s.id
        db.close()

        resp = self.client.delete(f"/monitoring/schedules/{sid}")
        self.assertEqual(resp.status_code, 200)

        # Verify 404 on subsequent get/delete
        resp2 = self.client.delete(f"/monitoring/schedules/{sid}")
        self.assertEqual(resp2.status_code, 404)

    def test_api_get_schedule_nonexistent_returns_404(self):
        """Test API 18: GET /monitoring/schedules/{id} for non-existent schedule returns 404."""
        resp = self.client.get("/monitoring/schedules/99999")
        self.assertEqual(resp.status_code, 404)

    def test_api_job_lifecycle_mocked_execution(self):
        """Test API 8: Job submitted through API transitions through lifecycle using mocked worker."""
        with patch.object(self.scan_worker_pool.pipeline, "discover_live_hosts", return_value=["192.168.1.50"]):
            with patch.object(self.scan_worker_pool.pipeline, "scan_single_host", return_value={
                "ip_address": "192.168.1.50",
                "hostname": "host50",
                "mac_address": "AA:BB:CC:DD:EE:01",
                "operating_system": "Linux 5.4",
                "open_ports": [{"port": "80", "service": "http"}],
                "vulnerabilities": [],
                "risk_result": {"risk_score": 10, "risk_level": "Low", "findings": []},
            }):
                resp = self.client.post("/monitoring/jobs", json={
                    "target": "192.168.1.50",
                    "scan_type": "single_host",
                })
                self.assertEqual(resp.status_code, 202)
                job_id = resp.json()["id"]

                # Execute the worker job logic directly using our test SessionLocal
                with patch("monitoring.worker.SessionLocal", side_effect=self.TestingSessionLocal):
                    self.scan_worker_pool._execute_scan_job(job_id, threading.Event())

                # Verify GET /monitoring/jobs/{id} shows Completed
                get_resp = self.client.get(f"/monitoring/jobs/{job_id}")
                self.assertEqual(get_resp.status_code, 200)
                job_data = get_resp.json()
                self.assertEqual(job_data["status"], "Completed")
                self.assertEqual(job_data["progress_percent"], 100)
                self.assertEqual(job_data["discovered_assets_count"], 1)

    def _seed_drift_events(self):
        db = self.TestingSessionLocal()
        job = models.ScanJob(target="192.168.1.0/24", scan_type="subnet_discovery", status="Completed")
        db.add(job)
        db.commit()
        job_id = job.id

        e1 = models.DriftEvent(scan_job_id=job_id, event_type="NEW_ASSET", title="New Asset", severity="Low")
        e2 = models.DriftEvent(scan_job_id=job_id, event_type="PORT_OPENED", title="Port 445 Opened", severity="High")
        e3 = models.DriftEvent(scan_job_id=job_id, event_type="PORT_CLOSED", title="Port 80 Closed", severity="Low")
        db.add_all([e1, e2, e3])
        db.commit()
        db.close()
        return job_id

    def test_api_get_drift_returns_events(self):
        """Test API 19: GET /monitoring/drift returns all recorded drift events."""
        self._seed_drift_events()
        resp = self.client.get("/monitoring/drift")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["total"], 3)
        self.assertEqual(len(data["events"]), 3)

    def test_api_get_drift_filter_by_severity(self):
        """Test API 20: GET /monitoring/drift filters correctly by severity level."""
        self._seed_drift_events()
        resp = self.client.get("/monitoring/drift?severity=High")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["events"][0]["event_type"], "PORT_OPENED")
        self.assertEqual(data["events"][0]["severity"], "High")

    def test_api_get_drift_filter_by_event_type(self):
        """Test API 21: GET /monitoring/drift filters correctly by event_type."""
        self._seed_drift_events()
        resp = self.client.get("/monitoring/drift?event_type=NEW_ASSET")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["events"][0]["event_type"], "NEW_ASSET")

    def test_api_get_drift_pagination(self):
        """Test API 22: GET /monitoring/drift supports limit and offset pagination."""
        self._seed_drift_events()
        resp = self.client.get("/monitoring/drift?limit=2&offset=0")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(len(data["events"]), 2)
        self.assertEqual(data["total"], 3)

    @patch("main.scan_host")
    @patch("main.calculate_risk")
    @patch("main.identify_vulnerabilities")
    def test_api_backward_compatibility_scan(self, mock_vuln, mock_risk, mock_scan):
        """Test API 23: Existing POST /scan remains 100% functional and backward compatible."""
        mock_scan.return_value = {
            "hostname": "test-host",
            "mac_address": "AA:BB:CC:DD:EE:FF",
            "operating_system": "Linux 5.4",
            "open_ports": [{"port": "80", "service": "http"}],
        }
        mock_risk.return_value = {
            "risk_score": 10,
            "risk_level": "Low",
            "findings": ["HTTP service exposed on port 80"],
        }
        mock_vuln.return_value = []

        resp = self.client.post("/scan?target=192.168.127.1")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["ip_address"], "192.168.127.1")
        self.assertEqual(data["risk_level"], "Low")
        self.assertEqual(data["message"], "Network scan completed and GRC risks registered")

    @patch("main.scan_host")
    @patch("main.discover_hosts")
    def test_api_backward_compatibility_discover(self, mock_discover, mock_scan):
        """Test API 24: Existing POST /discover remains 100% functional and backward compatible."""
        mock_discover.return_value = ["192.168.127.1"]
        mock_scan.return_value = {
            "hostname": "test-host",
            "mac_address": "AA:BB:CC:DD:EE:FF",
            "operating_system": "Linux",
            "open_ports": [{"port": "80", "service": "http"}],
        }

        resp = self.client.post("/discover?network=192.168.127.0/24")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["network"], "192.168.127.0/24")
        self.assertEqual(data["hosts_found"], 1)
        self.assertEqual(data["message"], "Network discovery completed")


if __name__ == "__main__":
    unittest.main()

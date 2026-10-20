"""Regression tests for non-root Nmap scanning and structured failure handling.

Verifies:
1. Nmap flags: Default Docker/non-root scan omits '-O' and uses '-sT' (TCP connect) and '-sV' (version detection).
2. OS detection: Optional '-O' flag handled safely via parameter or ENABLE_OS_DETECTION environment variable.
3. Privilege fallback: Automatic fallback without '-O' if root privileges are missing.
4. Error handling: Scan execution failures raise descriptive RuntimeError with exit codes and stderr.
5. Structured API errors: /scan and /discover endpoints return structured HTTP error payloads instead of unexplained 500s.
6. Monitoring pipeline: MonitoringScannerPipeline uses '-sT' and handles OS detection privilege fallback safely.
"""

import os
import sys
from pathlib import Path
import unittest
import subprocess
from unittest.mock import patch, MagicMock

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(BASE_DIR / "backend"))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import models
from scanner.nmap_scanner import scan_host, discover_hosts
from backend.monitoring.scanner_pipeline import MonitoringScannerPipeline


SAMPLE_NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sT -sV -oX - 192.168.127.1" version="7.93">
<host>
    <status state="up" reason="conn-refined"/>
    <address addr="192.168.127.1" addrtype="ipv4"/>
    <address addr="00:11:22:33:44:55" addrtype="mac"/>
    <hostnames>
        <hostname name="gateway.local" type="PTR"/>
    </hostnames>
    <ports>
        <port protocol="tcp" portid="80">
            <state state="open" reason="syn-ack"/>
            <service name="http" product="Apache httpd" version="2.4.52" extrainfo="(Ubuntu)">
                <cpe>cpe:/a:apache:http_server:2.4.52</cpe>
            </service>
        </port>
    </ports>
</host>
</nmaprun>
"""

SAMPLE_NMAP_XML_WITH_OS = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sT -sV -O -oX - 192.168.127.1" version="7.93">
<host>
    <status state="up" reason="conn-refined"/>
    <address addr="192.168.127.1" addrtype="ipv4"/>
    <hostnames>
        <hostname name="gateway.local" type="PTR"/>
    </hostnames>
    <os>
        <osmatch name="Linux 5.4 - 5.15" accuracy="96"/>
    </os>
    <ports>
        <port protocol="tcp" portid="22">
            <state state="open" reason="syn-ack"/>
            <service name="ssh" product="OpenSSH" version="8.9p1"/>
        </port>
    </ports>
</host>
</nmaprun>
"""


class TestNmapScannerNonRoot(unittest.TestCase):
    """Unit tests for scanner/nmap_scanner.py non-root compatibility."""

    def setUp(self):
        # Ensure clean environment
        self.orig_env = os.environ.get("ENABLE_OS_DETECTION")
        if "ENABLE_OS_DETECTION" in os.environ:
            del os.environ["ENABLE_OS_DETECTION"]

    def tearDown(self):
        if self.orig_env is not None:
            os.environ["ENABLE_OS_DETECTION"] = self.orig_env
        elif "ENABLE_OS_DETECTION" in os.environ:
            del os.environ["ENABLE_OS_DETECTION"]

    @patch("scanner.nmap_scanner.subprocess.run")
    def test_default_scan_flags_non_root_compatible(self, mock_run):
        """Default scan must use -sT, -sV, -oX and omit -O to run safely without root privileges."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = SAMPLE_NMAP_XML
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        result = scan_host("192.168.127.1")

        call_args = mock_run.call_args[0][0]
        self.assertIn("nmap", call_args)
        self.assertIn("-sT", call_args, "Must specify -sT (TCP connect scan) for unprivileged non-root user")
        self.assertIn("-sV", call_args, "Must specify -sV for service/version detection")
        self.assertNotIn("-O", call_args, "Default scan must NOT include -O because it requires root privileges")
        self.assertIn("-oX", call_args)
        self.assertIn("192.168.127.1", call_args)

        self.assertEqual(result["ip_address"], "192.168.127.1")
        self.assertEqual(result["hostname"], "gateway.local")
        self.assertEqual(result["mac_address"], "00:11:22:33:44:55")
        self.assertIsNone(result["operating_system"])
        self.assertEqual(len(result["open_ports"]), 1)
        self.assertEqual(result["open_ports"][0]["port"], "80")
        self.assertEqual(result["open_ports"][0]["service"], "http")

    @patch("scanner.nmap_scanner.subprocess.run")
    def test_scan_host_with_explicit_os_detection_enabled(self, mock_run):
        """When enable_os_detection=True, -O is added to the Nmap command."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = SAMPLE_NMAP_XML_WITH_OS
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        result = scan_host("192.168.127.1", enable_os_detection=True)

        call_args = mock_run.call_args[0][0]
        self.assertIn("-O", call_args)
        self.assertEqual(result["operating_system"], "Linux 5.4 - 5.15")

    @patch("scanner.nmap_scanner.subprocess.run")
    def test_scan_host_with_env_os_detection_enabled(self, mock_run):
        """When ENABLE_OS_DETECTION=true, -O is added to the Nmap command."""
        os.environ["ENABLE_OS_DETECTION"] = "true"
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = SAMPLE_NMAP_XML_WITH_OS
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        result = scan_host("192.168.127.1")

        call_args = mock_run.call_args[0][0]
        self.assertIn("-O", call_args)
        self.assertEqual(result["operating_system"], "Linux 5.4 - 5.15")

    @patch("scanner.nmap_scanner.subprocess.run")
    def test_privilege_error_triggers_fallback_without_os_scan(self, mock_run):
        """If -O fails with root privilege error, scan automatically retries without -O."""
        priv_error_result = MagicMock()
        priv_error_result.returncode = 1
        priv_error_result.stdout = ""
        priv_error_result.stderr = "TCP/IP fingerprinting (for OS scan) requires root privileges. QUITTING!\n"

        success_fallback_result = MagicMock()
        success_fallback_result.returncode = 0
        success_fallback_result.stdout = SAMPLE_NMAP_XML
        success_fallback_result.stderr = ""

        mock_run.side_effect = [priv_error_result, success_fallback_result]

        result = scan_host("192.168.127.1", enable_os_detection=True)

        self.assertEqual(mock_run.call_count, 2)
        # First call included -O
        first_call = mock_run.call_args_list[0][0][0]
        self.assertIn("-O", first_call)
        # Second fallback call omitted -O
        second_call = mock_run.call_args_list[1][0][0]
        self.assertNotIn("-O", second_call)
        self.assertIn("-sT", second_call)

        self.assertEqual(result["ip_address"], "192.168.127.1")
        self.assertIsNone(result["operating_system"])

    @patch("scanner.nmap_scanner.subprocess.run")
    def test_scan_failure_raises_descriptive_runtime_error(self, mock_run):
        """Standard scan failures raise RuntimeError with exit code and stderr."""
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "Failed to resolve target: host not found"
        mock_run.return_value = mock_result

        with self.assertRaises(RuntimeError) as ctx:
            scan_host("192.168.127.1")

        self.assertIn("exit code 1", str(ctx.exception))
        self.assertIn("Failed to resolve target", str(ctx.exception))

    @patch("scanner.nmap_scanner.subprocess.run")
    def test_scan_timeout_raises_runtime_error(self, mock_run):
        """Timeouts raise RuntimeError with clear target info."""
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["nmap"], timeout=120)

        with self.assertRaises(RuntimeError) as ctx:
            scan_host("192.168.127.1")

        self.assertIn("timed out after 120 seconds", str(ctx.exception))
        self.assertIn("192.168.127.1", str(ctx.exception))

    @patch("scanner.nmap_scanner.subprocess.run")
    def test_missing_nmap_executable_raises_runtime_error(self, mock_run):
        """Missing Nmap binary raises clear PATH error."""
        mock_run.side_effect = FileNotFoundError()

        with self.assertRaises(RuntimeError) as ctx:
            scan_host("192.168.127.1")

        self.assertIn("Nmap executable not found on system PATH", str(ctx.exception))

    @patch("scanner.nmap_scanner.subprocess.run")
    def test_discover_hosts_failure_raises_runtime_error(self, mock_run):
        """Host discovery failures raise RuntimeError with error details."""
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "Network unreachable"
        mock_run.return_value = mock_result

        with self.assertRaises(RuntimeError) as ctx:
            discover_hosts("192.168.127.0/24")

        self.assertIn("Nmap host discovery failed", str(ctx.exception))
        self.assertIn("Network unreachable", str(ctx.exception))


class TestMonitoringScannerPipelineNonRoot(unittest.TestCase):
    """Unit tests for MonitoringScannerPipeline non-root compatibility."""

    @patch("subprocess.Popen")
    def test_monitoring_pipeline_includes_st_flag(self, mock_popen):
        """MonitoringScannerPipeline Stage 2 must include -sT and exclude -O by default."""
        pipeline = MonitoringScannerPipeline(enable_os_detection=False)

        mock_proc = MagicMock()
        mock_proc.communicate.return_value = (SAMPLE_NMAP_XML, "")
        mock_proc.returncode = 0
        mock_popen.return_value = mock_proc

        result = pipeline.scan_single_host("192.168.127.1")

        call_args = mock_popen.call_args[0][0]
        self.assertIn("-sT", call_args)
        self.assertIn("-sV", call_args)
        self.assertIn("--top-ports", call_args)
        self.assertNotIn("-O", call_args)
        self.assertEqual(result["ip_address"], "192.168.127.1")

    @patch("subprocess.Popen")
    def test_monitoring_pipeline_privilege_fallback(self, mock_popen):
        """When Stage 2 has -O enabled but fails with root privilege error, it falls back without -O."""
        pipeline = MonitoringScannerPipeline(enable_os_detection=True)

        proc_priv_error = MagicMock()
        proc_priv_error.returncode = 1
        proc_priv_error.communicate.return_value = ("", "TCP/IP fingerprinting (for OS scan) requires root privileges. QUITTING!\n")

        proc_fallback = MagicMock()
        proc_fallback.returncode = 0
        proc_fallback.communicate.return_value = (SAMPLE_NMAP_XML, "")

        mock_popen.side_effect = [proc_priv_error, proc_fallback]

        result = pipeline.scan_single_host("192.168.127.1")

        self.assertEqual(mock_popen.call_count, 2)
        first_call = mock_popen.call_args_list[0][0][0]
        self.assertIn("-O", first_call)
        second_call = mock_popen.call_args_list[1][0][0]
        self.assertNotIn("-O", second_call)
        self.assertEqual(result["ip_address"], "192.168.127.1")


class TestScanAPIStructuredErrors(unittest.TestCase):
    """Integration tests verifying /scan and /discover return structured error responses."""

    def setUp(self):
        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        models.Base.metadata.create_all(bind=self.engine)
        self.TestingSessionLocal = sessionmaker(bind=self.engine, autocommit=False, autoflush=False)

        from main import app
        self.app = app

        self.session_patcher = patch("main.SessionLocal", side_effect=self.TestingSessionLocal)
        self.session_patcher.start()
        self.auth_session_patcher = patch("auth.dependencies.SessionLocal", side_effect=self.TestingSessionLocal)
        self.auth_session_patcher.start()

        from fastapi.testclient import TestClient
        self.client = TestClient(self.app)
        from tests.auth_test_utils import create_test_auth_headers
        db = self.TestingSessionLocal()
        try:
            self.client.headers.update(create_test_auth_headers(db, role="Security Analyst"))
        finally:
            db.close()

    def tearDown(self):
        self.session_patcher.stop()
        self.auth_session_patcher.stop()
        models.Base.metadata.drop_all(bind=self.engine)

    @patch("main.scan_host")
    def test_scan_endpoint_returns_structured_502_on_scan_failure(self, mock_scan):
        """When scan_host raises RuntimeError, /scan returns HTTP 502 with structured error details."""
        mock_scan.side_effect = RuntimeError("Nmap scan failed (exit code 1): Network unreachable")

        resp = self.client.post("/scan?target=192.168.127.1")

        self.assertEqual(resp.status_code, 502)
        body = resp.json()
        self.assertIn("detail", body)
        detail = body["detail"]
        self.assertEqual(detail["error"], "ScanExecutionError")
        self.assertIn("Network unreachable", detail["message"])
        self.assertEqual(detail["target"], "192.168.127.1")

    @patch("main.discover_hosts")
    def test_discover_endpoint_returns_structured_502_on_discovery_failure(self, mock_discover):
        """When discover_hosts raises RuntimeError, /discover returns HTTP 502 with structured error details."""
        mock_discover.side_effect = RuntimeError("Nmap host discovery failed (exit code 1): Network interface down")

        resp = self.client.post("/discover?network=192.168.127.0/24")

        self.assertEqual(resp.status_code, 502)
        body = resp.json()
        self.assertIn("detail", body)
        detail = body["detail"]
        self.assertEqual(detail["error"], "DiscoveryExecutionError")
        self.assertIn("Network interface down", detail["message"])
        self.assertEqual(detail["network"], "192.168.127.0/24")


if __name__ == "__main__":
    unittest.main()

"""Unit tests for Network Host Discovery, Multi-Probe Discovery, Timeout Handling, and Result Parsing.

Covers:
1. Multi-probe Nmap command generation (ICMP Echo/Timestamp, TCP SYN, TCP ACK, retries).
2. Nmap XML output parsing with MAC address, vendor, hostname, and status reason.
3. Subnet network (.0) and broadcast (.255) boundary exclusion.
4. Plaintext fallback parsing when output is not XML.
5. Unprivileged probe fallback when privileged raw socket access is unavailable.
6. TimeoutExpired handling and process termination.
7. Worker preservation of discovered hosts when individual port scan fails/times out.
8. Merging of Stage 1 discovery metadata (MAC, hostname) into asset scan results.
9. Honest reporting of responsive vs unresponsive host counts without hardcoding.
"""

import unittest
from unittest.mock import patch, MagicMock
import subprocess

from backend.monitoring.scanner_pipeline import MonitoringScannerPipeline
from scanner.nmap_scanner import discover_hosts as legacy_discover_hosts


SAMPLE_NMAP_XML_OUTPUT = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sn -PE -PP -PS22,80,443 -PA80,443 -oX - 192.168.1.0/24" start="1700000000" version="7.95">
<host>
  <status state="up" reason="arp-response" reason_ttl="0"/>
  <address addr="192.168.1.1" addrtype="ipv4"/>
  <address addr="AC:84:C6:64:C2:3C" addrtype="mac" vendor="TP-Link Technologies"/>
  <hostnames><hostname name="router.lan" type="user"/></hostnames>
</host>
<host>
  <status state="up" reason="syn-ack" reason_ttl="64"/>
  <address addr="192.168.1.100" addrtype="ipv4"/>
  <hostnames><hostname name="laptop-workstation" type="PTR"/></hostnames>
</host>
<host>
  <status state="up" reason="echo-reply" reason_ttl="128"/>
  <address addr="192.168.1.102" addrtype="ipv4"/>
  <address addr="E0:C2:64:2A:B4:08" addrtype="mac" vendor="Intel Corporate"/>
  <hostnames/>
</host>
<host>
  <status state="down" reason="no-response" reason_ttl="0"/>
  <address addr="192.168.1.103" addrtype="ipv4"/>
</host>
<host>
  <status state="up" reason="reset" reason_ttl="64"/>
  <address addr="192.168.1.149" addrtype="ipv4"/>
  <address addr="D8:3A:DD:32:F8:08" addrtype="mac" vendor="Raspberry Pi Trading"/>
  <hostnames><hostname name="raspberrypi" type="PTR"/></hostnames>
</host>
<host>
  <status state="up" reason="arp-response" reason_ttl="0"/>
  <address addr="192.168.1.0" addrtype="ipv4"/>
</host>
<host>
  <status state="up" reason="arp-response" reason_ttl="0"/>
  <address addr="192.168.1.255" addrtype="ipv4"/>
</host>
</nmaprun>
"""


class TestNetworkDiscovery(unittest.TestCase):
    """Test suite for reliable authorized LAN host discovery."""

    def setUp(self):
        self.pipeline = MonitoringScannerPipeline(ping_timeout_seconds=5, host_scan_timeout_seconds=5)

    @patch("backend.monitoring.scanner_pipeline.subprocess.Popen")
    def test_multi_probe_command_includes_icmp_syn_and_ack(self, mock_popen):
        """Host discovery must issue multi-probe options (-PE, -PP, -PS, -PA, --max-retries)."""
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = (SAMPLE_NMAP_XML_OUTPUT, "")
        mock_proc.returncode = 0
        mock_popen.return_value = mock_proc

        hosts = self.pipeline.discover_live_hosts("192.168.1.0/24")

        cmd = mock_popen.call_args[0][0]
        self.assertIn("-sn", cmd)
        self.assertIn("-PE", cmd)
        self.assertIn("-PP", cmd)
        self.assertTrue(any(arg.startswith("-PS") for arg in cmd), f"Expected -PS in {cmd}")
        self.assertTrue(any(arg.startswith("-PA") for arg in cmd), f"Expected -PA in {cmd}")
        self.assertIn("-oX", cmd)
        self.assertIn("--max-retries", cmd)

        # Hosts reported state="up" (excluding .0 and .255 and state="down")
        self.assertIn("192.168.1.1", hosts)
        self.assertIn("192.168.1.100", hosts)
        self.assertIn("192.168.1.102", hosts)
        self.assertIn("192.168.1.149", hosts)
        self.assertNotIn("192.168.1.103", hosts)  # state="down"
        self.assertNotIn("192.168.1.0", hosts)    # network boundary
        self.assertNotIn("192.168.1.255", hosts)  # broadcast boundary
        self.assertEqual(len(hosts), 4)

    @patch("backend.monitoring.scanner_pipeline.subprocess.Popen")
    def test_discovery_metadata_caches_mac_vendor_hostname_and_reason(self, mock_popen):
        """Pipeline must cache rich discovery metadata (MAC, vendor, hostname, reason) for discovered hosts."""
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = (SAMPLE_NMAP_XML_OUTPUT, "")
        mock_proc.returncode = 0
        mock_popen.return_value = mock_proc

        self.pipeline.discover_live_hosts("192.168.1.0/24")

        meta = self.pipeline.last_discovery_metadata
        self.assertIn("192.168.1.1", meta)
        self.assertEqual(meta["192.168.1.1"]["mac_address"], "AC:84:C6:64:C2:3C")
        self.assertEqual(meta["192.168.1.1"]["vendor"], "TP-Link Technologies")
        self.assertEqual(meta["192.168.1.1"]["hostname"], "router.lan")
        self.assertEqual(meta["192.168.1.1"]["reason"], "arp-response")

        self.assertIn("192.168.1.149", meta)
        self.assertEqual(meta["192.168.1.149"]["mac_address"], "D8:3A:DD:32:F8:08")
        self.assertEqual(meta["192.168.1.149"]["vendor"], "Raspberry Pi Trading")
        self.assertEqual(meta["192.168.1.149"]["reason"], "reset")

    @patch("backend.monitoring.scanner_pipeline.subprocess.Popen")
    def test_plaintext_output_parsing_fallback(self, mock_popen):
        """If XML output is missing or Nmap returns standard text, fallback parser extracts live hosts."""
        plaintext = (
            "Starting Nmap 7.95 ( https://nmap.org )\n"
            "Nmap scan report for router.lan (192.168.1.1)\n"
            "Host is up (0.0050s latency).\n"
            "Nmap scan report for host-alpha (192.168.1.50)\n"
            "Host is up (0.012s latency).\n"
            "Nmap scan report for 192.168.1.255\n"
            "Host is up (0.001s latency).\n"
            "Nmap done: 256 IP addresses (2 hosts up) scanned in 2.10 seconds\n"
        )
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = (plaintext, "")
        mock_proc.returncode = 0
        mock_popen.return_value = mock_proc

        hosts = self.pipeline.discover_live_hosts("192.168.1.0/24")
        self.assertEqual(hosts, ["192.168.1.1", "192.168.1.50"])
        self.assertNotIn("192.168.1.255", hosts)

    @patch("backend.monitoring.scanner_pipeline.subprocess.Popen")
    def test_unprivileged_fallback_when_raw_packets_fail(self, mock_popen):
        """When privileged multi-probe command fails with non-zero exit, fallback to unprivileged connect probes."""
        proc_privileged = MagicMock()
        proc_privileged.communicate.return_value = ("", "Operation not permitted")
        proc_privileged.returncode = 1

        proc_fallback = MagicMock()
        proc_fallback.communicate.return_value = (
            "<nmaprun><host><status state='up' reason='syn-ack'/><address addr='192.168.1.77' addrtype='ipv4'/></host></nmaprun>",
            ""
        )
        proc_fallback.returncode = 0

        mock_popen.side_effect = [proc_privileged, proc_fallback]

        hosts = self.pipeline.discover_live_hosts("192.168.1.0/24")
        self.assertEqual(hosts, ["192.168.1.77"])
        self.assertEqual(mock_popen.call_count, 2)
        fallback_cmd = mock_popen.call_args[0][0]
        self.assertNotIn("-PE", fallback_cmd)
        self.assertNotIn("-PA", fallback_cmd)
        self.assertTrue(any(arg.startswith("-PS") for arg in fallback_cmd))

    @patch("backend.monitoring.scanner_pipeline.subprocess.Popen")
    def test_discover_live_hosts_timeout_terminates_process(self, mock_popen):
        """Discovery timeout raises TimeoutError and terminates process."""
        mock_proc = MagicMock()
        mock_proc.communicate.side_effect = subprocess.TimeoutExpired(cmd=["nmap"], timeout=5)
        mock_popen.return_value = mock_proc

        with self.assertRaises(TimeoutError):
            self.pipeline.discover_live_hosts("192.168.1.0/24")

        mock_proc.kill.assert_called_once()

    def test_single_host_target_bypasses_sweep(self):
        """Single IP targets (/32 or plain IP) bypass subnet sweep and return single IP directly."""
        hosts1 = self.pipeline.discover_live_hosts("192.168.1.50")
        self.assertEqual(hosts1, ["192.168.1.50"])

        hosts2 = self.pipeline.discover_live_hosts("192.168.1.50/32")
        self.assertEqual(hosts2, ["192.168.1.50"])


class TestLegacyScannerDiscovery(unittest.TestCase):
    """Test suite for scanner.nmap_scanner.discover_hosts."""

    @patch("scanner.nmap_scanner.subprocess.run")
    def test_legacy_discover_hosts_multi_probe_and_xml_support(self, mock_run):
        mock_result = MagicMock()
        mock_result.stdout = SAMPLE_NMAP_XML_OUTPUT
        mock_result.stderr = ""
        mock_result.returncode = 0
        mock_run.return_value = mock_result

        hosts = legacy_discover_hosts("192.168.1.0/24")

        cmd = mock_run.call_args[0][0]
        self.assertIn("-sn", cmd)
        self.assertIn("-PE", cmd)
        self.assertIn("-PP", cmd)
        self.assertTrue(any(arg.startswith("-PS") for arg in cmd))
        self.assertIn("-oX", cmd)
        self.assertIn("192.168.1.1", hosts)
        self.assertIn("192.168.1.100", hosts)
        self.assertNotIn("192.168.1.0", hosts)
        self.assertNotIn("192.168.1.255", hosts)


class TestWorkerHostDiscoveryPreservation(unittest.TestCase):
    """Test suite ensuring worker retains all discovered hosts and merges discovery metadata."""

    def setUp(self):
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        import models

        self.engine = create_engine("sqlite:///:memory:", echo=False)
        models.Base.metadata.create_all(bind=self.engine)
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        self.db = self.SessionLocal()

    def tearDown(self):
        import models
        self.db.close()
        models.Base.metadata.drop_all(bind=self.engine)

    @patch.dict("os.environ", {"NMAP_AGENT_TOKEN": ""})
    @patch("monitoring.worker.SessionLocal")
    def test_worker_retains_host_even_if_port_scan_times_out(self, mock_session_cls):
        """Discovered hosts must remain in asset inventory even if Stage 2 port scan times out or fails."""
        import models
        from monitoring.worker import ScanWorkerPool

        mock_session_cls.side_effect = self.SessionLocal

        job = models.ScanJob(target="192.168.1.0/24", scan_type="subnet_discovery", status="Queued")
        self.db.add(job)
        self.db.commit()
        job_id = job.id

        mock_pipeline = MagicMock()
        # 2 hosts discovered in Stage 1
        mock_pipeline.discover_live_hosts.return_value = ["192.168.1.1", "192.168.1.112"]
        mock_pipeline.last_discovery_metadata = {
            "192.168.1.1": {"mac_address": "AC:84:C6:64:C2:3C", "hostname": "router.lan"},
            "192.168.1.112": {"mac_address": "A8:41:F4:0C:39:57", "hostname": None},
        }

        # Host 1 succeeds, Host 2 times out
        def mock_scan_single(host_ip, **kwargs):
            if host_ip == "192.168.1.1":
                return {
                    "ip_address": "192.168.1.1",
                    "hostname": "router.lan",
                    "mac_address": None,  # Routed scan did not detect MAC in Stage 2
                    "operating_system": "Embedded Linux",
                    "open_ports": [{"port": 80, "protocol": "tcp", "service": "http"}],
                    "vulnerabilities": [],
                    "risk_result": {"findings": [], "risk_score": 0, "risk_level": "Low"},
                }
            raise TimeoutError("Nmap scan timed out on target 192.168.1.112")

        mock_pipeline.scan_single_host.side_effect = mock_scan_single

        worker_pool = ScanWorkerPool(max_workers=3, pipeline=mock_pipeline)
        cancel_event = MagicMock()
        cancel_event.is_set.return_value = False

        worker_pool._execute_scan_job(job_id, cancel_event)

        session = self.SessionLocal()
        try:
            completed_job = session.query(models.ScanJob).filter_by(id=job_id).first()
            self.assertEqual(completed_job.status, "Completed")
            # Both discovered hosts are counted in discovered_assets_count
            self.assertEqual(completed_job.discovered_assets_count, 2)

            # Both hosts persisted as active assets in database
            assets = session.query(models.Asset).order_by(models.Asset.ip_address).all()
            self.assertEqual(len(assets), 2)
            self.assertEqual(assets[0].ip_address, "192.168.1.1")
            # Merged MAC address from Stage 1 discovery
            self.assertEqual(assets[0].mac_address, "AC:84:C6:64:C2:3C")

            self.assertEqual(assets[1].ip_address, "192.168.1.112")
            self.assertEqual(assets[1].status, "Active")
            self.assertEqual(assets[1].mac_address, "A8:41:F4:0C:39:57")
        finally:
            session.close()


    @patch("monitoring.worker.SessionLocal")
    @patch.dict("os.environ", {"NMAP_AGENT_TOKEN": "test_token_secret", "NMAP_AGENT_URL": "http://192.168.1.149:9000"})
    @patch("monitoring.worker.NmapAgentClient")
    def test_worker_prefers_pi_agent_discovery_when_configured(self, mock_agent_cls, mock_session_cls):
        """Worker must prioritize Pi agent discovery and persist MAC addresses from L2 discovery."""
        import models
        from monitoring.worker import ScanWorkerPool

        mock_session_cls.side_effect = self.SessionLocal

        job = models.ScanJob(target="192.168.1.0/24", scan_type="subnet_discovery", status="Queued")
        self.db.add(job)
        self.db.commit()
        job_id = job.id

        mock_agent_instance = MagicMock()
        mock_agent_instance.discover_hosts.return_value = [
            {"ip_address": "192.168.1.1", "mac_address": "AC:84:C6:64:C2:3C", "hostname": "router.lan"},
            {"ip_address": "192.168.1.100", "mac_address": "2C:3B:70:0F:76:D2", "hostname": "laptop"},
            {"ip_address": "192.168.1.149", "mac_address": "D8:3A:DD:32:F8:08", "hostname": "raspberrypi"},
            {"ip_address": "192.168.1.255", "mac_address": None, "hostname": None},  # Broadcast boundary
        ]
        # Single-host scans on Pi
        mock_agent_instance.submit_subnet_job.side_effect = lambda ip: f"job_{ip}"
        mock_agent_instance.wait_for_job.return_value = [{"open_ports": [{"port": 80, "service": "http"}]}]
        mock_agent_cls.return_value = mock_agent_instance

        mock_pipeline = MagicMock()
        worker_pool = ScanWorkerPool(max_workers=3, pipeline=mock_pipeline)
        cancel_event = MagicMock()
        cancel_event.is_set.return_value = False

        worker_pool._execute_scan_job(job_id, cancel_event)

        session = self.SessionLocal()
        try:
            completed_job = session.query(models.ScanJob).filter_by(id=job_id).first()
            self.assertEqual(completed_job.status, "Completed")
            self.assertEqual(completed_job.discovered_assets_count, 3)

            assets = session.query(models.Asset).order_by(models.Asset.ip_address).all()
            self.assertEqual(len(assets), 3)
            ips = [a.ip_address for a in assets]
            self.assertIn("192.168.1.1", ips)
            self.assertIn("192.168.1.100", ips)
            self.assertIn("192.168.1.149", ips)
            self.assertNotIn("192.168.1.255", ips)

            # Local container pipeline should not be called because Pi agent succeeded
            mock_pipeline.discover_live_hosts.assert_not_called()
        finally:
            session.close()

    @patch("monitoring.worker.SessionLocal")
    @patch.dict("os.environ", {"NMAP_AGENT_TOKEN": "test_token_secret"})
    @patch("monitoring.worker.NmapAgentClient")
    def test_worker_falls_back_to_container_pipeline_when_agent_fails(self, mock_agent_cls, mock_session_cls):
        """When Pi agent is unreachable or fails, worker must gracefully fall back to local scanner."""
        import models
        from monitoring.worker import ScanWorkerPool
        from backend.monitoring.remote_agent import NmapAgentConnectionError

        mock_session_cls.side_effect = self.SessionLocal

        job = models.ScanJob(target="192.168.1.0/24", scan_type="subnet_discovery", status="Queued")
        self.db.add(job)
        self.db.commit()
        job_id = job.id

        mock_agent_instance = MagicMock()
        mock_agent_instance.discover_hosts.side_effect = NmapAgentConnectionError("Agent offline")
        mock_agent_cls.return_value = mock_agent_instance

        mock_pipeline = MagicMock()
        mock_pipeline.discover_live_hosts.return_value = ["192.168.1.1"]
        mock_pipeline.last_discovery_metadata = {"192.168.1.1": {"mac_address": "AC:84:C6:64:C2:3C"}}
        mock_pipeline.scan_single_host.return_value = {
            "ip_address": "192.168.1.1",
            "open_ports": [],
            "vulnerabilities": [],
            "risk_result": {"risk_score": 0, "risk_level": "Low"},
        }

        worker_pool = ScanWorkerPool(max_workers=3, pipeline=mock_pipeline)
        cancel_event = MagicMock()
        cancel_event.is_set.return_value = False

        worker_pool._execute_scan_job(job_id, cancel_event)

        session = self.SessionLocal()
        try:
            completed_job = session.query(models.ScanJob).filter_by(id=job_id).first()
            self.assertEqual(completed_job.status, "Completed")
            self.assertEqual(completed_job.discovered_assets_count, 1)

            # Local pipeline fallback was invoked
            mock_pipeline.discover_live_hosts.assert_called_once()
        finally:
            session.close()


class TestTargetPrecedenceAndValidation(unittest.TestCase):
    """Test suite for target resolution, validation, and environment precedence."""

    def test_rfc1918_subnets_accepted_up_to_slash_24(self):
        from backend.monitoring.scanner_pipeline import validate_target_network
        self.assertEqual(validate_target_network("192.168.1.0/24"), "192.168.1.0/24")
        self.assertEqual(validate_target_network("10.0.1.0/24"), "10.0.1.0/24")
        self.assertEqual(validate_target_network("172.16.5.0/24"), "172.16.5.0/24")

    def test_subnets_larger_than_slash_24_rejected(self):
        from backend.monitoring.scanner_pipeline import validate_target_network
        with self.assertRaises(ValueError) as ctx:
            validate_target_network("192.168.0.0/16")
        self.assertIn("exceeds maximum allowed scope", str(ctx.exception))

    def test_public_and_loopback_targets_rejected(self):
        from backend.monitoring.scanner_pipeline import validate_target_network
        with self.assertRaises(ValueError):
            validate_target_network("8.8.8.8")
        with self.assertRaises(ValueError):
            validate_target_network("127.0.0.1", allow_loopback=False)

    @patch.dict("os.environ", {"NMAP_NETWORK_CIDR": "192.168.1.0/24"})
    def test_configured_cidr_takes_precedence_in_detection(self):
        from backend.monitoring.scheduler import detect_private_lan
        detected = detect_private_lan()
        self.assertEqual(detected, "192.168.1.0/24")

    @patch.dict("os.environ", {"NMAP_NETWORK_CIDR": "192.168.1.0/24"})
    def test_auto_sentinel_resolves_to_lan_in_main(self):
        from backend.main import validate_and_check_scan_target
        target = validate_and_check_scan_target("auto")
        self.assertEqual(target, "192.168.1.0/24")


class TestRemoteAgentClient(unittest.TestCase):
    """Unit tests for NmapAgentClient."""

    def test_init_requires_token(self):
        from backend.monitoring.remote_agent import NmapAgentClient
        with patch.dict("os.environ", {"NMAP_AGENT_TOKEN": ""}):
            with self.assertRaises(ValueError):
                NmapAgentClient()

    @patch.dict("os.environ", {"NMAP_AGENT_TOKEN": "valid_token", "NMAP_AGENT_URL": "http://192.168.1.149:9000"})
    @patch("backend.monitoring.remote_agent.requests.Session.request")
    def test_discover_hosts_normalizes_and_authenticates(self, mock_request):
        from backend.monitoring.remote_agent import NmapAgentClient
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.json.return_value = {
            "hosts": [
                {"ip": "192.168.1.1", "mac": "AC:84:C6:64:C2:3C", "hostnames": ["router.lan"]},
                {"ip_address": "192.168.1.100", "mac_address": "2C:3B:70:0F:76:D2", "hostname": "laptop"},
            ]
        }
        mock_request.return_value = mock_resp

        client = NmapAgentClient()
        hosts = client.discover_hosts("192.168.1.0/24")

        self.assertEqual(len(hosts), 2)
        self.assertEqual(hosts[0]["ip_address"], "192.168.1.1")
        self.assertEqual(hosts[0]["mac_address"], "AC:84:C6:64:C2:3C")
        self.assertEqual(hosts[0]["hostname"], "router.lan")

        headers = mock_request.call_args[1]["headers"]
        self.assertEqual(headers["Authorization"], "Bearer valid_token")

    @patch("backend.main.requests.get")
    @patch.dict("os.environ", {"NMAP_AGENT_TOKEN": "valid_token", "NMAP_AGENT_URL": "http://192.168.1.149:9000", "NMAP_NETWORK_CIDR": "192.168.1.0/24"})
    def test_get_monitoring_network_agent_online(self, mock_get):
        from backend.main import get_monitoring_network
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.json.return_value = {
            "service": "AI-GRC Nmap Agent",
            "status": "ok",
            "nmap_available": True,
            "token_configured": True,
        }
        mock_get.return_value = mock_resp

        status = get_monitoring_network(current_user=MagicMock())
        self.assertEqual(status["configured_subnet"], "192.168.1.0/24")
        self.assertTrue(status["agent_healthy"])
        self.assertTrue(status["nmap_available"])
        self.assertEqual(status["discovery_executor"], "Raspberry Pi Agent (Physical L2/L3)")
        self.assertIsNone(status["fallback_reason"])

    @patch("backend.main.requests.get")
    @patch.dict("os.environ", {"NMAP_AGENT_TOKEN": "valid_token", "NMAP_AGENT_URL": "http://192.168.1.149:9000", "NMAP_NETWORK_CIDR": "192.168.1.0/24"})
    def test_get_monitoring_network_agent_unreachable_reports_fallback(self, mock_get):
        from backend.main import get_monitoring_network
        mock_get.side_effect = Exception("Connection refused")

        status = get_monitoring_network(current_user=MagicMock())
        self.assertFalse(status["agent_healthy"])
        self.assertEqual(status["discovery_executor"], "Local Container (Multi-Probe Fallback)")
        self.assertIn("Cannot reach agent", status["fallback_reason"])


if __name__ == "__main__":
    unittest.main()


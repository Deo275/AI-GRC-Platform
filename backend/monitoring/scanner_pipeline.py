"""Network Target Validation and Multi-Stage Nmap Scanner Pipeline for Phase 5.

Provides:
- validate_target_network: Strict RFC 1918 and subnet bounds validation using python's ipaddress module.
- MonitoringScannerPipeline: 2-stage execution wrapper (ping sweep -> top-100 port scan) with process tracking.
"""

import os
import re
import ipaddress
import subprocess
import xml.etree.ElementTree as ET
import logging
from typing import List, Dict, Any, Optional, Tuple

try:
    from scanner.vulnerability_scanner import identify_vulnerabilities
    from scanner.risk_engine import calculate_risk
except ImportError:
    import sys
    from pathlib import Path
    base_dir = Path(__file__).resolve().parent.parent.parent
    if str(base_dir) not in sys.path:
        sys.path.insert(0, str(base_dir))
    from scanner.vulnerability_scanner import identify_vulnerabilities
    from scanner.risk_engine import calculate_risk

logger = logging.getLogger("ai_grc.monitoring.pipeline")

# RFC 1918 Private Address Ranges and Loopback
ALLOWED_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]


def validate_target_network(target_str: str) -> str:
    """Validate target string against RFC 1918 private ranges and max /24 subnet size.

    Allowed:
    - 10.0.0.0/8 subnets (with prefixlen >= 24)
    - 172.16.0.0/12 subnets (with prefixlen >= 24)
    - 192.168.0.0/16 subnets (with prefixlen >= 24)
    - 127.0.0.1/32 or 127.0.0.0/8 subnets (with prefixlen >= 24)
    - Single IPv4 addresses within those ranges

    Rejects:
    - Public IP addresses (e.g. 8.8.8.8)
    - Wide CIDRs with prefixlen < 24 (e.g. /16, /8)
    - IPv6 addresses
    - Malformed IP or CIDR strings

    Returns normalized string (e.g. '192.168.1.1' or '192.168.1.0/24').
    """
    if not target_str or not isinstance(target_str, str):
        raise ValueError("Target must be a non-empty string.")

    target_clean = target_str.strip()

    # Try parsing as single IP address first
    try:
        ip = ipaddress.ip_address(target_clean)
        if ip.version != 4:
            raise ValueError("Only IPv4 targets are supported.")
        # Check against allowed private networks
        if not any(ip in net for net in ALLOWED_PRIVATE_NETWORKS):
            raise ValueError(f"Target IP '{target_clean}' is not an allowed RFC 1918 private address or loopback.")
        return str(ip)
    except ValueError as ip_err:
        if "does not appear to be an IPv4 or IPv6 address" not in str(ip_err):
            if "Only IPv4" in str(ip_err) or "not an allowed" in str(ip_err):
                raise ip_err

    # Try parsing as network CIDR
    try:
        net = ipaddress.ip_network(target_clean, strict=False)
        if net.version != 4:
            raise ValueError("Only IPv4 targets are supported.")
        if net.prefixlen < 24:
            raise ValueError(
                f"Subnet size '/{net.prefixlen}' exceeds maximum allowed scope. Maximum allowed subnet size is /24 (256 hosts)."
            )
        if not any(net.subnet_of(parent) for parent in ALLOWED_PRIVATE_NETWORKS):
            raise ValueError(f"Target network '{target_clean}' is not within RFC 1918 private address ranges or loopback.")
        return str(net)
    except ValueError as net_err:
        if "Subnet size" in str(net_err) or "Only IPv4" in str(net_err) or "not within RFC 1918" in str(net_err):
            raise net_err
        raise ValueError(f"Invalid target '{target_clean}'. Must be a valid RFC 1918 IPv4 address or /24-/32 CIDR.")


class MonitoringScannerPipeline:
    """Multi-stage network scanner pipeline for continuous monitoring."""

    def __init__(
        self,
        enable_os_detection: Optional[bool] = None,
        ping_timeout_seconds: int = 60,
        host_scan_timeout_seconds: int = 120,
    ):
        if enable_os_detection is None:
            self.enable_os_detection = os.getenv("ENABLE_OS_DETECTION", "false").strip().lower() in ("true", "1", "yes")
        else:
            self.enable_os_detection = bool(enable_os_detection)

        self.ping_timeout = ping_timeout_seconds
        self.host_scan_timeout = host_scan_timeout_seconds

    def discover_live_hosts(
        self,
        target: str,
        process_callback=None,
        cancellation_check=None,
    ) -> List[str]:
        """Stage 1: Fast ping sweep (nmap -sn) to identify live hosts."""
        normalized_target = validate_target_network(target)

        # If target is a single IP, return it directly for port scanning
        if "/" not in normalized_target or normalized_target.endswith("/32"):
            single_ip = normalized_target.split("/")[0]
            return [single_ip]

        command = ["nmap", "-sn", normalized_target]
        logger.info(f"Stage 1 Host Discovery command: {' '.join(command)}")

        proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
        )

        if process_callback:
            process_callback(proc)

        try:
            stdout, stderr = proc.communicate(timeout=self.ping_timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            raise TimeoutError(f"Stage 1 ping sweep timed out after {self.ping_timeout}s for {normalized_target}")

        if cancellation_check and cancellation_check():
            return []

        if proc.returncode != 0 and not stdout:
            err = stderr.strip() or f"Exit code {proc.returncode}"
            raise RuntimeError(f"Nmap ping sweep failed: {err}")

        hosts: List[str] = []
        for line in stdout.splitlines():
            match = re.search(
                r"Nmap scan report for (?:[^\s(]+ \()?([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\)?",
                line,
            )
            if match:
                ip = match.group(1)
                if ip not in hosts:
                    hosts.append(ip)

        logger.info(f"Stage 1 discovered {len(hosts)} live host(s) on {normalized_target}")
        return hosts

    def scan_single_host(
        self,
        host_ip: str,
        process_callback=None,
        cancellation_check=None,
    ) -> Dict[str, Any]:
        """Stage 2: Targeted port scan (--top-ports 100 -sV [-O]) on an active host."""
        ip = validate_target_network(host_ip)

        command = ["nmap", "--top-ports", "100", "-sV", "-oX", "-"]
        if self.enable_os_detection:
            command.append("-O")
        command.append(ip)

        logger.info(f"Stage 2 Host Scan command: {' '.join(command)}")

        proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
        )

        if process_callback:
            process_callback(proc)

        try:
            stdout, stderr = proc.communicate(timeout=self.host_scan_timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            raise TimeoutError(f"Stage 2 host scan timed out after {self.host_scan_timeout}s for {ip}")

        if cancellation_check and cancellation_check():
            return {}

        if proc.returncode != 0 and not stdout:
            err = stderr.strip() or f"Exit code {proc.returncode}"
            raise RuntimeError(f"Nmap host scan failed for {ip}: {err}")

        parsed_data = self._parse_nmap_xml(stdout, ip)

        # Correlate vulnerabilities and GRC risks using existing engines
        vulnerabilities = identify_vulnerabilities(parsed_data["open_ports"])
        risk_result = calculate_risk(parsed_data["open_ports"])

        return {
            "ip_address": ip,
            "hostname": parsed_data.get("hostname"),
            "mac_address": parsed_data.get("mac_address"),
            "operating_system": parsed_data.get("operating_system"),
            "open_ports": parsed_data.get("open_ports", []),
            "vulnerabilities": vulnerabilities,
            "risk_result": risk_result,
        }

    def _parse_nmap_xml(self, xml_output: str, fallback_ip: str) -> Dict[str, Any]:
        """Parse Nmap XML output for host details and open ports."""
        if not xml_output or not xml_output.strip():
            return {
                "ip_address": fallback_ip,
                "hostname": None,
                "mac_address": None,
                "operating_system": None,
                "open_ports": [],
            }

        try:
            root = ET.fromstring(xml_output)
        except ET.ParseError as err:
            logger.warning(f"XML parse error for {fallback_ip}: {err}")
            return {
                "ip_address": fallback_ip,
                "hostname": None,
                "mac_address": None,
                "operating_system": None,
                "open_ports": [],
            }

        hostname = None
        mac_address = None
        operating_system = None

        hostname_el = root.find(".//host/hostnames/hostname")
        if hostname_el is not None:
            hostname = hostname_el.get("name")

        for addr_el in root.findall(".//host/address"):
            if addr_el.get("addrtype") == "mac":
                mac_address = addr_el.get("addr")
                break

        os_el = root.find(".//host/os/osmatch")
        if os_el is not None:
            operating_system = os_el.get("name")

        open_ports: List[Dict[str, Any]] = []
        for port_el in root.findall(".//host/ports/port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue

            port_id = port_el.get("portid")
            protocol = port_el.get("protocol", "tcp")

            svc_el = port_el.find("service")
            service = svc_el.get("name") if svc_el is not None else "unknown"
            product = svc_el.get("product") if svc_el is not None else None
            version = svc_el.get("version") if svc_el is not None else None
            details = svc_el.get("extrainfo") if svc_el is not None else None

            cpe = None
            if svc_el is not None:
                cpe_el = svc_el.find("cpe")
                if cpe_el is not None and cpe_el.text:
                    cpe = cpe_el.text

            open_ports.append({
                "port": port_id,
                "protocol": protocol,
                "service": service,
                "product": product,
                "version": version,
                "details": details,
                "cpe": cpe,
            })

        return {
            "ip_address": fallback_ip,
            "hostname": hostname,
            "mac_address": mac_address,
            "operating_system": operating_system,
            "open_ports": open_ports,
        }

"""Network Target Validation and Multi-Stage Nmap Scanner Pipeline for Phase 5.

Provides:
- validate_target_network: Strict RFC 1918 and subnet bounds validation using python's ipaddress module.
- MonitoringScannerPipeline: 2-stage execution wrapper (ping sweep -> top-100 port scan) with process tracking.
"""

import os
import time
import re
import ipaddress
import subprocess
import xml.etree.ElementTree as ET
import logging
from typing import List, Dict, Any, Optional, Tuple

try:
    from scanner.vulnerability_scanner import identify_vulnerabilities
    from scanner.risk_engine import calculate_risk
    from scanner.os_identifier import identify_os_and_device
except ImportError:
    import sys
    from pathlib import Path
    base_dir = Path(__file__).resolve().parent.parent.parent
    if str(base_dir) not in sys.path:
        sys.path.insert(0, str(base_dir))
    from scanner.vulnerability_scanner import identify_vulnerabilities
    from scanner.risk_engine import calculate_risk
    from scanner.os_identifier import identify_os_and_device

logger = logging.getLogger("ai_grc.monitoring.pipeline")

# RFC 1918 Private Address Ranges and Loopback
ALLOWED_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]


def validate_target_network(target_str: str, allow_loopback: bool = True) -> str:
    """Validate target string against RFC 1918 private ranges and max /24 subnet size.

    Allowed:
    - 10.0.0.0/8 subnets (with prefixlen >= 24)
    - 172.16.0.0/12 subnets (with prefixlen >= 24)
    - 192.168.0.0/16 subnets (with prefixlen >= 24)
    - 127.0.0.1/32 or 127.0.0.0/8 subnets (with prefixlen >= 24) if allow_loopback=True
    - Single IPv4 addresses within those ranges

    Rejects:
    - Public IP addresses (e.g. 8.8.8.8)
    - Wide CIDRs with prefixlen < 24 (e.g. /16, /8)
    - IPv6 addresses
    - Loopback or link-local if allow_loopback=False
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
        if not allow_loopback and (ip.is_loopback or ip in ipaddress.ip_network("127.0.0.0/8")):
            raise ValueError(f"Loopback target '{target_clean}' is not permitted.")
        if ip.is_link_local or ip in ipaddress.ip_network("169.254.0.0/16"):
            raise ValueError(f"Link-local target '{target_clean}' is not permitted.")
        # Check against allowed private networks
        if not any(ip in net for net in ALLOWED_PRIVATE_NETWORKS):
            raise ValueError(f"Target IP '{target_clean}' is not an allowed RFC 1918 private address or loopback.")
        return str(ip)
    except ValueError as ip_err:
        if "does not appear to be an IPv4 or IPv6 address" not in str(ip_err):
            if "Only IPv4" in str(ip_err) or "not an allowed" in str(ip_err) or "not permitted" in str(ip_err):
                raise ip_err

    # Try parsing as network CIDR
    try:
        net = ipaddress.ip_network(target_clean, strict=False)
        if net.version != 4:
            raise ValueError("Only IPv4 targets are supported.")
        if not allow_loopback and (net.is_loopback or net.subnet_of(ipaddress.ip_network("127.0.0.0/8"))):
            raise ValueError(f"Loopback target '{target_clean}' is not permitted.")
        if net.is_link_local or net.subnet_of(ipaddress.ip_network("169.254.0.0/16")):
            raise ValueError(f"Link-local target '{target_clean}' is not permitted.")
        if net.prefixlen < 24:
            raise ValueError(
                f"Subnet size '/{net.prefixlen}' exceeds maximum allowed scope. Maximum allowed subnet size is /24 (256 hosts)."
            )
        if not any(net.subnet_of(parent) for parent in ALLOWED_PRIVATE_NETWORKS):
            raise ValueError(f"Target network '{target_clean}' is not within RFC 1918 private address ranges or loopback.")
        return str(net)
    except ValueError as net_err:
        if "Subnet size" in str(net_err) or "Only IPv4" in str(net_err) or "not within RFC 1918" in str(net_err) or "not permitted" in str(net_err):
            raise net_err
        raise ValueError(f"Invalid target '{target_clean}'. Must be a valid RFC 1918 IPv4 address or /24-/32 CIDR.")


class MonitoringScannerPipeline:
    """Multi-stage network scanner pipeline for continuous monitoring."""

    def __init__(
        self,
        enable_os_detection: Optional[bool] = None,
        ping_timeout_seconds: Optional[int] = None,
        host_scan_timeout_seconds: Optional[int] = None,
    ):
        if enable_os_detection is None:
            self.enable_os_detection = os.getenv("ENABLE_OS_DETECTION", "false").strip().lower() in ("true", "1", "yes")
        else:
            self.enable_os_detection = bool(enable_os_detection)

        if ping_timeout_seconds is None:
            self.ping_timeout = int(os.getenv("PING_TIMEOUT_SECONDS", "180"))
        else:
            self.ping_timeout = int(ping_timeout_seconds)

        if host_scan_timeout_seconds is None:
            self.host_scan_timeout = int(os.getenv("HOST_SCAN_TIMEOUT_SECONDS", "180"))
        else:
            self.host_scan_timeout = int(host_scan_timeout_seconds)

        self.max_retries = int(os.getenv("DISCOVERY_MAX_RETRIES", "2"))
        self.last_discovery_metadata: Dict[str, Dict[str, Any]] = {}

    def discover_live_hosts(
        self,
        target: str,
        process_callback=None,
        cancellation_check=None,
    ) -> List[str]:
        """Stage 1: Multi-probe ping sweep to identify live hosts.

        Combines:
        - ARP ping (automatically used on local L2 subnet)
        - ICMP Echo (-PE) & Timestamp (-PP)
        - TCP SYN ping (-PS) to common services and IoT ports
        - TCP ACK ping (-PA) to elicit RST responses from stateful firewalls
        """
        start_time = time.time()
        normalized_target = validate_target_network(target)

        # Clear previous discovery metadata
        self.last_discovery_metadata = {}

        # If target is a single IP, return it directly for port scanning
        if "/" not in normalized_target or normalized_target.endswith("/32"):
            single_ip = normalized_target.split("/")[0]
            self.last_discovery_metadata[single_ip] = {
                "ip_address": single_ip,
                "hostname": None,
                "mac_address": None,
                "vendor": None,
                "reason": "single_host_target",
            }
            return [single_ip]

        syn_ports = os.getenv(
            "DISCOVERY_TCP_SYN_PORTS",
            "21,22,23,25,53,80,81,88,110,111,135,137,139,143,443,445,548,554,631,993,995,1025,1433,1723,1900,3000,3306,3389,5000,5001,5228,5357,5432,5900,7000,8000,8008,8080,8081,8443,8888,9000,9100",
        )
        ack_ports = os.getenv("DISCOVERY_TCP_ACK_PORTS", "80,443,135,445,3389,8080")

        # Multi-probe command with fallback to unprivileged TCP connect scan if raw sockets not permitted
        command = [
            "nmap",
            "-sn",
            "-PE",
            "-PP",
            f"-PS{syn_ports}",
            f"-PA{ack_ports}",
            "--max-retries",
            str(self.max_retries),
            "-oX",
            "-",
            normalized_target,
        ]
        logger.info(
            f"[HOST DISCOVERY START] Target: {normalized_target} | Method: Multi-Probe (ICMP+SYN+ACK) | Command: {' '.join(command)}"
        )

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
            try:
                proc.communicate()
            except Exception:
                pass
            logger.error(f"[HOST DISCOVERY TIMEOUT] Stage 1 sweep timed out after {self.ping_timeout}s for {normalized_target}")
            raise TimeoutError(f"Stage 1 ping sweep timed out after {self.ping_timeout}s for {normalized_target}")

        if cancellation_check and cancellation_check():
            logger.info(f"[HOST DISCOVERY CANCELLED] Target: {normalized_target}")
            return []

        # If multi-probe command failed (e.g. unprivileged user without raw socket access for -PE/-PA)
        if proc.returncode != 0 and not (stdout and stdout.strip()):
            err_msg = (stderr.strip() if stderr else "") or f"Exit code {proc.returncode}"
            logger.warning(
                f"[HOST DISCOVERY FALLBACK] Privileged discovery failed ({err_msg}). Retrying with unprivileged TCP connect probes."
            )
            fallback_command = [
                "nmap",
                "-sn",
                f"-PS{syn_ports}",
                "--max-retries",
                str(self.max_retries),
                "-oX",
                "-",
                normalized_target,
            ]
            fallback_proc = subprocess.Popen(
                fallback_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=False,
            )
            if process_callback:
                process_callback(fallback_proc)
            try:
                fallback_stdout, fallback_stderr = fallback_proc.communicate(timeout=self.ping_timeout)
            except subprocess.TimeoutExpired:
                fallback_proc.kill()
                try:
                    fallback_proc.communicate()
                except Exception:
                    pass
                raise TimeoutError(f"Stage 1 fallback ping sweep timed out after {self.ping_timeout}s for {normalized_target}")
            if fallback_proc.returncode != 0 and not (fallback_stdout and fallback_stdout.strip()):
                fallback_err = (fallback_stderr.strip() if fallback_stderr else "") or f"Exit code {fallback_proc.returncode}"
                logger.error(f"[HOST DISCOVERY ERROR] Nmap ping sweep failed: {fallback_err}")
                raise RuntimeError(f"Nmap ping sweep failed: {fallback_err}")
            stdout = fallback_stdout

        # Parse discovery results (supports both XML and plaintext fallback)
        hosts, metadata_map = self._parse_discovery_output(stdout, normalized_target)
        self.last_discovery_metadata = metadata_map

        duration = time.time() - start_time
        try:
            target_net = ipaddress.ip_network(normalized_target, strict=False)
            total_eval = max(0, target_net.num_addresses - 2) if target_net.num_addresses > 2 else target_net.num_addresses
        except Exception:
            total_eval = len(hosts)

        unresponsive = max(0, total_eval - len(hosts))
        logger.info(
            f"[HOST DISCOVERY COMPLETE] Target: {normalized_target} | Duration: {duration:.2f}s | "
            f"Evaluated Subnet Scope: {total_eval} | Active Hosts Discovered: {len(hosts)} | Unresponsive/Silent: {unresponsive}"
        )
        for h_ip in hosts:
            meta = metadata_map.get(h_ip, {})
            mac_str = f" | MAC: {meta['mac_address']} ({meta.get('vendor') or 'Unknown'})" if meta.get("mac_address") else ""
            reason_str = f" | Detected via: {meta.get('reason')}" if meta.get("reason") else ""
            hn_str = f" | Hostname: {meta.get('hostname')}" if meta.get("hostname") else ""
            logger.info(f"  -> Discovered Host: {h_ip}{hn_str}{mac_str}{reason_str}")

        return hosts

    def _parse_discovery_output(
        self,
        output: str,
        normalized_target: str,
    ) -> Tuple[List[str], Dict[str, Dict[str, Any]]]:
        """Parse Nmap discovery output supporting XML (-oX) and plaintext fallback.

        Filters out subnet network (.0) and broadcast (.255) addresses.
        Extracts status reason, MAC address, and hostname when available.
        """
        hosts: List[str] = []
        metadata_map: Dict[str, Dict[str, Any]] = {}

        try:
            target_net = ipaddress.ip_network(normalized_target, strict=False) if "/" in normalized_target else None
        except Exception:
            target_net = None

        if not output or not output.strip():
            return hosts, metadata_map

        # Check if output is XML
        is_xml = output.strip().startswith("<") or "<nmaprun" in output or "<host" in output

        if is_xml:
            try:
                root = ET.fromstring(output)
                for host_el in root.findall(".//host"):
                    status_el = host_el.find("status")
                    if status_el is not None and status_el.get("state") != "up":
                        continue

                    ip_addr = None
                    mac_addr = None
                    vendor = None
                    for addr_el in host_el.findall("address"):
                        addr_type = addr_el.get("addrtype")
                        if addr_type == "ipv4":
                            ip_addr = addr_el.get("addr")
                        elif addr_type == "mac":
                            mac_addr = addr_el.get("addr")
                            vendor = addr_el.get("vendor")

                    if not ip_addr:
                        continue

                    if target_net:
                        try:
                            ip_obj = ipaddress.ip_address(ip_addr)
                            if ip_obj == target_net.network_address or ip_obj == target_net.broadcast_address:
                                continue
                        except ValueError:
                            pass

                    hostname = None
                    hn_el = host_el.find(".//hostnames/hostname")
                    if hn_el is not None:
                        hostname = hn_el.get("name")

                    reason = status_el.get("reason") if status_el is not None else None

                    if ip_addr not in hosts:
                        hosts.append(ip_addr)
                    metadata_map[ip_addr] = {
                        "ip_address": ip_addr,
                        "hostname": hostname,
                        "mac_address": mac_addr,
                        "vendor": vendor,
                        "reason": reason,
                    }
                return hosts, metadata_map
            except ET.ParseError:
                pass  # Fall through to plaintext parsing if XML was malformed or truncated

        # Plaintext parsing fallback
        for line in output.splitlines():
            match = re.search(
                r"Nmap scan report for (?:[^\s(]+ \()?([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\)?",
                line,
            )
            if match:
                ip = match.group(1)
                if target_net:
                    try:
                        ip_obj = ipaddress.ip_address(ip)
                        if ip_obj == target_net.network_address or ip_obj == target_net.broadcast_address:
                            continue
                    except ValueError:
                        pass
                if ip not in hosts:
                    hosts.append(ip)
                if ip not in metadata_map:
                    metadata_map[ip] = {
                        "ip_address": ip,
                        "hostname": None,
                        "mac_address": None,
                        "vendor": None,
                        "reason": "plaintext_match",
                    }

        return hosts, metadata_map

    def scan_single_host(
        self,
        host_ip: str,
        process_callback=None,
        cancellation_check=None,
    ) -> Dict[str, Any]:
        """Stage 2: Targeted port scan (-Pn -sT --top-ports 100 -sV [-O]) on an active host."""
        ip = validate_target_network(host_ip)

        # -Pn ensures unprivileged Nmap does not drop the host if pre-scan ping to 80/443 fails
        command = ["nmap", "-Pn", "-sT", "--top-ports", "100", "-sV", "-oX", "-"]
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

        if proc.returncode != 0:
            err = stderr.strip() or stdout.strip() or f"Exit code {proc.returncode}"
            if "-O" in command and "root privileges" in err.lower():
                logger.warning(
                    f"Stage 2 host scan on {ip} failed due to root privilege requirement for -O. "
                    "Retrying scan without OS detection."
                )
                fallback_cmd = [arg for arg in command if arg != "-O"]
                fallback_proc = subprocess.Popen(
                    fallback_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    shell=False,
                )
                if process_callback:
                    process_callback(fallback_proc)
                try:
                    stdout, stderr = fallback_proc.communicate(timeout=self.host_scan_timeout)
                except subprocess.TimeoutExpired:
                    fallback_proc.kill()
                    fallback_proc.communicate()
                    raise TimeoutError(f"Stage 2 host scan timed out after {self.host_scan_timeout}s for {ip}")
                if fallback_proc.returncode != 0:
                    err = stderr.strip() or stdout.strip() or f"Exit code {fallback_proc.returncode}"
                    raise RuntimeError(f"Nmap host scan failed for {ip}: {err}")
            else:
                raise RuntimeError(f"Nmap host scan failed for {ip}: {err}")

        parsed_data = self._parse_nmap_xml(stdout, ip)

        # OS and device identification
        os_info = identify_os_and_device({
            "ip_address": ip,
            "hostname": parsed_data.get("hostname"),
            "mac_address": parsed_data.get("mac_address"),
            "operating_system": parsed_data.get("operating_system"),
            "open_ports": parsed_data.get("open_ports", []),
        })

        # Correlate vulnerabilities and GRC risks using existing engines
        vulnerabilities = identify_vulnerabilities(parsed_data["open_ports"])
        risk_result = calculate_risk(
            open_ports=parsed_data["open_ports"],
            vulnerabilities=vulnerabilities,
        )

        return {
            "ip_address": ip,
            "hostname": parsed_data.get("hostname"),
            "mac_address": parsed_data.get("mac_address"),
            "operating_system": os_info.get("operating_system") or parsed_data.get("operating_system"),
            "os_confidence": os_info.get("os_confidence"),
            "os_fingerprint_reason": os_info.get("os_fingerprint_reason"),
            "os_detection_source": os_info.get("detection_source"),
            "device_type": os_info.get("device_type"),
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

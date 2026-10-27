import os
import time
import logging
import subprocess
import re
import ipaddress
import xml.etree.ElementTree as ET

logger = logging.getLogger("ai_grc.scanner.nmap")

def scan_host(target: str, enable_os_detection: bool = None):

    if enable_os_detection is None:
        enable_os_detection = os.getenv("ENABLE_OS_DETECTION", "false").strip().lower() in ("true", "1", "yes")

    command = [
        "nmap",
        "-Pn",
        "-sT",
        "-sV",
    ]

    if enable_os_detection:
        command.append("-O")

    command.extend([
        "-oX",
        "-",
        target
    ])

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(
            f"Nmap host scan timed out after 120 seconds on target {target}"
        )
    except FileNotFoundError:
        raise RuntimeError(
            "Nmap executable not found on system PATH."
        )

    if result.returncode != 0:
        error_detail = result.stderr.strip()

        if not error_detail:
            error_detail = "Unknown error"

        # Check if failure is due to OS detection requiring root privileges
        if enable_os_detection and "-O" in command and "root privileges" in error_detail.lower():
            logger.warning(
                "Nmap OS detection (-O) requires root privileges; scan failed on target %s. "
                "Retrying scan without OS detection.",
                target,
            )
            fallback_command = [arg for arg in command if arg != "-O"]
            try:
                result = subprocess.run(
                    fallback_command,
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
            except subprocess.TimeoutExpired:
                raise RuntimeError(
                    f"Nmap host scan timed out after 120 seconds on target {target}"
                )
            except FileNotFoundError:
                raise RuntimeError(
                    "Nmap executable not found on system PATH."
                )
            if result.returncode != 0:
                fallback_error = result.stderr.strip() or "Unknown error"
                raise RuntimeError(
                    f"Nmap scan failed (exit code {result.returncode}): {fallback_error}"
                )
        else:
            raise RuntimeError(
                f"Nmap scan failed (exit code "
                f"{result.returncode}): {error_detail}"
            )

    output = result.stdout

    if not output.strip():
        raise RuntimeError(
            "Nmap did not return any scan output."
        )

    try:
        root = ET.fromstring(output)
    except ET.ParseError as pe:
        raise RuntimeError(
            f"Failed to parse Nmap XML output: {pe}"
        )

    hostname = None
    mac_address = None
    operating_system = None

    # -----------------------------
    # Hostname
    # -----------------------------

    hostname_element = root.find(
        ".//host/hostnames/hostname"
    )

    if hostname_element is not None:
        hostname = hostname_element.get("name")

    # -----------------------------
    # MAC Address
    # -----------------------------

    for address in root.findall(".//host/address"):

        if address.get("addrtype") == "mac":
            mac_address = address.get("addr")
            break

    # -----------------------------
    # Operating System
    # -----------------------------

    os_match = root.find(
        ".//host/os/osmatch"
    )

    os_accuracy = None
    if os_match is not None:
        operating_system = os_match.get(
            "name"
        )
        os_accuracy = os_match.get("accuracy")

    # -----------------------------
    # Open Ports
    # -----------------------------

    ports = []

    for port_element in root.findall(
        ".//host/ports/port"
    ):

        state = port_element.find("state")

        if state is None:
            continue

        if state.get("state") != "open":
            continue

        port = port_element.get("portid")

        service_element = port_element.find(
            "service"
        )

        if service_element is None:
            continue

        service = service_element.get(
            "name"
        )

        product = service_element.get(
            "product"
        )

        version = service_element.get(
            "version"
        )

        extra_info = service_element.get(
            "extrainfo"
        )

        cpe_element = service_element.find(
            "cpe"
        )

        cpe = None

        if cpe_element is not None:
            cpe = cpe_element.text

        ports.append({
            "port": port,
            "service": service,
            "product": product,
            "version": version,
            "details": extra_info,
            "cpe": cpe
        })

    return {
        "ip_address": target,
        "hostname": hostname,
        "mac_address": mac_address,
        "operating_system": operating_system,
        "os_accuracy": os_accuracy,
        "open_ports": ports
    }

def discover_hosts(network):
    """Multi-probe host discovery across authorized network subnet."""
    start_time = time.time()
    syn_ports = os.getenv(
        "DISCOVERY_TCP_SYN_PORTS",
        "21,22,23,25,53,80,81,88,110,111,135,137,139,143,443,445,548,554,631,993,995,1025,1433,1723,1900,3000,3306,3389,5000,5001,5228,5357,5432,5900,7000,8000,8008,8080,8081,8443,8888,9000,9100",
    )
    ack_ports = os.getenv("DISCOVERY_TCP_ACK_PORTS", "80,443,135,445,3389,8080")
    max_retries = os.getenv("DISCOVERY_MAX_RETRIES", "2")

    command = [
        "nmap",
        "-sn",
        "-PE",
        "-PP",
        f"-PS{syn_ports}",
        f"-PA{ack_ports}",
        "--max-retries",
        str(max_retries),
        "-oX",
        "-",
        network
    ]
    logger.info(f"[NMAP SCANNER DISCOVERY] Command: {' '.join(command)}")

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=180,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(
            f"Nmap host discovery timed out after 180 seconds on network {network}"
        )
    except FileNotFoundError:
        raise RuntimeError(
            "Nmap executable not found on system PATH."
        )

    output = result.stdout

    # Fallback to unprivileged TCP connect ping if raw socket access failed
    if result.returncode != 0 and not output.strip():
        logger.warning(
            f"Privileged discovery failed ({result.stderr.strip()}). Retrying with unprivileged TCP connect probes."
        )
        fallback_cmd = [
            "nmap",
            "-sn",
            f"-PS{syn_ports}",
            "--max-retries",
            str(max_retries),
            "-oX",
            "-",
            network,
        ]
        try:
            result = subprocess.run(
                fallback_cmd,
                capture_output=True,
                text=True,
                timeout=180,
            )
            output = result.stdout
        except subprocess.TimeoutExpired:
            raise RuntimeError(
                f"Nmap fallback host discovery timed out after 180 seconds on network {network}"
            )

        if result.returncode != 0 and not output.strip():
            error_detail = result.stderr.strip() or "Unknown error"
            raise RuntimeError(
                f"Nmap host discovery failed (exit code {result.returncode}): {error_detail}"
            )

    hosts = []
    try:
        target_net = ipaddress.ip_network(network, strict=False) if "/" in str(network) else None
    except Exception:
        target_net = None

    # Try parsing XML output first
    if output.strip().startswith("<") or "<nmaprun" in output or "<host" in output:
        try:
            root = ET.fromstring(output)
            for host_el in root.findall(".//host"):
                status_el = host_el.find("status")
                if status_el is not None and status_el.get("state") != "up":
                    continue

                for addr_el in host_el.findall("address"):
                    if addr_el.get("addrtype") == "ipv4":
                        ip_addr = addr_el.get("addr")
                        if target_net:
                            try:
                                ip_obj = ipaddress.ip_address(ip_addr)
                                if (
                                    ip_obj == target_net.network_address
                                    or ip_obj == target_net.broadcast_address
                                    or ip_addr.endswith(".255")
                                    or ip_addr.endswith(".0")
                                    or ip_obj not in target_net
                                ):
                                    continue
                            except ValueError:
                                pass
                        if ip_addr not in hosts:
                            hosts.append(ip_addr)
            duration = time.time() - start_time
            logger.info(f"[NMAP SCANNER DISCOVERY COMPLETE] Network: {network} | Found {len(hosts)} hosts in {duration:.2f}s")
            return hosts
        except ET.ParseError:
            pass

    # Fallback to plaintext regex parsing
    for line in output.splitlines():
        match = re.search(
            r"Nmap scan report for (?:[^\s(]+ \()?([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\)?",
            line
        )

        if match:
            ip_address = match.group(1)
            if target_net:
                try:
                    ip_obj = ipaddress.ip_address(ip_address)
                    if (
                        ip_obj == target_net.network_address
                        or ip_obj == target_net.broadcast_address
                        or ip_address.endswith(".255")
                        or ip_address.endswith(".0")
                        or ip_obj not in target_net
                    ):
                        continue
                except ValueError:
                    pass

            if ip_address not in hosts:
                hosts.append(ip_address)

    duration = time.time() - start_time
    logger.info(f"[NMAP SCANNER DISCOVERY COMPLETE] Network: {network} | Found {len(hosts)} hosts in {duration:.2f}s")
    return hosts
# -----------------------------
# Test scanner directly
# -----------------------------

if __name__ == "__main__":

    network = "192.168.127.0/24"

    hosts = discover_hosts(network)

    print("\nDiscovered Hosts:")

    for host in hosts:
        print("-", host)
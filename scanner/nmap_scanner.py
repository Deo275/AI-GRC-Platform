import os
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

    if os_match is not None:
        operating_system = os_match.get(
            "name"
        )

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
        "open_ports": ports
    }

def discover_hosts(network):

    command = [
        "nmap",
        "-sn",
        "-PS22,80,135,443,445,3389,8000,8080",
        "--max-retries",
        "1",
        network
    ]

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

    if result.returncode != 0:
        error_detail = result.stderr.strip() or "Unknown error"
        raise RuntimeError(
            f"Nmap host discovery failed (exit code {result.returncode}): {error_detail}"
        )

    output = result.stdout

    hosts = []
    try:
        target_net = ipaddress.ip_network(network, strict=False) if "/" in str(network) else None
    except Exception:
        target_net = None

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
                    if ip_obj == target_net.network_address or ip_obj == target_net.broadcast_address:
                        continue
                except ValueError:
                    pass

            if ip_address not in hosts:
                hosts.append(ip_address)

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
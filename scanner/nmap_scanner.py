import subprocess
import re
import xml.etree.ElementTree as ET

def scan_host(target):

    command = [
        "nmap",
        "-sV",
        "-O",
        "-oX",
        "-",
        target
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    output = result.stdout

    if not output.strip():
        raise RuntimeError(
            "Nmap did not return any scan output."
        )

    root = ET.fromstring(output)

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
        network
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    output = result.stdout

    hosts = []

    for line in output.splitlines():

        match = re.search(
            r"Nmap scan report for (?:[^\s(]+ \()?([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\)?",
            line
        )

        if match:
            ip_address = match.group(1)

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
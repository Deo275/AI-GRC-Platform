"""Authorized Router DHCP Static Client Registry.

Provides an authorized static registry mapping of known LAN DHCP client reservations
for the local subnet. This is a static configuration registry, NOT a live dynamic
router synchronization API, preserving network integrity without scraping credentials
or guessing router passwords.
"""

from typing import Dict, Any, Optional

# Static authorized router DHCP client registry for the configured LAN
AUTHORIZED_ROUTER_DHCP_CLIENTS = {
    "192.168.1.1": {
        "hostname": "TP-Link Gateway",
        "device_type": "Router / Gateway",
        "notes": "Default Gateway & DHCP Server",
    },
    "192.168.1.100": {
        "hostname": "Sujal",
        "device_type": "Workstation / Laptop",
        "notes": "Authorized client lease",
    },
    "192.168.1.101": {
        "hostname": "FLEMSIS",
        "device_type": "Workstation / Laptop",
        "notes": "Authorized client lease (Host Workstation)",
    },
    "192.168.1.102": {
        "hostname": "Joshua",
        "device_type": "Workstation / Laptop",
        "notes": "Authorized client lease",
    },
    "192.168.1.105": {
        "hostname": "iPhone",
        "device_type": "Mobile / Smartphone",
        "notes": "Authorized client lease (Apple iOS)",
    },
    "192.168.1.112": {
        "hostname": "Riddhi",
        "device_type": "Mobile / Smartphone",
        "notes": "Authorized client lease",
    },
    "192.168.1.123": {
        "hostname": "Nothing-Phone-2a",
        "device_type": "Mobile / Smartphone",
        "notes": "Authorized client lease (Android OS)",
    },
    "192.168.1.124": {
        "hostname": "Jack-s-A35",
        "device_type": "Mobile / Smartphone",
        "notes": "Authorized client lease (Samsung Galaxy A35 Android)",
    },
    "192.168.1.125": {
        "hostname": "Vallabh",
        "device_type": "Workstation / Laptop",
        "notes": "Authorized client lease",
    },
    "192.168.1.133": {
        "hostname": "iPhone",
        "device_type": "Mobile / Smartphone",
        "notes": "Authorized client lease (Apple iOS)",
    },
    "192.168.1.137": {
        "hostname": "LAPTOP-38GLGNUT",
        "device_type": "Workstation / Laptop",
        "notes": "Authorized client lease (Windows Laptop)",
    },
    "192.168.1.142": {
        "hostname": "realme-12-5G",
        "device_type": "Mobile / Smartphone",
        "notes": "Authorized client lease (Android OS)",
    },
    "192.168.1.149": {
        "hostname": "grc",
        "device_type": "Server / Appliance",
        "notes": "Authorized client lease (Raspberry Pi Nmap Agent)",
    },
}


def get_authorized_dhcp_info(ip: str) -> Optional[Dict[str, Any]]:
    """Return known authorized router DHCP client metadata for an IP address."""
    clean_ip = str(ip or "").strip()
    return AUTHORIZED_ROUTER_DHCP_CLIENTS.get(clean_ip)

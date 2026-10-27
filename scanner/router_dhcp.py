"""Authorized Router DHCP Static Client Registry & Import Manager.

Provides an authorized static registry mapping of known LAN DHCP client reservations
for the local subnet. This is an explicit static reference registry or imported snapshot,
NOT a live dynamic router synchronization API, preserving network integrity without
scraping credentials or guessing router passwords.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Dict, Any, Optional, List

logger = logging.getLogger("ai_grc.scanner.dhcp")

# Router hardware specification & integration capability metadata
ROUTER_METADATA = {
    "model": "TP-Link TL-WR840N",
    "integration_type": "static_reference_registry",
    "live_sync_supported": False,
    "live_sync_reason": (
        "TP-Link TL-WR840N SOHO firmware does not expose an authenticated public REST API "
        "or secure SNMP telemetry. Platform policy strictly forbids storing cleartext admin "
        "credentials or scraping web management sessions."
    ),
    "last_imported_at": "2026-10-27T12:00:00Z",
    "source_freshness": "static_reference",
}

# Known MAC address bindings for authorized DHCP clients in 192.168.1.0/24
KNOWN_ROUTER_DHCP_MACS: Dict[str, str] = {
    "192.168.1.1": "AC:84:C6:64:C2:3C",
    "192.168.1.100": "0A:CD:45:AB:91:A4",
    "192.168.1.101": "3C:6A:A7:8D:EA:87",
    "192.168.1.104": "24:EC:4A:06:5F:88",
    "192.168.1.108": "A8:41:F4:0C:39:57",
    "192.168.1.123": "2A:0C:FC:C4:4C:3D",
    "192.168.1.124": "02:EA:2F:FA:3C:B3",
    "192.168.1.127": "E0:C2:64:2A:B4:08",
    "192.168.1.133": "EE:37:8A:B3:BF:95",
    "192.168.1.142": "C6:8C:01:87:9D:3B",
}

# Static authorized router DHCP client registry for the configured LAN
AUTHORIZED_ROUTER_DHCP_CLIENTS: Dict[str, Dict[str, Any]] = {
    "192.168.1.1": {
        "hostname": "TP-Link Gateway",
        "device_type": "Router / Gateway",
        "mac_address": "AC:84:C6:64:C2:3C",
        "notes": "Default Gateway & DHCP Server",
        "lease_type": "static_reservation",
    },
    "192.168.1.100": {
        "hostname": "Sujal",
        "device_type": "Workstation / Laptop",
        "mac_address": "0A:CD:45:AB:91:A4",
        "notes": "Authorized client lease (Sujal)",
        "lease_type": "dynamic_lease",
    },
    "192.168.1.101": {
        "hostname": "FLEMSIS",
        "device_type": "Workstation / Laptop",
        "mac_address": "3C:6A:A7:8D:EA:87",
        "notes": "Authorized client lease (Host Workstation)",
        "lease_type": "dynamic_lease",
    },
    "192.168.1.102": {
        "hostname": "Joshua",
        "device_type": "Workstation / Laptop",
        "mac_address": "E0:C2:64:2A:B4:08",
        "notes": "Historical reservation (reassigned to 192.168.1.127)",
        "lease_type": "historical_lease",
    },
    "192.168.1.104": {
        "hostname": "IoT-Device",
        "device_type": "IoT / Embedded",
        "mac_address": "24:EC:4A:06:5F:88",
        "notes": "Authorized IoT appliance",
        "lease_type": "dynamic_lease",
    },
    "192.168.1.105": {
        "hostname": "iPhone",
        "device_type": "Mobile / Smartphone",
        "mac_address": "02:EA:2F:FA:3C:B3",
        "notes": "Authorized client lease (Apple iOS)",
        "lease_type": "historical_lease",
    },
    "192.168.1.108": {
        "hostname": "LAN-Client",
        "device_type": "Generic Network Host",
        "mac_address": "A8:41:F4:0C:39:57",
        "notes": "Authorized client lease",
        "lease_type": "dynamic_lease",
    },
    "192.168.1.112": {
        "hostname": "Riddhi",
        "device_type": "Mobile / Smartphone",
        "notes": "Authorized client lease",
        "lease_type": "dynamic_lease",
    },
    "192.168.1.123": {
        "hostname": "Nothing-Phone-2a",
        "device_type": "Mobile / Smartphone",
        "mac_address": "2A:0C:FC:C4:4C:3D",
        "notes": "Authorized client lease (Android OS)",
        "lease_type": "dynamic_lease",
    },
    "192.168.1.124": {
        "hostname": "Jack-s-A35",
        "device_type": "Mobile / Smartphone",
        "mac_address": "02:EA:2F:FA:3C:B3",
        "notes": "Authorized client lease (Samsung Galaxy A35 Android)",
        "lease_type": "dynamic_lease",
    },
    "192.168.1.125": {
        "hostname": "Vallabh",
        "device_type": "Workstation / Laptop",
        "mac_address": "E8:C7:CF:B6:89:7E",
        "notes": "Authorized client lease",
        "lease_type": "dynamic_lease",
    },
    "192.168.1.127": {
        "hostname": "Joshua",
        "device_type": "Workstation / Laptop",
        "mac_address": "E0:C2:64:2A:B4:08",
        "notes": "Active authorized client lease (Joshua Workstation)",
        "lease_type": "dynamic_lease",
    },
    "192.168.1.133": {
        "hostname": "iPhone",
        "device_type": "Mobile / Smartphone",
        "mac_address": "EE:37:8A:B3:BF:95",
        "notes": "Authorized client lease (Apple iOS)",
        "lease_type": "dynamic_lease",
    },
    "192.168.1.137": {
        "hostname": "LAPTOP-38GLGNUT",
        "device_type": "Workstation / Laptop",
        "mac_address": "A8:41:F4:59:25:8F",
        "notes": "Authorized client lease (Windows Laptop)",
        "lease_type": "dynamic_lease",
    },
    "192.168.1.142": {
        "hostname": "realme-12-5G",
        "device_type": "Mobile / Smartphone",
        "mac_address": "C6:8C:01:87:9D:3B",
        "notes": "Authorized client lease (Android OS)",
        "lease_type": "dynamic_lease",
    },
    "192.168.1.149": {
        "hostname": "grc",
        "device_type": "Server / Appliance",
        "notes": "Authorized client lease (Raspberry Pi Nmap Agent)",
        "lease_type": "static_reservation",
    },
}


def get_authorized_dhcp_info(ip: str) -> Optional[Dict[str, Any]]:
    """Return known authorized router DHCP client metadata for an IP address."""
    clean_ip = str(ip or "").strip()
    return AUTHORIZED_ROUTER_DHCP_CLIENTS.get(clean_ip)


def normalize_mac_address(mac: Optional[str]) -> Optional[str]:
    """Clean and normalize a MAC address to standard uppercase colon-separated format."""
    if not mac or not isinstance(mac, str):
        return None
    cleaned = mac.strip().upper().replace("-", ":").replace(".", ":")
    parts = cleaned.split(":")
    if len(parts) == 6 and all(len(p) <= 2 for p in parts) and all(all(c in "0123456789ABCDEF" for c in p) for p in parts if p):
        norm = ":".join(p.zfill(2) for p in parts)
        if norm in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF") or norm.startswith("01:00:5E") or norm.startswith("33:33:"):
            return None
        return norm
    return None



def is_valid_client_name(name: Optional[str]) -> bool:
    """Validate that a client name is meaningful and not empty or placeholder."""
    if not name or not isinstance(name, str):
        return False
    stripped = name.strip()
    if not stripped:
        return False
    if stripped.lower() in ("none", "unknown", "null", "not available", "(none)"):
        return False
    return True


def find_router_dhcp_entry(mac: Optional[str] = None, ip: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Map router DHCP entry primarily using normalized MAC address with IP as fallback.

    Precedence:
    1. Primary: Match by normalized MAC address across all registered/imported client leases.
    2. Fallback: Match by IP address only if candidate has no conflicting MAC with the registered entry.
    """
    clean_mac = normalize_mac_address(mac) if mac else None
    clean_ip = str(ip or "").strip() if ip else None

    # Priority 1: Primary match by normalized MAC address
    if clean_mac:
        for reg_ip, entry in AUTHORIZED_ROUTER_DHCP_CLIENTS.items():
            entry_mac = normalize_mac_address(entry.get("mac_address") or KNOWN_ROUTER_DHCP_MACS.get(reg_ip))
            if entry_mac and entry_mac == clean_mac:
                raw_name = entry.get("client_name") or entry.get("hostname")
                return {
                    "registered_ip": reg_ip,
                    "current_ip": clean_ip or reg_ip,
                    "client_name": raw_name.strip() if is_valid_client_name(raw_name) else None,
                    "hostname": entry.get("hostname"),
                    "mac_address": entry_mac,
                    "device_type": entry.get("device_type"),
                    "dhcp_lease_source": entry.get("lease_type", "static_registry"),
                    "lease_source": "Static DHCP Registry Reference" if entry.get("lease_type") != "imported_lease" else "Imported Router DHCP Registry",
                    "matched_by": "mac_address",
                    "is_live_sync": False,
                    "provenance": "Static router client list reference (matched via MAC)",
                }

    # Priority 2: Controlled fallback match by IP
    if clean_ip:
        entry = AUTHORIZED_ROUTER_DHCP_CLIENTS.get(clean_ip)
        if entry:
            entry_mac = normalize_mac_address(entry.get("mac_address") or KNOWN_ROUTER_DHCP_MACS.get(clean_ip))
            if clean_mac and entry_mac and clean_mac != entry_mac:
                logger.info(
                    "DHCP IP fallback match rejected for IP %s: Candidate MAC %s conflicts with registered MAC %s",
                    clean_ip, clean_mac, entry_mac
                )
                return None

            raw_name = entry.get("client_name") or entry.get("hostname")
            return {
                "registered_ip": clean_ip,
                "current_ip": clean_ip,
                "client_name": raw_name.strip() if is_valid_client_name(raw_name) else None,
                "hostname": entry.get("hostname"),
                "mac_address": entry_mac or clean_mac,
                "device_type": entry.get("device_type"),
                "notes": entry.get("notes"),
                "dhcp_lease_source": entry.get("lease_type", "static_registry"),
                "lease_source": "Static DHCP Registry Reference" if entry.get("lease_type") != "imported_lease" else "Imported Router DHCP Registry",
                "matched_by": "ip_address",
                "is_live_sync": False,
                "provenance": "Static router client list reference (fallback via IP)",
            }

    return None


def get_authorized_dhcp_info_for_host(ip: str, mac: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Return authorized DHCP metadata using primary MAC mapping with safe IP fallback."""
    return find_router_dhcp_entry(mac=mac, ip=ip)


def get_dhcp_registry_status() -> Dict[str, Any]:
    """Return explicit metadata and provenance regarding router DHCP source of truth."""
    return {
        **ROUTER_METADATA,
        "total_clients": len(AUTHORIZED_ROUTER_DHCP_CLIENTS),
        "clients": [
            {
                "ip_address": ip,
                "hostname": data.get("hostname"),
                "client_name": data.get("client_name") or data.get("hostname"),
                "display_name": data.get("client_name") or data.get("hostname") or f"Host {ip}",
                "mac_address": data.get("mac_address") or KNOWN_ROUTER_DHCP_MACS.get(ip),
                "device_type": data.get("device_type"),
                "lease_type": data.get("lease_type", "dynamic_lease"),
            }
            for ip, data in sorted(AUTHORIZED_ROUTER_DHCP_CLIENTS.items())
        ],
    }


def import_dhcp_client_list(records: List[Dict[str, Any]], source_label: str = "imported_router_export") -> int:
    """Import an exported DHCP client list from router admin export (CSV/JSON).

    Updates in-memory authorized registry with fresh metadata without scraping.
    """
    imported_count = 0
    now_iso = datetime.utcnow().isoformat() + "Z"

    for r in records:
        ip = str(r.get("ip_address") or r.get("ip") or "").strip()
        if not ip:
            continue
        mac = normalize_mac_address(r.get("mac_address") or r.get("mac"))
        client_name = str(r.get("client_name") or r.get("hostname") or "").strip()
        device_type = r.get("device_type") or "Generic Network Host"

        AUTHORIZED_ROUTER_DHCP_CLIENTS[ip] = {
            "hostname": client_name or f"Host-{ip}",
            "client_name": client_name or f"Host-{ip}",
            "device_type": device_type,
            "mac_address": mac or None,
            "notes": f"Imported from {source_label} on {now_iso}",
            "lease_type": "imported_lease",
        }
        if mac:
            KNOWN_ROUTER_DHCP_MACS[ip] = mac
        imported_count += 1

    ROUTER_METADATA["last_imported_at"] = now_iso
    ROUTER_METADATA["source_freshness"] = f"imported_from_{source_label}"
    logger.info("Imported %d DHCP client records from %s", imported_count, source_label)
    return imported_count

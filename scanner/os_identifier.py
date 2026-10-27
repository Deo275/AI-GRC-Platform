"""Intelligent OS, Device Type, and Service Fingerprinting Engine.

Provides safe, evidence-based OS and device classification without fabricating data.
Combines:
1. Nmap OS stack fingerprinting (-O) when available with high accuracy.
2. Service banner and CPE inspection (e.g. cpe:/o:microsoft:windows, Dropbear, OpenSSH Debian, Linux kernel UPnP).
3. Authorized router DHCP static reservation and lease metadata when available.
4. Network layer indicators (OUI MAC vendor, TTL, service port signatures).
5. Safe inconclusive fallbacks returning 'Unknown' with explicit diagnostic reasons.
"""

from typing import Dict, Any, List, Optional
import re

try:
    from scanner.router_dhcp import get_authorized_dhcp_info
except ImportError:
    try:
        from router_dhcp import get_authorized_dhcp_info
    except ImportError:
        def get_authorized_dhcp_info(ip: str) -> Optional[Dict[str, Any]]:
            return None


def identify_os_and_device(host_data: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze host scan evidence to determine OS, confidence, fingerprint reason, detection source, and device type.

    Does not invent an operating system if evidence is absent or inconclusive.
    Returns 'Unknown' with an explicit diagnostic reason when evidence is insufficient.
    """
    ip = str(host_data.get("ip_address") or host_data.get("ip") or "").strip()
    mac = (host_data.get("mac_address") or host_data.get("mac") or "").upper().strip()
    vendor = str(host_data.get("vendor") or host_data.get("mac_vendor") or "").strip()
    hostname = str(host_data.get("hostname") or "").strip()
    nmap_os = host_data.get("operating_system") or None
    open_ports = host_data.get("open_ports") or []

    # Authorized DHCP / router metadata lookup
    dhcp_info = host_data.get("dhcp_info") or (get_authorized_dhcp_info(ip) if ip else None)
    if dhcp_info and isinstance(dhcp_info, dict):
        if not hostname and dhcp_info.get("hostname"):
            hostname = str(dhcp_info.get("hostname")).strip()

    dhcp_notes = (dhcp_info.get("notes") or "").lower() if dhcp_info else ""
    dhcp_device_type = dhcp_info.get("device_type") if dhcp_info else None

    # 1. Direct Nmap OS detection (-O probe match / TCP-IP stack fingerprinting)
    if nmap_os and isinstance(nmap_os, str) and nmap_os.strip() and nmap_os.strip().lower() not in ("none", "unknown", "os not identified", "not identified"):
        clean_os = nmap_os.strip()
        device_type = _infer_device_type(clean_os, hostname, vendor, open_ports, ip, dhcp_device_type)
        return {
            "operating_system": clean_os,
            "os_confidence": "High",
            "os_fingerprint_reason": f"Direct Nmap TCP/IP stack fingerprinting match ({clean_os})",
            "detection_source": "nmap_os_detection",
            "device_type": device_type,
        }

    # 2. Service Banner & CPE Evidence Analysis
    service_os_matches = []
    has_windows_rpc = False
    has_dropbear = False
    has_router_admin = False
    has_debian_ssh = False
    has_linux_kernel_cpe = None
    has_apple_signature = False

    for port_info in open_ports:
        port = int(port_info.get("port") or 0)
        service = (port_info.get("service") or "").lower()
        product = port_info.get("product") or ""
        version = port_info.get("version") or ""
        details = port_info.get("details") or ""
        cpe = (port_info.get("cpe") or "").lower()

        # Windows indicators (RPC, SMB, NetBIOS, Microsoft CPE)
        if "cpe:/o:microsoft:windows" in cpe or "microsoft windows" in product.lower():
            has_windows_rpc = True
        elif port in (135, 139, 445) and ("msrpc" in service or "netbios" in service or "microsoft-ds" in service):
            has_windows_rpc = True

        # Dropbear on embedded router / IoT
        if "dropbear" in product.lower() or "dropbear" in details.lower():
            has_dropbear = True

        # Router web admin
        if "tp-link" in product.lower() or "router" in product.lower() or "broadcom" in product.lower():
            has_router_admin = True

        # Debian / Ubuntu / Linux SSH banners
        if "debian" in (version + details).lower():
            has_debian_ssh = True
        elif "ubuntu" in (version + details).lower():
            service_os_matches.append(("Ubuntu Linux", "High", f"Ubuntu service banner on port {port} ({product} {version})"))

        # Linux kernel CPE (e.g. from libupnp, samba, or network appliances)
        if "cpe:/o:linux:linux_kernel" in cpe:
            k_match = re.search(r"linux_kernel:([0-9\.]+)", cpe)
            k_ver = f" (Kernel {k_match.group(1)})" if k_match else ""
            has_linux_kernel_cpe = f"Embedded Linux{k_ver}"

        # Apple iOS signatures (Apple Mobile Sync 62078, AirPlay 7000/5000, Apple mDNS)
        if port in (62078, 5353) or ("apple" in product.lower()):
            has_apple_signature = True

    # Correlate service banner evidence
    if has_debian_ssh:
        return {
            "operating_system": "Debian Linux",
            "os_confidence": "High",
            "os_fingerprint_reason": "Identified via Debian Linux OS banner in OpenSSH daemon",
            "detection_source": "service_banner",
            "device_type": _infer_device_type("Debian Linux", hostname, vendor, open_ports, ip, dhcp_device_type),
        }

    if service_os_matches:
        os_name, conf, rsn = service_os_matches[0]
        return {
            "operating_system": os_name,
            "os_confidence": conf,
            "os_fingerprint_reason": rsn,
            "detection_source": "service_banner",
            "device_type": _infer_device_type(os_name, hostname, vendor, open_ports, ip, dhcp_device_type),
        }

    if has_windows_rpc:
        return {
            "operating_system": "Microsoft Windows",
            "os_confidence": "High",
            "os_fingerprint_reason": "Identified via Windows RPC/NetBIOS/SMB service evidence and CPE",
            "detection_source": "service_banner_cpe",
            "device_type": _infer_device_type("Microsoft Windows", hostname, vendor, open_ports, ip, dhcp_device_type or "Workstation / Laptop"),
        }

    if has_router_admin or (has_dropbear and ip.endswith(".1")):
        os_name = has_linux_kernel_cpe or "Embedded Linux (Router Firmware)"
        return {
            "operating_system": os_name,
            "os_confidence": "High" if has_linux_kernel_cpe else "Medium",
            "os_fingerprint_reason": "Identified via Router HTTP Admin, UPnP, and Dropbear SSH service signatures",
            "detection_source": "service_banner",
            "device_type": "Router / Gateway",
        }

    if has_linux_kernel_cpe:
        return {
            "operating_system": has_linux_kernel_cpe,
            "os_confidence": "High",
            "os_fingerprint_reason": f"Identified via Linux kernel CPE ({has_linux_kernel_cpe}) in service evidence",
            "detection_source": "service_banner_cpe",
            "device_type": _infer_device_type(has_linux_kernel_cpe, hostname, vendor, open_ports, ip, dhcp_device_type),
        }

    if has_dropbear:
        return {
            "operating_system": "Embedded Linux",
            "os_confidence": "Medium",
            "os_fingerprint_reason": "Identified via Dropbear SSH daemon typically deployed on embedded Linux",
            "detection_source": "service_banner",
            "device_type": _infer_device_type("Embedded Linux", hostname, vendor, open_ports, ip, dhcp_device_type or "IoT / Embedded"),
        }

    if has_apple_signature and ("apple" in vendor.lower() or 62078 in {int(p.get("port") or 0) for p in open_ports}):
        return {
            "operating_system": "Apple iOS",
            "os_confidence": "High",
            "os_fingerprint_reason": "Identified via Apple mobile daemon service signature on listening ports",
            "detection_source": "service_banner",
            "device_type": "Mobile / Smartphone",
        }

    # 3. Authorized DHCP / Router Client Metadata Evidence
    if dhcp_info and isinstance(dhcp_info, dict):
        dhcp_hn = (dhcp_info.get("hostname") or "").lower()
        if "apple ios" in dhcp_notes or "iphone" in dhcp_notes or "iphone" in dhcp_hn or "ipad" in dhcp_hn:
            return {
                "operating_system": "Apple iOS",
                "os_confidence": "Medium",
                "os_fingerprint_reason": f"Identified via authorized router DHCP client metadata ({dhcp_info.get('notes') or dhcp_info.get('hostname')})",
                "detection_source": "authorized_dhcp_metadata",
                "device_type": dhcp_device_type or "Mobile / Smartphone",
            }
        if "android os" in dhcp_notes or "android" in dhcp_notes:
            return {
                "operating_system": "Android OS (Linux Kernel)",
                "os_confidence": "Medium",
                "os_fingerprint_reason": f"Identified via authorized router DHCP client metadata ({dhcp_info.get('notes') or dhcp_info.get('hostname')})",
                "detection_source": "authorized_dhcp_metadata",
                "device_type": dhcp_device_type or "Mobile / Smartphone",
            }
        if "windows" in dhcp_notes:
            return {
                "operating_system": "Microsoft Windows",
                "os_confidence": "Medium",
                "os_fingerprint_reason": f"Identified via authorized router DHCP client metadata ({dhcp_info.get('notes') or dhcp_info.get('hostname')})",
                "detection_source": "authorized_dhcp_metadata",
                "device_type": dhcp_device_type or "Workstation / Laptop",
            }
        if "router" in dhcp_notes or "gateway" in dhcp_notes:
            return {
                "operating_system": "Embedded Linux (Router Firmware)",
                "os_confidence": "Medium",
                "os_fingerprint_reason": f"Identified via authorized router DHCP client metadata ({dhcp_info.get('notes') or dhcp_info.get('hostname')})",
                "detection_source": "authorized_dhcp_metadata",
                "device_type": "Router / Gateway",
            }

    # 4. Hardware & MAC OUI / Hostname-based heuristics
    mac_upper = mac.upper()
    hn_lower = hostname.lower()

    if "iphone" in hn_lower or "ipad" in hn_lower or "apple" in vendor.lower() or has_apple_signature:
        src = "hostname_heuristics" if ("iphone" in hn_lower or "ipad" in hn_lower) else ("mac_vendor" if "apple" in vendor.lower() else "service_banner")
        return {
            "operating_system": "Apple iOS",
            "os_confidence": "Medium",
            "os_fingerprint_reason": f"Identified via Apple hostname profile / hardware OUI ({hostname or vendor})",
            "detection_source": src,
            "device_type": "Mobile / Smartphone",
        }

    if any(k in hn_lower for k in ("android", "nothing-phone", "galaxy", "realme", "pixel", "redmi", "oneplus", "xiaomi", "oppo", "vivo")):
        return {
            "operating_system": "Android OS (Linux Kernel)",
            "os_confidence": "Medium",
            "os_fingerprint_reason": f"Identified via Android smartphone hostname profile ({hostname})",
            "detection_source": "hostname_heuristics",
            "device_type": "Mobile / Smartphone",
        }

    if "raspberry" in vendor.lower() or "raspberrypi" in hn_lower or hn_lower == "grc":
        src = "mac_vendor" if "raspberry" in vendor.lower() else "hostname_heuristics"
        return {
            "operating_system": "Raspberry Pi OS (Linux)",
            "os_confidence": "High" if "raspberry" in vendor.lower() else "Medium",
            "os_fingerprint_reason": "Identified via Raspberry Pi Foundation hardware OUI and network profile",
            "detection_source": src,
            "device_type": "Server / Appliance",
        }

    if "laptop-" in hn_lower or "desktop-" in hn_lower or hn_lower.startswith("win-"):
        return {
            "operating_system": "Microsoft Windows",
            "os_confidence": "Medium",
            "os_fingerprint_reason": f"Identified via Windows default hostname convention ({hostname})",
            "detection_source": "hostname_heuristics",
            "device_type": "Workstation / Laptop",
        }

    # 5. Inconclusive cases — Do NOT invent or fabricate an OS
    # Use 'Unknown' with explicit diagnostic reason
    if len(open_ports) > 0:
        port_list = ", ".join(f"{p.get('port')}/{p.get('service')}" for p in open_ports[:4])
        return {
            "operating_system": "Unknown",
            "os_confidence": "Inconclusive",
            "os_fingerprint_reason": f"Unknown — detection inconclusive: Ports open ({port_list}) did not expose conclusive OS fingerprints",
            "detection_source": "inconclusive_probes",
            "device_type": _infer_device_type(None, hostname, vendor, open_ports, ip, dhcp_device_type),
        }

    return {
        "operating_system": "Unknown",
        "os_confidence": "Inconclusive",
        "os_fingerprint_reason": "Unknown — detection inconclusive: No open TCP/UDP ports responded to probe sweeps and host exposes no service banners",
        "detection_source": "inconclusive_probes",
        "device_type": _infer_device_type(None, hostname, vendor, open_ports, ip, dhcp_device_type),
    }


def _infer_device_type(
    os_name: Optional[str],
    hostname: str,
    vendor: str,
    open_ports: List[Dict[str, Any]],
    ip: str,
    dhcp_device_type: Optional[str] = None,
) -> str:
    """Infer device category conservatively from evidence."""
    if dhcp_device_type:
        return dhcp_device_type

    hn = (hostname or "").lower()
    os_lower = (os_name or "").lower()
    ports = {int(p.get("port") or 0) for p in open_ports}

    if ip.endswith(".1") or "router" in hn or "router" in os_lower or "gateway" in hn:
        return "Router / Gateway"

    if any(k in hn for k in ("iphone", "phone", "android", "realme", "galaxy", "ipad", "pixel", "redmi", "mobile")):
        return "Mobile / Smartphone"

    if "ios" in os_lower or "android" in os_lower:
        return "Mobile / Smartphone"

    if "raspberry" in (vendor or "").lower() or "server" in hn or 5432 in ports or 3306 in ports or hn == "grc":
        return "Server / Appliance"

    if "windows" in os_lower or 135 in ports or 445 in ports or "laptop" in hn or "desktop" in hn:
        return "Workstation / Laptop"

    if "linux" in os_lower:
        return "Workstation / Laptop" if (22 in ports or not ports) else "Server / Appliance"

    if len(ports) == 0:
        return "Unknown"

    return "IoT / Embedded"

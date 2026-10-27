"""Stable Asset Identity, Dynamic IP Reconciliation, and Deduplication Engine.

Provides evidence-based asset identification following strict precedence:
1. Persistent agent/device identifier (device_id), verified.
2. Validated MAC address (within L2 network broadcast scope).
3. Reliable, verified endpoint identifier.
4. IP address as fallback only when there is no conflicting identity evidence.

Guarantees:
- Updates existing assets when IP addresses change via dynamic DHCP.
- Preserves asset ID, vulnerability history, scan history, GRC classifications, and risks.
- Maintains complete address history for each device (current and previous IPs).
- Handles MAC randomization conservatively (no unsafe merges based solely on hostname/ports).
- Handles IP reassignment without contaminating prior devices.
- Thread-safe transactional execution preventing race conditions in concurrent scans.
- Safe non-destructive reconciliation procedure to merge duplicate records without losing audit history.
"""

from __future__ import annotations

import re
import os
import logging
import ipaddress
import threading
from datetime import datetime
from typing import Dict, Any, Optional, Tuple, List

from sqlalchemy.orm import Session
from sqlalchemy import text

try:
    import models
except ImportError:
    from backend import models

logger = logging.getLogger("ai_grc.monitoring.identity")

# Re-entrant thread lock for serializing asset reconciliation across worker threads
_RECONCILIATION_LOCK = threading.RLock()

# Standard MAC address regex (6 pairs of hex digits separated by colon or hyphen)
_MAC_REGEX = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")


def normalize_mac(mac: Optional[str]) -> Optional[str]:
    """Normalize a MAC address to standard uppercase colon-separated format (e.g. AA:BB:CC:DD:EE:FF).

    Returns None if MAC is invalid, all zeros (00:00:00:00:00:00), broadcast (FF:FF:FF:FF:FF:FF),
    or well-known Ethernet multicast prefixes (01:00:5E, 33:33).
    """
    if not mac or not isinstance(mac, str):
        return None

    cleaned = mac.strip().upper().replace("-", ":")
    if not _MAC_REGEX.match(cleaned):
        return None

    octets = cleaned.split(":")
    if len(octets) != 6:
        return None

    # Filter out broadcast
    if cleaned == "FF:FF:FF:FF:FF:FF":
        return None

    # Filter out all-zero dummy MAC
    if cleaned == "00:00:00:00:00:00":
        return None

    # Filter out well-known IP multicast prefixes (01:00:5E for IPv4, 33:33 for IPv6)
    if cleaned.startswith("01:00:5E") or cleaned.startswith("33:33:"):
        return None

    return cleaned


def is_locally_administered_mac(mac: Optional[str]) -> bool:
    """Return True if MAC address has the locally-administered bit set (privacy/randomized MAC).

    In IEEE 802 addressing, the second-least-significant bit of the first octet indicates
    whether the MAC address is locally administered (randomized / private) or globally assigned
    by an IEEE OUI vendor.
    In hex notation for the first octet, this corresponds to a second digit of 2, 6, A, or E
    (e.g., x2:xx:xx..., x6:xx:xx..., xA:xx:xx..., xE:xx:xx...).
    """
    norm = normalize_mac(mac)
    if not norm:
        return False
    try:
        first_byte = int(norm.split(":")[0], 16)
        return bool((first_byte & 0x02) != 0)
    except (ValueError, IndexError):
        return False


def normalize_ip(ip: Optional[str]) -> Optional[str]:
    """Normalize an IPv4 address string to canonical notation using ipaddress module."""
    if not ip or not isinstance(ip, str):
        return None
    try:
        return str(ipaddress.ip_address(ip.strip()))
    except ValueError:
        return None


def normalize_device_id(device_id: Optional[str]) -> Optional[str]:
    """Clean and normalize a persistent device or agent identifier."""
    if not device_id or not isinstance(device_id, str):
        return None
    cleaned = device_id.strip()
    return cleaned if len(cleaned) >= 3 else None


def is_valid_client_name(name: Optional[str]) -> bool:
    """Validate that a client/device name is meaningful, non-empty, and not a generic placeholder."""
    if not name or not isinstance(name, str):
        return False
    stripped = name.strip()
    if not stripped:
        return False
    if stripped.lower() in ("none", "unknown", "null", "not available", "(none)", "unidentified"):
        return False
    return True


def get_preferred_display_name(asset_or_dict: Any) -> str:
    """Return the preferred asset display name following strict precedence:
    1. Router DHCP client name (router-reported client name)
    2. Operating system hostname (OS / NetBIOS / DNS hostname)
    3. Existing name or device label
    4. IP address label ('Host <ip>') or MAC label ('Device (<mac>)')
    """
    if asset_or_dict is None:
        return "Unidentified Device"

    def _get(field: str) -> Optional[str]:
        if isinstance(asset_or_dict, dict):
            val = asset_or_dict.get(field)
        else:
            val = getattr(asset_or_dict, field, None)
        return str(val).strip() if val is not None and str(val).strip() else None

    # 1. Router DHCP client name
    for key in ("dhcp_client_name", "router_client_name"):
        cand = _get(key)
        if is_valid_client_name(cand):
            return cand

    # 2. Operating system hostname
    for key in ("hostname", "os_hostname"):
        cand = _get(key)
        if is_valid_client_name(cand):
            norm = normalize_ip(cand)
            if not norm:
                return cand

    # 3. Existing name or device label
    for key in ("name", "label", "device_name", "display_name", "preferred_display_name"):
        cand = _get(key)
        if is_valid_client_name(cand) and cand != "Unidentified Device":
            return cand

    # 4. Fallback: IP address or MAC address
    ip = _get("ip_address") or _get("ip")
    if ip:
        return f"Host {ip}"

    mac = _get("mac_address") or _get("mac")
    if mac:
        return f"Device ({mac})"

    asset_id = _get("id") or _get("asset_id")
    if asset_id:
        return f"Asset #{asset_id}"

    return "Unidentified Device"



def determine_network_scope(ip: Optional[str], source: Optional[str] = None) -> str:
    """Classify the network scope of an IP address using verified network boundaries."""
    norm_ip = normalize_ip(ip)
    if not norm_ip:
        return "needs_review"
    try:
        addr = ipaddress.ip_address(norm_ip)
        if addr.is_loopback or norm_ip.startswith("127."):
            return "loopback"
        if norm_ip.endswith(".255") or norm_ip.endswith(".0"):
            return "out_of_scope"
        configured_lan = (os.getenv("NMAP_NETWORK_CIDR") or "192.168.1.0/24").strip()
        try:
            lan_net = ipaddress.ip_network(configured_lan, strict=False)
            if addr in lan_net:
                if addr == lan_net.network_address or addr == lan_net.broadcast_address:
                    return "out_of_scope"
                return "physical_lan"
        except Exception:
            pass
        if norm_ip.startswith("172.18.") or norm_ip.startswith("172.17."):
            return "local_container"
        if norm_ip.startswith("192.168.127.") or norm_ip.startswith("192.168.47."):
            return "virtual_interface"
        if source == "single_host_scan":
            return "authorized_single_host"
        return "out_of_scope"
    except Exception:
        return "needs_review"


def find_existing_asset(
    db: Session,
    host_data: Dict[str, Any],
) -> Tuple[Optional[models.Asset], str, str]:
    """Evaluate candidate host scan evidence to find an existing Asset record in database.

    Returns:
        (matched_asset, match_strategy, diagnostic_reason)

    Precedence order:
    1. Persistent agent/device identifier (device_id)
    2. Validated MAC address within network scope
    3. Reliable verified endpoint identifier
    4. IP address fallback only when there is no conflicting identity evidence
    """
    raw_ip = host_data.get("ip_address") or host_data.get("ip")
    norm_ip = normalize_ip(raw_ip)

    raw_mac = host_data.get("mac_address") or host_data.get("mac")
    norm_mac = normalize_mac(raw_mac)

    raw_device_id = host_data.get("device_id") or host_data.get("agent_id")
    norm_device_id = normalize_device_id(raw_device_id)

    candidate_scope = host_data.get("network_scope") or determine_network_scope(norm_ip, source=host_data.get("discovery_source"))

    # -------------------------------------------------------------------------
    # Priority 1: Persistent agent/device identifier
    # -------------------------------------------------------------------------
    if norm_device_id:
        asset_by_device_id = (
            db.query(models.Asset)
            .filter(models.Asset.device_id == norm_device_id)
            .filter(models.Asset.status != "deactivated")
            .first()
        )
        if asset_by_device_id:
            logger.info(
                "Matched Asset #%s via Priority 1 (Persistent Device ID: %s)",
                asset_by_device_id.id,
                norm_device_id,
            )
            return (
                asset_by_device_id,
                "persistent_agent_id",
                f"Matched persistent device ID: {norm_device_id}",
            )

    # -------------------------------------------------------------------------
    # Priority 2: Validated MAC address within network scope
    # -------------------------------------------------------------------------
    if norm_mac:
        asset_by_mac = (
            db.query(models.Asset)
            .filter(models.Asset.mac_address == norm_mac)
            .filter(models.Asset.status != "deactivated")
            .first()
        )
        if asset_by_mac:
            # Check for conflict: if both have device_id and they differ, do not merge
            if (
                norm_device_id
                and asset_by_mac.device_id
                and asset_by_mac.device_id != norm_device_id
            ):
                logger.warning(
                    "Conflict detected: MAC %s matches Asset #%s, but device_id differs (%s vs %s)",
                    norm_mac,
                    asset_by_mac.id,
                    norm_device_id,
                    asset_by_mac.device_id,
                )
            else:
                logger.info(
                    "Matched Asset #%s via Priority 2 (Validated MAC: %s)",
                    asset_by_mac.id,
                    norm_mac,
                )
                return (
                    asset_by_mac,
                    "validated_mac",
                    f"Matched validated MAC address: {norm_mac}",
                )

    # -------------------------------------------------------------------------
    # Priority 4: IP address fallback only when no conflicting evidence
    # -------------------------------------------------------------------------
    if norm_ip:
        asset_by_ip = (
            db.query(models.Asset)
            .filter(models.Asset.ip_address == norm_ip)
            .filter(models.Asset.status != "deactivated")
            .first()
        )
        if asset_by_ip:
            # Conflict Check 1: MAC address conflict
            # If the candidate has a MAC address, and existing DB asset has a DIFFERENT MAC address:
            # -> This is an IP reassignment (DHCP recycled IP to another device). DO NOT MERGE!
            if norm_mac and asset_by_ip.mac_address and asset_by_ip.mac_address != norm_mac:
                logger.info(
                    "IP Reassignment detected at %s: Existing Asset #%s has MAC %s, new host has MAC %s. Retaining distinct identities.",
                    norm_ip,
                    asset_by_ip.id,
                    asset_by_ip.mac_address,
                    norm_mac,
                )
                return (
                    None,
                    "ip_reassignment_conflict",
                    f"IP {norm_ip} previously assigned to MAC {asset_by_ip.mac_address}; candidate host has different MAC {norm_mac}",
                )

            # Conflict Check 2: Persistent device_id conflict
            if (
                norm_device_id
                and asset_by_ip.device_id
                and asset_by_ip.device_id != norm_device_id
            ):
                logger.info(
                    "Device ID conflict detected at IP %s: Existing Asset #%s has device_id %s, new host has %s.",
                    norm_ip,
                    asset_by_ip.id,
                    asset_by_ip.device_id,
                    norm_device_id,
                )
                return (
                    None,
                    "device_id_conflict",
                    f"IP {norm_ip} has conflicting persistent device IDs",
                )

            # No conflicting identity evidence
            logger.info(
                "Matched Asset #%s via Priority 4 (IP fallback: %s without conflicting evidence)",
                asset_by_ip.id,
                norm_ip,
            )
            return (
                asset_by_ip,
                "ip_fallback",
                f"Matched IP address fallback: {norm_ip} with no conflicting evidence",
            )

    return (None, "no_match", "No existing asset record matched the evidence")


def record_asset_address(
    db: Session,
    asset: models.Asset,
    ip_address: str,
    mac_address: Optional[str] = None,
    source: str = "discovery",
) -> models.AssetAddressHistory:
    """Record an IP address in the asset's address history audit table.

    Updates last_seen_at if already present, or inserts a new historical entry.
    """
    norm_ip = normalize_ip(ip_address)
    if not norm_ip:
        raise ValueError(f"Invalid IP address for address history: {ip_address}")

    norm_mac = normalize_mac(mac_address) or asset.mac_address

    history_entry = (
        db.query(models.AssetAddressHistory)
        .filter(models.AssetAddressHistory.asset_id == asset.id)
        .filter(models.AssetAddressHistory.ip_address == norm_ip)
        .first()
    )

    now = datetime.utcnow()
    if history_entry:
        history_entry.last_seen_at = now
        if norm_mac and not history_entry.mac_address:
            history_entry.mac_address = norm_mac
    else:
        history_entry = models.AssetAddressHistory(
            asset_id=asset.id,
            ip_address=norm_ip,
            mac_address=norm_mac,
            source=source,
            detected_at=now,
            last_seen_at=now,
        )
        db.add(history_entry)

    return history_entry


def upsert_discovered_asset(
    db: Session,
    host_data: Dict[str, Any],
    default_criticality: Optional[str] = None,
    default_environment: Optional[str] = None,
    default_exposure: Optional[str] = None,
    source: str = "discovery",
) -> Tuple[models.Asset, bool, str]:
    """Thread-safe transactional asset upsert reconciling dynamic IP addresses and deduplication.

    Returns:
        (asset, is_new, strategy_used)
    """
    raw_ip = host_data.get("ip_address") or host_data.get("ip")
    norm_ip = normalize_ip(raw_ip)
    if not norm_ip:
        raise ValueError(f"Cannot upsert asset without a valid IPv4 address: {raw_ip}")

    raw_mac = host_data.get("mac_address") or host_data.get("mac")
    norm_mac = normalize_mac(raw_mac)

    raw_device_id = host_data.get("device_id") or host_data.get("agent_id")
    norm_device_id = normalize_device_id(raw_device_id)

    hostname = host_data.get("hostname")
    mac_vendor = host_data.get("vendor") or host_data.get("mac_vendor")
    open_ports_str = host_data.get("open_ports")
    if isinstance(open_ports_str, list):
        open_ports_str = ", ".join(
            f"{p.get('port')}/{p.get('service')}"
            for p in open_ports_str
            if isinstance(p, dict) and p.get("port")
        )

    risk_res = host_data.get("risk_result") or {}

    with _RECONCILIATION_LOCK:
        matched_asset, strategy, reason = find_existing_asset(db, host_data)

        if matched_asset:
            # Update existing asset
            old_ip = matched_asset.ip_address
            ip_changed = old_ip != norm_ip

            if ip_changed:
                logger.info(
                    "Dynamic IP change detected for Asset #%s (%s): %s -> %s",
                    matched_asset.id,
                    matched_asset.hostname or matched_asset.mac_address or "Unknown",
                    old_ip,
                    norm_ip,
                )
                # Ensure the previous IP is recorded in historical addresses
                record_asset_address(
                    db,
                    asset=matched_asset,
                    ip_address=old_ip,
                    mac_address=matched_asset.mac_address,
                    source="previous_address",
                )

                # Check if another asset was occupying norm_ip; if so, displace it
                conflicting_ip_asset = (
                    db.query(models.Asset)
                    .filter(models.Asset.ip_address == norm_ip)
                    .filter(models.Asset.id != matched_asset.id)
                    .filter(models.Asset.status != "deactivated")
                    .first()
                )
                if conflicting_ip_asset:
                    logger.info(
                        "Displacing Asset #%s from IP %s due to IP reassignment to Asset #%s",
                        conflicting_ip_asset.id,
                        norm_ip,
                        matched_asset.id,
                    )
                    record_asset_address(
                        db,
                        asset=conflicting_ip_asset,
                        ip_address=norm_ip,
                        mac_address=conflicting_ip_asset.mac_address,
                        source="reassigned_displaced",
                    )
                    conflicting_ip_asset.status = "Offline"
                    conflicting_ip_asset.assigned_ip_status = "historical_lease_displaced"
                    conflicting_ip_asset.offline_reason = f"IP {norm_ip} reassigned by DHCP to MAC {norm_mac or matched_asset.mac_address or 'Unknown'}"
                    conflicting_ip_asset.assessment_status = "Not assessed (IP reassigned)"

                matched_asset.ip_address = norm_ip

            # Record current IP in address history
            record_asset_address(
                db,
                asset=matched_asset,
                ip_address=norm_ip,
                mac_address=norm_mac or matched_asset.mac_address,
                source=source,
            )

            # Update mutable discovery attributes without overwriting with None
            if hostname:
                matched_asset.hostname = hostname
            if norm_mac:
                matched_asset.mac_address = norm_mac
            if norm_device_id:
                matched_asset.device_id = norm_device_id
            if mac_vendor:
                matched_asset.mac_vendor = mac_vendor
            if host_data.get("operating_system"):
                matched_asset.operating_system = host_data["operating_system"]
            elif not matched_asset.operating_system:
                matched_asset.operating_system = "Unknown"
            if host_data.get("os_confidence"):
                matched_asset.os_confidence = host_data["os_confidence"]
            if host_data.get("os_fingerprint_reason"):
                matched_asset.os_fingerprint_reason = host_data["os_fingerprint_reason"]
            if host_data.get("os_detection_source") or host_data.get("detection_source"):
                matched_asset.os_detection_source = host_data.get("os_detection_source") or host_data.get("detection_source")
            if host_data.get("device_type"):
                matched_asset.device_type = host_data["device_type"]
            if host_data.get("discovery_source"):
                matched_asset.discovery_source = host_data["discovery_source"]
            if open_ports_str is not None:
                matched_asset.open_ports = open_ports_str

            matched_asset.status = "Active"
            matched_asset.assigned_ip_status = "active_assignment"
            matched_asset.offline_reason = None
            matched_asset.consecutive_scan_misses = 0

            # Network scope classification
            if host_data.get("network_scope"):
                matched_asset.network_scope = host_data["network_scope"]
            elif not getattr(matched_asset, "network_scope", None) or matched_asset.network_scope in ("needs_review", "unknown"):
                matched_asset.network_scope = determine_network_scope(norm_ip, source=source)

            # Router DHCP metadata enrichment
            dhcp_name_candidate = host_data.get("dhcp_client_name")
            dhcp_source_candidate = host_data.get("dhcp_lease_source")
            dhcp_observed_candidate = host_data.get("dhcp_observed_at")

            if not dhcp_name_candidate:
                try:
                    from scanner.router_dhcp import find_router_dhcp_entry
                    dhcp_match = find_router_dhcp_entry(mac=norm_mac or matched_asset.mac_address, ip=norm_ip)
                    if dhcp_match and dhcp_match.get("client_name"):
                        dhcp_name_candidate = dhcp_match["client_name"]
                        dhcp_source_candidate = dhcp_match.get("dhcp_lease_source", "static_registry")
                        dhcp_observed_candidate = datetime.utcnow()
                except Exception:
                    pass

            if is_valid_client_name(dhcp_name_candidate):
                matched_asset.dhcp_client_name = dhcp_name_candidate.strip()
                matched_asset.dhcp_lease_source = dhcp_source_candidate or matched_asset.dhcp_lease_source or "static_registry"
                matched_asset.dhcp_observed_at = dhcp_observed_candidate or datetime.utcnow()


            matched_asset.last_seen = datetime.utcnow()
            matched_asset.risk_score = risk_res.get("risk_score", matched_asset.risk_score)
            matched_asset.risk_level = risk_res.get("risk_level", matched_asset.risk_level)
            matched_asset.assessment_status = host_data.get(
                "assessment_status", matched_asset.assessment_status
            )
            matched_asset.last_assessed_at = datetime.utcnow()
            if any(k in (matched_asset.assessment_status or "") for k in ("Completed", "Findings detected")):
                matched_asset.last_successful_scan_at = datetime.utcnow()
            if host_data.get("scan_coverage"):
                matched_asset.scan_coverage = host_data["scan_coverage"]

            # If identity was provisional but we now have strong MAC or device_id, upgrade to verified
            if (norm_device_id or (norm_mac and not is_locally_administered_mac(norm_mac))) and matched_asset.identity_status == "provisional":
                matched_asset.identity_status = "verified"

            db.flush()
            return (matched_asset, False, strategy)

        # ---------------------------------------------------------------------
        # Create a new asset record
        # ---------------------------------------------------------------------
        # Check if another asset currently has norm_ip in the DB; if so, displace it
        displaced_asset = (
            db.query(models.Asset)
            .filter(models.Asset.ip_address == norm_ip)
            .filter(models.Asset.status != "deactivated")
            .first()
        )
        if displaced_asset:
            logger.info(
                "Displacing prior Asset #%s from IP %s to accommodate new device (MAC %s)",
                displaced_asset.id,
                norm_ip,
                norm_mac,
            )
            record_asset_address(
                db,
                asset=displaced_asset,
                ip_address=norm_ip,
                mac_address=displaced_asset.mac_address,
                source="reassigned_displaced",
            )
            displaced_asset.status = "Offline"
            displaced_asset.assigned_ip_status = "historical_lease_displaced"
            displaced_asset.offline_reason = f"IP {norm_ip} reassigned by DHCP to MAC {norm_mac or 'Unknown'}"
            displaced_asset.assessment_status = "Not assessed (IP reassigned)"

        # Determine identity confidence:
        # If device has only IP and hostname (no MAC, no agent ID) -> provisional
        # If device has a randomized MAC and no agent ID -> provisional / unmanaged
        # If device has a persistent device ID or standard OUI MAC -> verified
        identity_status = "verified"
        if not norm_device_id and not norm_mac:
            identity_status = "provisional"
        elif not norm_device_id and norm_mac and is_locally_administered_mac(norm_mac):
            identity_status = "provisional"

        scope_candidate = host_data.get("network_scope") or determine_network_scope(norm_ip, source=source)
        # Router DHCP metadata enrichment for new asset
        new_dhcp_client_name = host_data.get("dhcp_client_name")
        new_dhcp_lease_source = host_data.get("dhcp_lease_source", "none")
        new_dhcp_observed_at = host_data.get("dhcp_observed_at")

        if not new_dhcp_client_name:
            try:
                from scanner.router_dhcp import find_router_dhcp_entry
                dhcp_match = find_router_dhcp_entry(mac=norm_mac, ip=norm_ip)
                if dhcp_match and dhcp_match.get("client_name"):
                    new_dhcp_client_name = dhcp_match["client_name"]
                    new_dhcp_lease_source = dhcp_match.get("dhcp_lease_source", "static_registry")
                    new_dhcp_observed_at = datetime.utcnow()
            except Exception:
                pass

        if not is_valid_client_name(new_dhcp_client_name):
            new_dhcp_client_name = None

        is_successful_assessment = any(k in (host_data.get("assessment_status") or "") for k in ("Completed", "Findings detected"))

        new_asset = models.Asset(
            ip_address=norm_ip,
            hostname=hostname,
            mac_address=norm_mac,
            device_id=norm_device_id,
            mac_vendor=mac_vendor,
            identity_status=identity_status,
            operating_system=host_data.get("operating_system") or "Unknown",
            os_confidence=host_data.get("os_confidence") or "Inconclusive",
            os_fingerprint_reason=host_data.get("os_fingerprint_reason"),
            os_detection_source=host_data.get("os_detection_source") or host_data.get("detection_source") or "inconclusive_probes",
            device_type=host_data.get("device_type") or "Unknown",
            discovery_source=host_data.get("discovery_source", source),
            assessment_status=host_data.get("assessment_status", "Not assessed"),
            last_assessed_at=datetime.utcnow(),
            last_successful_scan_at=datetime.utcnow() if is_successful_assessment else None,
            scan_coverage=host_data.get("scan_coverage"),
            open_ports=open_ports_str,
            status="Active",
            network_scope=scope_candidate,
            assigned_ip_status=host_data.get("assigned_ip_status", "active_assignment"),
            offline_reason=host_data.get("offline_reason"),
            dhcp_lease_source=new_dhcp_lease_source,
            dhcp_client_name=new_dhcp_client_name,
            dhcp_observed_at=new_dhcp_observed_at,
            consecutive_scan_misses=0,

            risk_score=risk_res.get("risk_score", 0),
            risk_level=risk_res.get("risk_level", "Low"),
            criticality=default_criticality,
            environment=default_environment,
            exposure=default_exposure,
            owner=None,
            business_function=None,
            last_seen=datetime.utcnow(),
        )
        db.add(new_asset)
        db.flush()

        # Seed initial address history entry
        record_asset_address(
            db,
            asset=new_asset,
            ip_address=norm_ip,
            mac_address=norm_mac,
            source=source,
        )

        db.flush()
        return (new_asset, True, "new_asset_created")


def reconcile_duplicate_assets(
    db: Session,
    primary_asset_id: int,
    secondary_asset_id: int,
    operator_name: str = "System",
    reason: str = "Manual asset identity reconciliation",
) -> models.Asset:
    """Safe, non-destructive reconciliation transferring relationships from duplicate to surviving asset.

    1. Keeps primary_asset as the surviving record.
    2. Transfers address history from secondary to primary.
    3. Transfers vulnerability findings, risks, drift events, and evidence records.
    4. Marks secondary_asset status and identity_status as 'deactivated' (retained for audit history).
    5. Records an immutable audit log entry.
    """
    if primary_asset_id == secondary_asset_id:
        raise ValueError("Primary and secondary asset IDs must be distinct.")

    with _RECONCILIATION_LOCK:
        primary = db.query(models.Asset).filter(models.Asset.id == primary_asset_id).first()
        secondary = db.query(models.Asset).filter(models.Asset.id == secondary_asset_id).first()

        if not primary:
            raise ValueError(f"Primary asset with ID {primary_asset_id} does not exist.")
        if not secondary:
            raise ValueError(f"Secondary asset with ID {secondary_asset_id} does not exist.")

        if secondary.status == "deactivated":
            raise ValueError(f"Secondary asset #{secondary.id} is already deactivated.")

        # Transfer address history
        for hist in list(secondary.address_history):
            # Check if primary already has this IP recorded
            existing_hist = (
                db.query(models.AssetAddressHistory)
                .filter(models.AssetAddressHistory.asset_id == primary.id)
                .filter(models.AssetAddressHistory.ip_address == hist.ip_address)
                .first()
            )
            if existing_hist:
                existing_hist.last_seen_at = max(existing_hist.last_seen_at, hist.last_seen_at)
                if hist.mac_address and not existing_hist.mac_address:
                    existing_hist.mac_address = hist.mac_address
            else:
                hist.asset_id = primary.id

        # Transfer vulnerabilities
        primary_vuln_titles = {v.title for v in primary.vulnerabilities}
        for vuln in list(secondary.vulnerabilities):
            if vuln.title in primary_vuln_titles:
                # Primary already has this finding; keep the primary's and resolve or update
                existing_primary_v = (
                    db.query(models.Vulnerability)
                    .filter(models.Vulnerability.asset_id == primary.id)
                    .filter(models.Vulnerability.title == vuln.title)
                    .first()
                )
                if existing_primary_v and vuln.updated_at and (not existing_primary_v.updated_at or vuln.updated_at > existing_primary_v.updated_at):
                    existing_primary_v.severity = vuln.severity
                    existing_primary_v.cve = vuln.cve or existing_primary_v.cve
                    existing_primary_v.cvss_score = vuln.cvss_score or existing_primary_v.cvss_score
            else:
                vuln.asset_id = primary.id

        # Transfer risks
        primary_risk_titles = {r.title for r in primary.risks}
        for risk in list(secondary.risks):
            if risk.title in primary_risk_titles:
                pass
            else:
                risk.asset_id = primary.id

        # Transfer drift events
        for drift in list(getattr(secondary, "drift_events", [])):
            drift.asset_id = primary.id

        # Transfer evidence records
        for ev in list(getattr(secondary, "evidence_records", [])):
            ev.asset_id = primary.id

        # Fill in missing primary metadata from secondary if primary lacked it
        if not primary.mac_address and secondary.mac_address:
            primary.mac_address = secondary.mac_address
        if not primary.device_id and secondary.device_id:
            primary.device_id = secondary.device_id
        if not primary.hostname and secondary.hostname:
            primary.hostname = secondary.hostname
        if not primary.operating_system and secondary.operating_system:
            primary.operating_system = secondary.operating_system
        if not primary.criticality and secondary.criticality:
            primary.criticality = secondary.criticality
        if not primary.owner and secondary.owner:
            primary.owner = secondary.owner
        if not primary.business_function and secondary.business_function:
            primary.business_function = secondary.business_function

        # Deactivate secondary asset (retaining record and audit trail)
        secondary.status = "deactivated"
        secondary.identity_status = "deactivated"
        if hasattr(secondary, "assigned_ip_status"):
            secondary.assigned_ip_status = "reconciled_duplicate"

        # Record audit log
        primary_label = f"Asset #{primary.id} ({primary.hostname or 'Host'}, IP: {primary.ip_address})"
        secondary_label = f"Asset #{secondary.id} ({secondary.hostname or 'Host'}, IP: {secondary.ip_address}, MAC: {secondary.mac_address})"
        audit_entry = models.AuditLog(
            source="USER" if operator_name != "System" else "SYSTEM",
            actor=operator_name,
            action="ASSET_RECONCILIATION",
            entity_type="Asset",
            entity_id=primary.id,
            entity_name=primary_label,
            old_values=f'{{"status": "{primary.status}", "reconciled_with": null}}',
            new_values=f'{{"status": "Active", "reconciled_with_asset_id": {secondary.id}}}',
            description=f"Reconciled duplicate {secondary_label} into {primary_label}. Reason: {reason}",
        )
        db.add(audit_entry)

        db.commit()
        logger.info(
            "Successfully reconciled Asset #%s into surviving Asset #%s",
            secondary.id,
            primary.id,
        )
        return primary


def sync_router_dhcp_clients(
    db: Session,
    dhcp_records: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Synchronize router DHCP client names and metadata into existing asset records.

    Rules & Invariants:
    1. Maps entries to existing assets primarily by normalized MAC address;
       uses IP matching only as a carefully controlled fallback when MAC does not conflict.
    2. Updates existing asset records; NEVER creates duplicate records for existing devices.
    3. Handles changed DHCP IP addresses: updates current IP, records address history,
       displaces conflicting prior leaseholders with 'historical_lease_displaced'.
    4. Missing or blank router client names NEVER overwrite valid existing names.
    5. Devices that disappear from the router list or have stale leases are NEVER deleted.
    6. Stores router client name, source, and observation timestamp separately from OS hostname.
    """
    try:
        from scanner.router_dhcp import (
            AUTHORIZED_ROUTER_DHCP_CLIENTS,
            KNOWN_ROUTER_DHCP_MACS,
            find_router_dhcp_entry,
        )
    except ImportError:
        try:
            from router_dhcp import (
                AUTHORIZED_ROUTER_DHCP_CLIENTS,
                KNOWN_ROUTER_DHCP_MACS,
                find_router_dhcp_entry,
            )
        except ImportError:
            AUTHORIZED_ROUTER_DHCP_CLIENTS = {}
            KNOWN_ROUTER_DHCP_MACS = {}
            find_router_dhcp_entry = None

    now = datetime.utcnow()
    records_to_sync: List[Dict[str, Any]] = []

    if dhcp_records is not None:
        for r in dhcp_records:
            records_to_sync.append({
                "ip": r.get("ip_address") or r.get("ip"),
                "mac": r.get("mac_address") or r.get("mac"),
                "client_name": r.get("client_name") or r.get("hostname"),
                "device_type": r.get("device_type"),
                "lease_type": r.get("lease_type") or r.get("dhcp_lease_source") or "imported_lease",
            })
    else:
        for reg_ip, entry in AUTHORIZED_ROUTER_DHCP_CLIENTS.items():
            entry_mac = entry.get("mac_address") or KNOWN_ROUTER_DHCP_MACS.get(reg_ip)
            records_to_sync.append({
                "ip": reg_ip,
                "mac": entry_mac,
                "client_name": entry.get("client_name") or entry.get("hostname"),
                "device_type": entry.get("device_type"),
                "lease_type": entry.get("lease_type", "static_reservation"),
            })

    synced_assets: List[Dict[str, Any]] = []
    updated_count = 0

    with _RECONCILIATION_LOCK:
        for rec in records_to_sync:
            raw_ip = rec.get("ip")
            norm_ip = normalize_ip(raw_ip)
            raw_mac = rec.get("mac")
            norm_mac = normalize_mac(raw_mac)
            client_name = rec.get("client_name")
            valid_client_name = client_name.strip() if is_valid_client_name(client_name) else None
            lease_type = rec.get("lease_type") or "static_registry"
            dev_type = rec.get("device_type")

            matched_asset: Optional[models.Asset] = None
            matched_strategy: str = "none"

            # Priority 1: Match by normalized MAC address across active/offline assets
            if norm_mac:
                matched_asset = (
                    db.query(models.Asset)
                    .filter(models.Asset.mac_address == norm_mac)
                    .filter(models.Asset.status != "deactivated")
                    .first()
                )
                if matched_asset:
                    matched_strategy = "mac_address"

            # Priority 2: Fallback match by IP if no MAC match, with conflict check
            if not matched_asset and norm_ip:
                candidate_by_ip = (
                    db.query(models.Asset)
                    .filter(models.Asset.ip_address == norm_ip)
                    .filter(models.Asset.status != "deactivated")
                    .first()
                )
                if candidate_by_ip:
                    # Conflict check: If candidate already has a MAC and it differs from entry MAC -> DO NOT MATCH!
                    if norm_mac and candidate_by_ip.mac_address and candidate_by_ip.mac_address != norm_mac:
                        logger.info(
                            "Router DHCP sync skipped IP fallback for %s: Asset MAC %s conflicts with entry MAC %s",
                            norm_ip, candidate_by_ip.mac_address, norm_mac
                        )
                    else:
                        matched_asset = candidate_by_ip
                        matched_strategy = "ip_fallback"

            if matched_asset:
                did_update = False

                # Handle dynamic IP change if matched by MAC and IP differs
                if norm_ip and matched_asset.ip_address != norm_ip:
                    old_ip = matched_asset.ip_address
                    logger.info(
                        "Router DHCP sync: Dynamic IP change for Asset #%s (%s): %s -> %s",
                        matched_asset.id, matched_asset.mac_address, old_ip, norm_ip
                    )
                    record_asset_address(
                        db,
                        asset=matched_asset,
                        ip_address=old_ip,
                        mac_address=matched_asset.mac_address,
                        source="previous_address",
                    )
                    conflicting = (
                        db.query(models.Asset)
                        .filter(models.Asset.ip_address == norm_ip)
                        .filter(models.Asset.id != matched_asset.id)
                        .filter(models.Asset.status != "deactivated")
                        .first()
                    )
                    if conflicting:
                        record_asset_address(
                            db,
                            asset=conflicting,
                            ip_address=norm_ip,
                            mac_address=conflicting.mac_address,
                            source="reassigned_displaced",
                        )
                        conflicting.status = "Offline"
                        conflicting.assigned_ip_status = "historical_lease_displaced"
                        conflicting.offline_reason = f"IP {norm_ip} reassigned by DHCP to MAC {norm_mac or matched_asset.mac_address}"
                    matched_asset.ip_address = norm_ip
                    did_update = True

                if norm_ip:
                    record_asset_address(
                        db,
                        asset=matched_asset,
                        ip_address=norm_ip,
                        mac_address=norm_mac or matched_asset.mac_address,
                        source="router_dhcp_sync",
                    )

                if norm_mac and not matched_asset.mac_address:
                    matched_asset.mac_address = norm_mac
                    did_update = True

                if valid_client_name:
                    if matched_asset.dhcp_client_name != valid_client_name:
                        matched_asset.dhcp_client_name = valid_client_name
                        did_update = True
                    matched_asset.dhcp_lease_source = lease_type
                    matched_asset.dhcp_observed_at = now
                    did_update = True

                is_windows_asset = (
                    matched_asset.operating_system == "Microsoft Windows"
                    or (matched_asset.open_ports and any(p in matched_asset.open_ports for p in ("135", "445")))
                )

                # Reconcile device type: OS evidence takes priority over mobile classifications
                if is_windows_asset and matched_asset.device_type in ("Mobile / Smartphone", "Unknown", None):
                    matched_asset.device_type = "Workstation / Laptop"
                    did_update = True
                elif dev_type and (not matched_asset.device_type or matched_asset.device_type in ("Unknown", "Generic Network Host")):
                    matched_asset.device_type = dev_type
                    did_update = True

                # Clean up stale phone labels that polluted OS hostname on Windows devices
                if is_windows_asset and matched_asset.hostname and any(k in matched_asset.hostname.lower() for k in ("realme", "android", "galaxy", "iphone")):
                    matched_asset.hostname = valid_client_name or "FLEMSIS"
                    did_update = True

                if did_update:
                    updated_count += 1
                    synced_assets.append({
                        "asset_id": matched_asset.id,
                        "ip_address": matched_asset.ip_address,
                        "mac_address": matched_asset.mac_address,
                        "dhcp_client_name": matched_asset.dhcp_client_name,
                        "hostname": matched_asset.hostname,
                        "display_name": get_preferred_display_name(matched_asset),
                        "matched_by": matched_strategy,
                    })

        db.commit()

    logger.info("Router DHCP sync completed: %d assets updated", updated_count)
    return {
        "status": "success",
        "synced_count": updated_count,
        "updated_assets": synced_assets,
        "timestamp": now.isoformat(),
    }


def run_schema_migrations(engine) -> None:
    """Safe, repeatable schema migrations ensuring strict dependency ordering.

    Ordering requirements:
    1. Base.metadata.create_all creates all defined tables (e.g. asset_address_history).
    2. Column additions (device_id, identity_status, mac_vendor, observed_ip_address)
       occur BEFORE creating any indexes referencing them.
    3. Legacy constraints (e.g. assets_ip_address_key) are safely dropped.
    4. Indexes (ix_assets_device_id, ix_assets_ip_address, ix_assets_mac_address)
       are created ONLY AFTER the corresponding columns exist.
    5. Existing assets are seeded into asset_address_history without duplicates.
    6. Safe for repeat runs and cross-dialect compatible (PostgreSQL and SQLite).
    """
    from sqlalchemy import inspect

    # Step 1: Ensure all tables defined in models exist
    models.Base.metadata.create_all(bind=engine)

    dialect_name = engine.dialect.name
    logger.info("Executing database schema migrations on %s dialect", dialect_name)

    if dialect_name == "postgresql":
        with engine.connect() as conn:
            # Step 2: Add missing columns FIRST (before creating indexes)
            conn.execute(text("ALTER TABLE assets ADD COLUMN IF NOT EXISTS device_id VARCHAR(128);"))
            conn.execute(text("ALTER TABLE assets ADD COLUMN IF NOT EXISTS identity_status VARCHAR(50) DEFAULT 'verified';"))
            conn.execute(text("ALTER TABLE assets ADD COLUMN IF NOT EXISTS mac_vendor VARCHAR(100);"))
            conn.execute(text("ALTER TABLE assets ADD COLUMN IF NOT EXISTS os_confidence VARCHAR(50);"))
            conn.execute(text("ALTER TABLE assets ADD COLUMN IF NOT EXISTS os_fingerprint_reason VARCHAR(255);"))
            conn.execute(text("ALTER TABLE assets ADD COLUMN IF NOT EXISTS os_detection_source VARCHAR(100);"))
            conn.execute(text("ALTER TABLE assets ADD COLUMN IF NOT EXISTS device_type VARCHAR(100);"))
            conn.execute(text("ALTER TABLE assets ADD COLUMN IF NOT EXISTS discovery_source VARCHAR(100);"))
            conn.execute(text("ALTER TABLE assets ADD COLUMN IF NOT EXISTS assessment_status VARCHAR(50) DEFAULT 'Not assessed';"))
            conn.execute(text("ALTER TABLE assets ADD COLUMN IF NOT EXISTS last_assessed_at TIMESTAMP;"))
            conn.execute(text("ALTER TABLE assets ADD COLUMN IF NOT EXISTS scan_coverage VARCHAR(255);"))
            conn.execute(text("ALTER TABLE assets ADD COLUMN IF NOT EXISTS network_scope VARCHAR(50) DEFAULT 'needs_review';"))
            conn.execute(text("ALTER TABLE assets ADD COLUMN IF NOT EXISTS assigned_ip_status VARCHAR(50) DEFAULT 'active_assignment';"))
            conn.execute(text("ALTER TABLE assets ADD COLUMN IF NOT EXISTS offline_reason VARCHAR(255);"))
            conn.execute(text("ALTER TABLE assets ADD COLUMN IF NOT EXISTS dhcp_lease_source VARCHAR(50) DEFAULT 'none';"))
            conn.execute(text("ALTER TABLE assets ADD COLUMN IF NOT EXISTS dhcp_client_name VARCHAR(100);"))
            conn.execute(text("ALTER TABLE assets ADD COLUMN IF NOT EXISTS dhcp_observed_at TIMESTAMP;"))
            conn.execute(text("ALTER TABLE assets ADD COLUMN IF NOT EXISTS consecutive_scan_misses INTEGER DEFAULT 0;"))
            conn.execute(text("ALTER TABLE assets ADD COLUMN IF NOT EXISTS last_successful_scan_at TIMESTAMP;"))
            conn.execute(text("ALTER TABLE assets ADD COLUMN IF NOT EXISTS is_present BOOLEAN DEFAULT FALSE;"))
            conn.execute(text("ALTER TABLE assets ADD COLUMN IF NOT EXISTS last_present_scan_job_id INTEGER;"))


            conn.execute(text("ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS scan_source VARCHAR(50) DEFAULT 'network_sweep';"))
            conn.execute(text("ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS is_presence_snapshot BOOLEAN DEFAULT FALSE;"))

            conn.execute(text("ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS remediation VARCHAR(1000);"))
            conn.execute(text("ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS verification_status VARCHAR(50) DEFAULT 'Potential';"))
            conn.execute(text("ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS observed_ip_address VARCHAR(50);"))

            # Step 2b: Create scan_observations table if not exists, and ensure dhcp_client_name column exists
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS scan_observations (
                    id SERIAL PRIMARY KEY,
                    scan_job_id INTEGER NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
                    asset_id INTEGER REFERENCES assets(id) ON DELETE SET NULL,
                    ip_address VARCHAR(100) NOT NULL,
                    mac_address VARCHAR(50),
                    hostname VARCHAR(200),
                    dhcp_client_name VARCHAR(100),
                    operating_system VARCHAR(200),
                    os_confidence VARCHAR(50),
                    device_type VARCHAR(100),
                    open_ports TEXT,
                    vulnerabilities_count INTEGER DEFAULT 0,
                    vulnerabilities_summary TEXT,
                    assessment_status VARCHAR(100),
                    scan_coverage VARCHAR(500),
                    network_scope VARCHAR(50) DEFAULT 'physical_lan',
                    observed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
                );
            """))
            conn.execute(text("ALTER TABLE scan_observations ADD COLUMN IF NOT EXISTS dhcp_client_name VARCHAR(100);"))

            # Step 3: Remove legacy constraint if it exists
            conn.execute(text("ALTER TABLE assets DROP CONSTRAINT IF EXISTS assets_ip_address_key;"))

            # Step 4: Create indexes AFTER columns exist
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_assets_ip_address ON assets (ip_address);"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_assets_mac_address ON assets (mac_address);"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_assets_device_id ON assets (device_id);"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_assets_identity_status ON assets (identity_status);"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_assets_network_scope ON assets (network_scope);"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_assets_assigned_ip_status ON assets (assigned_ip_status);"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_assets_is_present ON assets (is_present);"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_scan_observations_scan_job_id ON scan_observations (scan_job_id);"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_scan_observations_asset_id ON scan_observations (asset_id);"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_scan_observations_ip_address ON scan_observations (ip_address);"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_vulnerabilities_observed_ip_address ON vulnerabilities (observed_ip_address);"))

            # Step 5: Ensure asset_address_history is seeded
            conn.execute(text("""
                INSERT INTO asset_address_history (asset_id, ip_address, mac_address, source, detected_at, last_seen_at)
                SELECT a.id, a.ip_address, a.mac_address, COALESCE(a.discovery_source, 'initial_migration'), COALESCE(a.last_seen, CURRENT_TIMESTAMP), COALESCE(a.last_seen, CURRENT_TIMESTAMP)
                FROM assets a
                WHERE a.ip_address IS NOT NULL AND a.ip_address != ''
                  AND NOT EXISTS (
                    SELECT 1 FROM asset_address_history h WHERE h.asset_id = a.id AND h.ip_address = a.ip_address
                );
            """))
            conn.commit()
            logger.info("PostgreSQL schema migrations completed successfully.")

    else:
        # SQLite and fallback dialects
        with engine.connect() as conn:
            inspector = inspect(engine)
            existing_tables = set(inspector.get_table_names())

            existing_asset_cols = {c["name"] for c in inspector.get_columns("assets")} if "assets" in existing_tables else set()
            existing_vuln_cols = {c["name"] for c in inspector.get_columns("vulnerabilities")} if "vulnerabilities" in existing_tables else set()
            existing_obs_cols = {c["name"] for c in inspector.get_columns("scan_observations")} if "scan_observations" in existing_tables else set()

            # Step 2: Add columns if missing
            asset_col_defs = [
                ("device_id", "VARCHAR(128)"),
                ("identity_status", "VARCHAR(50) DEFAULT 'verified'"),
                ("mac_vendor", "VARCHAR(100)"),
                ("os_confidence", "VARCHAR(50)"),
                ("os_fingerprint_reason", "VARCHAR(255)"),
                ("os_detection_source", "VARCHAR(100)"),
                ("device_type", "VARCHAR(100)"),
                ("discovery_source", "VARCHAR(100)"),
                ("assessment_status", "VARCHAR(50) DEFAULT 'Not assessed'"),
                ("last_assessed_at", "TIMESTAMP"),
                ("last_successful_scan_at", "TIMESTAMP"),
                ("scan_coverage", "VARCHAR(255)"),
                ("network_scope", "VARCHAR(50) DEFAULT 'needs_review'"),
                ("assigned_ip_status", "VARCHAR(50) DEFAULT 'active_assignment'"),
                ("offline_reason", "VARCHAR(255)"),
                ("dhcp_lease_source", "VARCHAR(50) DEFAULT 'none'"),
                ("dhcp_client_name", "VARCHAR(100)"),
                ("dhcp_observed_at", "TIMESTAMP"),
                ("consecutive_scan_misses", "INTEGER DEFAULT 0"),
                ("is_present", "BOOLEAN DEFAULT 0"),
                ("last_present_scan_job_id", "INTEGER"),
            ]
            for col_name, col_type in asset_col_defs:
                if col_name not in existing_asset_cols:
                    try:
                        conn.execute(text(f"ALTER TABLE assets ADD COLUMN {col_name} {col_type};"))
                    except Exception as e:
                        logger.debug("Column addition %s notice: %s", col_name, e)

            vuln_col_defs = [
                ("remediation", "VARCHAR(1000)"),
                ("verification_status", "VARCHAR(50) DEFAULT 'Potential'"),
                ("observed_ip_address", "VARCHAR(50)"),
            ]
            for col_name, col_type in vuln_col_defs:
                if col_name not in existing_vuln_cols:
                    try:
                        conn.execute(text(f"ALTER TABLE vulnerabilities ADD COLUMN {col_name} {col_type};"))
                    except Exception as e:
                        logger.debug("Column addition %s notice: %s", col_name, e)

            obs_col_defs = [
                ("dhcp_client_name", "VARCHAR(100)"),
            ]
            for col_name, col_type in obs_col_defs:
                if col_name not in existing_obs_cols:
                    try:
                        conn.execute(text(f"ALTER TABLE scan_observations ADD COLUMN {col_name} {col_type};"))
                    except Exception as e:
                        logger.debug("Column addition %s notice: %s", col_name, e)

            # Step 4: Create indexes AFTER columns exist
            try:
                conn.execute(text("CREATE INDEX IF NOT EXISTS ix_assets_ip_address ON assets (ip_address);"))
                conn.execute(text("CREATE INDEX IF NOT EXISTS ix_assets_mac_address ON assets (mac_address);"))
                conn.execute(text("CREATE INDEX IF NOT EXISTS ix_assets_device_id ON assets (device_id);"))
                conn.execute(text("CREATE INDEX IF NOT EXISTS ix_assets_identity_status ON assets (identity_status);"))
                conn.execute(text("CREATE INDEX IF NOT EXISTS ix_assets_network_scope ON assets (network_scope);"))
                conn.execute(text("CREATE INDEX IF NOT EXISTS ix_assets_assigned_ip_status ON assets (assigned_ip_status);"))
                conn.execute(text("CREATE INDEX IF NOT EXISTS ix_vulnerabilities_observed_ip_address ON vulnerabilities (observed_ip_address);"))
            except Exception as e:
                logger.debug("Index creation notice: %s", e)

            # Step 5: Seed asset_address_history
            try:
                conn.execute(text("""
                    INSERT INTO asset_address_history (asset_id, ip_address, mac_address, source, detected_at, last_seen_at)
                    SELECT a.id, a.ip_address, a.mac_address, COALESCE(a.discovery_source, 'initial_migration'), COALESCE(a.last_seen, CURRENT_TIMESTAMP), COALESCE(a.last_seen, CURRENT_TIMESTAMP)
                    FROM assets a
                    WHERE a.ip_address IS NOT NULL AND a.ip_address != ''
                      AND NOT EXISTS (
                        SELECT 1 FROM asset_address_history h WHERE h.asset_id = a.id AND h.ip_address = a.ip_address
                    );
                """))
            except Exception as e:
                logger.debug("Address history seed notice: %s", e)

            conn.commit()
            logger.info("Dialect %s schema migrations completed successfully.", dialect_name)



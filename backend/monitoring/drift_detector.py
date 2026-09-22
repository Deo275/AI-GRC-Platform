"""Deterministic Snapshot Comparison and Drift Detection Engine for Phase 5.

Provides:
- Deterministic identities (normalized IP, port, service).
- Snapshot extraction from database / scan results.
- Drift detection against the latest successfully completed scan baseline.
- DriftEvent record generation linked to scan_job_id.
"""

import ipaddress
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Set, Tuple, Optional, Any
from sqlalchemy.orm import Session

try:
    from models import ScanJob, Asset, Vulnerability, DriftEvent
except ImportError:
    import sys
    from pathlib import Path
    base_dir = Path(__file__).resolve().parent.parent.parent
    if str(base_dir) not in sys.path:
        sys.path.insert(0, str(base_dir))
    from backend.models import ScanJob, Asset, Vulnerability, DriftEvent

logger = logging.getLogger("ai_grc.monitoring.drift")


def normalize_ip(ip_str: str) -> str:
    """Deterministic normalization for IPv4 addresses."""
    return str(ipaddress.ip_address(ip_str.strip()))


def normalize_port_identity(ip: str, port: int, protocol: str = "tcp") -> Tuple[str, int, str]:
    """Deterministic port identity: (normalized_ip, port, protocol)."""
    return (normalize_ip(ip), int(port), str(protocol).strip().lower())


def normalize_service_identity(ip: str, port: int, protocol: str = "tcp", service_name: str = "unknown") -> Tuple[str, int, str, str]:
    """Deterministic service identity: (normalized_ip, port, protocol, service_name)."""
    return (
        normalize_ip(ip),
        int(port),
        str(protocol).strip().lower(),
        str(service_name).strip().lower() if service_name else "unknown",
    )


@dataclass
class AssetSnapshot:
    """Snapshot of technical attributes for an asset at scan time."""
    ip_address: str
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    operating_system: Optional[str] = None
    open_ports: Set[Tuple[int, str]] = field(default_factory=set)  # {(445, 'tcp'), (139, 'tcp')}
    services: Dict[Tuple[int, str], str] = field(default_factory=dict)  # {(445, 'tcp'): 'microsoft-ds'}
    vulnerabilities: Dict[str, Dict[str, Any]] = field(default_factory=dict)  # vuln_title -> vuln_dict


@dataclass
class ScanSnapshot:
    """Aggregated snapshot for a target across all observed hosts."""
    target: str
    scan_job_id: Optional[int] = None
    assets: Dict[str, AssetSnapshot] = field(default_factory=dict)  # normalized_ip -> AssetSnapshot


class DriftDetector:
    """Detects technical changes by comparing current scan results against the baseline."""

    @staticmethod
    def get_baseline_snapshot(db: Session, target: str, current_job_id: Optional[int] = None) -> Optional[ScanSnapshot]:
        """Retrieve baseline snapshot strictly from the latest successfully completed scan for this target.

        Only status == 'Completed' scans are used. Failed or Cancelled scans NEVER become baseline.
        If current_job_id is provided, it is excluded so we don't compare against the current run.
        """
        query = (
            db.query(ScanJob)
            .filter(ScanJob.target == target)
            .filter(ScanJob.status == "Completed")
        )
        if current_job_id is not None:
            query = query.filter(ScanJob.id != current_job_id)

        last_successful_job = query.order_by(ScanJob.completed_at.desc(), ScanJob.id.desc()).first()

        if not last_successful_job:
            return None

        # Build snapshot from database state of assets associated with this target
        snapshot = ScanSnapshot(target=target, scan_job_id=last_successful_job.id)

        # Parse target network to find which assets belong to it
        try:
            target_net = ipaddress.ip_network(target, strict=False)
            all_assets = db.query(Asset).all()
            matched_assets = [a for a in all_assets if ipaddress.ip_address(a.ip_address) in target_net]
        except ValueError:
            matched_assets = db.query(Asset).filter(Asset.ip_address == target).all()

        for asset in matched_assets:
            norm_ip = normalize_ip(asset.ip_address)
            asset_snap = AssetSnapshot(
                ip_address=norm_ip,
                hostname=asset.hostname,
                mac_address=asset.mac_address,
                operating_system=asset.operating_system,
            )

            # Parse open_ports string: "445/microsoft-ds, 139/netbios-ssn" or "445/tcp"
            if asset.open_ports:
                for chunk in asset.open_ports.split(","):
                    chunk = chunk.strip()
                    if "/" in chunk:
                        parts = chunk.split("/", 1)
                        try:
                            p_num = int(parts[0])
                            svc_name = parts[1]
                            proto = "tcp"
                            asset_snap.open_ports.add((p_num, proto))
                            asset_snap.services[(p_num, proto)] = svc_name
                        except ValueError:
                            pass

            # Associated vulnerabilities
            for vuln in asset.vulnerabilities:
                if vuln.status == "Open":
                    asset_snap.vulnerabilities[vuln.title] = {
                        "id": vuln.id,
                        "title": vuln.title,
                        "port": vuln.port,
                        "cve": vuln.cve,
                        "cvss_score": vuln.cvss_score,
                        "severity": vuln.severity or "Medium",
                    }

            snapshot.assets[norm_ip] = asset_snap

        return snapshot

    @staticmethod
    def build_snapshot_from_scan_results(target: str, scan_results: List[Dict[str, Any]], scan_job_id: int) -> ScanSnapshot:
        """Construct a ScanSnapshot from fresh raw scan pipeline results."""
        snapshot = ScanSnapshot(target=target, scan_job_id=scan_job_id)

        for host_data in scan_results:
            raw_ip = host_data.get("ip_address")
            if not raw_ip:
                continue
            norm_ip = normalize_ip(raw_ip)

            asset_snap = AssetSnapshot(
                ip_address=norm_ip,
                hostname=host_data.get("hostname"),
                mac_address=host_data.get("mac_address"),
                operating_system=host_data.get("operating_system"),
            )

            for port_info in host_data.get("open_ports", []):
                try:
                    p_num = int(port_info["port"])
                    proto = port_info.get("protocol", "tcp").lower()
                    svc = port_info.get("service", "unknown")
                    asset_snap.open_ports.add((p_num, proto))
                    asset_snap.services[(p_num, proto)] = svc
                except (ValueError, KeyError):
                    continue

            for vuln in host_data.get("vulnerabilities", []):
                v_title = vuln.get("title")
                if v_title:
                    asset_snap.vulnerabilities[v_title] = {
                        "title": v_title,
                        "port": vuln.get("port"),
                        "cve": vuln.get("cve"),
                        "cvss_score": vuln.get("cvss_score"),
                        "severity": vuln.get("severity") or "Medium",
                    }

            snapshot.assets[norm_ip] = asset_snap

        return snapshot

    @classmethod
    def detect_drift(
        cls,
        baseline: Optional[ScanSnapshot],
        current: ScanSnapshot,
        scan_job_id: int,
        existing_db_ips: Optional[Set[str]] = None,
        asset_id_map: Optional[Dict[str, int]] = None,
    ) -> List[Dict[str, Any]]:
        """Compare current snapshot against baseline and generate drift events.

        Events detected:
        - NEW_ASSET: New host detected that was not in baseline or DB.
        - PORT_OPENED: Port present in current but absent in baseline.
        - PORT_CLOSED: Port present in baseline but absent in current.
        - CVE_DETECTED: Vulnerability/CVE finding established by scanner.
        - FINDING_RESOLVED: Finding in baseline no longer observed.
        """
        events: List[Dict[str, Any]] = []
        if existing_db_ips is None:
            existing_db_ips = set()
        if asset_id_map is None:
            asset_id_map = {}

        now = datetime.utcnow()

        # 1. Initial Scan (No previous baseline completed)
        if baseline is None:
            for ip, curr_asset in current.assets.items():
                asset_id = asset_id_map.get(ip)
                # If asset was not previously in the DB at all
                if ip not in existing_db_ips:
                    events.append({
                        "scan_job_id": scan_job_id,
                        "asset_id": asset_id,
                        "event_type": "NEW_ASSET",
                        "title": f"New Asset Discovered: {ip}",
                        "description": f"Host {ip} discovered on network. Technical attributes recorded; business context remains unclassified.",
                        "severity": "Low",
                        "detected_at": now,
                    })

                # In initial baseline, confirmed high/critical CVE findings established by existing pipeline
                for v_title, v_data in curr_asset.vulnerabilities.items():
                    if v_data.get("cve"):
                        sev = v_data.get("severity", "Medium")
                        events.append({
                            "scan_job_id": scan_job_id,
                            "asset_id": asset_id,
                            "event_type": "CVE_DETECTED",
                            "title": f"Vulnerability Identified: {v_title} ({v_data.get('cve')})",
                            "description": f"Established technical finding on {ip} port {v_data.get('port')}. CVSS score: {v_data.get('cvss_score')}.",
                            "severity": sev,
                            "detected_at": now,
                        })

            return events

        # 2. Rescan against Existing Baseline
        # Check for new assets
        for ip, curr_asset in current.assets.items():
            asset_id = asset_id_map.get(ip)
            if ip not in baseline.assets and ip not in existing_db_ips:
                events.append({
                    "scan_job_id": scan_job_id,
                    "asset_id": asset_id,
                    "event_type": "NEW_ASSET",
                    "title": f"New Asset Discovered: {ip}",
                    "description": f"New host {ip} detected on network. Unclassified until assigned by operator.",
                    "severity": "Low",
                    "detected_at": now,
                })

            # Check port changes for host
            prev_asset = baseline.assets.get(ip)
            if prev_asset:
                # Newly opened ports
                opened_ports = curr_asset.open_ports - prev_asset.open_ports
                for p_num, proto in sorted(opened_ports):
                    svc = curr_asset.services.get((p_num, proto), "unknown")
                    # Rate severity higher for high-risk ports
                    if p_num in (445, 139, 3389):
                        port_sev = "High"
                    elif p_num in (135, 5432, 3306, 1433, 22, 23):
                        port_sev = "Medium"
                    else:
                        port_sev = "Low"

                    events.append({
                        "scan_job_id": scan_job_id,
                        "asset_id": asset_id,
                        "event_type": "PORT_OPENED",
                        "title": f"Port {p_num}/{proto} Opened on {ip} ({svc})",
                        "description": f"New open service '{svc}' detected on port {p_num}/{proto}. Potential attack surface expansion.",
                        "severity": port_sev,
                        "detected_at": now,
                    })

                # Closed ports
                closed_ports = prev_asset.open_ports - curr_asset.open_ports
                for p_num, proto in sorted(closed_ports):
                    prev_svc = prev_asset.services.get((p_num, proto), "unknown")
                    events.append({
                        "scan_job_id": scan_job_id,
                        "asset_id": asset_id,
                        "event_type": "PORT_CLOSED",
                        "title": f"Port {p_num}/{proto} Closed on {ip} ({prev_svc})",
                        "description": f"Service on port {p_num}/{proto} ({prev_svc}) is no longer listening or accessible.",
                        "severity": "Low",
                        "detected_at": now,
                    })

                # Vulnerability drift
                # New CVEs / findings
                for v_title, v_data in curr_asset.vulnerabilities.items():
                    if v_title not in prev_asset.vulnerabilities:
                        cve_id = v_data.get("cve")
                        cve_suffix = f" ({cve_id})" if cve_id else ""
                        events.append({
                            "scan_job_id": scan_job_id,
                            "asset_id": asset_id,
                            "event_type": "CVE_DETECTED",
                            "title": f"Vulnerability Detected: {v_title}{cve_suffix}",
                            "description": f"Finding '{v_title}' on port {v_data.get('port')} (CVE: {cve_id}, CVSS: {v_data.get('cvss_score')}).",
                            "severity": v_data.get("severity", "Medium"),
                            "detected_at": now,
                        })

                # Resolved findings
                for v_title, v_data in prev_asset.vulnerabilities.items():
                    if v_title not in curr_asset.vulnerabilities:
                        events.append({
                            "scan_job_id": scan_job_id,
                            "asset_id": asset_id,
                            "event_type": "FINDING_RESOLVED",
                            "title": f"Vulnerability Resolved: {v_title}",
                            "description": f"Finding '{v_title}' previously present on port {v_data.get('port')} is no longer observed.",
                            "severity": "Low",
                            "detected_at": now,
                        })

        return events

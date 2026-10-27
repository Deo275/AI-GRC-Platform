"""Bounded Asynchronous Scan Worker and Job Execution Pool for Phase 5.

Provides:
- ScanWorkerPool: Manages a bounded ThreadPoolExecutor(max_workers=3).
- Cooperative cancellation with active subprocess termination.
- Isolated SessionLocal() lifecycle per worker thread.
- Multi-host subnet scanning, asset persistence, vulnerability correlation,
  drift detection, and authoritative GRC recalculation.
"""

import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Dict, Optional, List, Any
import subprocess

try:
    from database import SessionLocal
    import models
except ImportError:
    import sys
    from pathlib import Path
    base_dir = Path(__file__).resolve().parent.parent
    if str(base_dir) not in sys.path:
        sys.path.insert(0, str(base_dir))
    from backend.database import SessionLocal
    import backend.models as models

import ipaddress
import json
import os

from scanner.grc_engine import (
    criticality_to_impact,
    calculate_likelihood,
    calculate_inherent_risk,
    calculate_residual_risk,
)
from .scanner_pipeline import MonitoringScannerPipeline, validate_target_network
from .drift_detector import DriftDetector, normalize_ip
from .drift_detector import DriftDetector, normalize_ip
from .remote_agent import NmapAgentClient, NmapAgentError
from .asset_identity import (
    find_existing_asset,
    upsert_discovered_asset,
    record_asset_address,
    normalize_mac,
)
try:
    from scanner.vulnerability_scanner import identify_vulnerabilities
    from scanner.risk_engine import calculate_risk
    from scanner.os_identifier import identify_os_and_device
    from scanner.router_dhcp import (
        get_authorized_dhcp_info,
        get_authorized_dhcp_info_for_host,
        AUTHORIZED_ROUTER_DHCP_CLIENTS,
    )
except ImportError:
    import sys
    from pathlib import Path
    base_dir = Path(__file__).resolve().parent.parent.parent
    if str(base_dir) not in sys.path:
        sys.path.insert(0, str(base_dir))
    from scanner.vulnerability_scanner import identify_vulnerabilities
    from scanner.risk_engine import calculate_risk
    from scanner.os_identifier import identify_os_and_device
    from scanner.router_dhcp import (
        get_authorized_dhcp_info,
        get_authorized_dhcp_info_for_host,
        AUTHORIZED_ROUTER_DHCP_CLIENTS,
    )

logger = logging.getLogger("ai_grc.monitoring.worker")

MAX_SCAN_WORKERS = 3
DEFAULT_MAX_PENDING_JOBS = 10


def is_special_or_boundary_ip(ip_str: str, target_cidr: Optional[str] = None) -> bool:
    """Check if IP is a broadcast, network, loopback, or multicast address."""
    try:
        addr = ipaddress.ip_address(ip_str)
        if addr.is_multicast or addr.is_loopback or addr.is_link_local or addr.is_unspecified:
            return True
        if target_cidr and "/" in target_cidr:
            net = ipaddress.ip_network(target_cidr, strict=False)
            if addr == net.network_address or addr == net.broadcast_address:
                return True
        parts = ip_str.split(".")
        if len(parts) == 4 and (parts[3] == "0" or parts[3] == "255"):
            return True
    except Exception:
        pass
    return False


def recalculate_asset_grc_risks(asset: models.Asset):
    """Deterministically recalculate inherent and residual risks for an asset."""
    impact = criticality_to_impact(asset.criticality)
    for risk in asset.risks:
        likelihood = calculate_likelihood(
            severity_str=risk.likelihood,
            exposure=asset.exposure,
            fallback_likelihood=risk.likelihood,
        )
        inh = calculate_inherent_risk(likelihood, impact)
        res = calculate_residual_risk(likelihood, impact, risk.controls)

        risk.likelihood_score = inh["likelihood_score"]
        risk.impact_score = inh["impact_score"]
        risk.inherent_risk_score = inh["inherent_risk_score"]
        risk.inherent_risk_level = inh["inherent_risk_level"]
        risk.residual_likelihood = res["residual_likelihood"]
        risk.residual_impact = res["residual_impact"]
        risk.residual_risk_score = res["residual_risk_score"]
        risk.residual_risk_level = res["residual_risk_level"]
        risk.updated_at = datetime.utcnow()


class ScanWorkerPool:
    """Bounded worker pool for asynchronous scan execution."""

    def __init__(
        self,
        max_workers: int = MAX_SCAN_WORKERS,
        pipeline: Optional[MonitoringScannerPipeline] = None,
        max_pending_jobs: int = DEFAULT_MAX_PENDING_JOBS,
    ):
        self.max_workers = max_workers
        self.max_pending_jobs = max_pending_jobs
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.pipeline = pipeline or MonitoringScannerPipeline(
            enable_os_detection=os.getenv("ENABLE_OS_DETECTION", "true").strip().lower() in ("true", "1", "yes")
        )

        self._lock = threading.Lock()
        self._cancel_events: Dict[int, threading.Event] = {}
        self._active_processes: Dict[int, subprocess.Popen] = {}
        self._active_agent_jobs: Dict[int, str] = {}
        self._futures: Dict[int, Any] = {}

    def get_pending_job_count(self) -> int:
        """Return the count of active and queued jobs currently in the worker pool."""
        with self._lock:
            done_keys = [jid for jid, f in self._futures.items() if hasattr(f, "done") and f.done()]
            for jid in done_keys:
                self._futures.pop(jid, None)
                self._cancel_events.pop(jid, None)
                self._active_agent_jobs.pop(jid, None)
            return len(self._futures)

    def can_accept_job(self) -> bool:
        """Check whether the worker pool has capacity for an additional scan job."""
        return self.get_pending_job_count() < self.max_pending_jobs

    def submit_scan_job(self, job_id: int) -> bool:
        """Submit a job to the worker pool if within capacity bounds.

        If the maximum active + queued scan jobs limit is reached, returns False.
        """
        with self._lock:
            done_keys = [jid for jid, f in self._futures.items() if hasattr(f, "done") and f.done()]
            for jid in done_keys:
                self._futures.pop(jid, None)
                self._cancel_events.pop(jid, None)
                self._active_agent_jobs.pop(jid, None)

            if len(self._futures) >= self.max_pending_jobs:
                logger.warning(
                    f"ScanWorkerPool reached maximum capacity ({len(self._futures)}/{self.max_pending_jobs}). "
                    f"ScanJob #{job_id} cannot be accepted."
                )
                return False
            cancel_event = threading.Event()
            self._cancel_events[job_id] = cancel_event

            future = self.executor.submit(self._execute_scan_job, job_id, cancel_event)
            self._futures[job_id] = future
            return True

    def cancel_scan_job(self, job_id: int) -> bool:
        """Cooperatively cancel a scan job.

        1. Set cancellation event.
        2. Attempt to cancel future if still queued in executor.
        3. Cancel remote Pi agent job if running.
        4. Terminate active local Nmap subprocess if running.
        5. Mark the job Cancelled in the database.
        """
        with self._lock:
            cancel_event = self._cancel_events.get(job_id)
            active_proc = self._active_processes.get(job_id)
            agent_job_id = self._active_agent_jobs.get(job_id)
            future = self._futures.get(job_id)

        if cancel_event:
            cancel_event.set()

        # If future is still queued in executor and hasn't started, cancel directly
        if future and hasattr(future, "cancel") and future.cancel():
            with self._lock:
                self._futures.pop(job_id, None)
                self._cancel_events.pop(job_id, None)
                self._active_agent_jobs.pop(job_id, None)

        # Cancel remote agent job if active
        if agent_job_id:
            try:
                agent_token = os.getenv("NMAP_AGENT_TOKEN", "").strip()
                agent_url = os.getenv("NMAP_AGENT_URL", "").strip()
                if agent_token:
                    NmapAgentClient(base_url=agent_url or None, token=agent_token).cancel_job(agent_job_id)
                    logger.info("Sent cancellation request for backend job %s to Pi agent job %s", job_id, agent_job_id)
            except Exception as e:
                logger.warning(f"Error cancelling Pi agent job {agent_job_id} for backend job {job_id}: {e}")

        # Terminate active process if running
        if active_proc is not None:
            logger.info(f"Terminating active subprocess for job {job_id}...")
            try:
                active_proc.terminate()
                try:
                    active_proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    active_proc.kill()
                    active_proc.wait(timeout=5)
            except Exception as e:
                logger.warning(f"Error terminating subprocess for job {job_id}: {e}")

        # Update DB status to Cancelled with clean session
        db = SessionLocal()
        try:
            job = db.query(models.ScanJob).filter(models.ScanJob.id == job_id).first()
            if job and job.status in ("Queued", "Running"):
                job.status = "Cancelled"
                job.completed_at = datetime.utcnow()
                db.commit()
                logger.info(f"Scan job {job_id} marked as Cancelled.")
                return True
        finally:
            db.close()

        return False

    def is_job_cancelled(self, job_id: int) -> bool:
        with self._lock:
            event = self._cancel_events.get(job_id)
            return bool(event and event.is_set())

    def _execute_scan_job(self, job_id: int, cancel_event: threading.Event):
        """Worker thread entry point for executing a scan job."""
        db = SessionLocal()
        job = None
        try:
            job = db.query(models.ScanJob).filter(models.ScanJob.id == job_id).first()
            if not job:
                logger.error(f"ScanJob {job_id} not found in database.")
                return

            if cancel_event.is_set() or job.status == "Cancelled":
                logger.info(f"Job {job_id} was cancelled before starting.")
                job.status = "Cancelled"
                job.completed_at = datetime.utcnow()
                db.commit()
                return

            job.status = "Running"
            job.started_at = datetime.utcnow()
            job.progress_percent = 10
            db.commit()

            target = job.target

            # Process callback to register active subprocess for cooperative cancellation
            def on_process_created(proc: subprocess.Popen):
                with self._lock:
                    self._active_processes[job_id] = proc

            def check_cancelled() -> bool:
                return cancel_event.is_set()

            # Retrieve baseline snapshot strictly from the latest successfully completed scan
            baseline_snapshot = DriftDetector.get_baseline_snapshot(db, target, current_job_id=job_id)

            # Stage 1: Live host discovery
            # Priority 1: Physical LAN Discovery via Raspberry Pi Agent (L2 ARP visibility)
            # Priority 2: Multi-Probe Container Discovery Fallback
            agent_client = None
            agent_token = os.getenv("NMAP_AGENT_TOKEN", "").strip()
            agent_url = os.getenv("NMAP_AGENT_URL", "").strip()
            use_agent = False
            discovered_hosts_info: List[Dict[str, Any]] = []

            fallback_reason: Optional[str] = None
            is_subnet = "/" in target and not target.endswith("/32")
            configured_cidr = os.getenv("NMAP_NETWORK_CIDR", "192.168.1.0/24").strip()
            is_agent_target = is_subnet and (target == configured_cidr or target in ("192.168.1.0/24", "auto", "current_lan"))

            if agent_token and is_agent_target:
                try:
                    agent_client = NmapAgentClient(base_url=agent_url or None, token=agent_token)
                    logger.info("Attempting physical LAN discovery via Raspberry Pi agent on target %s", target)
                    raw_agent_hosts = agent_client.discover_hosts(target)
                    if isinstance(raw_agent_hosts, list):
                        use_agent = True
                        logger.info(
                            "Raspberry Pi agent successfully discovered %d hosts on physical LAN for %s",
                            len(raw_agent_hosts),
                            target,
                        )
                        for h in raw_agent_hosts:
                            if not isinstance(h, dict):
                                continue
                            ip = h.get("ip_address") or h.get("ip")
                            if not ip or not isinstance(ip, str):
                                continue
                            norm = normalize_ip(ip)
                            if is_special_or_boundary_ip(norm, target):
                                continue
                            mac_addr = normalize_mac(h.get("mac_address") or h.get("mac"))
                            hostnames = h.get("hostnames") or []
                            hostname = h.get("hostname") or (hostnames[0] if hostnames else None)
                            dhcp_meta = get_authorized_dhcp_info_for_host(norm, mac=mac_addr)
                            dhcp_name = (dhcp_meta.get("client_name") or dhcp_meta.get("hostname")) if dhcp_meta else None
                            device_type = (dhcp_meta.get("device_type") if dhcp_meta else None) or h.get("device_type")
                            discovered_hosts_info.append({
                                "ip_address": norm,
                                "hostname": hostname,
                                "mac_address": mac_addr,
                                "vendor": h.get("vendor"),
                                "operating_system": h.get("operating_system"),
                                "open_ports": h.get("open_ports") or [],
                                "discovery_source": "pi_agent_l2",
                                "network_scope": "physical_lan" if is_agent_target else None,
                                "device_type": device_type,
                                "dhcp_info": dhcp_meta,
                                "dhcp_lease_source": dhcp_meta.get("dhcp_lease_source") if dhcp_meta else "none",
                                "dhcp_client_name": dhcp_name,
                                "dhcp_observed_at": datetime.utcnow() if dhcp_meta else None,
                            })
                except Exception as agent_exc:
                    fallback_reason = f"Raspberry Pi agent unavailable: {agent_exc}. Container fallback scan used."
                    logger.warning(
                        "Raspberry Pi agent discovery unavailable or failed for target %s: %s. "
                        "Falling back to container multi-probe discovery.",
                        target,
                        agent_exc,
                    )
                    use_agent = False
            elif is_subnet:
                fallback_reason = "Raspberry Pi agent not configured. Container multi-probe scan used."

            if not use_agent:
                # Stage 1 Fallback: Container multi-probe ping sweep
                if check_cancelled():
                    self._handle_cancellation(job, db, job_id)
                    return

                raw_live_hosts = self.pipeline.discover_live_hosts(
                    target=target,
                    process_callback=on_process_created,
                    cancellation_check=check_cancelled,
                )

                with self._lock:
                    self._active_processes.pop(job_id, None)

                if check_cancelled():
                    self._handle_cancellation(job, db, job_id)
                    return

                disc_meta = getattr(self.pipeline, "last_discovery_metadata", {}) or {}
                for host_ip in raw_live_hosts:
                    norm = normalize_ip(host_ip)
                    if is_special_or_boundary_ip(norm, target):
                        continue
                    meta = disc_meta.get(host_ip, {}) if isinstance(disc_meta, dict) else {}
                    mac_addr = normalize_mac(meta.get("mac_address"))
                    dhcp_meta = get_authorized_dhcp_info_for_host(norm, mac=mac_addr)
                    dhcp_name = (dhcp_meta.get("client_name") or dhcp_meta.get("hostname")) if dhcp_meta else None
                    hostname = meta.get("hostname")
                    device_type = (dhcp_meta.get("device_type") if dhcp_meta else None)
                    discovered_hosts_info.append({
                        "ip_address": norm,
                        "hostname": hostname,
                        "mac_address": mac_addr,
                        "vendor": meta.get("vendor"),
                        "operating_system": None,
                        "open_ports": [],
                        "discovery_source": "container_fallback_multiprobe",
                        "network_scope": "physical_lan" if is_agent_target else None,
                        "device_type": device_type,
                        "dhcp_info": dhcp_meta,
                        "dhcp_lease_source": dhcp_meta.get("dhcp_lease_source") if dhcp_meta else "none",
                        "dhcp_client_name": dhcp_name,
                        "dhcp_observed_at": datetime.utcnow() if dhcp_meta else None,
                    })

            if check_cancelled():
                self._handle_cancellation(job, db, job_id)
                return

            job.progress_percent = 30
            db.commit()

            # Stage 2: Host port scanning & enumeration
            scan_results: List[Dict[str, Any]] = []
            total_hosts = len(discovered_hosts_info)

            for idx, host_info in enumerate(discovered_hosts_info):
                if check_cancelled():
                    self._handle_cancellation(job, db, job_id)
                    return

                host_ip = host_info["ip_address"]
                host_result = dict(host_info)

                if use_agent and agent_client:
                    try:
                        scan_res = agent_client.scan_host(host_ip)
                        if isinstance(scan_res, dict):
                            if scan_res.get("open_ports"):
                                host_result["open_ports"] = scan_res["open_ports"]
                            if scan_res.get("operating_system"):
                                host_result["operating_system"] = scan_res["operating_system"]
                            if scan_res.get("hostname") and not host_result.get("hostname"):
                                host_result["hostname"] = scan_res["hostname"]
                            if scan_res.get("mac_address") and not host_result.get("mac_address"):
                                host_result["mac_address"] = scan_res["mac_address"]
                            if scan_res.get("vendor") and not host_result.get("vendor"):
                                host_result["vendor"] = scan_res["vendor"]
                            if scan_res.get("cpe"):
                                host_result["cpe"] = scan_res["cpe"]
                    except Exception as scan_err:
                        logger.warning(
                            "Direct agent port scan failed for host %s: %s. Retaining discovered host in inventory.",
                            host_ip,
                            scan_err,
                        )
                        # Safe fallback to local pipeline probe if agent errored on this host
                        try:
                            local_res = self.pipeline.scan_single_host(
                                host_ip=host_ip,
                                process_callback=on_process_created,
                                cancellation_check=check_cancelled,
                            )
                            if isinstance(local_res, dict) and local_res.get("open_ports"):
                                host_result["open_ports"] = local_res["open_ports"]
                        except Exception:
                            pass
                        finally:
                            with self._lock:
                                self._active_processes.pop(job_id, None)
                else:
                    # Scan single host locally
                    try:
                        local_res = self.pipeline.scan_single_host(
                            host_ip=host_ip,
                            process_callback=on_process_created,
                            cancellation_check=check_cancelled,
                        )
                        if isinstance(local_res, dict):
                            if local_res.get("open_ports"):
                                host_result["open_ports"] = local_res["open_ports"]
                            if local_res.get("operating_system"):
                                host_result["operating_system"] = local_res["operating_system"]
                            if local_res.get("hostname") and not host_result.get("hostname"):
                                host_result["hostname"] = local_res["hostname"]
                            if local_res.get("mac_address") and not host_result.get("mac_address"):
                                host_result["mac_address"] = local_res["mac_address"]
                            if local_res.get("vendor") and not host_result.get("vendor"):
                                host_result["vendor"] = local_res["vendor"]
                    except Exception as scan_err:
                        logger.warning(
                            "[HOST SCAN WARNING] Host %s detailed port scan encountered an error: %s. "
                            "Retaining discovered host in active asset inventory with 0 open ports.",
                            host_ip,
                            scan_err,
                        )
                        host_result["scan_failed"] = True
                        host_result["scan_failure_reason"] = str(scan_err)
                    finally:
                        with self._lock:
                            self._active_processes.pop(job_id, None)

                if check_cancelled():
                    self._handle_cancellation(job, db, job_id)
                    return

                # Stage 3: OS & Device Identification
                os_info = identify_os_and_device(host_result)
                host_result["operating_system"] = os_info.get("operating_system") or "Unknown"
                host_result["os_confidence"] = os_info.get("os_confidence")
                host_result["os_fingerprint_reason"] = os_info.get("os_fingerprint_reason")
                host_result["os_detection_source"] = os_info.get("detection_source")
                host_result["device_type"] = os_info.get("device_type") or host_result.get("device_type") or "Unknown"

                # Stage 4: Vulnerability & Risk Calculation
                open_ports = host_result.get("open_ports") or []
                host_vulns = identify_vulnerabilities(open_ports)
                host_result["vulnerabilities"] = host_vulns

                # Retrieve existing asset context if in DB (for criticality/exposure weighting)
                existing_asset, _, _ = find_existing_asset(db, host_result)
                asset_ctx = {
                    "criticality": existing_asset.criticality if existing_asset else None,
                    "exposure": existing_asset.exposure if existing_asset else None,
                    "scan_failed": host_result.get("scan_failed", False),
                    "scan_failure_reason": host_result.get("scan_failure_reason"),
                }
                risk_res = calculate_risk(
                    open_ports=open_ports if not host_result.get("scan_failed") else None,
                    vulnerabilities=host_vulns,
                    asset_context=asset_ctx,
                )
                host_result["risk_result"] = risk_res

                if host_result.get("scan_failed"):
                    host_result["assessment_status"] = "Assessment failed"
                    host_result["scan_coverage"] = f"Scan failed: {host_result.get('scan_failure_reason', 'Host probe error')}"
                elif len(open_ports) == 0:
                    host_result["assessment_status"] = "Completed — no findings detected"
                    host_result["scan_coverage"] = "0 open ports detected across scanned scope (host firewall or device isolation may restrict inbound service exposure)"
                else:
                    host_result["assessment_status"] = risk_res.get("assessment_status", "Completed — no findings detected" if not host_vulns else "Findings detected")
                    host_result["scan_coverage"] = f"{len(open_ports)} open port(s) evaluated"

                scan_results.append(host_result)

                # Update incremental progress
                if total_hosts > 0:
                    pct = 30 + int((idx + 1) / total_hosts * 40)
                    job.progress_percent = min(pct, 70)
                    db.commit()

            # Build current snapshot from scan results
            current_snapshot = DriftDetector.build_snapshot_from_scan_results(
                target=target,
                scan_results=scan_results,
                scan_job_id=job_id,
            )

            # Persist Assets, Vulnerabilities, Risks into PostgreSQL
            existing_db_ips = {normalize_ip(a.ip_address) for a in db.query(models.Asset).filter(models.Asset.status != "deactivated").all()}
            asset_id_map: Dict[str, int] = {}
            total_vulns = 0

            for host_data in scan_results:
                raw_ip = host_data["ip_address"]
                norm_ip = normalize_ip(raw_ip)

                risk_res = host_data.get("risk_result", {})

                # Reconcile or create asset using stable identity hierarchy
                asset, is_new, match_strat = upsert_discovered_asset(
                    db=db,
                    host_data=host_data,
                    default_criticality=None,
                    source=host_data.get("discovery_source", "network_scan"),
                )

                asset_id_map[norm_ip] = asset.id

                # Update live presence if this is a physical LAN discovery sweep
                if is_agent_target or target == configured_cidr:
                    if getattr(asset, "network_scope", None) == "physical_lan":
                        asset.is_present = True
                        asset.last_present_scan_job_id = job.id
                        asset.last_successful_scan_at = datetime.utcnow()
                        asset.consecutive_scan_misses = 0

                # Record ScanObservation for permanent scan history
                try:
                    open_ports_val = host_data.get("open_ports") or []
                    if isinstance(open_ports_val, (list, tuple)):
                        open_ports_str = json.dumps(open_ports_val)
                    else:
                        open_ports_str = str(open_ports_val)

                    vulns_list = host_data.get("vulnerabilities") or []
                    vulns_summary_list = [v.get("title") for v in vulns_list if isinstance(v, dict) and v.get("title")]

                    obs = models.ScanObservation(
                        scan_job_id=job.id,
                        asset_id=asset.id,
                        ip_address=norm_ip,
                        mac_address=host_data.get("mac_address"),
                        hostname=host_data.get("hostname"),
                        dhcp_client_name=host_data.get("dhcp_client_name") or getattr(asset, "dhcp_client_name", None),
                        operating_system=host_data.get("operating_system"),
                        os_confidence=host_data.get("os_confidence"),
                        device_type=host_data.get("device_type"),
                        open_ports=open_ports_str,
                        vulnerabilities_count=len(vulns_list),
                        vulnerabilities_summary=json.dumps(vulns_summary_list),
                        assessment_status=host_data.get("assessment_status"),
                        scan_coverage=host_data.get("scan_coverage"),
                        network_scope=getattr(asset, "network_scope", "physical_lan") or "physical_lan",
                        observed_at=datetime.utcnow(),
                    )
                    db.add(obs)
                except Exception as obs_exc:
                    logger.warning("Error creating ScanObservation for %s: %s", norm_ip, obs_exc)

                # Update vulnerabilities for this asset
                current_vuln_titles = set()
                for v in host_data.get("vulnerabilities", []):
                    v_title = v.get("title")
                    if not v_title:
                        continue
                    current_vuln_titles.add(v_title)
                    total_vulns += 1

                    existing_v = (
                        db.query(models.Vulnerability)
                        .filter(models.Vulnerability.asset_id == asset.id)
                        .filter(models.Vulnerability.title == v_title)
                        .first()
                    )

                    if existing_v:
                        existing_v.severity = v.get("severity") or existing_v.severity
                        existing_v.cve = v.get("cve") or existing_v.cve
                        existing_v.cvss_score = v.get("cvss_score") or existing_v.cvss_score
                        existing_v.cvss_version = v.get("cvss_version") or existing_v.cvss_version
                        existing_v.cve_confidence = v.get("cve_confidence") or existing_v.cve_confidence
                        existing_v.remediation = v.get("remediation") or existing_v.remediation
                        existing_v.verification_status = v.get("verification_status") or existing_v.verification_status
                        existing_v.observed_ip_address = norm_ip
                        existing_v.status = "Open"
                        existing_v.updated_at = datetime.utcnow()
                    else:
                        new_v = models.Vulnerability(
                            asset_id=asset.id,
                            port=int(v.get("port")) if v.get("port") else None,
                            service=v.get("service"),
                            product=v.get("product"),
                            version=v.get("version"),
                            title=v_title,
                            severity=v.get("severity") or "Medium",
                            description=v.get("description"),
                            cve=v.get("cve"),
                            cvss_score=v.get("cvss_score"),
                            cvss_version=v.get("cvss_version"),
                            cve_confidence=v.get("cve_confidence") or "Unknown",
                            remediation=v.get("remediation"),
                            verification_status=v.get("verification_status") or "Potential",
                            observed_ip_address=norm_ip,
                            status="Open",
                        )
                        db.add(new_v)

                # Mark resolved vulnerabilities for this asset ONLY if assessment was verified & complete
                can_resolve_vulns = (
                    not host_data.get("scan_failed")
                    and host_data.get("assessment_status") in (
                        "Completed — no findings detected",
                        "Completed — hardening advisories only",
                        "Findings detected",
                    )
                )
                if can_resolve_vulns:
                    for old_v in asset.vulnerabilities:
                        if old_v.title not in current_vuln_titles:
                            old_v.status = "Resolved"
                            old_v.updated_at = datetime.utcnow()
                else:
                    logger.info(
                        "Preserving existing vulnerabilities for Asset #%s (%s) — assessment was incomplete or unverified (%s)",
                        asset.id,
                        asset.ip_address,
                        host_data.get("assessment_status"),
                    )

                # Update GRC Risks for this asset
                current_findings = set(risk_res.get("findings", []))
                for finding in current_findings:
                    existing_r = (
                        db.query(models.Risk)
                        .filter(models.Risk.asset_id == asset.id)
                        .filter(models.Risk.title == finding)
                        .first()
                    )

                    if not existing_r:
                        # Determine compliance control suggestion
                        comp_ctrl = "PR.AC-4" if any(w in finding for w in ("SMB", "NetBIOS", "RPC", "PostgreSQL", "VMware")) else "PR.IP-1"
                        new_r = models.Risk(
                            asset_id=asset.id,
                            title=finding,
                            description=finding,
                            likelihood="Medium",
                            impact="Medium",
                            status="Open",
                            compliance_framework="NIST CSF",
                            compliance_control=comp_ctrl,
                            recommendation="Review the exposed service and apply appropriate security controls.",
                        )
                        db.add(new_r)
                        db.flush()
                    else:
                        existing_r.status = "Open"

                # Mark missing risks resolved ONLY if scan was complete and successful
                if can_resolve_vulns:
                    for old_r in asset.risks:
                        if old_r.title not in current_findings:
                            old_r.status = "Resolved"
                            old_r.updated_at = datetime.utcnow()

                # Deterministically recalculate GRC inherent & residual risk scores
                recalculate_asset_grc_risks(asset)

            # Handle offline assets with consecutive-miss hysteresis
            scanned_ips = {host_data["ip_address"] for host_data in scan_results}

            is_physical_lan_sweep = bool(is_agent_target or target == configured_cidr)
            if is_subnet:
                try:
                    target_net = ipaddress.ip_network(target, strict=False)
                    offline_threshold = int(os.getenv("OFFLINE_THRESHOLD_CYCLES", "2"))
                    for db_asset in db.query(models.Asset).filter(models.Asset.status != "deactivated").all():
                        try:
                            a_ip = ipaddress.ip_address(db_asset.ip_address)
                            if a_ip in target_net and db_asset.ip_address not in scanned_ips:
                                # In a full physical LAN discovery sweep, any absent device is no longer reachable in the live view
                                if is_physical_lan_sweep and getattr(db_asset, "network_scope", None) == "physical_lan":
                                    db_asset.is_present = False
                                    if db_asset.status == "Active":
                                        db_asset.status = "Offline"
                                        db_asset.offline_reason = f"Absent from latest LAN scan (Job #{job_id})"

                                db_asset.consecutive_scan_misses = (db_asset.consecutive_scan_misses or 0) + 1
                                if db_asset.consecutive_scan_misses >= offline_threshold:
                                    if db_asset.status == "Active":
                                        db_asset.status = "Offline"
                                        db_asset.assessment_status = "Not assessed (Host offline)"
                                        db_asset.offline_reason = f"Host unreached across {db_asset.consecutive_scan_misses} consecutive scan cycles"
                                        db_asset.scan_coverage = f"Host unreachable across {db_asset.consecutive_scan_misses} consecutive scan cycles"
                                        logger.info(
                                            "Marked asset %s as Offline (unreached across %d consecutive scan cycles)",
                                            db_asset.ip_address,
                                            db_asset.consecutive_scan_misses,
                                        )
                                else:
                                    logger.info(
                                        "Asset %s missed in current scan cycle (%d/%d); retaining Active status per hysteresis policy",
                                        db_asset.ip_address,
                                        db_asset.consecutive_scan_misses,
                                        offline_threshold,
                                    )
                        except Exception:
                            pass

                    enable_dhcp_leases = os.getenv("SYNC_ROUTER_DHCP_LEASES", "false").strip().lower() in ("true", "1")
                    if enable_dhcp_leases:
                        # Process authorized static router DHCP client registry
                        for dhcp_ip, dhcp_info in AUTHORIZED_ROUTER_DHCP_CLIENTS.items():
                            try:
                                d_addr = ipaddress.ip_address(dhcp_ip)
                                if d_addr in target_net and dhcp_ip not in scanned_ips:
                                    dhcp_host_payload = {
                                        "ip_address": dhcp_ip,
                                        "hostname": dhcp_info.get("hostname"),
                                        "device_type": dhcp_info.get("device_type"),
                                        "discovery_source": "static_dhcp_registry",
                                        "assessment_status": "Not assessed",
                                        "scan_coverage": "Static DHCP registry entry; host not responsive to active probes",
                                    }
                                    existing_dhcp_asset, _, _ = find_existing_asset(db, dhcp_host_payload)
                                    if not existing_dhcp_asset:
                                        new_dhcp_asset = models.Asset(
                                            ip_address=dhcp_ip,
                                            hostname=dhcp_info.get("hostname"),
                                            device_type=dhcp_info.get("device_type"),
                                            discovery_source="static_dhcp_registry",
                                            status="lease-only/unverified",
                                            identity_status="provisional",
                                            assessment_status="Not assessed",
                                            risk_score=0,
                                            risk_level="Low",
                                            scan_coverage="Static DHCP registry entry; host not responsive to active probes",
                                            criticality=None,
                                            environment=None,
                                            exposure=None,
                                        )
                                        db.add(new_dhcp_asset)
                                        db.flush()
                                        record_asset_address(db, new_dhcp_asset, dhcp_ip, None, source="static_dhcp_registry")
                                        logger.info("Added lease-only/unverified asset from static DHCP registry for %s (%s)", dhcp_ip, dhcp_info.get("hostname"))
                            except Exception:
                                pass
                except Exception as subnet_err:
                    logger.warning("Error processing offline/DHCP assets for subnet %s: %s", target, subnet_err)

            db.flush()

            # Drift Detection
            drift_events_data = DriftDetector.detect_drift(
                baseline=baseline_snapshot,
                current=current_snapshot,
                scan_job_id=job_id,
                existing_db_ips=existing_db_ips,
                asset_id_map=asset_id_map,
            )

            for d in drift_events_data:
                db.add(
                    models.DriftEvent(
                        scan_job_id=d["scan_job_id"],
                        asset_id=d.get("asset_id"),
                        event_type=d["event_type"],
                        title=d["title"],
                        description=d.get("description"),
                        severity=d.get("severity", "Low"),
                        detected_at=d.get("detected_at", datetime.utcnow()),
                    )
                )

            # Finalize Job
            job.status = "Completed"
            job.progress_percent = 100
            job.discovered_assets_count = len(scan_results)
            job.discovered_vulns_count = total_vulns
            job.completed_at = datetime.utcnow()
            job.error_message = None
            job.scan_source = "pi_agent_l2" if use_agent else ("container_fallback_multiprobe" if is_subnet else "single_host")
            job.is_presence_snapshot = is_physical_lan_sweep
            db.commit()

            logger.info(
                f"ScanJob {job_id} Completed: {len(scan_results)} assets, {total_vulns} vulns, {len(drift_events_data)} drift events."
            )

        except Exception as err:
            logger.exception(f"ScanJob {job_id} execution failed: {err}")
            if job:
                try:
                    job.status = "Failed"
                    job.error_message = str(err)
                    job.completed_at = datetime.utcnow()
                    db.commit()
                except Exception:
                    pass
        finally:
            with self._lock:
                self._active_processes.pop(job_id, None)
                self._cancel_events.pop(job_id, None)
                self._futures.pop(job_id, None)
            db.close()

    def _handle_cancellation(self, job: models.ScanJob, db: SessionLocal, job_id: int):
        """Mark job cancelled and clean up."""
        logger.info(f"ScanJob {job_id} execution stopped due to cooperative cancellation.")
        job.status = "Cancelled"
        job.completed_at = datetime.utcnow()
        db.commit()

    def shutdown(self, wait: bool = False):
        """Shut down the worker executor cleanly."""
        with self._lock:
            # Cancel all active subprocesses
            for jid, proc in list(self._active_processes.items()):
                try:
                    proc.terminate()
                except Exception:
                    pass
        self.executor.shutdown(wait=wait)

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

from scanner.grc_engine import (
    criticality_to_impact,
    calculate_likelihood,
    calculate_inherent_risk,
    calculate_residual_risk,
)
from .scanner_pipeline import MonitoringScannerPipeline, validate_target_network
from .drift_detector import DriftDetector, normalize_ip

logger = logging.getLogger("ai_grc.monitoring.worker")

MAX_SCAN_WORKERS = 3
DEFAULT_MAX_PENDING_JOBS = 10


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
        self.pipeline = pipeline or MonitoringScannerPipeline()

        self._lock = threading.Lock()
        self._cancel_events: Dict[int, threading.Event] = {}
        self._active_processes: Dict[int, subprocess.Popen] = {}
        self._futures: Dict[int, Any] = {}

    def get_pending_job_count(self) -> int:
        """Return the count of active and queued jobs currently in the worker pool."""
        with self._lock:
            done_keys = [jid for jid, f in self._futures.items() if hasattr(f, "done") and f.done()]
            for jid in done_keys:
                self._futures.pop(jid, None)
                self._cancel_events.pop(jid, None)
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
        3. Terminate active Nmap subprocess if running.
        4. Wait for process termination.
        5. Mark the job Cancelled in the database.
        Never mark a job Cancelled while its Nmap subprocess is still running.
        """
        with self._lock:
            cancel_event = self._cancel_events.get(job_id)
            active_proc = self._active_processes.get(job_id)
            future = self._futures.get(job_id)

        if cancel_event:
            cancel_event.set()

        # If future is still queued in executor and hasn't started, cancel directly
        if future and hasattr(future, "cancel") and future.cancel():
            with self._lock:
                self._futures.pop(job_id, None)
                self._cancel_events.pop(job_id, None)

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

            # Stage 1: Host discovery (ping sweep)
            if check_cancelled():
                self._handle_cancellation(job, db, job_id)
                return

            live_hosts = self.pipeline.discover_live_hosts(
                target=target,
                process_callback=on_process_created,
                cancellation_check=check_cancelled,
            )

            with self._lock:
                self._active_processes.pop(job_id, None)

            if check_cancelled():
                self._handle_cancellation(job, db, job_id)
                return

            job.progress_percent = 30
            db.commit()

            # Stage 2: Host port scanning & enumeration
            scan_results: List[Dict[str, Any]] = []
            total_hosts = len(live_hosts)

            for idx, host_ip in enumerate(live_hosts):
                if check_cancelled():
                    self._handle_cancellation(job, db, job_id)
                    return

                host_result = self.pipeline.scan_single_host(
                    host_ip=host_ip,
                    process_callback=on_process_created,
                    cancellation_check=check_cancelled,
                )

                with self._lock:
                    self._active_processes.pop(job_id, None)

                if check_cancelled():
                    self._handle_cancellation(job, db, job_id)
                    return

                if host_result:
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
            existing_db_ips = {normalize_ip(a.ip_address) for a in db.query(models.Asset).all()}
            asset_id_map: Dict[str, int] = {}
            total_vulns = 0

            for host_data in scan_results:
                raw_ip = host_data["ip_address"]
                norm_ip = normalize_ip(raw_ip)

                asset = db.query(models.Asset).filter(models.Asset.ip_address == norm_ip).first()

                port_str = ", ".join(
                    f"{p['port']}/{p['service']}" for p in host_data.get("open_ports", [])
                )

                risk_res = host_data.get("risk_result", {})

                if asset:
                    # Update existing asset
                    asset.hostname = host_data.get("hostname") or asset.hostname
                    asset.mac_address = host_data.get("mac_address") or asset.mac_address
                    if host_data.get("operating_system"):
                        asset.operating_system = host_data.get("operating_system")
                    asset.open_ports = port_str
                    asset.status = "Active"
                    asset.risk_score = risk_res.get("risk_score", asset.risk_score)
                    asset.risk_level = risk_res.get("risk_level", asset.risk_level)
                    asset.last_seen = datetime.utcnow()
                else:
                    # Create NEW unclassified asset
                    asset = models.Asset(
                        ip_address=norm_ip,
                        hostname=host_data.get("hostname"),
                        mac_address=host_data.get("mac_address"),
                        operating_system=host_data.get("operating_system"),
                        open_ports=port_str,
                        status="Active",
                        risk_score=risk_res.get("risk_score", 0),
                        risk_level=risk_res.get("risk_level", "Low"),
                        criticality=None,  # Unclassified by default
                        environment=None,
                        exposure=None,
                        owner=None,
                        business_function=None,
                    )
                    db.add(asset)
                    db.flush()

                asset_id_map[norm_ip] = asset.id

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
                            status="Open",
                        )
                        db.add(new_v)

                # Mark resolved vulnerabilities for this asset
                for old_v in asset.vulnerabilities:
                    if old_v.title not in current_vuln_titles:
                        old_v.status = "Resolved"
                        old_v.updated_at = datetime.utcnow()

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

                # Mark missing risks resolved
                for old_r in asset.risks:
                    if old_r.title not in current_findings:
                        old_r.status = "Resolved"
                        old_r.updated_at = datetime.utcnow()

                # Deterministically recalculate GRC inherent & residual risk scores
                recalculate_asset_grc_risks(asset)

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

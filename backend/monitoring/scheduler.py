"""Lightweight In-Process Continuous Monitoring Scheduler for Phase 5.

Provides:
- MonitoringScheduler: Single background daemon thread managing recurring scan sweeps.

CRITICAL DEPLOYMENT ARCHITECTURE CONSTRAINT:
- Designed strictly for a single FastAPI process / single application instance.
- Multi-worker deployments (e.g. gunicorn -w 4) are NOT supported for this in-process scheduler
  as multiple scheduler threads would produce duplicate scheduled job submissions.
- Celery, Redis, RabbitMQ, or external brokers are intentionally not required.
"""

import ipaddress
import os
import re
import subprocess
import time
import logging
import threading
from datetime import datetime, timedelta
from typing import Optional

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

from .worker import ScanWorkerPool

logger = logging.getLogger("ai_grc.monitoring.scheduler")


def detect_private_lan() -> Optional[str]:
    """Return the active private LAN CIDR, with precedence for NMAP_NETWORK_CIDR."""
    # 1. Direct environment variable override takes highest config precedence
    env_cidr = os.getenv("NMAP_NETWORK_CIDR", "").strip()
    if env_cidr:
        try:
            lan = ipaddress.ip_network(env_cidr, strict=False)
            if isinstance(lan, ipaddress.IPv4Network) and lan.is_private and 24 <= lan.prefixlen <= 31:
                return str(lan)
        except ValueError:
            logger.warning("NMAP_NETWORK_CIDR has invalid CIDR syntax: %r", env_cidr)

    # 2. If NMAP_AUTO_DETECT_NETWORK is enabled
    auto_detect = os.getenv("NMAP_AUTO_DETECT_NETWORK", "true").strip().lower() in {"1", "true", "yes", "on"}
    if not auto_detect:
        return None

    try:
        if os.name == "nt":
            ps_command = (
                "$r=Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' "
                "| Where-Object { $n=Get-NetAdapter -InterfaceIndex $_.InterfaceIndex -ErrorAction SilentlyContinue; "
                "$n.Status -eq 'Up' -and $n.HardwareInterface } "
                "| Sort-Object RouteMetric,InterfaceMetric | Select-Object -First 1; "
                "if($r){$a=Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $r.InterfaceIndex "
                "-AddressState Preferred | Where-Object { $_.IPAddress -notmatch '^(127\\.|169\\.254\\.)' "
                "-and $_.PrefixLength -ge 24 -and $_.PrefixLength -le 31 } "
                "| Select-Object -First 1; if($a){Write-Output \"$($a.IPAddress)/$($a.PrefixLength)\"}}"
            )
            result = subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps_command],
                capture_output=True,
                text=True,
                timeout=8,
                check=False,
            )
            interface_cidr = result.stdout.strip().splitlines()[-1] if result.stdout.strip() else ""
            if result.returncode != 0 or not interface_cidr:
                logger.warning("Could not determine active LAN from Windows routes: %s", result.stderr.strip())
                return None
        else:
            route = subprocess.run(
                ["ip", "-4", "route", "get", "1.1.1.1"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            source_match = re.search(r"\bsrc\s+(\d+\.\d+\.\d+\.\d+)", route.stdout)
            if route.returncode != 0 or not source_match:
                logger.warning("Could not determine active LAN from IPv4 route: %s", route.stderr.strip())
                return None
            source_ip = source_match.group(1)
            addresses = subprocess.run(
                ["ip", "-o", "-4", "addr", "show"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            interface_cidr = ""
            for line in addresses.stdout.splitlines():
                match = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+/\d+)", line)
                if match and match.group(1).split("/")[0] == source_ip:
                    interface_cidr = match.group(1)
                    break
            if not interface_cidr:
                return None

        interface = ipaddress.ip_interface(interface_cidr)
        lan = interface.network

        # If detected network is inside Docker container virtual bridge (e.g. 172.17.0.0/16 or 172.18.0.0/16)
        # do not substitute it for the user's physical LAN!
        docker_bridges = ["172.17.0.0/16", "172.18.0.0/16", "172.19.0.0/16", "172.20.0.0/16"]
        if any(lan.subnet_of(ipaddress.ip_network(b)) for b in docker_bridges):
            logger.info("Detected IP network %s is a Docker container bridge; ignoring bridge substitution", lan)
            return None

        private_ranges = (
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
        )
        if (
            isinstance(lan, ipaddress.IPv4Network)
            and any(lan.subnet_of(p) for p in private_ranges)
            and 24 <= lan.prefixlen <= 31
        ):
            return str(lan)
        return None
    except Exception as exc:
        logger.warning("Automatic LAN detection failed: %s", exc)
        return None


class MonitoringScheduler:
    """Single-instance background scheduler for recurring continuous monitoring sweeps."""

    def __init__(
        self,
        worker_pool: ScanWorkerPool,
        poll_interval_seconds: int = 30,
    ):
        self.worker_pool = worker_pool
        self.poll_interval = poll_interval_seconds

        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    def start(self):
        """Start the scheduler background daemon thread."""
        with self._lock:
            if self._thread and self._thread.is_alive():
                logger.warning("MonitoringScheduler is already running.")
                return

            self._stop_event.clear()
            self._thread = threading.Thread(
                target=self._run_loop,
                name="MonitoringSchedulerThread",
                daemon=True,
            )
            self._thread.start()
            logger.info(
                f"MonitoringScheduler started (Single-process mode, tick={self.poll_interval}s)."
            )

    def stop(self, timeout: float = 5.0):
        """Cleanly stop the scheduler background thread."""
        with self._lock:
            if not self._thread or not self._thread.is_alive():
                return

            self._stop_event.set()
            self._thread.join(timeout=timeout)
            logger.info("MonitoringScheduler stopped.")

    def is_running(self) -> bool:
        with self._lock:
            return bool(self._thread and self._thread.is_alive())

    def _run_loop(self):
        """Scheduler daemon main execution loop."""
        while not self._stop_event.is_set():
            try:
                self.evaluate_due_schedules()
            except Exception as err:
                logger.error(f"Error during scheduler evaluation tick: {err}")

            # Sleep in short increments to allow rapid shutdown
            for _ in range(self.poll_interval):
                if self._stop_event.is_set():
                    break
                time.sleep(1)

    def evaluate_due_schedules(self):
        """Evaluate active ScanSchedule records and submit due jobs to the worker pool."""
        db = SessionLocal()
        try:
            now = datetime.utcnow()
            auto_detect = os.getenv("NMAP_AUTO_DETECT_NETWORK", "true").strip().lower() in {
                "1", "true", "yes", "on"
            }
            detected_lan = detect_private_lan() if auto_detect else None

            # Query all active schedules
            schedules = (
                db.query(models.ScanSchedule)
                .filter(models.ScanSchedule.is_active == True)
                .all()
            )

            for schedule in schedules:
                if detected_lan and schedule.target != detected_lan and schedule.target in {"auto", "current_lan"}:
                    logger.info(
                        "Network updated for schedule '%s': %s -> %s",
                        schedule.name,
                        schedule.target,
                        detected_lan,
                    )
                    schedule.target = detected_lan
                    schedule.updated_at = now
                    db.commit()

                # Check if schedule is due
                if schedule.next_run_at and schedule.next_run_at > now:
                    continue

                target = schedule.target

                # Prevent duplicate scheduled sweeps:
                # Check if there is already an existing Queued or Running job for the exact same target
                existing_active_job = (
                    db.query(models.ScanJob)
                    .filter(models.ScanJob.target == target)
                    .filter(models.ScanJob.status.in_(["Queued", "Running"]))
                    .first()
                )

                if existing_active_job:
                    logger.info(
                        f"Skipping scheduled sweep for {target} (Schedule '{schedule.name}'): "
                        f"Job #{existing_active_job.id} is already {existing_active_job.status}."
                    )
                    # Advance next_run_at to avoid immediate re-attempting every tick
                    schedule.next_run_at = now + timedelta(minutes=max(schedule.interval_minutes, 15))
                    db.commit()
                    continue

                # Create new ScanJob
                new_job = models.ScanJob(
                    target=target,
                    scan_type="scheduled_sweep",
                    status="Queued",
                    progress_percent=0,
                )
                db.add(new_job)
                db.flush()

                # Update schedule tracking
                schedule.last_run_at = now
                interval_mins = max(schedule.interval_minutes, 15)  # Enforce minimum 15m interval
                schedule.next_run_at = now + timedelta(minutes=interval_mins)
                schedule.updated_at = now
                db.commit()

                logger.info(
                    f"Scheduled sweep queued: Job #{new_job.id} for target '{target}' "
                    f"(Schedule '{schedule.name}', next run at {schedule.next_run_at})."
                )

                # Submit to worker pool
                self.worker_pool.submit_scan_job(new_job.id)

        finally:
            db.close()

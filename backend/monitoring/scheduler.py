"""Lightweight In-Process Continuous Monitoring Scheduler for Phase 5.

Provides:
- MonitoringScheduler: Single background daemon thread managing recurring scan sweeps.

CRITICAL DEPLOYMENT ARCHITECTURE CONSTRAINT:
- Designed strictly for a single FastAPI process / single application instance.
- Multi-worker deployments (e.g. gunicorn -w 4) are NOT supported for this in-process scheduler
  as multiple scheduler threads would produce duplicate scheduled job submissions.
- Celery, Redis, RabbitMQ, or external brokers are intentionally not required.
"""

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

            # Query all active schedules
            schedules = (
                db.query(models.ScanSchedule)
                .filter(models.ScanSchedule.is_active == True)
                .all()
            )

            for schedule in schedules:
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

"""Continuous Network Monitoring, Automated Background Scanning, and Asset Drift Engine (Phase 5)."""

from .scanner_pipeline import validate_target_network, MonitoringScannerPipeline
from .drift_detector import (
    DriftDetector,
    AssetSnapshot,
    ScanSnapshot,
    normalize_ip,
    normalize_port_identity,
    normalize_service_identity,
)
from .worker import ScanWorkerPool, MAX_SCAN_WORKERS, recalculate_asset_grc_risks
from .scheduler import MonitoringScheduler
from .remote_agent import NmapAgentClient, NmapAgentError
from .asset_identity import (
    find_existing_asset,
    upsert_discovered_asset,
    record_asset_address,
    reconcile_duplicate_assets,
    normalize_mac,
    is_locally_administered_mac,
    run_schema_migrations,
)

__all__ = [
    "validate_target_network",
    "MonitoringScannerPipeline",
    "DriftDetector",
    "AssetSnapshot",
    "ScanSnapshot",
    "normalize_ip",
    "normalize_port_identity",
    "normalize_service_identity",
    "ScanWorkerPool",
    "MAX_SCAN_WORKERS",
    "recalculate_asset_grc_risks",
    "MonitoringScheduler",
    "NmapAgentClient",
    "NmapAgentError",
    "find_existing_asset",
    "upsert_discovered_asset",
    "record_asset_address",
    "reconcile_duplicate_assets",
    "normalize_mac",
    "is_locally_administered_mac",
    "run_schema_migrations",
]
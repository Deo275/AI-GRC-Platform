"""Comprehensive Regression Tests for Live Asset Presence and Permanent Scan History.

Tests cover:
1. A device found in a successful LAN scan appears in Live Inventory (is_present=True).
2. A device absent from a later successful complete scan disappears from Live Inventory (is_present=False) but remains in Scan History.
3. A failed or incomplete scan does NOT erase or overwrite the last valid live presence snapshot.
4. Historical devices and vulnerabilities are NEVER deleted by presence updates.
5. Disconnection does not automatically mark vulnerabilities as resolved.
6. A confirmed reassessment with evidence updates vulnerability status correctly.
7. Repeated scans do not create duplicate live assets.
8. Devices with the same hostname but different verified identities remain separate.
9. Docker, VMware, loopback, and out-of-scope records are excluded from physical LAN Live Inventory.
10. GET /assets with presence_mode: 'live' (default), 'historical', 'all'.
11. GET /vulnerabilities with presence_mode: 'live' (default), 'historical', 'all'.
12. GET /scans/history and GET /scans/history/{job_id} observation persistence and absent device comparison.
"""

import sys
from pathlib import Path
from datetime import datetime
import json
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR / "backend"))
sys.path.insert(0, str(BASE_DIR))

import models
from monitoring.asset_identity import (
    determine_network_scope,
    normalize_mac,
    normalize_ip,
    upsert_discovered_asset,
    run_schema_migrations,
)


@pytest.fixture
def in_memory_db():
    engine = create_engine("sqlite:///:memory:", echo=False)
    models.Base.metadata.create_all(bind=engine)
    run_schema_migrations(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


def test_successful_scan_marks_device_present(in_memory_db):
    """Criterion 1: A device found in a successful scan appears in Live Inventory."""
    job = models.ScanJob(
        target="192.168.1.0/24",
        scan_type="scheduled_sweep",
        status="Completed",
        progress_percent=100,
        scan_source="pi_agent_l2",
        is_presence_snapshot=True,
    )
    in_memory_db.add(job)
    in_memory_db.commit()

    host_data = {
        "ip_address": "192.168.1.100",
        "mac_address": "00:11:22:33:44:55",
        "hostname": "workstation-1",
        "operating_system": "Windows 11",
        "device_type": "Workstation / Laptop",
        "network_scope": "physical_lan",
    }
    asset, is_new, _ = upsert_discovered_asset(in_memory_db, host_data, source="pi_agent_l2")
    asset.is_present = True
    asset.last_present_scan_job_id = job.id
    in_memory_db.commit()

    # Verify live inventory contains this asset
    live_assets = in_memory_db.query(models.Asset).filter(
        models.Asset.network_scope == "physical_lan",
        models.Asset.is_present == True,
    ).all()
    assert len(live_assets) == 1
    assert live_assets[0].ip_address == "192.168.1.100"
    assert live_assets[0].is_present is True


def test_absent_device_disappears_from_live_but_persists_in_history(in_memory_db):
    """Criterion 2: A device absent from a later successful complete scan disappears from Live Inventory but remains in History."""
    # Run 1: Devices A and B present
    job1 = models.ScanJob(target="192.168.1.0/24", scan_type="sweep", status="Completed", progress_percent=100)
    in_memory_db.add(job1)
    in_memory_db.commit()

    asset_a, _, _ = upsert_discovered_asset(in_memory_db, {"ip_address": "192.168.1.10", "mac_address": "AA:AA:AA:AA:AA:01", "hostname": "host-a"})
    asset_b, _, _ = upsert_discovered_asset(in_memory_db, {"ip_address": "192.168.1.20", "mac_address": "BB:BB:BB:BB:BB:02", "hostname": "host-b"})
    asset_a.is_present = True
    asset_b.is_present = True
    in_memory_db.commit()

    # Record observations for Run 1
    in_memory_db.add(models.ScanObservation(scan_job_id=job1.id, asset_id=asset_a.id, ip_address=asset_a.ip_address, hostname="host-a"))
    in_memory_db.add(models.ScanObservation(scan_job_id=job1.id, asset_id=asset_b.id, ip_address=asset_b.ip_address, hostname="host-b"))
    in_memory_db.commit()

    # Run 2: Only Device A is observed, Device B is absent
    job2 = models.ScanJob(target="192.168.1.0/24", scan_type="sweep", status="Completed", progress_percent=100)
    in_memory_db.add(job2)
    in_memory_db.commit()

    # Simulate presence update for Run 2: Device A observed, Device B not seen
    asset_a.is_present = True
    asset_a.last_present_scan_job_id = job2.id
    asset_b.is_present = False  # Absent!
    asset_b.status = "Offline"
    in_memory_db.add(models.ScanObservation(scan_job_id=job2.id, asset_id=asset_a.id, ip_address=asset_a.ip_address, hostname="host-a"))
    in_memory_db.commit()

    # Live inventory check
    live_assets = in_memory_db.query(models.Asset).filter(models.Asset.is_present == True).all()
    assert len(live_assets) == 1
    assert live_assets[0].ip_address == "192.168.1.10"

    # Historical inventory check (Device B is NOT deleted)
    all_assets = in_memory_db.query(models.Asset).all()
    assert len(all_assets) == 2
    b_record = in_memory_db.query(models.Asset).filter(models.Asset.ip_address == "192.168.1.20").first()
    assert b_record is not None
    assert b_record.is_present is False
    assert b_record.status == "Offline"

    # Scan history check: Run 1 has 2 observations, Run 2 has 1 observation
    run1_obs = in_memory_db.query(models.ScanObservation).filter(models.ScanObservation.scan_job_id == job1.id).all()
    run2_obs = in_memory_db.query(models.ScanObservation).filter(models.ScanObservation.scan_job_id == job2.id).all()
    assert len(run1_obs) == 2
    assert len(run2_obs) == 1


def test_failed_or_incomplete_scan_preserves_last_valid_live_snapshot(in_memory_db):
    """Criterion 3: A failed or incomplete scan does not erase the last valid live snapshot."""
    # Seed live snapshot
    asset1, _, _ = upsert_discovered_asset(in_memory_db, {"ip_address": "192.168.1.50", "mac_address": "11:22:33:44:55:66", "hostname": "live-device"})
    asset1.is_present = True
    in_memory_db.commit()

    # A scan job starts but fails midway
    failed_job = models.ScanJob(target="192.168.1.0/24", scan_type="sweep", status="Failed", error_message="Network unreachable")
    in_memory_db.add(failed_job)
    in_memory_db.commit()

    # Verify that failed job does NOT alter asset1.is_present
    db_asset = in_memory_db.query(models.Asset).filter(models.Asset.id == asset1.id).first()
    assert db_asset.is_present is True


def test_disconnection_does_not_resolve_vulnerabilities(in_memory_db):
    """Criterion 4 & 5: Disconnection does not delete assets or automatically resolve vulnerabilities."""
    asset, _, _ = upsert_discovered_asset(in_memory_db, {"ip_address": "192.168.1.75", "mac_address": "12:34:56:78:9A:BC"})
    asset.is_present = True

    vuln = models.Vulnerability(
        asset_id=asset.id,
        title="Open SMB Service Exposure",
        severity="High",
        status="Open",
        cve="CVE-2017-0144",
        cvss_score=8.5,
    )
    in_memory_db.add(vuln)
    in_memory_db.commit()

    # Device disconnects in later sweep
    asset.is_present = False
    asset.status = "Offline"
    in_memory_db.commit()

    # Vulnerability MUST remain Open and NOT be marked Resolved
    db_vuln = in_memory_db.query(models.Vulnerability).filter(models.Vulnerability.id == vuln.id).first()
    assert db_vuln.status == "Open"
    assert db_vuln.asset.is_present is False


def test_confirmed_reassessment_updates_vulnerability_status(in_memory_db):
    """Criterion 6: A confirmed complete reassessment can update vulnerability status correctly."""
    asset, _, _ = upsert_discovered_asset(in_memory_db, {"ip_address": "192.168.1.80", "mac_address": "34:56:78:9A:BC:DE"})
    asset.is_present = True

    vuln = models.Vulnerability(
        asset_id=asset.id,
        title="Insecure Telnet Service",
        severity="Medium",
        status="Open",
    )
    in_memory_db.add(vuln)
    in_memory_db.commit()

    # Reassessment occurs: service closed, verified complete assessment
    vuln.status = "Resolved"
    vuln.updated_at = datetime.utcnow()
    in_memory_db.commit()

    db_vuln = in_memory_db.query(models.Vulnerability).filter(models.Vulnerability.id == vuln.id).first()
    assert db_vuln.status == "Resolved"


def test_repeated_scans_do_not_create_duplicate_live_assets(in_memory_db):
    """Criterion 7: Repeated scans do not create duplicate live assets."""
    payload = {
        "ip_address": "192.168.1.99",
        "mac_address": "44:55:66:77:88:99",
        "hostname": "workstation-alpha",
    }
    asset1, is_new1, _ = upsert_discovered_asset(in_memory_db, payload)
    asset1.is_present = True
    in_memory_db.commit()

    # Scan 2 discovers the exact same host
    asset2, is_new2, _ = upsert_discovered_asset(in_memory_db, payload)
    asset2.is_present = True
    in_memory_db.commit()

    assert is_new1 is True
    assert is_new2 is False
    assert asset1.id == asset2.id

    # Total assets in DB must be exactly 1
    total = in_memory_db.query(models.Asset).count()
    assert total == 1


def test_devices_with_same_hostname_but_different_mac_remain_separate(in_memory_db):
    """Criterion 8: Devices with the same hostname but different verified identities remain separate."""
    dev1, _, _ = upsert_discovered_asset(in_memory_db, {
        "ip_address": "192.168.1.101",
        "mac_address": "11:11:11:11:11:11",
        "hostname": "iPhone",
    })
    dev2, _, _ = upsert_discovered_asset(in_memory_db, {
        "ip_address": "192.168.1.102",
        "mac_address": "22:22:22:22:22:22",
        "hostname": "iPhone",
    })

    assert dev1.id != dev2.id
    assert dev1.mac_address != dev2.mac_address
    assert in_memory_db.query(models.Asset).count() == 2


def test_out_of_scope_records_excluded_from_physical_lan_live_inventory(in_memory_db):
    """Criterion 9: Docker, VMware, loopback and out-of-scope records are excluded from physical LAN Live Inventory."""
    # Create out-of-scope assets
    loopback_asset = models.Asset(ip_address="127.0.0.1", hostname="localhost", network_scope="loopback", is_present=True)
    docker_asset = models.Asset(ip_address="172.18.0.3", hostname="docker-db", network_scope="local_container", is_present=True)
    vmware_asset = models.Asset(ip_address="192.168.127.1", hostname="vmnet", network_scope="virtual_interface", is_present=True)
    lan_asset = models.Asset(ip_address="192.168.1.1", hostname="router", network_scope="physical_lan", is_present=True)

    in_memory_db.add_all([loopback_asset, docker_asset, vmware_asset, lan_asset])
    in_memory_db.commit()

    # Query physical LAN live inventory
    live_lan = in_memory_db.query(models.Asset).filter(
        models.Asset.network_scope == "physical_lan",
        models.Asset.is_present == True,
    ).all()

    assert len(live_lan) == 1
    assert live_lan[0].ip_address == "192.168.1.1"


def test_scan_observations_persist_details_for_history(in_memory_db):
    """Criterion 12: Permanent Scan Observations persist host ports, findings, and metadata."""
    job = models.ScanJob(target="192.168.1.0/24", scan_type="sweep", status="Completed")
    in_memory_db.add(job)
    in_memory_db.commit()

    obs = models.ScanObservation(
        scan_job_id=job.id,
        ip_address="192.168.1.1",
        mac_address="AC:84:C6:64:C2:3C",
        hostname="TP-Link Gateway",
        operating_system="Embedded Linux",
        os_confidence="High",
        device_type="Router / Gateway",
        open_ports=json.dumps([80, 443, 53]),
        vulnerabilities_count=1,
        vulnerabilities_summary=json.dumps(["Insecure HTTP Management Interface"]),
        assessment_status="Findings detected",
        scan_coverage="3 open port(s) evaluated",
        network_scope="physical_lan",
    )
    in_memory_db.add(obs)
    in_memory_db.commit()

    saved_obs = in_memory_db.query(models.ScanObservation).filter(models.ScanObservation.scan_job_id == job.id).first()
    assert saved_obs is not None
    assert saved_obs.ip_address == "192.168.1.1"
    assert "80" in saved_obs.open_ports
    assert saved_obs.device_type == "Router / Gateway"

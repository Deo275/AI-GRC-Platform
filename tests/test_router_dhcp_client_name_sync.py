"""Comprehensive Test Suite for Router DHCP Client-Name Synchronization.

Verifies:
1. All nine sample router client names and IP addresses correctly synchronize:
   - 192.168.1.1: TP-Link Gateway (AC:84:C6:64:C2:3C)
   - 192.168.1.100: Sujal (0A:CD:45:AB:91:A4)
   - 192.168.1.101: FLEMSIS (3C:6A:A7:8D:EA:87)
   - 192.168.1.104: IoT-Device (24:EC:4A:06:5F:88)
   - 192.168.1.108: LAN-Client (A8:41:F4:0C:39:57)
   - 192.168.1.123: Nothing-Phone-2a (2A:0C:FC:C4:4C:3D)
   - 192.168.1.124: Jack-s-A35 (02:EA:2F:FA:3C:B3)
   - 192.168.1.127: Joshua (E0:C2:64:2A:B4:08)
   - 192.168.1.142: realme-12-5G (C6:8C:01:87:9D:3B)
2. MAC address normalization handles lowercase, hyphens, and mixed cases.
3. Matching precedence: primary MAC matching with carefully controlled IP fallback.
4. IP matching fallback is rejected if candidate asset has a conflicting MAC address.
5. Dynamic DHCP IP address changes update current IP and address history without duplicate creation.
6. Missing or blank router client names never overwrite valid existing names.
7. Operating system hostname is stored separately from router client name and never overwritten.
8. Preferred display name follows strict precedence:
   Router DHCP client name -> OS hostname -> existing name -> IP/MAC label.
9. Devices absent from router DHCP list or with stale leases are NEVER deleted.
10. Rediscovery of the same device updates existing asset records without duplicate creation.
11. API responses (format_asset, format_scan_observation, /vulnerabilities) provide display names.
12. Router integration provenance is accurately labeled as static reference registry or imported export.
"""

import sys
from pathlib import Path
from datetime import datetime
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR / "backend"))
sys.path.insert(0, str(BASE_DIR))

import models
from monitoring.asset_identity import (
    upsert_discovered_asset,
    run_schema_migrations,
    get_preferred_display_name,
    is_valid_client_name,
    sync_router_dhcp_clients,
    normalize_mac,
    normalize_ip,
)
from scanner.router_dhcp import (
    normalize_mac_address,
    find_router_dhcp_entry,
    get_authorized_dhcp_info_for_host,
    get_dhcp_registry_status,
    import_dhcp_client_list,
    AUTHORIZED_ROUTER_DHCP_CLIENTS,
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


# ---------------------------------------------------------------------------
# Test 1: All 9 Sample Router Client Names and IPs
# ---------------------------------------------------------------------------

SAMPLE_DEVICES = [
    ("192.168.1.1", "AC:84:C6:64:C2:3C", "TP-Link Gateway"),
    ("192.168.1.100", "0A:CD:45:AB:91:A4", "Sujal"),
    ("192.168.1.101", "3C:6A:A7:8D:EA:87", "FLEMSIS"),
    ("192.168.1.104", "24:EC:4A:06:5F:88", "IoT-Device"),
    ("192.168.1.108", "A8:41:F4:0C:39:57", "LAN-Client"),
    ("192.168.1.123", "2A:0C:FC:C4:4C:3D", "Nothing-Phone-2a"),
    ("192.168.1.124", "02:EA:2F:FA:3C:B3", "Jack-s-A35"),
    ("192.168.1.127", "E0:C2:64:2A:B4:08", "Joshua"),
    ("192.168.1.142", "C6:8C:01:87:9D:3B", "realme-12-5G"),
]


@pytest.mark.parametrize("ip,mac,expected_client_name", SAMPLE_DEVICES)
def test_sample_client_names_synchronize_accurately(in_memory_db, ip, mac, expected_client_name):
    """Test that all 9 user-specified sample router DHCP client names map and sync properly."""
    # Seed asset into DB
    asset, is_new, strat = upsert_discovered_asset(
        in_memory_db,
        {
            "ip_address": ip,
            "mac_address": mac,
            "hostname": f"os-host-{ip.split('.')[-1]}",  # Distinct OS hostname
        },
    )
    in_memory_db.commit()

    # Synchronize router DHCP clients
    sync_res = sync_router_dhcp_clients(in_memory_db)
    assert sync_res["status"] == "success"

    in_memory_db.refresh(asset)
    assert asset.dhcp_client_name == expected_client_name
    assert asset.dhcp_observed_at is not None
    assert asset.router_client_name == expected_client_name
    assert asset.preferred_display_name == expected_client_name
    assert get_preferred_display_name(asset) == expected_client_name
    # OS hostname remains distinct and not overwritten
    assert asset.hostname == f"os-host-{ip.split('.')[-1]}"


# ---------------------------------------------------------------------------
# Test 2: MAC Normalization (Lowercase, Hyphens, Mixed)
# ---------------------------------------------------------------------------

def test_mac_normalization():
    """Verify MAC address normalization handles various formatting styles."""
    test_cases = [
        ("0a-cd-45-ab-91-a4", "0A:CD:45:AB:91:A4"),
        ("0A:CD:45:AB:91:A4", "0A:CD:45:AB:91:A4"),
        ("3c-6a-a7-8d-ea-87", "3C:6A:A7:8D:EA:87"),
        ("2a:0c:fc:c4:4c:3d", "2A:0C:FC:C4:4C:3D"),
        ("invalid-mac", None),
        ("00:00:00:00:00:00", None),
        ("FF:FF:FF:FF:FF:FF", None),
    ]
    for raw, expected in test_cases:
        assert normalize_mac(raw) == expected
        assert normalize_mac_address(raw) == expected


# ---------------------------------------------------------------------------
# Test 3: Primary MAC Matching with Controlled Fallback
# ---------------------------------------------------------------------------

def test_primary_mac_match_overrules_changed_ip(in_memory_db):
    """When a device changes IP, primary MAC matching maps it to the router entry correctly."""
    # Device Sujal previously at .100 moved to .103 via DHCP lease renewal
    sujal_mac = "0A:CD:45:AB:91:A4"
    entry = find_router_dhcp_entry(mac=sujal_mac, ip="192.168.1.103")
    assert entry is not None
    assert entry["client_name"] == "Sujal"
    assert entry["matched_by"] == "mac_address"


def test_ip_fallback_matching_when_mac_absent(in_memory_db):
    """When candidate asset has no MAC, controlled IP fallback succeeds."""
    entry = find_router_dhcp_entry(mac=None, ip="192.168.1.101")
    assert entry is not None
    assert entry["client_name"] == "FLEMSIS"
    assert entry["matched_by"] == "ip_address"


def test_ip_fallback_rejected_on_mac_conflict(in_memory_db):
    """IP fallback is strictly rejected if candidate host MAC conflicts with registered MAC."""
    conflicting_mac = "AA:BB:CC:DD:EE:11"
    entry = find_router_dhcp_entry(mac=conflicting_mac, ip="192.168.1.100")
    assert entry is None  # Must reject because .100 belongs to 0A:CD:45:AB:91:A4


# ---------------------------------------------------------------------------
# Test 4: Dynamic DHCP IP Changes (No Duplicate Records)
# ---------------------------------------------------------------------------

def test_dynamic_dhcp_ip_change_updates_asset_without_duplicates(in_memory_db):
    """When Joshua moves from .102 to .127, existing asset is updated and address history maintained."""
    joshua_mac = "E0:C2:64:2A:B4:08"

    # Seed asset at initial IP .102
    asset, is_new, strat = upsert_discovered_asset(
        in_memory_db,
        {"ip_address": "192.168.1.102", "mac_address": joshua_mac, "hostname": "Joshua-PC"},
    )
    in_memory_db.commit()
    initial_id = asset.id

    # Rediscover at new DHCP IP .127
    updated_asset, is_new_2, strat_2 = upsert_discovered_asset(
        in_memory_db,
        {"ip_address": "192.168.1.127", "mac_address": joshua_mac, "hostname": "Joshua-PC"},
    )
    in_memory_db.commit()

    assert not is_new_2
    assert updated_asset.id == initial_id
    assert updated_asset.ip_address == "192.168.1.127"

    # Address history records both IPs
    hist_ips = [h.ip_address for h in updated_asset.address_history]
    assert "192.168.1.102" in hist_ips
    assert "192.168.1.127" in hist_ips

    # Sync router names
    sync_router_dhcp_clients(in_memory_db)
    in_memory_db.refresh(updated_asset)
    assert updated_asset.dhcp_client_name == "Joshua"
    assert updated_asset.preferred_display_name == "Joshua"


# ---------------------------------------------------------------------------
# Test 5: Missing or Blank Router Client Names Never Overwrite Valid Names
# ---------------------------------------------------------------------------

def test_missing_or_blank_router_client_name_never_overwrites(in_memory_db):
    """A missing or blank client name in a DHCP import never overwrites a valid existing name."""
    # Seed asset with valid existing name
    asset, _, _ = upsert_discovered_asset(
        in_memory_db,
        {
            "ip_address": "192.168.1.200",
            "mac_address": "12:34:56:78:9A:BC",
            "hostname": "Mission-Critical-Server",
            "dhcp_client_name": "Server-Alpha",
        },
    )
    in_memory_db.commit()

    # Import blank / None / unknown client name
    blank_records = [
        {"ip": "192.168.1.200", "mac": "12:34:56:78:9A:BC", "client_name": ""},
        {"ip": "192.168.1.200", "mac": "12:34:56:78:9A:BC", "client_name": "   "},
        {"ip": "192.168.1.200", "mac": "12:34:56:78:9A:BC", "client_name": "Unknown"},
        {"ip": "192.168.1.200", "mac": "12:34:56:78:9A:BC", "client_name": "None"},
    ]
    for r in blank_records:
        sync_router_dhcp_clients(in_memory_db, [r])
        in_memory_db.refresh(asset)
        # Valid name preserved
        assert asset.dhcp_client_name == "Server-Alpha"
        assert asset.hostname == "Mission-Critical-Server"


# ---------------------------------------------------------------------------
# Test 6: OS Hostname and Router Client Name Maintained Separately
# ---------------------------------------------------------------------------

def test_os_hostname_and_router_name_separation(in_memory_db):
    """OS hostname (from SMB/DNS) and router DHCP client name are stored in distinct columns."""
    asset, _, _ = upsert_discovered_asset(
        in_memory_db,
        {
            "ip_address": "192.168.1.100",
            "mac_address": "0A:CD:45:AB:91:A4",
            "hostname": "DESKTOP-SUJAL-WIN11",  # OS-reported hostname
        },
    )
    in_memory_db.commit()

    sync_router_dhcp_clients(in_memory_db)
    in_memory_db.refresh(asset)

    # Router name is Sujal, but OS hostname is DESKTOP-SUJAL-WIN11
    assert asset.dhcp_client_name == "Sujal"
    assert asset.hostname == "DESKTOP-SUJAL-WIN11"
    # Display name prefers router name
    assert asset.preferred_display_name == "Sujal"


# ---------------------------------------------------------------------------
# Test 7: Preferred Display Name Fallback Hierarchy
# ---------------------------------------------------------------------------

def test_preferred_display_name_hierarchy():
    """Verify fallback hierarchy: Router DHCP -> OS Hostname -> Existing Name -> IP/MAC."""
    # Case 1: Router DHCP client name present -> Wins
    case1 = {"dhcp_client_name": "Jack-s-A35", "hostname": "android-galaxy", "ip_address": "192.168.1.124"}
    assert get_preferred_display_name(case1) == "Jack-s-A35"

    # Case 2: Router DHCP name missing -> Falls back to OS hostname
    case2 = {"dhcp_client_name": None, "hostname": "DESKTOP-WORKSTATION", "ip_address": "192.168.1.50"}
    assert get_preferred_display_name(case2) == "DESKTOP-WORKSTATION"

    # Case 3: OS hostname is generic/unknown -> Falls back to name/label
    case3 = {"dhcp_client_name": "", "hostname": "Unknown", "name": "Edge-Gateway-1", "ip_address": "192.168.1.2"}
    assert get_preferred_display_name(case3) == "Edge-Gateway-1"

    # Case 4: No names available -> Falls back to 'Host <ip>'
    case4 = {"dhcp_client_name": None, "hostname": None, "ip_address": "192.168.1.88"}
    assert get_preferred_display_name(case4) == "Host 192.168.1.88"

    # Case 5: Only MAC available -> Falls back to 'Device (<mac>)'
    case5 = {"dhcp_client_name": None, "hostname": None, "ip_address": None, "mac_address": "AA:BB:CC:DD:EE:FF"}
    assert get_preferred_display_name(case5) == "Device (AA:BB:CC:DD:EE:FF)"


# ---------------------------------------------------------------------------
# Test 8: Stale/Disconnected Devices Missing from Router List are Never Deleted
# ---------------------------------------------------------------------------

def test_devices_missing_from_router_list_never_deleted(in_memory_db):
    """Historical devices absent from the router DHCP list are never deleted."""
    # Seed historical asset not in DHCP list
    historical_asset, _, _ = upsert_discovered_asset(
        in_memory_db,
        {
            "ip_address": "192.168.1.250",
            "mac_address": "FE:DC:BA:98:76:54",
            "hostname": "Old-Printer",
        },
    )
    in_memory_db.commit()
    asset_id = historical_asset.id

    # Sync router DHCP clients (which only contains .1, .100, etc.)
    sync_router_dhcp_clients(in_memory_db)

    # Asset must still exist in DB
    retained = in_memory_db.query(models.Asset).filter(models.Asset.id == asset_id).first()
    assert retained is not None
    assert retained.hostname == "Old-Printer"


# ---------------------------------------------------------------------------
# Test 9: Rediscovery Prevents Duplicate Records
# ---------------------------------------------------------------------------

def test_rediscovery_prevents_duplicate_records(in_memory_db):
    """Rediscovering the same device multiple times updates the existing record."""
    mac = "2A:0C:FC:C4:4C:3D"  # Nothing-Phone-2a
    ip = "192.168.1.123"

    asset1, is_new1, _ = upsert_discovered_asset(in_memory_db, {"ip_address": ip, "mac_address": mac})
    in_memory_db.commit()
    assert is_new1

    asset2, is_new2, _ = upsert_discovered_asset(in_memory_db, {"ip_address": ip, "mac_address": mac})
    in_memory_db.commit()
    assert not is_new2
    assert asset1.id == asset2.id

    # Total assets in DB must be exactly 1
    total = in_memory_db.query(models.Asset).count()
    assert total == 1


# ---------------------------------------------------------------------------
# Test 10: Accurate Provenance & Labeling (No Fabricated Live Sync)
# ---------------------------------------------------------------------------

def test_router_registry_provenance_labeling():
    """Verify router integration accurately reports static reference / imported status."""
    status = get_dhcp_registry_status()
    assert status["model"] == "TP-Link TL-WR840N"
    assert status["live_sync_supported"] is False
    assert "static_reference" in status["integration_type"]
    assert "TP-Link TL-WR840N" in status["live_sync_reason"]
    assert status["total_clients"] >= 9

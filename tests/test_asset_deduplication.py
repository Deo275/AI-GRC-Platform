"""Comprehensive Regression Test Suite for Asset Deduplication, Dynamic IP Handling,
Stable Identity Hierarchy, Concurrency Protection, and Safe Reconciliation.

Covers:
1. Same MAC, different IP: update the existing asset.
2. Same stable agent ID, different IP: update the existing asset.
3. Same IP, different MAC: do not merge different devices.
4. Different MAC and ambiguous identity: create a separate provisional asset.
5. MAC randomization: avoid an unsafe automatic merge.
6. Repeated discovery: no duplicate asset.
7. Concurrent discovery jobs: no duplicate asset.
8. IP reassignment: preserve the old device's history and create/update the correct new device.
9. Vulnerability findings and scan history remain linked to the correct asset.
10. Asset history records old and new IP addresses.
11. Existing database records survive migrations and reconciliation.
12. Frontend displays the current IP and does not count inactive duplicate records as separate active devices.
"""

import sys
import unittest
import threading
from pathlib import Path
from datetime import datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))
if str(BASE_DIR / "backend") not in sys.path:
    sys.path.insert(0, str(BASE_DIR / "backend"))

import models
from monitoring.asset_identity import (
    find_existing_asset,
    upsert_discovered_asset,
    record_asset_address,
    reconcile_duplicate_assets,
    normalize_mac,
    normalize_ip,
    is_locally_administered_mac,
    run_schema_migrations,
)
from main import format_asset


class TestAssetDeduplicationAndDynamicIP(unittest.TestCase):
    def setUp(self):
        # Use an in-memory SQLite database for isolated unit tests
        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
            echo=False,
        )
        models.Base.metadata.create_all(bind=self.engine)
        self.Session = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        self.db = self.Session()

    def tearDown(self):
        self.db.close()
        models.Base.metadata.drop_all(bind=self.engine)

    # -------------------------------------------------------------------------
    # 1. Same MAC, different IP: update the existing asset
    # -------------------------------------------------------------------------
    def test_same_mac_different_ip_updates_existing_asset(self):
        """When an asset receives a new IP address via DHCP, its existing record must be updated."""
        mac = "AC:84:C6:64:C2:3C"
        old_ip = "192.168.1.105"
        new_ip = "192.168.1.118"

        # Initial discovery
        host_initial = {
            "ip_address": old_ip,
            "mac_address": mac,
            "hostname": "laptop-engineer",
            "operating_system": "Microsoft Windows 11",
            "open_ports": [{"port": 135, "service": "msrpc"}],
        }
        asset, is_new, strat = upsert_discovered_asset(self.db, host_initial, default_criticality="High")
        self.db.commit()
        initial_id = asset.id
        self.assertTrue(is_new)
        self.assertEqual(asset.criticality, "High")

        # Laptop reconnects and DHCP hands it a new IP address
        host_reconnected = {
            "ip_address": new_ip,
            "mac_address": mac,
            "hostname": "laptop-engineer",
            "operating_system": "Microsoft Windows 11",
            "open_ports": [{"port": 135, "service": "msrpc"}],
        }
        updated_asset, is_new2, strat2 = upsert_discovered_asset(self.db, host_reconnected)
        self.db.commit()

        # Must be the SAME asset ID, NOT a new asset
        self.assertFalse(is_new2)
        self.assertEqual(strat2, "validated_mac")
        self.assertEqual(updated_asset.id, initial_id)
        self.assertEqual(updated_asset.ip_address, new_ip)
        self.assertEqual(updated_asset.criticality, "High", "Custom GRC classification must be preserved")

        # Database must have only 1 asset record
        total_assets = self.db.query(models.Asset).count()
        self.assertEqual(total_assets, 1)

    # -------------------------------------------------------------------------
    # 2. Same stable agent ID, different IP: update the existing asset
    # -------------------------------------------------------------------------
    def test_same_stable_agent_id_different_ip_updates_existing_asset(self):
        """When a host with persistent agent ID changes IP, match via Priority 1."""
        agent_id = "agent-node-rpi-001"
        old_ip = "192.168.1.149"
        new_ip = "192.168.1.180"

        host_initial = {
            "ip_address": old_ip,
            "device_id": agent_id,
            "hostname": "grc-sensor",
            "operating_system": "Debian Linux",
            "open_ports": [{"port": 22, "service": "ssh"}],
        }
        asset, is_new, _ = upsert_discovered_asset(self.db, host_initial, default_criticality="Critical")
        self.db.commit()
        asset_id = asset.id

        # Sensor changes IP
        host_moved = {
            "ip_address": new_ip,
            "device_id": agent_id,
            "hostname": "grc-sensor",
            "operating_system": "Debian Linux",
            "open_ports": [{"port": 22, "service": "ssh"}],
        }
        updated, is_new_moved, strat = upsert_discovered_asset(self.db, host_moved)
        self.db.commit()

        self.assertFalse(is_new_moved)
        self.assertEqual(strat, "persistent_agent_id")
        self.assertEqual(updated.id, asset_id)
        self.assertEqual(updated.ip_address, new_ip)
        self.assertEqual(updated.criticality, "Critical")
        self.assertEqual(self.db.query(models.Asset).count(), 1)

    # -------------------------------------------------------------------------
    # 3. Same IP, different MAC: do not merge different devices
    # -------------------------------------------------------------------------
    def test_same_ip_different_mac_does_not_merge(self):
        """When an IP is recycled to a different physical MAC, keep distinct identities."""
        shared_ip = "192.168.1.110"
        mac_device_a = "AA:AA:AA:11:11:11"
        mac_device_b = "BB:BB:BB:22:22:22"

        # Device A acquires IP
        host_a = {
            "ip_address": shared_ip,
            "mac_address": mac_device_a,
            "hostname": "device-alice",
        }
        asset_a, is_new_a, _ = upsert_discovered_asset(self.db, host_a, default_criticality="High")
        self.db.commit()

        # Device B acquires the same IP later (DHCP reassignment)
        host_b = {
            "ip_address": shared_ip,
            "mac_address": mac_device_b,
            "hostname": "device-bob",
        }
        asset_b, is_new_b, _ = upsert_discovered_asset(self.db, host_b, default_criticality="Low")
        self.db.commit()

        # Two distinct records must exist
        self.assertTrue(is_new_b)
        self.assertNotEqual(asset_a.id, asset_b.id)
        self.assertEqual(asset_a.mac_address, mac_device_a)
        self.assertEqual(asset_b.mac_address, mac_device_b)
        self.assertEqual(asset_a.criticality, "High")
        self.assertEqual(asset_b.criticality, "Low")

        # Device A was displaced and marked Offline
        self.db.refresh(asset_a)
        self.assertEqual(asset_a.status, "Offline")

    # -------------------------------------------------------------------------
    # 4. Different MAC and ambiguous identity: create separate provisional asset
    # -------------------------------------------------------------------------
    def test_different_mac_and_ambiguous_identity_creates_separate_provisional(self):
        """Host with no persistent identifier and different MAC is created as separate provisional."""
        host_a = {
            "ip_address": "192.168.1.50",
            "hostname": "host-generic",
            "mac_address": "11:22:33:44:55:66",
        }
        asset_a, _, _ = upsert_discovered_asset(self.db, host_a)
        self.db.commit()

        # New host with only IP and generic hostname (e.g. routed scan without L2 MAC)
        host_b = {
            "ip_address": "192.168.1.60",
            "hostname": "host-generic",
            "mac_address": None,
        }
        asset_b, is_new_b, _ = upsert_discovered_asset(self.db, host_b)
        self.db.commit()

        self.assertTrue(is_new_b)
        self.assertNotEqual(asset_a.id, asset_b.id)
        self.assertEqual(asset_b.identity_status, "provisional")

    # -------------------------------------------------------------------------
    # 5. MAC randomization: avoid an unsafe automatic merge
    # -------------------------------------------------------------------------
    def test_mac_randomization_avoids_unsafe_automatic_merge(self):
        """Randomized MAC addresses with shared hostname (e.g. 'iPhone') must NOT merge automatically."""
        # Both MACs have locally administered bit set (second digit 2, 6, A, or E)
        mac_rand_1 = "02:EA:2F:FA:3C:B3"
        mac_rand_2 = "DA:A1:33:44:55:66"

        self.assertTrue(is_locally_administered_mac(mac_rand_1))
        self.assertTrue(is_locally_administered_mac(mac_rand_2))

        host_1 = {
            "ip_address": "192.168.1.105",
            "mac_address": mac_rand_1,
            "hostname": "iPhone",
            "device_type": "Mobile / Smartphone",
        }
        asset_1, _, _ = upsert_discovered_asset(self.db, host_1)
        self.db.commit()

        # Another iPhone or the same phone after MAC rotation appears
        host_2 = {
            "ip_address": "192.168.1.120",
            "mac_address": mac_rand_2,
            "hostname": "iPhone",
            "device_type": "Mobile / Smartphone",
        }
        asset_2, is_new_2, strat_2 = upsert_discovered_asset(self.db, host_2)
        self.db.commit()

        # Must not merge blindly on hostname 'iPhone'
        self.assertTrue(is_new_2)
        self.assertNotEqual(asset_1.id, asset_2.id)
        self.assertEqual(self.db.query(models.Asset).count(), 2)

    # -------------------------------------------------------------------------
    # 6. Repeated discovery: no duplicate asset
    # -------------------------------------------------------------------------
    def test_repeated_discovery_no_duplicate_asset(self):
        """Repeated scans of the same host produce 1 asset."""
        host = {
            "ip_address": "192.168.1.101",
            "mac_address": "2C:3B:70:0F:76:D2",
            "hostname": "FLEMSIS",
            "operating_system": "Microsoft Windows 11",
        }
        for _ in range(5):
            asset, _, _ = upsert_discovered_asset(self.db, host)
            self.db.commit()

        count = self.db.query(models.Asset).filter(models.Asset.mac_address == "2C:3B:70:0F:76:D2").count()
        self.assertEqual(count, 1)

    # -------------------------------------------------------------------------
    # 7. Concurrent discovery jobs: no duplicate asset
    # -------------------------------------------------------------------------
    def test_concurrent_discovery_jobs_no_duplicate_asset(self):
        """Multiple threads discovering the same host concurrently create exactly 1 asset record."""
        host = {
            "ip_address": "192.168.1.101",
            "mac_address": "2C:3B:70:0F:76:D2",
            "hostname": "FLEMSIS",
            "operating_system": "Microsoft Windows 11",
        }

        created_ids = []
        errors = []

        def worker_task():
            session = self.Session()
            try:
                asset, _, _ = upsert_discovered_asset(session, host)
                session.commit()
                created_ids.append(asset.id)
            except Exception as e:
                session.rollback()
                errors.append(e)
            finally:
                session.close()

        threads = [threading.Thread(target=worker_task) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0, f"Concurrent workers encountered errors: {errors}")
        # All workers should have operated on the single identical asset ID
        self.assertEqual(len(set(created_ids)), 1)
        total_in_db = self.db.query(models.Asset).filter(models.Asset.mac_address == "2C:3B:70:0F:76:D2").count()
        self.assertEqual(total_in_db, 1)

    # -------------------------------------------------------------------------
    # 8. IP reassignment: preserve old device history, create/update new device
    # -------------------------------------------------------------------------
    def test_ip_reassignment_preserves_old_history_and_updates_new(self):
        """When IP is reassigned, old device's history is not overwritten or merged."""
        ip = "192.168.1.130"
        mac_old = "00:11:22:33:44:55"
        mac_new = "66:77:88:99:AA:BB"

        # Old device was at this IP
        asset_old, _, _ = upsert_discovered_asset(
            self.db,
            {"ip_address": ip, "mac_address": mac_old, "hostname": "old-workstation"},
            default_criticality="High",
        )
        self.db.commit()
        old_id = asset_old.id

        # New device joins and receives the IP
        asset_new, is_new, strat = upsert_discovered_asset(
            self.db,
            {"ip_address": ip, "mac_address": mac_new, "hostname": "new-laptop"},
            default_criticality="Low",
        )
        self.db.commit()

        self.assertTrue(is_new)
        self.assertNotEqual(old_id, asset_new.id)

        # Old device is preserved
        self.db.refresh(asset_old)
        self.assertEqual(asset_old.status, "Offline")
        self.assertEqual(asset_old.criticality, "High")

        # New device has its own record
        self.assertEqual(asset_new.ip_address, ip)
        self.assertEqual(asset_new.criticality, "Low")

    # -------------------------------------------------------------------------
    # 9. Vulnerability findings and scan history remain linked to the correct asset
    # -------------------------------------------------------------------------
    def test_vulnerabilities_remain_linked_when_ip_changes(self):
        """Findings stay linked to asset ID and record observed_ip_address."""
        mac = "AC:84:C6:64:C2:3C"
        old_ip = "192.168.1.105"
        new_ip = "192.168.1.118"

        asset, _, _ = upsert_discovered_asset(
            self.db,
            {"ip_address": old_ip, "mac_address": mac, "hostname": "dev-box"},
        )
        self.db.commit()

        # Add initial vulnerability finding detected at old_ip
        v1 = models.Vulnerability(
            asset_id=asset.id,
            port=445,
            title="SMB Signing Disabled",
            severity="Medium",
            observed_ip_address=old_ip,
            status="Open",
        )
        self.db.add(v1)
        self.db.commit()

        # Asset changes IP
        updated_asset, _, _ = upsert_discovered_asset(
            self.db,
            {"ip_address": new_ip, "mac_address": mac, "hostname": "dev-box"},
        )
        self.db.commit()

        # Vulnerabilities must still be linked to this asset
        vulns = updated_asset.vulnerabilities
        self.assertEqual(len(vulns), 1)
        self.assertEqual(vulns[0].title, "SMB Signing Disabled")
        self.assertEqual(vulns[0].observed_ip_address, old_ip)

        # Fresh scan at new IP discovers another finding
        v2 = models.Vulnerability(
            asset_id=updated_asset.id,
            port=22,
            title="OpenSSH Deprecated Cipher",
            severity="Low",
            observed_ip_address=new_ip,
            status="Open",
        )
        self.db.add(v2)
        self.db.commit()

        self.db.refresh(updated_asset)
        self.assertEqual(len(updated_asset.vulnerabilities), 2)
        ips_observed = {v.observed_ip_address for v in updated_asset.vulnerabilities}
        self.assertEqual(ips_observed, {old_ip, new_ip})

    # -------------------------------------------------------------------------
    # 10. Asset history records old and new IP addresses
    # -------------------------------------------------------------------------
    def test_asset_address_history_records_old_and_new_ips(self):
        """Address history records all IPs where device was observed."""
        mac = "E0:C2:64:2A:B4:08"
        ip1 = "192.168.1.102"
        ip2 = "192.168.1.115"
        ip3 = "192.168.1.122"

        asset, _, _ = upsert_discovered_asset(self.db, {"ip_address": ip1, "mac_address": mac})
        self.db.commit()
        asset, _, _ = upsert_discovered_asset(self.db, {"ip_address": ip2, "mac_address": mac})
        self.db.commit()
        asset, _, _ = upsert_discovered_asset(self.db, {"ip_address": ip3, "mac_address": mac})
        self.db.commit()

        self.db.refresh(asset)
        history_ips = [h.ip_address for h in asset.address_history]
        self.assertIn(ip1, history_ips)
        self.assertIn(ip2, history_ips)
        self.assertIn(ip3, history_ips)
        self.assertEqual(asset.ip_address, ip3)

    # -------------------------------------------------------------------------
    # 11. Existing database records survive migrations and reconciliation
    # -------------------------------------------------------------------------
    def test_safe_reconciliation_preserves_audit_history(self):
        """Safe non-destructive reconciliation transfers relationships and retains deactivated record."""
        # Create primary asset
        primary = models.Asset(
            ip_address="192.168.1.101",
            mac_address="2C:3B:70:0F:76:D2",
            hostname="FLEMSIS",
            criticality="High",
        )
        self.db.add(primary)
        self.db.commit()

        # Create duplicate record accidentally created by old pipeline
        duplicate = models.Asset(
            ip_address="192.168.1.118",
            mac_address=None,
            hostname="FLEMSIS",
            criticality=None,
        )
        self.db.add(duplicate)
        self.db.commit()

        # Add risk to duplicate
        r_dup = models.Risk(asset_id=duplicate.id, title="RDP Exposed", likelihood="High", impact="High")
        self.db.add(r_dup)
        self.db.commit()

        # Perform safe reconciliation
        surviving = reconcile_duplicate_assets(
            self.db,
            primary_asset_id=primary.id,
            secondary_asset_id=duplicate.id,
            operator_name="analyst_test",
            reason="Confirmed same laptop after DHCP lease changed",
        )

        self.assertEqual(surviving.id, primary.id)
        self.db.refresh(duplicate)
        self.assertEqual(duplicate.status, "deactivated")
        self.assertEqual(duplicate.identity_status, "deactivated")

        # The risk was transferred to primary
        self.db.refresh(primary)
        self.assertTrue(any(r.title == "RDP Exposed" for r in primary.risks))

        # Audit log was created
        audit = (
            self.db.query(models.AuditLog)
            .filter(models.AuditLog.entity_id == primary.id)
            .first()
        )
        self.assertIsNotNone(audit)
        self.assertIn("FLEMSIS", audit.description)

    # -------------------------------------------------------------------------
    # 12. Frontend displays current IP and does not count inactive duplicates
    # -------------------------------------------------------------------------
    def test_frontend_format_and_deactivated_exclusion(self):
        """format_asset returns current IP and address history; deactivated records are filtered."""
        asset = models.Asset(
            ip_address="192.168.1.118",
            mac_address="2C:3B:70:0F:76:D2",
            hostname="FLEMSIS",
            status="Active",
        )
        self.db.add(asset)
        self.db.flush()

        record_asset_address(self.db, asset, "192.168.1.101", asset.mac_address)
        record_asset_address(self.db, asset, "192.168.1.118", asset.mac_address)
        self.db.commit()

        formatted = format_asset(asset)
        self.assertEqual(formatted["ip_address"], "192.168.1.118")
        self.assertEqual(len(formatted["address_history"]), 2)
        history_ips = [h["ip_address"] for h in formatted["address_history"]]
        self.assertIn("192.168.1.101", history_ips)
        self.assertIn("192.168.1.118", history_ips)

        # Deactivated duplicate record
        dup = models.Asset(
            ip_address="192.168.1.101",
            status="deactivated",
        )
        self.db.add(dup)
        self.db.commit()

        # Query excluding deactivated (standard endpoint behavior)
        active_assets = self.db.query(models.Asset).filter(models.Asset.status != "deactivated").all()
        self.assertEqual(len(active_assets), 1)
        self.assertEqual(active_assets[0].id, asset.id)

    # -------------------------------------------------------------------------
    # 13. Migration ordering: columns created BEFORE indexes referencing them
    # -------------------------------------------------------------------------
    def test_migration_ordering_creates_columns_before_indexes(self):
        """Simulate an existing legacy database missing device_id and asset_address_history.
        Verify that run_schema_migrations creates columns before indexes and seeds history."""
        from sqlalchemy import inspect, text

        test_engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
            echo=False,
        )

        with test_engine.connect() as conn:
            # Create a legacy assets table WITHOUT device_id, identity_status, mac_vendor
            conn.execute(text("""
                CREATE TABLE assets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    hostname VARCHAR,
                    ip_address VARCHAR NOT NULL,
                    mac_address VARCHAR,
                    status VARCHAR DEFAULT 'Active',
                    risk_score INTEGER DEFAULT 0,
                    risk_level VARCHAR DEFAULT 'Low',
                    last_seen DATETIME
                );
            """))
            # Create a legacy vulnerabilities table WITHOUT observed_ip_address
            conn.execute(text("""
                CREATE TABLE vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    asset_id INTEGER NOT NULL,
                    title VARCHAR NOT NULL,
                    severity VARCHAR DEFAULT 'Medium',
                    status VARCHAR DEFAULT 'Open',
                    discovered_at DATETIME
                );
            """))
            # Insert a legacy pre-existing asset record
            conn.execute(text("""
                INSERT INTO assets (hostname, ip_address, mac_address, status, last_seen)
                VALUES ('legacy-server', '192.168.1.50', 'AA:BB:CC:DD:EE:01', 'Active', '2026-01-01 12:00:00');
            """))
            conn.commit()

        # Run migration on the legacy database
        run_schema_migrations(test_engine)

        inspector = inspect(test_engine)
        asset_cols = {c["name"] for c in inspector.get_columns("assets")}
        vuln_cols = {c["name"] for c in inspector.get_columns("vulnerabilities")}
        tables = set(inspector.get_table_names())

        # 1. Columns must exist
        self.assertIn("device_id", asset_cols)
        self.assertIn("identity_status", asset_cols)
        self.assertIn("mac_vendor", asset_cols)
        self.assertIn("observed_ip_address", vuln_cols)

        # 2. Table asset_address_history must exist
        self.assertIn("asset_address_history", tables)

        # 3. Indexes must exist
        asset_indexes = {idx["name"] for idx in inspector.get_indexes("assets")}
        self.assertIn("ix_assets_device_id", asset_indexes)

        # 4. Existing legacy asset must be preserved and seeded into history
        with test_engine.connect() as conn:
            seeded = conn.execute(text("SELECT asset_id, ip_address, mac_address FROM asset_address_history;")).fetchall()
            self.assertEqual(len(seeded), 1)
            self.assertEqual(seeded[0][1], "192.168.1.50")
            self.assertEqual(seeded[0][2], "AA:BB:CC:DD:EE:01")

            asset_row = conn.execute(text("SELECT hostname, ip_address FROM assets WHERE id = 1;")).fetchone()
            self.assertEqual(asset_row[0], "legacy-server")
            self.assertEqual(asset_row[1], "192.168.1.50")

    # -------------------------------------------------------------------------
    # 14. Migration repeat execution: safe and idempotent
    # -------------------------------------------------------------------------
    def test_migration_repeat_execution_is_idempotent(self):
        """Calling run_schema_migrations multiple times must succeed without error or duplicate records."""
        from sqlalchemy import text

        test_engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
            echo=False,
        )

        with test_engine.connect() as conn:
            conn.execute(text("""
                CREATE TABLE assets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    hostname VARCHAR,
                    ip_address VARCHAR NOT NULL,
                    mac_address VARCHAR,
                    status VARCHAR DEFAULT 'Active',
                    last_seen DATETIME
                );
            """))
            conn.execute(text("""
                INSERT INTO assets (hostname, ip_address, mac_address, status, last_seen)
                VALUES ('workstation-1', '10.0.0.25', '00:11:22:33:44:55', 'Active', '2026-02-01 10:00:00');
            """))
            conn.commit()

        # Run first time
        run_schema_migrations(test_engine)

        # Run second time (repeat execution)
        run_schema_migrations(test_engine)

        # Run third time
        run_schema_migrations(test_engine)

        with test_engine.connect() as conn:
            history_rows = conn.execute(text("SELECT * FROM asset_address_history;")).fetchall()
            # Must NOT duplicate seeded history
            self.assertEqual(len(history_rows), 1)

            asset_count = conn.execute(text("SELECT COUNT(*) FROM assets;")).scalar()
            self.assertEqual(asset_count, 1)

    # -------------------------------------------------------------------------
    # 15. Index creation fails if attempted before column creation (reproduces bug)
    # -------------------------------------------------------------------------
    def test_index_creation_fails_if_attempted_before_column_creation(self):
        """Demonstrates that creating an index before the column exists raises an error.
        This directly reproduces the failure that run_schema_migrations prevents."""
        from sqlalchemy import text, exc

        test_engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
            echo=False,
        )

        with test_engine.connect() as conn:
            conn.execute(text("CREATE TABLE assets (id INTEGER PRIMARY KEY, ip_address VARCHAR);"))
            # Attempting to create index on non-existent column 'device_id' MUST fail
            with self.assertRaises((exc.OperationalError, exc.DatabaseError)):
                conn.execute(text("CREATE INDEX ix_assets_device_id ON assets (device_id);"))


if __name__ == "__main__":
    unittest.main()


"""Safe, transactional database migration script for asset network scope and reconciliation.

Preserves all records, audit logs, risks, and vulnerabilities.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

# Add project root to path
base_dir = Path(__file__).resolve().parent.parent
if str(base_dir) not in sys.path:
    sys.path.insert(0, str(base_dir))
backend_dir = base_dir / "backend"
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from sqlalchemy import text
from backend.database import engine

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("migration")


def run_migration():
    logger.info("Connecting to database...")

    with engine.connect() as conn:
        trans = conn.begin()
        try:
            # 1. Pre-migration verification
            pre_assets = conn.execute(text("SELECT count(*) FROM assets;")).scalar()
            pre_vulns = conn.execute(text("SELECT count(*) FROM vulnerabilities;")).scalar()
            pre_risks = conn.execute(text("SELECT count(*) FROM risks;")).scalar()
            pre_drift = conn.execute(text("SELECT count(*) FROM drift_events;")).scalar()
            pre_audit = conn.execute(text("SELECT count(*) FROM audit_logs;")).scalar()

            logger.info("=== PRE-MIGRATION RECORD COUNTS ===")
            logger.info(f"Assets: {pre_assets}")
            logger.info(f"Vulnerabilities: {pre_vulns}")
            logger.info(f"Risks: {pre_risks}")
            logger.info(f"Drift Events: {pre_drift}")
            logger.info(f"Audit Logs: {pre_audit}")

            # 2. Add columns if missing (strictly additive)
            logger.info("Adding schema columns if missing...")
            conn.execute(text("ALTER TABLE assets ADD COLUMN IF NOT EXISTS network_scope VARCHAR(50) DEFAULT 'needs_review';"))
            conn.execute(text("ALTER TABLE assets ADD COLUMN IF NOT EXISTS assigned_ip_status VARCHAR(50) DEFAULT 'active_assignment';"))
            conn.execute(text("ALTER TABLE assets ADD COLUMN IF NOT EXISTS offline_reason VARCHAR(255);"))
            conn.execute(text("ALTER TABLE assets ADD COLUMN IF NOT EXISTS dhcp_lease_source VARCHAR(50) DEFAULT 'none';"))
            conn.execute(text("ALTER TABLE assets ADD COLUMN IF NOT EXISTS dhcp_client_name VARCHAR(100);"))
            conn.execute(text("ALTER TABLE assets ADD COLUMN IF NOT EXISTS consecutive_scan_misses INTEGER DEFAULT 0;"))
            conn.execute(text("ALTER TABLE assets ADD COLUMN IF NOT EXISTS last_successful_scan_at TIMESTAMP;"))

            # 3. Create indexes
            logger.info("Creating indexes...")
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_assets_network_scope ON assets (network_scope);"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_assets_assigned_ip_status ON assets (assigned_ip_status);"))

            # 4. Backfill scopes using verified network boundaries & evidence
            logger.info("Backfilling network scopes...")

            # Localhost / loopback
            conn.execute(text("""
                UPDATE assets
                SET network_scope = 'loopback',
                    status = 'Offline',
                    offline_reason = 'Localhost loopback interface (isolated from physical LAN inventory)'
                WHERE ip_address = '127.0.0.1' OR hostname = 'localhost';
            """))

            # Subnet broadcast address
            conn.execute(text("""
                UPDATE assets
                SET network_scope = 'out_of_scope',
                    status = 'Offline',
                    assigned_ip_status = 'historical_lease_displaced',
                    offline_reason = 'Subnet broadcast address (excluded from active host inventory)'
                WHERE ip_address LIKE '%.255';
            """))

            # Docker container infrastructure
            conn.execute(text("""
                UPDATE assets
                SET network_scope = 'local_container',
                    offline_reason = 'Docker bridge container infrastructure'
                WHERE ip_address LIKE '172.18.%' OR hostname LIKE '%ai-grc-platform%';
            """))

            # VMware virtual host adapters
            conn.execute(text("""
                UPDATE assets
                SET network_scope = 'virtual_interface',
                    offline_reason = 'VMware virtual adapter host interface'
                WHERE ip_address LIKE '192.168.127.%' AND ip_address != '192.168.127.255';
            """))

            # Unrelated private IP outside 192.168.1.0/24
            conn.execute(text("""
                UPDATE assets
                SET network_scope = 'out_of_scope',
                    status = 'Offline',
                    assigned_ip_status = 'historical_lease_displaced',
                    offline_reason = 'Non-LAN private address outside configured 192.168.1.0/24 scope'
                WHERE ip_address LIKE '172.16.%';
            """))

            # Physical LAN hosts in 192.168.1.0/24
            conn.execute(text("""
                UPDATE assets
                SET network_scope = 'physical_lan'
                WHERE (ip_address LIKE '192.168.1.%' OR discovery_source = 'pi_agent_l2')
                  AND ip_address != '192.168.1.255'
                  AND network_scope = 'needs_review';
            """))

            # Displaced historical leaseholders
            logger.info("Marking displaced historical DHCP leaseholders...")
            conn.execute(text("""
                UPDATE assets
                SET assigned_ip_status = 'historical_lease_displaced',
                    offline_reason = 'IP 192.168.1.100 reassigned by DHCP to MAC 0A:CD:45:AB:91:A4 (Sujal)'
                WHERE id = 7 AND ip_address = '192.168.1.100';
            """))

            conn.execute(text("""
                UPDATE assets
                SET assigned_ip_status = 'historical_lease_displaced',
                    offline_reason = 'IP 192.168.1.103 reassigned by DHCP to MAC 5E:47:31:96:B8:14'
                WHERE id = 18 AND ip_address = '192.168.1.103';
            """))

            conn.execute(text("""
                UPDATE assets
                SET assigned_ip_status = 'historical_lease_displaced',
                    offline_reason = 'IP 192.168.1.133 reassigned by DHCP to MAC EE:37:8A:B3:BF:95 (iPhone)'
                WHERE id = 12 AND ip_address = '192.168.1.133';
            """))

            # Static infrastructure
            conn.execute(text("""
                UPDATE assets
                SET assigned_ip_status = 'static_reservation',
                    dhcp_lease_source = 'static_registry',
                    dhcp_client_name = 'TP-Link Gateway'
                WHERE id = 6 AND ip_address = '192.168.1.1';
            """))

            conn.execute(text("""
                UPDATE assets
                SET assigned_ip_status = 'static_reservation',
                    dhcp_lease_source = 'static_registry',
                    dhcp_client_name = 'grc'
                WHERE id = 9 AND ip_address = '192.168.1.149';
            """))

            # Active holders of reassigned IPs with static DHCP registry metadata
            conn.execute(text("""
                UPDATE assets
                SET assigned_ip_status = 'active_assignment',
                    dhcp_lease_source = 'static_registry',
                    dhcp_client_name = 'Sujal'
                WHERE id = 24 AND ip_address = '192.168.1.100';
            """))

            conn.execute(text("""
                UPDATE assets
                SET assigned_ip_status = 'active_assignment',
                    dhcp_lease_source = 'static_registry',
                    dhcp_client_name = 'iPhone'
                WHERE id = 30 AND ip_address = '192.168.1.133';
            """))

            # Populate last_successful_scan_at where assessment was completed
            conn.execute(text("""
                UPDATE assets
                SET last_successful_scan_at = COALESCE(last_assessed_at, last_seen)
                WHERE (assessment_status LIKE '%Completed%' OR assessment_status LIKE '%Findings detected%')
                  AND last_successful_scan_at IS NULL;
            """))

            # 5. Reconcile exact duplicate Asset #19 into surviving Asset #8
            logger.info("Reconciling exact duplicate Asset #19 into Asset #8...")
            conn.execute(text("UPDATE drift_events SET asset_id = 8 WHERE asset_id = 19;"))
            conn.execute(text("""
                UPDATE assets
                SET status = 'deactivated',
                    identity_status = 'deactivated',
                    network_scope = 'physical_lan',
                    assigned_ip_status = 'deactivated',
                    offline_reason = 'Reconciled duplicate of verified Asset #8 (same IP 192.168.1.127 and verified MAC E0:C2:64:2A:B4:08)'
                WHERE id = 19;
            """))

            # Ensure Asset #8 has last_successful_scan_at and offline_reason null
            conn.execute(text("""
                UPDATE assets
                SET last_successful_scan_at = COALESCE(last_assessed_at, last_seen),
                    offline_reason = NULL,
                    consecutive_scan_misses = 0
                WHERE id = 8;
            """))

            # Audit log entry for reconciliation
            conn.execute(text("""
                INSERT INTO audit_logs (source, actor, action, entity_type, entity_id, entity_name, old_values, new_values, description, timestamp)
                SELECT 'SYSTEM', 'System Migration', 'UPDATE', 'Asset', 8, 'Asset #8 (Joshua, IP: 192.168.1.127)',
                       '{"status": "Active", "reconciled_with": null}',
                       '{"status": "Active", "reconciled_with_asset_id": 19}',
                       'Safely reconciled exact duplicate Asset #19 (IP: 192.168.1.127, MAC: E0:C2:64:2A:B4:08) into surviving Asset #8. Retained all drift events and historical records.',
                       CURRENT_TIMESTAMP
                WHERE NOT EXISTS (
                    SELECT 1 FROM audit_logs WHERE description LIKE '%reconciled exact duplicate Asset #19%'
                );
            """))

            # 6. Post-migration verification
            post_assets = conn.execute(text("SELECT count(*) FROM assets;")).scalar()
            post_vulns = conn.execute(text("SELECT count(*) FROM vulnerabilities;")).scalar()
            post_risks = conn.execute(text("SELECT count(*) FROM risks;")).scalar()
            post_drift = conn.execute(text("SELECT count(*) FROM drift_events;")).scalar()
            post_audit = conn.execute(text("SELECT count(*) FROM audit_logs;")).scalar()

            logger.info("=== POST-MIGRATION RECORD COUNTS ===")
            logger.info(f"Assets: {post_assets} (Expected: {pre_assets} - NO records deleted)")
            logger.info(f"Vulnerabilities: {post_vulns} (Expected: {pre_vulns} - NO records deleted)")
            logger.info(f"Risks: {post_risks} (Expected: {pre_risks} - NO records deleted)")
            logger.info(f"Drift Events: {post_drift} (Expected: {pre_drift} - NO records deleted)")
            logger.info(f"Audit Logs: {post_audit} (Expected: {pre_audit} + 1 audit entry)")

            assert post_assets == pre_assets, f"Asset count mismatch: {post_assets} != {pre_assets}"
            assert post_vulns == pre_vulns, f"Vulnerability count mismatch: {post_vulns} != {pre_vulns}"
            assert post_risks == pre_risks, f"Risk count mismatch: {post_risks} != {pre_risks}"
            assert post_drift == pre_drift, f"Drift count mismatch: {post_drift} != {pre_drift}"

            trans.commit()
            logger.info("MIGRATION TRANSACTION COMMITTED SUCCESSFULLY.")

        except Exception as e:
            trans.rollback()
            logger.error("Migration failed, transaction rolled back: %s", e, exc_info=True)
            raise


if __name__ == "__main__":
    run_migration()

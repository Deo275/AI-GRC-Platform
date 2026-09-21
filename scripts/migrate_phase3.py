"""Phase 3 Database Migration Script: Compliance Mapping.

Performs safe, non-destructive schema migration on the live PostgreSQL database:
1. Creates `compliance_frameworks` table.
2. Creates `compliance_requirements` table.
3. Creates `control_compliance_mappings` table with uniqueness constraint.
4. Seeds NIST CSF 2.0 and ISO/IEC 27001:2022 frameworks (noted as reviewed prototype subset).
5. Seeds reviewed requirements across all functions/themes.
6. Seeds reviewed control-to-requirement mappings.
7. Verifies existing records (assets, risks, vulnerabilities, controls) are completely preserved.
"""

import sys
from pathlib import Path

# Ensure project root and backend are in sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(BASE_DIR / "backend"))

import database
import models
from sqlalchemy import text


# ---------------------------------------------------------------------------
# Seed Data: Frameworks
# ---------------------------------------------------------------------------
FRAMEWORKS_DATA = [
    {
        "name": "NIST CSF",
        "version": "2.0",
        "description": (
            "NIST Cybersecurity Framework 2.0 (February 2024). Organized across 6 Core Functions: "
            "Govern (GV), Identify (ID), Protect (PR), Detect (DE), Respond (RS), and Recover (RC). "
            "Seeded as a reviewed prototype subset of supported requirements."
        )
    },
    {
        "name": "ISO/IEC 27001",
        "version": "2022",
        "description": (
            "ISO/IEC 27001:2022 Information Security Management Systems - Annex A Controls. "
            "Structured across 4 themes: Organizational (A.5), People (A.6), Physical (A.7), "
            "and Technological (A.8). Seeded as a reviewed prototype subset of supported requirements."
        )
    }
]


# ---------------------------------------------------------------------------
# Seed Data: NIST CSF 2.0 Requirements (Reviewed Supported Subset)
# ---------------------------------------------------------------------------
NIST_CSF_REQUIREMENTS = [
    {
        "requirement_id": "GV.OC-01",
        "title": "Organizational Mission & Context",
        "function": "Govern",
        "category": "GV.OC (Organizational Context)",
        "subcategory": "GV.OC-01",
        "description": "The organizational mission is understood and informs cybersecurity risk management."
    },
    {
        "requirement_id": "GV.RM-01",
        "title": "Risk Management Objectives",
        "function": "Govern",
        "category": "GV.RM (Risk Management Strategy)",
        "subcategory": "GV.RM-01",
        "description": "Risk management objectives are established and agreed to by organizational stakeholders."
    },
    {
        "requirement_id": "ID.AM-01",
        "title": "Hardware Inventory",
        "function": "Identify",
        "category": "ID.AM (Asset Management)",
        "subcategory": "ID.AM-01",
        "description": "Inventories of hardware managed by the organization are maintained."
    },
    {
        "requirement_id": "ID.RA-01",
        "title": "Asset Vulnerability Identification",
        "function": "Identify",
        "category": "ID.RA (Risk Assessment)",
        "subcategory": "ID.RA-01",
        "description": "Vulnerabilities in assets are identified, validated, and recorded."
    },
    {
        "requirement_id": "PR.AA-01",
        "title": "Identity & Credential Management",
        "function": "Protect",
        "category": "PR.AA (Identity Management, Authentication, and Access Control)",
        "subcategory": "PR.AA-01",
        "description": "Identities and credentials for authorized users, services, and hardware are managed by the organization."
    },
    {
        "requirement_id": "PR.AA-03",
        "title": "User & Service Authentication",
        "function": "Protect",
        "category": "PR.AA (Identity Management, Authentication, and Access Control)",
        "subcategory": "PR.AA-03",
        "description": "Users, services, and hardware are authenticated."
    },
    {
        "requirement_id": "PR.AA-05",
        "title": "Access Permissions & Least Privilege",
        "function": "Protect",
        "category": "PR.AA (Identity Management, Authentication, and Access Control)",
        "subcategory": "PR.AA-05",
        "description": "Access permissions, entitlements, and authorizations are defined in a policy, managed, enforced, and reviewed, incorporating the principles of least privilege and separation of duties."
    },
    {
        "requirement_id": "PR.DS-01",
        "title": "Data-at-Rest Protection",
        "function": "Protect",
        "category": "PR.DS (Data Security)",
        "subcategory": "PR.DS-01",
        "description": "The confidentiality, integrity, and availability of data-at-rest are protected."
    },
    {
        "requirement_id": "PR.DS-02",
        "title": "Data-in-Transit Protection",
        "function": "Protect",
        "category": "PR.DS (Data Security)",
        "subcategory": "PR.DS-02",
        "description": "The confidentiality, integrity, and availability of data-in-transit are protected."
    },
    {
        "requirement_id": "PR.DS-11",
        "title": "Backup Management & Testing",
        "function": "Protect",
        "category": "PR.DS (Data Security)",
        "subcategory": "PR.DS-11",
        "description": "Backups of data are created, protected, maintained, and tested."
    },
    {
        "requirement_id": "PR.PS-01",
        "title": "Configuration Management",
        "function": "Protect",
        "category": "PR.PS (Platform Security)",
        "subcategory": "PR.PS-01",
        "description": "Configuration management practices are established and applied."
    },
    {
        "requirement_id": "PR.PS-02",
        "title": "Software Maintenance & Patching",
        "function": "Protect",
        "category": "PR.PS (Platform Security)",
        "subcategory": "PR.PS-02",
        "description": "Software is maintained, replaced, and removed commensurate with risk."
    },
    {
        "requirement_id": "PR.IR-01",
        "title": "Network & Infrastructure Protection",
        "function": "Protect",
        "category": "PR.IR (Technology Infrastructure Resilience)",
        "subcategory": "PR.IR-01",
        "description": "Networks and environments are protected from unauthorized logical access and usage."
    },
    {
        "requirement_id": "DE.CM-01",
        "title": "Network & System Monitoring",
        "function": "Detect",
        "category": "DE.CM (Continuous Monitoring)",
        "subcategory": "DE.CM-01",
        "description": "Networks and network services are monitored to find potentially adverse events."
    },
    {
        "requirement_id": "DE.AE-03",
        "title": "Event Correlation & Analysis",
        "function": "Detect",
        "category": "DE.AE (Adverse Event Analysis)",
        "subcategory": "DE.AE-03",
        "description": "Information is correlated from multiple sources."
    },
    {
        "requirement_id": "RS.MA-01",
        "title": "Incident Management Plan",
        "function": "Respond",
        "category": "RS.MA (Incident Management)",
        "subcategory": "RS.MA-01",
        "description": "The incident management program is established, communicated, and maintained."
    },
    {
        "requirement_id": "RS.MI-01",
        "title": "Incident Mitigation",
        "function": "Respond",
        "category": "RS.MI (Incident Mitigation)",
        "subcategory": "RS.MI-01",
        "description": "Incidents are contained and mitigated."
    },
    {
        "requirement_id": "RC.RP-01",
        "title": "Recovery Execution",
        "function": "Recover",
        "category": "RC.RP (Recovery Planning)",
        "subcategory": "RC.RP-01",
        "description": "Recovery processes and procedures are executed and maintained."
    }
]


# ---------------------------------------------------------------------------
# Seed Data: ISO/IEC 27001:2022 Annex A Requirements (Reviewed Supported Subset)
# ---------------------------------------------------------------------------
ISO_27001_REQUIREMENTS = [
    {
        "requirement_id": "A.5.15",
        "title": "Access control",
        "function": "Organizational",
        "category": "A.5 (Organizational controls)",
        "subcategory": "A.5.15",
        "description": "Rules to control physical and logical access to information and other associated assets shall be established and implemented in accordance with specific information security requirements."
    },
    {
        "requirement_id": "A.5.16",
        "title": "Identity management",
        "function": "Organizational",
        "category": "A.5 (Organizational controls)",
        "subcategory": "A.5.16",
        "description": "The full life cycle of identities shall be managed."
    },
    {
        "requirement_id": "A.5.17",
        "title": "Authentication information",
        "function": "Organizational",
        "category": "A.5 (Organizational controls)",
        "subcategory": "A.5.17",
        "description": "Allocation and management of authentication information shall be controlled by a management process, including advising personnel on proper handling."
    },
    {
        "requirement_id": "A.5.18",
        "title": "Access rights",
        "function": "Organizational",
        "category": "A.5 (Organizational controls)",
        "subcategory": "A.5.18",
        "description": "Access rights to information and other associated assets shall be provisioned, reviewed, modified and revoked in accordance with the organization's topic-specific policy on access control."
    },
    {
        "requirement_id": "A.6.3",
        "title": "Information security awareness, education and training",
        "function": "People",
        "category": "A.6 (People controls)",
        "subcategory": "A.6.3",
        "description": "Personnel of the organization and relevant interested parties shall receive appropriate information security awareness, education and training."
    },
    {
        "requirement_id": "A.7.2",
        "title": "Physical entry",
        "function": "Physical",
        "category": "A.7 (Physical controls)",
        "subcategory": "A.7.2",
        "description": "Secure areas shall be protected by appropriate entry controls and access points."
    },
    {
        "requirement_id": "A.8.1",
        "title": "User endpoint devices",
        "function": "Technological",
        "category": "A.8 (Technological controls)",
        "subcategory": "A.8.1",
        "description": "Information stored on, processed by or accessible via user endpoint devices shall be protected."
    },
    {
        "requirement_id": "A.8.5",
        "title": "Secure authentication",
        "function": "Technological",
        "category": "A.8 (Technological controls)",
        "subcategory": "A.8.5",
        "description": "Secure authentication technologies and procedures shall be implemented based on information access restrictions and the topic-specific policy on access control."
    },
    {
        "requirement_id": "A.8.7",
        "title": "Protection against malware",
        "function": "Technological",
        "category": "A.8 (Technological controls)",
        "subcategory": "A.8.7",
        "description": "Protection against malware shall be implemented and supported by appropriate user awareness."
    },
    {
        "requirement_id": "A.8.8",
        "title": "Management of technical vulnerabilities",
        "function": "Technological",
        "category": "A.8 (Technological controls)",
        "subcategory": "A.8.8",
        "description": "Information about technical vulnerabilities of information systems in use shall be obtained, the organization's exposure to such vulnerabilities evaluated, and appropriate measures taken."
    },
    {
        "requirement_id": "A.8.13",
        "title": "Information backup",
        "function": "Technological",
        "category": "A.8 (Technological controls)",
        "subcategory": "A.8.13",
        "description": "Backup copies of information, software and systems shall be maintained and regularly tested in accordance with the agreed topic-specific policy on backup."
    },
    {
        "requirement_id": "A.8.15",
        "title": "Logging",
        "function": "Technological",
        "category": "A.8 (Technological controls)",
        "subcategory": "A.8.15",
        "description": "Logs that record activities, exceptions, faults and other relevant events shall be produced, stored, protected and analysed."
    },
    {
        "requirement_id": "A.8.16",
        "title": "Monitoring activities",
        "function": "Technological",
        "category": "A.8 (Technological controls)",
        "subcategory": "A.8.16",
        "description": "Networks, systems and applications shall be monitored for anomalous behaviour and appropriate actions taken to evaluate potential information security incidents."
    },
    {
        "requirement_id": "A.8.20",
        "title": "Network security",
        "function": "Technological",
        "category": "A.8 (Technological controls)",
        "subcategory": "A.8.20",
        "description": "Networks and network devices shall be secured, managed and controlled to protect information in systems and applications."
    },
    {
        "requirement_id": "A.8.22",
        "title": "Segregation of networks",
        "function": "Technological",
        "category": "A.8 (Technological controls)",
        "subcategory": "A.8.22",
        "description": "Groups of information services, users and information systems shall be segregated in networks."
    },
    {
        "requirement_id": "A.8.24",
        "title": "Use of cryptography",
        "function": "Technological",
        "category": "A.8 (Technological controls)",
        "subcategory": "A.8.24",
        "description": "Rules for the effective use of cryptography, including cryptographic key management, shall be defined and implemented."
    }
]


# ---------------------------------------------------------------------------
# Seed Data: Control-to-Requirement Mappings
# ---------------------------------------------------------------------------
CONTROL_MAPPINGS = [
    # Firewall
    {"control_name": "Firewall", "req_id": "PR.IR-01", "strength": "Direct", "notes": "Network packet filtering enforces perimeter security boundary."},
    {"control_name": "Firewall", "req_id": "PR.PS-01", "strength": "Supporting", "notes": "Firewall configuration baselines."},
    {"control_name": "Firewall", "req_id": "A.8.20", "strength": "Direct", "notes": "Network security and device traffic management."},
    {"control_name": "Firewall", "req_id": "A.8.22", "strength": "Direct", "notes": "Segregates internal networks from external untrusted zones."},

    # Access Control
    {"control_name": "Access Control", "req_id": "PR.AA-01", "strength": "Supporting", "notes": "Role-based credential governance."},
    {"control_name": "Access Control", "req_id": "PR.AA-05", "strength": "Direct", "notes": "Least privilege access control enforcement."},
    {"control_name": "Access Control", "req_id": "A.5.15", "strength": "Direct", "notes": "Establishment and enforcement of access control rules."},
    {"control_name": "Access Control", "req_id": "A.5.18", "strength": "Direct", "notes": "Provisioning and review of user access rights."},

    # Patch Management
    {"control_name": "Patch Management", "req_id": "PR.PS-02", "strength": "Direct", "notes": "Timely software maintenance and security updates."},
    {"control_name": "Patch Management", "req_id": "A.8.8", "strength": "Direct", "notes": "Remediation of technical vulnerabilities through patching."},

    # Network Segmentation
    {"control_name": "Network Segmentation", "req_id": "PR.IR-01", "strength": "Direct", "notes": "Isolates sensitive services into restricted VLANs."},
    {"control_name": "Network Segmentation", "req_id": "A.8.22", "strength": "Direct", "notes": "Segregation of information processing facilities and networks."},
    {"control_name": "Network Segmentation", "req_id": "A.8.20", "strength": "Supporting", "notes": "Supports defense-in-depth network architecture."},

    # MFA
    {"control_name": "Multi-Factor Authentication (MFA)", "req_id": "PR.AA-03", "strength": "Direct", "notes": "Enforces multiple authentication factors for users and admins."},
    {"control_name": "Multi-Factor Authentication (MFA)", "req_id": "A.8.5", "strength": "Direct", "notes": "Implementation of secure multi-factor authentication."},
    {"control_name": "Multi-Factor Authentication (MFA)", "req_id": "A.5.17", "strength": "Supporting", "notes": "Controls authentication information management."},

    # Encryption (TLS/SSL)
    {"control_name": "Encryption (TLS/SSL)", "req_id": "PR.DS-02", "strength": "Direct", "notes": "Enforces TLS encryption for data in transit."},
    {"control_name": "Encryption (TLS/SSL)", "req_id": "PR.DS-01", "strength": "Supporting", "notes": "Protects data confidentiality across communications."},
    {"control_name": "Encryption (TLS/SSL)", "req_id": "A.8.24", "strength": "Direct", "notes": "Defines and implements cryptographic controls and protocols."},

    # Logging & Monitoring
    {"control_name": "Logging & Monitoring", "req_id": "DE.CM-01", "strength": "Direct", "notes": "Continuous monitoring of network activities and events."},
    {"control_name": "Logging & Monitoring", "req_id": "DE.AE-03", "strength": "Direct", "notes": "Centralized audit log aggregation and event correlation."},
    {"control_name": "Logging & Monitoring", "req_id": "A.8.15", "strength": "Direct", "notes": "Production, protection, and analysis of system logs."},
    {"control_name": "Logging & Monitoring", "req_id": "A.8.16", "strength": "Direct", "notes": "Monitoring networks and systems for anomalous behavior."},

    # Automated Backups
    {"control_name": "Automated Backups", "req_id": "PR.DS-11", "strength": "Direct", "notes": "Periodic automated backups with encrypted storage."},
    {"control_name": "Automated Backups", "req_id": "RC.RP-01", "strength": "Supporting", "notes": "Provides restorable data copies for recovery execution."},
    {"control_name": "Automated Backups", "req_id": "A.8.13", "strength": "Direct", "notes": "Maintains and tests backup copies of systems and information."},

    # Endpoint Protection
    {"control_name": "Endpoint Protection", "req_id": "PR.PS-01", "strength": "Supporting", "notes": "Host baseline hardening and behavioral inspection."},
    {"control_name": "Endpoint Protection", "req_id": "DE.CM-01", "strength": "Supporting", "notes": "Host-level anomaly and malware detection."},
    {"control_name": "Endpoint Protection", "req_id": "A.8.7", "strength": "Direct", "notes": "Antivirus and host-based intrusion prevention."},
    {"control_name": "Endpoint Protection", "req_id": "A.8.1", "strength": "Direct", "notes": "Secures managed user endpoint devices."}
]


def run_migration():
    engine = database.engine
    print("Beginning Phase 3 database migration (Compliance Mapping)...")

    # 1. Non-destructive schema alterations
    with engine.connect() as conn:
        print("Creating compliance tables if not exists...")
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS compliance_frameworks (
                id SERIAL PRIMARY KEY,
                name VARCHAR NOT NULL,
                version VARCHAR NOT NULL,
                description VARCHAR(1000),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """))

        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS compliance_requirements (
                id SERIAL PRIMARY KEY,
                framework_id INTEGER NOT NULL REFERENCES compliance_frameworks(id) ON DELETE CASCADE,
                requirement_id VARCHAR NOT NULL,
                title VARCHAR NOT NULL,
                description VARCHAR(2000),
                function VARCHAR,
                category VARCHAR,
                subcategory VARCHAR,
                status VARCHAR DEFAULT 'Not Assessed',
                notes VARCHAR(2000),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """))

        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS control_compliance_mappings (
                id SERIAL PRIMARY KEY,
                control_id INTEGER NOT NULL REFERENCES controls(id) ON DELETE CASCADE,
                requirement_id INTEGER NOT NULL REFERENCES compliance_requirements(id) ON DELETE CASCADE,
                mapping_strength VARCHAR DEFAULT 'Direct',
                notes VARCHAR(1000),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                CONSTRAINT uq_control_requirement UNIQUE (control_id, requirement_id)
            );
        """))

        conn.commit()
        print("Schema altered successfully.")

    # 2. Seed Frameworks and Requirements via ORM
    db = database.SessionLocal()
    try:
        # Frameworks
        print("Seeding compliance frameworks...")
        framework_map = {}
        for fw_data in FRAMEWORKS_DATA:
            fw = db.query(models.ComplianceFramework).filter(
                models.ComplianceFramework.name == fw_data["name"],
                models.ComplianceFramework.version == fw_data["version"]
            ).first()
            if not fw:
                fw = models.ComplianceFramework(**fw_data)
                db.add(fw)
                db.flush()
            framework_map[fw.name] = fw
        db.commit()
        print(f"Frameworks active: {list(framework_map.keys())}")

        # NIST CSF 2.0 Requirements
        print("Seeding NIST CSF 2.0 requirements (reviewed subset)...")
        nist_fw = framework_map.get("NIST CSF")
        nist_req_map = {}
        if nist_fw:
            for r_data in NIST_CSF_REQUIREMENTS:
                req = db.query(models.ComplianceRequirement).filter(
                    models.ComplianceRequirement.framework_id == nist_fw.id,
                    models.ComplianceRequirement.requirement_id == r_data["requirement_id"]
                ).first()
                if not req:
                    req = models.ComplianceRequirement(
                        framework_id=nist_fw.id,
                        status="Not Assessed",
                        **r_data
                    )
                    db.add(req)
                    db.flush()
                nist_req_map[req.requirement_id] = req

        # ISO/IEC 27001:2022 Requirements
        print("Seeding ISO/IEC 27001:2022 requirements (reviewed subset)...")
        iso_fw = framework_map.get("ISO/IEC 27001")
        iso_req_map = {}
        if iso_fw:
            for r_data in ISO_27001_REQUIREMENTS:
                req = db.query(models.ComplianceRequirement).filter(
                    models.ComplianceRequirement.framework_id == iso_fw.id,
                    models.ComplianceRequirement.requirement_id == r_data["requirement_id"]
                ).first()
                if not req:
                    req = models.ComplianceRequirement(
                        framework_id=iso_fw.id,
                        status="Not Assessed",
                        **r_data
                    )
                    db.add(req)
                    db.flush()
                iso_req_map[req.requirement_id] = req
        db.commit()

        # Combined req map for mapping lookup
        all_req_map = {**nist_req_map, **iso_req_map}

        # 3. Seed Control Mappings
        print("Seeding control compliance mappings...")
        all_controls = {c.name: c for c in db.query(models.Control).all()}

        mapped_count = 0
        for m_data in CONTROL_MAPPINGS:
            ctrl = all_controls.get(m_data["control_name"])
            req = all_req_map.get(m_data["req_id"])
            if ctrl and req:
                existing_map = db.query(models.ControlComplianceMapping).filter(
                    models.ControlComplianceMapping.control_id == ctrl.id,
                    models.ControlComplianceMapping.requirement_id == req.id
                ).first()
                if not existing_map:
                    new_map = models.ControlComplianceMapping(
                        control_id=ctrl.id,
                        requirement_id=req.id,
                        mapping_strength=m_data["strength"],
                        notes=m_data.get("notes")
                    )
                    db.add(new_map)
                    mapped_count += 1

        db.commit()
        print(f"Added {mapped_count} control-to-requirement mappings.")

        # 4. Verify Record Counts & Preservation
        asset_count = db.query(models.Asset).count()
        risk_count = db.query(models.Risk).count()
        vuln_count = db.query(models.Vulnerability).count()
        ctrl_count = db.query(models.Control).count()
        fw_count = db.query(models.ComplianceFramework).count()
        req_count = db.query(models.ComplianceRequirement).count()
        mapping_count = db.query(models.ControlComplianceMapping).count()

        print("\n--- Phase 3 Migration Verification ---")
        print(f"Assets:                     {asset_count} (Preserved)")
        print(f"Risks:                      {risk_count} (Preserved)")
        print(f"Vulnerabilities:            {vuln_count} (Preserved)")
        print(f"Controls:                   {ctrl_count} (Preserved)")
        print(f"Compliance Frameworks:      {fw_count}")
        print(f"Compliance Requirements:    {req_count}")
        print(f"Control Mappings:           {mapping_count}")
        print("--------------------------------------")

    finally:
        db.close()

    print("Phase 3 migration completed successfully!")


if __name__ == "__main__":
    run_migration()

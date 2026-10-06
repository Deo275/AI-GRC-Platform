"""Evidence Repository & Tamper-Evident Artifact Management for Phase 6A.

Provides:
- calculate_sha256: Cryptographic SHA-256 calculation for content verification.
- create_evidence_record: Validated evidence creation with 50 KB bound, M2M linkage, and audit logging.
- format_evidence: Comprehensive serialization including linked risks, controls, and requirements.
- delete_evidence_record: Audited evidence removal.
"""

import hashlib
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

try:
    import models
except ImportError:
    from backend import models

from .audit_logger import log_audit_event

logger = logging.getLogger("ai_grc.governance.evidence_manager")

# Maximum content length: 50 KB (51,200 bytes)
MAX_CONTENT_BYTES = 50 * 1024


def calculate_sha256(content: Optional[str]) -> Optional[str]:
    """Calculate deterministic SHA-256 hex digest for evidence content."""
    if content is None:
        return None
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def create_evidence_record(
    db: Session,
    title: str,
    evidence_type: str,
    description: Optional[str] = None,
    content_text: Optional[str] = None,
    reference_url: Optional[str] = None,
    source_system: str = "AI-GRC Platform",
    collector: str = "Security Analyst",
    collected_at: Optional[datetime] = None,
    asset_id: Optional[int] = None,
    scan_job_id: Optional[int] = None,
    risk_ids: Optional[List[int]] = None,
    control_ids: Optional[List[int]] = None,
    requirement_ids: Optional[List[int]] = None,
    actor: str = "Security Analyst",
    ip_address: Optional[str] = None,
) -> models.EvidenceRecord:
    """Create a tamper-evident evidence record with M2M governance linkages."""
    # 1. Validate content length
    if content_text is not None:
        content_bytes = len(content_text.encode("utf-8"))
        if content_bytes > MAX_CONTENT_BYTES:
            raise ValueError(
                f"Evidence content exceeds 50 KB limit ({content_bytes} bytes provided, max {MAX_CONTENT_BYTES} bytes)"
            )

    # 2. Calculate deterministic SHA-256
    checksum = calculate_sha256(content_text)

    # 3. Validate optional single foreign keys
    if asset_id is not None:
        asset = db.query(models.Asset).filter(models.Asset.id == asset_id).first()
        if not asset:
            raise ValueError(f"Asset with ID {asset_id} does not exist")

    if scan_job_id is not None:
        scan_job = db.query(models.ScanJob).filter(models.ScanJob.id == scan_job_id).first()
        if not scan_job:
            raise ValueError(f"ScanJob with ID {scan_job_id} does not exist")

    # 4. Create EvidenceRecord instance
    record = models.EvidenceRecord(
        title=title.strip()[:200],
        description=description[:2000] if description else None,
        evidence_type=evidence_type.strip()[:50],
        source_system=source_system.strip()[:100] if source_system else "AI-GRC Platform",
        collector=collector.strip()[:100] if collector else "Security Analyst",
        collected_at=collected_at or datetime.utcnow(),
        content_text=content_text,
        reference_url=reference_url.strip()[:500] if reference_url else None,
        checksum_sha256=checksum,
        asset_id=asset_id,
        scan_job_id=scan_job_id,
        created_at=datetime.utcnow(),
    )

    # 5. Populate M2M relationships
    if risk_ids:
        risks = db.query(models.Risk).filter(models.Risk.id.in_(risk_ids)).all()
        record.risks.extend(risks)

    if control_ids:
        controls = db.query(models.Control).filter(models.Control.id.in_(control_ids)).all()
        record.controls.extend(controls)

    if requirement_ids:
        requirements = (
            db.query(models.ComplianceRequirement)
            .filter(models.ComplianceRequirement.id.in_(requirement_ids))
            .all()
        )
        record.requirements.extend(requirements)

    db.add(record)
    db.commit()
    db.refresh(record)

    # 6. Emit governance audit event
    audit_res = log_audit_event(
        db=db,
        source="USER",
        actor=actor,
        action="CREATE",
        entity_type="EvidenceRecord",
        entity_id=record.id,
        entity_name=record.title,
        new_values={
            "id": record.id,
            "title": record.title,
            "evidence_type": record.evidence_type,
            "checksum_sha256": record.checksum_sha256,
            "linked_risks": [r.id for r in record.risks],
            "linked_controls": [c.id for c in record.controls],
            "linked_requirements": [req.id for req in record.requirements],
        },
        description=f"Registered evidence '{record.title}' with SHA-256 {record.checksum_sha256 or 'N/A'}",
        ip_address=ip_address,
        commit=True,
    )
    if audit_res is None:
        logger.warning(
            f"[AUDIT LOG RECORDING FAILED] EvidenceRecord #{record.id} was created, "
            f"but its governance audit log could not be persisted."
        )


    return record


def format_evidence(record: models.EvidenceRecord) -> Dict[str, Any]:
    """Format an EvidenceRecord ORM instance into an API-ready dictionary."""
    return {
        "id": record.id,
        "title": record.title,
        "description": record.description,
        "evidence_type": record.evidence_type,
        "source_system": record.source_system,
        "collector": record.collector,
        "collected_at": record.collected_at.isoformat() if record.collected_at else None,
        "content_text": record.content_text,
        "reference_url": record.reference_url,
        "checksum_sha256": record.checksum_sha256,
        "created_at": record.created_at.isoformat() if record.created_at else None,
        "asset_id": record.asset_id,
        "asset_ip": record.asset.ip_address if record.asset else None,
        "scan_job_id": record.scan_job_id,
        "scan_target": record.scan_job.target if record.scan_job else None,
        "linked_risk_ids": [r.id for r in record.risks],
        "linked_control_ids": [c.id for c in record.controls],
        "linked_requirement_ids": [req.id for req in record.requirements],
    }


def delete_evidence_record(
    db: Session,
    evidence_id: int,
    actor: str = "Security Analyst",
    ip_address: Optional[str] = None,
) -> bool:
    """Delete an evidence record and emit a corresponding audit log."""
    record = db.query(models.EvidenceRecord).filter(models.EvidenceRecord.id == evidence_id).first()
    if not record:
        return False

    old_info = {
        "id": record.id,
        "title": record.title,
        "evidence_type": record.evidence_type,
        "checksum_sha256": record.checksum_sha256,
    }
    title = record.title

    try:
        db.delete(record)

        audit_res = log_audit_event(
            db=db,
            source="USER",
            actor=actor,
            action="DELETE",
            entity_type="EvidenceRecord",
            entity_id=evidence_id,
            entity_name=title,
            old_values=old_info,
            description=f"Deleted evidence record '{title}' (ID #{evidence_id})",
            ip_address=ip_address,
            commit=False,
        )
        if audit_res is None:
            db.rollback()
            logger.critical(
                f"[ATOMIC TRANSACTION ABORTED] Could not record audit log for EvidenceRecord #{evidence_id} deletion. "
                f"Evidence deletion was rolled back."
            )
            return False

        db.commit()
        return True
    except Exception as err:
        db.rollback()
        logger.error(
            f"Failed to atomically delete evidence record #{evidence_id}: {err}",
            exc_info=True,
        )
        raise

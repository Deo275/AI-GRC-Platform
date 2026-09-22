"""Centralized Governance Audit Logging for Phase 6A.

Provides:
- calculate_audit_integrity_hash: Deterministic SHA-256 over canonical immutable event fields.
- log_audit_event: Synchronous, append-only governance milestone logger with integrity hash.
- sanitize_sensitive_data: Cryptographic hygiene preventing secret leakage in diffs.
- format_audit_log: Consistent JSON serialization for audit trail API.

TERMINOLOGY & DESIGN GUARANTEE:
- The audit log is tamper-evident via deterministic SHA-256 integrity hashes computed
  over canonical immutable event payloads upon creation, and append-only via application
  API constraints (no UPDATE or DELETE endpoints are exposed).
- It is NOT claimed to be 'cryptographically immutable' against direct PostgreSQL
  superuser database manipulation.
"""

import hashlib
import json
import logging
from typing import Any, Optional, Dict
from datetime import datetime
from sqlalchemy.orm import Session

try:
    import models
except ImportError:
    from backend import models

logger = logging.getLogger("ai_grc.governance.audit_logger")

SENSITIVE_KEY_SUBSTRINGS = (
    "api_key",
    "apikey",
    "password",
    "token",
    "secret",
    "authorization",
    "bearer",
    "cred",
    "private_key",
    "client_secret",
)


def sanitize_sensitive_data(val: Any) -> Any:
    """Recursively sanitize sensitive keys in nested dictionaries and lists."""
    if isinstance(val, dict):
        sanitized = {}
        for k, v in val.items():
            k_lower = str(k).lower()
            if any(sub in k_lower for sub in SENSITIVE_KEY_SUBSTRINGS):
                sanitized[k] = "[REDACTED]"
            else:
                sanitized[k] = sanitize_sensitive_data(v)
        return sanitized
    elif isinstance(val, list):
        return [sanitize_sensitive_data(item) for item in val]
    return val


def calculate_audit_integrity_hash(
    timestamp: Any,
    source: str,
    actor: str,
    action: str,
    entity_type: str,
    entity_id: Optional[int] = None,
    entity_name: Optional[str] = None,
    old_values: Optional[str] = None,
    new_values: Optional[str] = None,
    description: Optional[str] = None,
    ip_address: Optional[str] = None,
) -> str:
    """Calculate deterministic SHA-256 integrity hash over immutable audit event fields.

    The integrity hash itself is strictly omitted from the payload to prevent circularity.
    Uses canonical JSON representation with sorted keys and normalized separators.
    """
    ts_str = timestamp.isoformat() if isinstance(timestamp, datetime) else str(timestamp) if timestamp else ""
    canonical_payload = {
        "action": str(action or "").strip().upper(),
        "actor": str(actor or "").strip(),
        "description": str(description or "") if description else None,
        "entity_id": entity_id,
        "entity_name": str(entity_name or "") if entity_name else None,
        "entity_type": str(entity_type or "").strip(),
        "ip_address": str(ip_address or "") if ip_address else None,
        "new_values": new_values,
        "old_values": old_values,
        "source": str(source or "").strip().upper(),
        "timestamp": ts_str,
    }
    encoded = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def log_audit_event(
    db: Session,
    source: str,
    actor: str,
    action: str,
    entity_type: str,
    entity_id: Optional[int] = None,
    entity_name: Optional[str] = None,
    old_values: Optional[Any] = None,
    new_values: Optional[Any] = None,
    description: Optional[str] = None,
    ip_address: Optional[str] = None,
    commit: bool = True,
) -> Optional[models.AuditLog]:
    """Append a governance-level audit event to the audit_logs table.

    Never exposes or logs raw passwords, tokens, or API keys.
    Computes a deterministic SHA-256 integrity hash across immutable event fields.
    """
    try:
        old_json = None
        if old_values is not None:
            sanitized_old = sanitize_sensitive_data(old_values)
            old_json = json.dumps(sanitized_old, default=str)

        new_json = None
        if new_values is not None:
            sanitized_new = sanitize_sensitive_data(new_values)
            new_json = json.dumps(sanitized_new, default=str)

        now = datetime.utcnow()
        clean_source = source.strip().upper()
        clean_actor = actor.strip() if actor else "system"
        clean_action = action.strip().upper()
        clean_entity_type = entity_type.strip()
        clean_entity_name = entity_name[:200] if entity_name else None
        clean_desc = description[:1000] if description else None
        clean_ip = ip_address[:50] if ip_address else None

        integrity_hash = calculate_audit_integrity_hash(
            timestamp=now,
            source=clean_source,
            actor=clean_actor,
            action=clean_action,
            entity_type=clean_entity_type,
            entity_id=entity_id,
            entity_name=clean_entity_name,
            old_values=old_json,
            new_values=new_json,
            description=clean_desc,
            ip_address=clean_ip,
        )

        audit_entry = models.AuditLog(
            timestamp=now,
            source=clean_source,
            actor=clean_actor,
            action=clean_action,
            entity_type=clean_entity_type,
            entity_id=entity_id,
            entity_name=clean_entity_name,
            old_values=old_json,
            new_values=new_json,
            description=clean_desc,
            ip_address=clean_ip,
            integrity_hash=integrity_hash,
        )

        db.add(audit_entry)
        if commit:
            db.commit()
            db.refresh(audit_entry)
        else:
            db.flush()

        return audit_entry
    except Exception as err:
        logger.critical(
            f"[AUDIT LOGGING FAILURE] Could not record audit log entry for action '{action}' "
            f"on entity '{entity_type}' (id={entity_id}) by actor '{actor}': {err}. "
            f"Audit event was NOT persisted.",
            exc_info=True,
        )
        return None


def format_audit_log(entry: models.AuditLog) -> Dict[str, Any]:
    """Format an AuditLog ORM instance into an API-ready dictionary."""
    old_parsed = None
    if entry.old_values:
        try:
            old_parsed = json.loads(entry.old_values)
        except Exception:
            old_parsed = entry.old_values

    new_parsed = None
    if entry.new_values:
        try:
            new_parsed = json.loads(entry.new_values)
        except Exception:
            new_parsed = entry.new_values

    return {
        "id": entry.id,
        "timestamp": entry.timestamp.isoformat() if entry.timestamp else None,
        "source": entry.source,
        "actor": entry.actor,
        "ip_address": entry.ip_address,
        "action": entry.action,
        "entity_type": entry.entity_type,
        "entity_id": entry.entity_id,
        "entity_name": entry.entity_name,
        "old_values": old_parsed,
        "new_values": new_parsed,
        "description": entry.description,
        "integrity_hash": entry.integrity_hash,
    }

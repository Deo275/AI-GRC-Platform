"""Centralized Governance Audit Logging for Phase 6A.

Provides:
- log_audit_event: Synchronous, append-only governance milestone logger.
- sanitize_sensitive_data: Cryptographic hygiene preventing secret leakage in diffs.
- format_audit_log: Consistent JSON serialization for audit trail API.

TERMINOLOGY & DESIGN GUARANTEE:
- The audit log is tamper-evident via SHA-256 verification of related evidence and
  strictly append-only via application API constraints (no UPDATE or DELETE endpoints).
- It is NOT claimed to be 'cryptographically immutable' against direct PostgreSQL
  superuser database manipulation.
"""

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

        audit_entry = models.AuditLog(
            timestamp=datetime.utcnow(),
            source=source.strip().upper(),
            actor=actor.strip() if actor else "system",
            action=action.strip().upper(),
            entity_type=entity_type.strip(),
            entity_id=entity_id,
            entity_name=entity_name[:200] if entity_name else None,
            old_values=old_json,
            new_values=new_json,
            description=description[:1000] if description else None,
            ip_address=ip_address[:50] if ip_address else None,
        )

        db.add(audit_entry)
        if commit:
            db.commit()
            db.refresh(audit_entry)
        else:
            db.flush()

        return audit_entry
    except Exception as err:
        logger.error(f"Failed to record audit log: {err}", exc_info=True)
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
    }

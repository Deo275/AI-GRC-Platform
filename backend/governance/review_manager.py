"""Human Review & Risk Sign-off Management Subsystem for Phase 6C.

Core Guarantees:
- Enforces human-in-the-loop governance: AI models and background workers cannot create or approve reviews.
- Exactly one current active review per risk (enforced by DB partial unique index and transaction).
- Attributed human reviewer/operator: X-Operator-Name and X-Operator-Role provide attribution metadata
  only and do not constitute authentication or authorization.
- Authoritative snapshot_vulnerability_hash: SHA-256 over ONLY vulnerability findings relevant to the
  specific Risk being reviewed, preventing unrelated vulnerabilities on the same asset from causing false staleness.
- Risk-relevant drift correlation: evaluates port and CVE relevance before invalidating reviews.
- Audit event deduplication: RISK_REVIEW_STALE is emitted ONLY upon actual state transition from Approved to Stale.
- Human treatment overrides are explicitly logged to the audit trail.
"""

import hashlib
import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime
from sqlalchemy.orm import Session

try:
    import models
    from governance.audit_logger import log_audit_event, sanitize_sensitive_data
except ImportError:
    from backend import models
    from backend.governance.audit_logger import log_audit_event, sanitize_sensitive_data

logger = logging.getLogger("ai_grc.governance.review_manager")

VALID_DECISIONS = ("APPROVED", "REJECTED", "CHANGES_REQUESTED")
VALID_TREATMENTS = ("Mitigate", "Accept", "Transfer", "Avoid")
TREATMENT_MAP = {t.lower(): t for t in VALID_TREATMENTS}


def extract_port_from_text(text: Optional[str]) -> Optional[int]:
    """Deterministic heuristic extracting port numbers from risk titles or descriptions."""
    if not text:
        return None
    match = re.search(r"\b(?:port\s*|/)?(\d{1,5})\b", text, re.IGNORECASE)
    if match:
        try:
            port = int(match.group(1))
            if 1 <= port <= 65535:
                return port
        except ValueError:
            pass
    return None


def get_relevant_vulnerabilities_for_risk(risk: models.Risk, db: Session) -> List[models.Vulnerability]:
    """Identifies vulnerability findings specifically correlated with this Risk.

    Narrow Correlation Heuristic:
    - Queries vulnerabilities belonging to the risk's asset.
    - Matches port if risk mentions a specific port number.
    - Matches service/protocol substring if risk mentions the service.
    - Matches title substring.
    - If risk is general/asset-wide or only 1 vulnerability exists, includes asset findings.
    - Excludes unrelated vulnerabilities on the same host (e.g. port 22 SSH vs port 5432 PostgreSQL).
    """
    if not risk or not risk.asset_id:
        return []

    asset_vulns = db.query(models.Vulnerability).filter(
        models.Vulnerability.asset_id == risk.asset_id
    ).all()

    if not asset_vulns:
        return []

    if len(asset_vulns) == 1:
        return asset_vulns

    risk_title = (risk.title or "").lower()
    risk_desc = (risk.description or "").lower()
    combined_text = f"{risk_title} {risk_desc}"
    risk_port = extract_port_from_text(combined_text)

    correlated: List[models.Vulnerability] = []
    for v in asset_vulns:
        # 1. Port match
        if risk_port is not None and v.port is not None:
            if v.port == risk_port:
                correlated.append(v)
                continue

        # 2. Service match
        if v.service and v.service.lower() in combined_text:
            correlated.append(v)
            continue

        # 3. Product match
        if v.product and v.product.lower() in combined_text:
            correlated.append(v)
            continue

        # 4. Title / CVE match
        v_title = (v.title or "").lower()
        if v_title and (v_title in risk_title or risk_title in v_title):
            correlated.append(v)
            continue
        if v.cve and v.cve.lower() in combined_text:
            correlated.append(v)
            continue

    # Fallback to asset findings if no specific port/service was isolated
    return correlated if correlated else asset_vulns


def calculate_vulnerability_hash(vulnerabilities: List[models.Vulnerability]) -> str:
    """Calculates deterministic SHA-256 over relevant vulnerability findings.

    Authoritative for detecting vulnerability mutations (CVE, CVSS, status, severity).
    """
    if not vulnerabilities:
        return hashlib.sha256(b"NO_RELEVANT_VULNERABILITIES").hexdigest()

    records = []
    for v in vulnerabilities:
        records.append({
            "id": v.id,
            "cve": v.cve.strip() if v.cve else None,
            "cvss_score": round(float(v.cvss_score), 2) if v.cvss_score is not None else None,
            "port": v.port,
            "severity": (v.severity or "medium").strip().lower(),
            "status": (v.status or "Open").strip(),
        })

    # Sort deterministically
    records.sort(key=lambda r: (r["port"] or 0, r["id"], r["cve"] or ""))
    canonical = json.dumps(records, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def calculate_review_snapshot_hash(
    inherent_score: int,
    residual_score: int,
    criticality: Optional[str],
    exposure: Optional[str],
    cvss_score: Optional[float],
    control_ids: List[int],
    vulnerability_hash: str,
) -> str:
    """Computes deterministic SHA-256 baseline signature of the state reviewed."""
    payload = {
        "criticality": (criticality or "").strip().capitalize(),
        "cvss_score": round(float(cvss_score), 2) if cvss_score is not None else None,
        "exposure": (exposure or "").strip().capitalize(),
        "inherent_score": int(inherent_score),
        "mitigating_control_ids": sorted(control_ids),
        "residual_score": int(residual_score),
        "vulnerability_hash": vulnerability_hash,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def evaluate_review_staleness(
    db: Session,
    risk: models.Risk,
    review: models.RiskReview,
) -> Tuple[bool, List[str]]:
    """Evaluates whether an active Approved review has become stale due to material changes.

    Ignores non-material edits (descriptions, notes, unchanged scans).
    """
    if not review or not review.is_current or review.decision != "APPROVED":
        return False, []

    reasons: List[str] = []

    # 1. Authoritative Risk Score Deltas
    if risk.inherent_risk_score != review.snapshot_inherent_score:
        reasons.append(
            f"Inherent risk score changed from {review.snapshot_inherent_score} to {risk.inherent_risk_score}"
        )
    if risk.residual_risk_score != review.snapshot_residual_score:
        reasons.append(
            f"Residual risk score changed from {review.snapshot_residual_score} to {risk.residual_risk_score}"
        )

    # 2. Asset Context Deltas
    asset = risk.asset
    if asset:
        curr_crit = (asset.criticality or "").strip().capitalize()
        snap_crit = (review.snapshot_asset_criticality or "").strip().capitalize()
        if curr_crit != snap_crit:
            reasons.append(f"Asset criticality changed from '{snap_crit or 'None'}' to '{curr_crit or 'None'}'")

        curr_expo = (asset.exposure or "").strip().capitalize()
        snap_expo = (review.snapshot_asset_exposure or "").strip().capitalize()
        if curr_expo != snap_expo:
            reasons.append(f"Asset exposure changed from '{snap_expo or 'None'}' to '{curr_expo or 'None'}'")

    # 3. Mitigating Controls Delta
    curr_ctrl_ids = sorted(c.id for c in risk.controls)
    snap_ctrl_str = review.snapshot_control_ids or ""
    snap_ctrl_ids = [int(cid) for cid in snap_ctrl_str.split(",") if cid.strip().isdigit()]
    if curr_ctrl_ids != snap_ctrl_ids:
        reasons.append(
            f"Mitigating controls changed: snapshot had controls {snap_ctrl_ids}, current is {curr_ctrl_ids}"
        )

    # 4. Relevant Vulnerability Findings Delta
    relevant_vulns = get_relevant_vulnerabilities_for_risk(risk, db)
    curr_vuln_hash = calculate_vulnerability_hash(relevant_vulns)
    if curr_vuln_hash != review.snapshot_vulnerability_hash:
        reasons.append(
            "Relevant vulnerability findings state changed (CVSS score, CVE correlation, or status modification)"
        )

    # 5. Risk-Relevant Network Drift Events
    if asset:
        drift_events = (
            db.query(models.DriftEvent)
            .filter(
                models.DriftEvent.asset_id == asset.id,
                models.DriftEvent.detected_at > review.created_at,
            )
            .all()
        )

        risk_port = extract_port_from_text(f"{risk.title} {risk.description}")
        for de in drift_events:
            if de.event_type in ("PORT_OPENED", "PORT_CLOSED"):
                drift_port = extract_port_from_text(f"{de.title} {de.description}")
                if risk_port is not None and drift_port is not None and drift_port == risk_port:
                    reasons.append(f"Material network drift on relevant port {risk_port}: {de.title}")
            elif de.event_type == "CVE_DETECTED":
                # Check if CVE correlates with this risk's findings
                cve_match = any(v.cve and v.cve.lower() in de.title.lower() for v in relevant_vulns)
                if cve_match or (risk_port is not None and str(risk_port) in de.title):
                    reasons.append(f"Material vulnerability drift detected: {de.title}")

    return len(reasons) > 0, reasons


def submit_risk_review(
    db: Session,
    risk_id: int,
    decision: str,
    agreed_treatment: str,
    comments: str,
    ai_analysis_acknowledged: bool = False,
    reviewer_name: str = "Security Analyst",
    reviewer_role: str = "Operator",
    ip_address: Optional[str] = None,
) -> models.RiskReview:
    """Submits a formal human governance review for a Risk.

    Executes in a single atomic transaction:
    1. Sets is_current = FALSE on prior active review.
    2. Inserts new review with is_current = TRUE.
    3. Handles treatment overrides and emits audit trail events.
    """
    clean_decision = decision.strip().upper()
    if clean_decision not in VALID_DECISIONS:
        raise ValueError(
            f"Invalid decision '{decision}'. Allowed decisions: {', '.join(VALID_DECISIONS)}"
        )

    clean_treat = TREATMENT_MAP.get(agreed_treatment.strip().lower())
    if not clean_treat:
        raise ValueError(
            f"Invalid agreed_treatment '{agreed_treatment}'. Allowed treatments: {', '.join(VALID_TREATMENTS)}"
        )

    clean_comments = comments.strip() if comments else ""
    if len(clean_comments) < 5:
        raise ValueError("Comments are mandatory and must contain at least 5 characters.")

    risk = db.query(models.Risk).filter(models.Risk.id == risk_id).first()
    if not risk:
        raise ValueError(f"Risk with ID {risk_id} not found.")

    # Gather technical snapshot
    asset = risk.asset
    rel_vulns = get_relevant_vulnerabilities_for_risk(risk, db)
    vuln_hash = calculate_vulnerability_hash(rel_vulns)

    max_cvss = None
    cvss_candidates = [v.cvss_score for v in rel_vulns if v.cvss_score is not None]
    if cvss_candidates:
        max_cvss = max(cvss_candidates)

    ctrl_ids = sorted(c.id for c in risk.controls)
    ctrl_str = ",".join(str(c) for c in ctrl_ids) if ctrl_ids else None

    snap_hash = calculate_review_snapshot_hash(
        inherent_score=risk.inherent_risk_score,
        residual_score=risk.residual_risk_score,
        criticality=asset.criticality if asset else None,
        exposure=asset.exposure if asset else None,
        cvss_score=max_cvss,
        control_ids=ctrl_ids,
        vulnerability_hash=vuln_hash,
    )

    # Check for latest AI analysis ID if acknowledged
    latest_ai_id = None
    if ai_analysis_acknowledged:
        latest_ai = (
            db.query(models.AIRiskAnalysis)
            .filter(models.AIRiskAnalysis.risk_id == risk.id)
            .order_by(models.AIRiskAnalysis.id.desc())
            .first()
        )
        if latest_ai:
            latest_ai_id = latest_ai.id

    # Atomic transaction: supersede prior current review
    db.query(models.RiskReview).filter(
        models.RiskReview.risk_id == risk.id,
        models.RiskReview.is_current == True,
    ).update({"is_current": False})

    new_review = models.RiskReview(
        risk_id=risk.id,
        reviewer_name=reviewer_name.strip() if reviewer_name else "Security Analyst",
        reviewer_role=reviewer_role.strip() if reviewer_role else "Operator",
        decision=clean_decision,
        agreed_treatment=clean_treat,
        comments=clean_comments,
        ai_analysis_acknowledged=bool(ai_analysis_acknowledged),
        ai_analysis_id=latest_ai_id,
        snapshot_inherent_score=risk.inherent_risk_score,
        snapshot_inherent_level=risk.inherent_risk_level,
        snapshot_residual_score=risk.residual_risk_score,
        snapshot_residual_level=risk.residual_risk_level,
        snapshot_asset_criticality=asset.criticality if asset else None,
        snapshot_asset_exposure=asset.exposure if asset else None,
        snapshot_cvss_score=max_cvss,
        snapshot_control_ids=ctrl_str,
        snapshot_vulnerability_hash=vuln_hash,
        snapshot_hash=snap_hash,
        is_current=True,
        created_at=datetime.utcnow(),
    )
    db.add(new_review)
    db.flush()

    # Update risk governance review_status
    if clean_decision == "APPROVED":
        risk.review_status = "Approved"

        # Check for human treatment override
        if risk.treatment != clean_treat:
            old_treat = risk.treatment
            risk.treatment = clean_treat
            log_audit_event(
                db=db,
                source="USER",
                actor=reviewer_name,
                action="TREATMENT_OVERRIDDEN",
                entity_type="Risk",
                entity_id=risk.id,
                entity_name=risk.title,
                old_values={"treatment": old_treat},
                new_values={
                    "treatment": clean_treat,
                    "review_id": new_review.id,
                    "reviewer": reviewer_name,
                },
                description=(
                    f"Human reviewer '{reviewer_name}' overrode risk #{risk.id} treatment "
                    f"from '{old_treat}' to '{clean_treat}' during review #{new_review.id}"
                ),
                ip_address=ip_address,
                commit=False,
            )

    elif clean_decision == "REJECTED":
        risk.review_status = "Rejected"
    else:  # CHANGES_REQUESTED
        risk.review_status = "Changes Requested"

    risk.updated_at = datetime.utcnow()

    # Emit formal review submission audit event
    log_audit_event(
        db=db,
        source="USER",
        actor=reviewer_name,
        action="RISK_REVIEW_SUBMITTED",
        entity_type="RiskReview",
        entity_id=new_review.id,
        entity_name=risk.title,
        new_values={
            "risk_id": risk.id,
            "decision": clean_decision,
            "agreed_treatment": clean_treat,
            "ai_analysis_acknowledged": bool(ai_analysis_acknowledged),
            "snapshot_hash": snap_hash,
            "comments": clean_comments[:500],
        },
        description=f"Submitted formal governance review for risk #{risk.id} with decision '{clean_decision}'",
        ip_address=ip_address,
        commit=False,
    )

    db.commit()
    db.refresh(new_review)
    return new_review


def get_or_evaluate_risk_reviews(
    db: Session,
    risk_id: int,
) -> Tuple[Optional[models.RiskReview], List[models.RiskReview], bool, List[str]]:
    """Retrieves review history for a risk, evaluating real-time staleness dynamically.

    Deduplication Rule: Emits RISK_REVIEW_STALE audit event ONLY when the review
    actually transitions from 'Approved' to 'Stale'.
    """
    risk = db.query(models.Risk).filter(models.Risk.id == risk_id).first()
    if not risk:
        raise ValueError(f"Risk with ID {risk_id} not found.")

    all_reviews = (
        db.query(models.RiskReview)
        .filter(models.RiskReview.risk_id == risk_id)
        .order_by(models.RiskReview.created_at.desc(), models.RiskReview.id.desc())
        .all()
    )

    current_review = next((r for r in all_reviews if r.is_current), None)
    is_stale = False
    stale_reasons: List[str] = []

    if current_review and current_review.decision == "APPROVED":
        is_stale, stale_reasons = evaluate_review_staleness(db, risk, current_review)

        # Dynamic real-time transition if material change occurred
        if is_stale:
            # DEDUPLICATION: Only transition and emit audit event if NOT already Stale
            if risk.review_status != "Stale":
                risk.review_status = "Stale"
                risk.updated_at = datetime.utcnow()

                log_audit_event(
                    db=db,
                    source="SYSTEM",
                    actor="governance_engine",
                    action="RISK_REVIEW_STALE",
                    entity_type="Risk",
                    entity_id=risk.id,
                    entity_name=risk.title,
                    new_values={"stale_reasons": stale_reasons, "review_id": current_review.id},
                    description=(
                        f"Review #{current_review.id} for risk #{risk.id} transitioned to Stale: "
                        f"{'; '.join(stale_reasons)}"
                    ),
                    commit=True,
                )
                db.commit()

    return current_review, all_reviews, is_stale, stale_reasons


def format_risk_review(
    review: models.RiskReview,
    is_stale: bool = False,
    stale_reasons: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Serializes a RiskReview model into a clean API response."""
    ctrl_list = []
    if review.snapshot_control_ids:
        ctrl_list = [int(c) for c in review.snapshot_control_ids.split(",") if c.strip().isdigit()]

    return {
        "id": review.id,
        "risk_id": review.risk_id,
        "reviewer_name": review.reviewer_name,
        "reviewer_role": review.reviewer_role,
        "decision": review.decision,
        "agreed_treatment": review.agreed_treatment,
        "comments": review.comments,
        "ai_analysis_acknowledged": review.ai_analysis_acknowledged,
        "ai_analysis_id": review.ai_analysis_id,
        "is_current": review.is_current,
        "is_stale": is_stale,
        "stale_reasons": stale_reasons or [],
        "snapshot": {
            "inherent_score": review.snapshot_inherent_score,
            "inherent_level": review.snapshot_inherent_level,
            "residual_score": review.snapshot_residual_score,
            "residual_level": review.snapshot_residual_level,
            "asset_criticality": review.snapshot_asset_criticality,
            "asset_exposure": review.snapshot_asset_exposure,
            "cvss_score": review.snapshot_cvss_score,
            "control_ids": ctrl_list,
            "vulnerability_hash": review.snapshot_vulnerability_hash,
            "snapshot_hash": review.snapshot_hash,
        },
        "created_at": review.created_at.isoformat() if review.created_at else None,
    }

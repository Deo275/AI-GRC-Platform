"""Core Report Aggregation and Dispatch Engine for Phase 6B.

Supports 5 Governance Report Types:
1. executive_summary: High-level risk metrics, Inherent vs Residual posture, top risks.
2. technical_vulnerabilities: Asset inventory, ports, CVE-correlated findings, CVSS scores.
3. compliance_gap: Framework requirements, control mappings, implementation status, gaps.
4. risk_register: Full authoritative risk matrix coordinates, treatments, owners, AI suggestions.
5. governance_audit: Append-only audit trail with deterministic SHA-256 integrity hashes & evidence.

Architectural Guarantees:
- Safe row limit: MAX_REPORT_ROWS (10,000) strictly enforced; oversized queries raise ValueError
  rather than silently omitting records.
- Strict separation between Authoritative GRC calculations and AI Advisory decision support.
- CVE findings use accurate terminology ("CVE findings", "CVE-correlated vulnerabilities").
- Mandatory compliance disclaimer embedded across all formats.
"""

import json
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy import func

try:
    import models
    from governance.audit_logger import sanitize_sensitive_data
except ImportError:
    from backend import models
    from backend.governance.audit_logger import sanitize_sensitive_data

from .csv_export import build_csv_report, MAX_REPORT_ROWS, STANDARD_DISCLAIMER
from .html_export import build_html_report


def _validate_row_limit(count: int, report_name: str) -> None:
    """Rejects queries exceeding MAX_REPORT_ROWS with a descriptive error."""
    if count > MAX_REPORT_ROWS:
        raise ValueError(
            f"Query for report '{report_name}' returned {count} records, exceeding the maximum "
            f"supported export limit of {MAX_REPORT_ROWS} rows. Please apply query filters "
            f"to narrow the export range."
        )


# ---------------------------------------------------------------------------
# 1. Executive Summary Report
# ---------------------------------------------------------------------------
def generate_executive_summary_data(db: Session, operator: str, filters: Optional[Dict] = None) -> Dict[str, Any]:
    total_assets = db.query(models.Asset).count()
    risks_query = db.query(models.Risk)
    
    if filters and filters.get("risk_level"):
        risks_query = risks_query.filter(models.Risk.residual_risk_level == filters["risk_level"])
        
    risks = risks_query.all()
    _validate_row_limit(len(risks), "Executive Summary")

    total_risks = len(risks)
    crit_high = sum(1 for r in risks if r.residual_risk_level in ("Critical", "High"))
    avg_inh = round(sum(r.inherent_risk_score for r in risks) / max(total_risks, 1), 1) if risks else 0.0
    avg_res = round(sum(r.residual_risk_score for r in risks) / max(total_risks, 1), 1) if risks else 0.0

    # Compliance readiness %
    total_reqs = db.query(models.ComplianceRequirement).count()
    impl_reqs = db.query(models.ComplianceRequirement).filter(
        models.ComplianceRequirement.status == "Implemented"
    ).count()
    compliance_pct = round((impl_reqs / max(total_reqs, 1)) * 100, 1) if total_reqs else 0.0

    summary_cards = [
        {"label": "Total Monitored Assets", "value": total_assets, "color": "accent"},
        {"label": "Total Active Risks", "value": total_risks, "color": "accent"},
        {"label": "Critical / High Risks", "value": crit_high, "color": "danger" if crit_high > 0 else "success"},
        {"label": "Avg Inherent Risk", "value": avg_inh, "sub": "Scale 1 - 16", "color": "warning"},
        {"label": "Avg Residual Risk", "value": avg_res, "sub": f"Post-controls reduction: -{round(max(0, avg_inh - avg_res), 1)}", "color": "success"},
        {"label": "Compliance Readiness", "value": f"{compliance_pct}%", "sub": f"{impl_reqs}/{total_reqs} implemented", "color": "accent"},
    ]

    table_headers = [
        "Risk ID",
        "Asset IP",
        "Risk Title",
        "Inherent Level",
        "Inherent Score",
        "Residual Level",
        "Residual Score",
        "Treatment",
        "Status",
        "Owner",
    ]

    table_rows = []
    for r in risks:
        asset_ip = r.asset.ip_address if r.asset else "Unassigned"
        table_rows.append([
            r.id,
            asset_ip,
            r.title,
            r.inherent_risk_level,
            r.inherent_risk_score,
            r.residual_risk_level,
            r.residual_risk_score,
            r.treatment,
            r.status,
            r.risk_owner or "Unassigned",
        ])

    # Collect AI advisory insights
    ai_advisories = []
    analyses = db.query(models.AIRiskAnalysis).order_by(models.AIRiskAnalysis.id.desc()).limit(10).all()
    for a in analyses:
        risk_title = a.risk.title if a.risk else "System Finding"
        rec_text = ""
        if a.recommendation:
            try:
                rec_list = json.loads(a.recommendation)
                rec_text = "; ".join(rec_list) if isinstance(rec_list, list) else str(rec_list)
            except Exception:
                rec_text = a.recommendation

        ai_advisories.append({
            "title": risk_title,
            "priority": a.priority,
            "simple_explanation": a.simple_explanation,
            "recommendation": rec_text,
        })

    return {
        "title": "Executive Risk & Posture Summary",
        "subtitle": "Authoritative GRC Posture, Risk Reduction Dynamics, and Advisory Intelligence",
        "summary_cards": summary_cards,
        "table_headers": table_headers,
        "table_rows": table_rows,
        "ai_advisories": ai_advisories,
        "metadata": {
            "report_type": "executive_summary",
            "generated_by": operator,
            "total_records": len(table_rows),
            "disclaimer": STANDARD_DISCLAIMER,
        },
    }


# ---------------------------------------------------------------------------
# 2. Technical Vulnerabilities & Attack Surface Report
# ---------------------------------------------------------------------------
def generate_technical_vulnerabilities_data(db: Session, operator: str, filters: Optional[Dict] = None) -> Dict[str, Any]:
    vuln_query = db.query(models.Vulnerability)
    if filters:
        if filters.get("asset_id"):
            vuln_query = vuln_query.filter(models.Vulnerability.asset_id == filters["asset_id"])
        if filters.get("severity"):
            vuln_query = vuln_query.filter(models.Vulnerability.severity == filters["severity"])
        if filters.get("status"):
            vuln_query = vuln_query.filter(models.Vulnerability.status == filters["status"])

    vulns = vuln_query.all()
    _validate_row_limit(len(vulns), "Technical Vulnerabilities")

    total_vulns = len(vulns)
    crit_count = sum(1 for v in vulns if (v.severity or "").lower() == "critical")
    high_count = sum(1 for v in vulns if (v.severity or "").lower() == "high")
    cve_count = sum(1 for v in vulns if v.cve)

    summary_cards = [
        {"label": "Total Findings", "value": total_vulns, "color": "accent"},
        {"label": "Critical Severity", "value": crit_count, "color": "danger" if crit_count > 0 else "success"},
        {"label": "High Severity", "value": high_count, "color": "warning" if high_count > 0 else "success"},
        {"label": "CVE-Correlated Findings", "value": cve_count, "sub": "Enriched via NVD/vulnerability scanner", "color": "accent"},
    ]

    table_headers = [
        "Vuln ID",
        "Asset IP",
        "Port",
        "Service",
        "Vulnerability Title",
        "CVE ID",
        "CVSS Score",
        "Severity",
        "Status",
        "Discovered At",
    ]

    table_rows = []
    for v in vulns:
        asset_ip = v.asset.ip_address if v.asset else "Unassigned"
        table_rows.append([
            v.id,
            asset_ip,
            v.port or "N/A",
            v.service or "unknown",
            v.title,
            v.cve or "None",
            v.cvss_score if v.cvss_score is not None else "N/A",
            v.severity,
            v.status or "Open",
            v.discovered_at.strftime("%Y-%m-%d %H:%M") if v.discovered_at else "N/A",
        ])

    return {
        "title": "Technical Vulnerability & Attack Surface Report",
        "subtitle": "Authoritative Discovery Findings with CVE Correlation and Severity Ratings",
        "summary_cards": summary_cards,
        "table_headers": table_headers,
        "table_rows": table_rows,
        "ai_advisories": None,
        "metadata": {
            "report_type": "technical_vulnerabilities",
            "generated_by": operator,
            "total_records": len(table_rows),
            "disclaimer": STANDARD_DISCLAIMER,
        },
    }


# ---------------------------------------------------------------------------
# 3. Compliance Readiness & Gap Analysis Report
# ---------------------------------------------------------------------------
def generate_compliance_gap_data(db: Session, operator: str, filters: Optional[Dict] = None) -> Dict[str, Any]:
    req_query = db.query(models.ComplianceRequirement)
    if filters and filters.get("framework_id"):
        req_query = req_query.filter(models.ComplianceRequirement.framework_id == filters["framework_id"])
    if filters and filters.get("status"):
        req_query = req_query.filter(models.ComplianceRequirement.status == filters["status"])

    reqs = req_query.all()
    _validate_row_limit(len(reqs), "Compliance Readiness & Gap Analysis")

    total_reqs = len(reqs)
    implemented = sum(1 for r in reqs if r.status == "Implemented")
    partial = sum(1 for r in reqs if r.status == "Partially Implemented")
    not_assessed = sum(1 for r in reqs if r.status in ("Not Assessed", "Not Implemented"))
    coverage_pct = round((implemented / max(total_reqs, 1)) * 100, 1) if total_reqs else 0.0

    summary_cards = [
        {"label": "Total Requirements", "value": total_reqs, "color": "accent"},
        {"label": "Implemented", "value": implemented, "color": "success"},
        {"label": "Partially Implemented", "value": partial, "color": "warning"},
        {"label": "Gaps / Not Assessed", "value": not_assessed, "color": "danger" if not_assessed > 0 else "success"},
        {"label": "Coverage Readiness", "value": f"{coverage_pct}%", "sub": "Internal readiness (non-certification)", "color": "accent"},
    ]

    table_headers = [
        "Req ID",
        "Framework",
        "Requirement Code",
        "Title",
        "Function / Domain",
        "Status",
        "Mapped Controls",
        "Evidence Count",
    ]

    table_rows = []
    for r in reqs:
        fw_name = r.framework.name if r.framework else "General"
        ctrl_names = ", ".join(m.control.name for m in r.control_mappings if m.control) or "None (GAP)"
        ev_count = len(r.evidence_records) if hasattr(r, "evidence_records") else 0
        table_rows.append([
            r.id,
            fw_name,
            r.requirement_id,
            r.title,
            r.function or r.category or "General",
            r.status,
            ctrl_names,
            ev_count,
        ])

    return {
        "title": "Compliance Readiness & Gap Analysis Report",
        "subtitle": "Control Mapping Matrix, Implementation Readiness, and Deficit Inventory",
        "summary_cards": summary_cards,
        "table_headers": table_headers,
        "table_rows": table_rows,
        "ai_advisories": None,
        "metadata": {
            "report_type": "compliance_gap",
            "generated_by": operator,
            "total_records": len(table_rows),
            "disclaimer": (
                "DISCLAIMER: This compliance readiness report is an internal gap evaluation tool. "
                "Calculated implementation coverage and status indicators do not constitute formal legal counsel, "
                "regulatory certification, or guarantee of audit attestation."
            ),
        },
    }


# ---------------------------------------------------------------------------
# 4. Enterprise Risk Register Report
# ---------------------------------------------------------------------------
def generate_risk_register_data(db: Session, operator: str, filters: Optional[Dict] = None) -> Dict[str, Any]:
    risk_query = db.query(models.Risk)
    if filters:
        if filters.get("status"):
            risk_query = risk_query.filter(models.Risk.status == filters["status"])
        if filters.get("treatment"):
            risk_query = risk_query.filter(models.Risk.treatment == filters["treatment"])
        if filters.get("owner"):
            risk_query = risk_query.filter(models.Risk.risk_owner == filters["owner"])

    risks = risk_query.all()
    _validate_row_limit(len(risks), "Enterprise Risk Register")

    total_risks = len(risks)
    crit_count = sum(1 for r in risks if r.residual_risk_level == "Critical")
    high_count = sum(1 for r in risks if r.residual_risk_level == "High")
    mitigated = sum(1 for r in risks if r.treatment == "Mitigate")

    summary_cards = [
        {"label": "Total Registered Risks", "value": total_risks, "color": "accent"},
        {"label": "Residual Critical", "value": crit_count, "color": "danger" if crit_count > 0 else "success"},
        {"label": "Residual High", "value": high_count, "color": "warning" if high_count > 0 else "success"},
        {"label": "Mitigation Treatment", "value": mitigated, "sub": f"{round((mitigated/max(total_risks, 1))*100)}% of total", "color": "accent"},
    ]

    table_headers = [
        "Risk ID",
        "Asset IP",
        "Title",
        "Inherent Score",
        "Inherent Level",
        "Residual Score",
        "Residual Level",
        "Treatment",
        "Status",
        "Owner",
        "Due Date",
        "Linked Controls",
    ]

    table_rows = []
    for r in risks:
        asset_ip = r.asset.ip_address if r.asset else "Unassigned"
        ctrls = ", ".join(c.name for c in r.controls) or "None"
        due = r.due_date.strftime("%Y-%m-%d") if r.due_date else "Open"
        table_rows.append([
            r.id,
            asset_ip,
            r.title,
            r.inherent_risk_score,
            r.inherent_risk_level,
            r.residual_risk_score,
            r.residual_risk_level,
            r.treatment,
            r.status,
            r.risk_owner or "Unassigned",
            due,
            ctrls,
        ])

    return {
        "title": "Enterprise Risk Register Report",
        "subtitle": "Authoritative Risk Matrix Coordinates, Owner Attribution, and Treatment Tracking",
        "summary_cards": summary_cards,
        "table_headers": table_headers,
        "table_rows": table_rows,
        "ai_advisories": None,
        "metadata": {
            "report_type": "risk_register",
            "generated_by": operator,
            "total_records": len(table_rows),
            "disclaimer": STANDARD_DISCLAIMER,
        },
    }


# ---------------------------------------------------------------------------
# 5. Governance Audit & Evidence Trail Report
# ---------------------------------------------------------------------------
def generate_governance_audit_data(db: Session, operator: str, filters: Optional[Dict] = None) -> Dict[str, Any]:
    audit_query = db.query(models.AuditLog).order_by(models.AuditLog.timestamp.desc())
    if filters:
        if filters.get("source"):
            audit_query = audit_query.filter(models.AuditLog.source == filters["source"].upper())
        if filters.get("actor"):
            audit_query = audit_query.filter(models.AuditLog.actor == filters["actor"])
        if filters.get("start_time"):
            audit_query = audit_query.filter(models.AuditLog.timestamp >= filters["start_time"])
        if filters.get("end_time"):
            audit_query = audit_query.filter(models.AuditLog.timestamp <= filters["end_time"])

    logs = audit_query.all()
    _validate_row_limit(len(logs), "Governance Audit Trail")

    total_logs = len(logs)
    unique_actors = len(set(l.actor for l in logs))
    evidence_count = db.query(models.EvidenceRecord).count()

    summary_cards = [
        {"label": "Total Audit Events", "value": total_logs, "color": "accent"},
        {"label": "Evidence Catalog Items", "value": evidence_count, "color": "accent"},
        {"label": "Active Actors", "value": unique_actors, "color": "accent"},
        {"label": "Log Integrity", "value": "SHA-256", "sub": "Tamper-evident hashing", "color": "success"},
    ]

    table_headers = [
        "Audit ID",
        "Timestamp (UTC)",
        "Source",
        "Actor",
        "Action",
        "Entity Type",
        "Entity ID",
        "Entity Name",
        "Description",
        "Integrity Hash (SHA-256)",
        "Client IP",
    ]

    table_rows = []
    for l in logs:
        ts = l.timestamp.strftime("%Y-%m-%d %H:%M:%S") if l.timestamp else "N/A"
        table_rows.append([
            l.id,
            ts,
            l.source,
            l.actor,
            l.action,
            l.entity_type,
            l.entity_id if l.entity_id is not None else "N/A",
            l.entity_name or "N/A",
            l.description or "N/A",
            l.integrity_hash or "Pending",
            l.ip_address or "N/A",
        ])

    return {
        "title": "Governance Audit Trail & Evidence Report",
        "subtitle": "Append-Only Governance Milestones with Deterministic SHA-256 Integrity Verification",
        "summary_cards": summary_cards,
        "table_headers": table_headers,
        "table_rows": table_rows,
        "ai_advisories": None,
        "metadata": {
            "report_type": "governance_audit",
            "generated_by": operator,
            "total_records": len(table_rows),
            "disclaimer": STANDARD_DISCLAIMER,
        },
    }


# ---------------------------------------------------------------------------
# Unified Report Dispatcher
# ---------------------------------------------------------------------------
REPORT_GENERATORS = {
    "executive_summary": generate_executive_summary_data,
    "technical_vulnerabilities": generate_technical_vulnerabilities_data,
    "compliance_gap": generate_compliance_gap_data,
    "risk_register": generate_risk_register_data,
    "governance_audit": generate_governance_audit_data,
}


def generate_report(
    report_type: str,
    format_type: str,
    db: Session,
    operator: str = "system",
    filters: Optional[Dict] = None,
) -> Tuple[str, str, str]:
    """Generates a complete report in JSON, CSV, or HTML format.

    Returns:
        Tuple[content: str, media_type: str, safe_filename: str]
    """
    clean_report = report_type.strip().lower()
    clean_format = format_type.strip().lower()

    if clean_report not in REPORT_GENERATORS:
        raise ValueError(
            f"Unsupported report type '{report_type}'. Available report types: "
            f"{', '.join(REPORT_GENERATORS.keys())}"
        )

    if clean_format not in ("json", "csv", "html"):
        raise ValueError(
            f"Unsupported format '{format_type}'. Supported export formats: 'json', 'csv', 'html'."
        )

    generator_func = REPORT_GENERATORS[clean_report]
    report_data = generator_func(db=db, operator=operator, filters=filters)

    now_str = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    safe_filename = f"ai_grc_{clean_report}_{now_str}.{clean_format}"

    if clean_format == "json":
        # Partition authoritative data and AI advisory insights
        formatted_json = {
            "metadata": report_data["metadata"],
            "summary_metrics": report_data["summary_cards"],
            "authoritative_data": {
                "headers": report_data["table_headers"],
                "records": [
                    dict(zip(report_data["table_headers"], row))
                    for row in report_data["table_rows"]
                ],
            },
            "ai_advisory_data": {
                "notice": "NON-AUTHORITATIVE: Generated by automated LLM decision support for human review.",
                "insights": report_data.get("ai_advisories") or [],
            },
        }
        content = json.dumps(formatted_json, indent=2, default=str)
        return content, "application/json", safe_filename

    elif clean_format == "csv":
        content = build_csv_report(
            headers=report_data["table_headers"],
            rows=report_data["table_rows"],
            title=report_data["title"],
            disclaimer=report_data["metadata"].get("disclaimer", STANDARD_DISCLAIMER),
        )
        return content, "text/csv; charset=utf-8", safe_filename

    else:  # html
        content = build_html_report(
            title=report_data["title"],
            subtitle=report_data["subtitle"],
            summary_cards=report_data["summary_cards"],
            table_headers=report_data["table_headers"],
            table_rows=report_data["table_rows"],
            ai_advisories=report_data.get("ai_advisories"),
            generated_by=operator,
            disclaimer=report_data["metadata"].get("disclaimer", STANDARD_DISCLAIMER),
        )
        return content, "text/html; charset=utf-8", safe_filename

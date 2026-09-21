"""AI Risk Analyzer Service for GRC Security Intelligence (Phase 4A).

Coordinates:
- Security context normalization & credential sanitization
- AI provider invocation (RuleAssistedAIProvider or ExternalLLMProvider)
- Structured AI response validation
- Database persistence for full auditability
- Strict immutability guarantee for official rule-based risk scores
- Standalone vulnerability/finding analysis capability
"""

import json
import re
import logging
from typing import Optional, List, Dict, Any
from sqlalchemy.orm import Session

try:
    from models import Risk, Asset, Vulnerability, Control, AIRiskAnalysis
except ImportError:
    from backend.models import Risk, Asset, Vulnerability, Control, AIRiskAnalysis
from .schemas import (
    NormalizedSecurityContext,
    AIAnalysisResult,
    RemediationSteps,
    RecommendedControl,
)
from .provider import get_ai_provider, AIProvider, AIProviderError

logger = logging.getLogger("ai_grc.risk_analyzer")

CREDENTIAL_KEY_VAL = re.compile(
    r"(password|passwd|pwd|secret|api_key|apikey|token|bearer|auth|private_key)\s*[:=]\s*([^\s,;]+)",
    re.IGNORECASE,
)
DATABASE_URI_PATTERN = re.compile(
    r"([a-zA-Z0-9+]+://)([^:]+):([^@]+)@([^\s/]+/[^\s]*)",
    re.IGNORECASE,
)
PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN [A-Z ]+ PRIVATE KEY-----.*?-----END [A-Z ]+ PRIVATE KEY-----",
    re.DOTALL,
)


def sanitize_text(text: Optional[str]) -> Optional[str]:
    """Sanitize free text of potential passwords, tokens, or credentials."""
    if not text:
        return text
    sanitized = CREDENTIAL_KEY_VAL.sub(r"\1=[REDACTED]", text)
    sanitized = DATABASE_URI_PATTERN.sub(r"\1\2:[REDACTED]@\4", sanitized)
    sanitized = PRIVATE_KEY_PATTERN.sub("[REDACTED PRIVATE KEY]", sanitized)
    return sanitized


def build_security_context(
    risk: Risk,
    asset: Optional[Asset] = None,
    vuln: Optional[Vulnerability] = None,
    available_controls: Optional[List[str]] = None,
) -> NormalizedSecurityContext:
    """Construct a normalized, sanitized security context for AI analysis."""
    # Active controls mapped to this risk
    existing_controls = []
    if risk.controls:
        for c in risk.controls:
            existing_controls.append({
                "name": c.name,
                "category": c.category,
                "effectiveness": c.effectiveness,
                "status": c.status,
            })

    # Available platform controls catalog
    if available_controls is None:
        available_controls = [
            "Network Segmentation",
            "Firewall Protection",
            "Access Control (RBAC)",
            "Patch Management",
            "Multi-Factor Authentication (MFA)",
            "Logging and Monitoring",
            "Endpoint Protection",
            "Data Encryption",
            "Vulnerability Management",
        ]

    # Vulnerability details (if matched)
    port = vuln.port if vuln else None
    service = vuln.service if vuln else None
    product = vuln.product if vuln else None
    version = vuln.version if vuln else None
    cve = vuln.cve if vuln else None
    cvss_score = vuln.cvss_score if vuln else None
    cvss_version = vuln.cvss_version if vuln else None
    cve_confidence = vuln.cve_confidence if vuln else None

    # Fallback extraction from title/description if vuln not matched
    if port is None and risk.title:
        match = re.search(r"\b(?:port\s*|/)?(\d{1,5})\b", risk.title, re.IGNORECASE)
        if match:
            try:
                candidate = int(match.group(1))
                if candidate in [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 1521, 3306, 3389, 5432, 6379, 8080, 8443, 27017]:
                    port = candidate
            except ValueError:
                pass

    if service is None and risk.title:
        tl = risk.title.lower()
        if "postgresql" in tl or "postgres" in tl:
            service = "postgresql"
            product = product or "PostgreSQL"
        elif "ssh" in tl:
            service = "ssh"
            product = product or "OpenSSH"
        elif "http" in tl or "web" in tl or "nginx" in tl or "apache" in tl:
            service = "http"
        elif "smb" in tl or "microsoft-ds" in tl or "samba" in tl:
            service = "smb"
        elif "mysql" in tl:
            service = "mysql"
        elif "redis" in tl:
            service = "redis"

    crit = asset.criticality if (asset and asset.criticality) else "Medium"
    env = asset.environment if (asset and asset.environment) else "Production"
    exp = asset.exposure if (asset and asset.exposure) else "Internal"
    is_crit_default = not bool(asset and asset.criticality)
    is_env_default = not bool(asset and asset.environment)
    is_exp_default = not bool(asset and asset.exposure)

    return NormalizedSecurityContext(
        risk_title=sanitize_text(risk.title) or "Security Risk",
        risk_description=sanitize_text(risk.description),
        service=service,
        port=port,
        product=product,
        version=version,
        cve=cve,
        cvss_score=cvss_score,
        cvss_version=cvss_version,
        cve_confidence=cve_confidence,
        asset_criticality=crit,
        asset_environment=env,
        asset_exposure=exp,
        asset_business_function=asset.business_function if asset else None,
        is_criticality_default=is_crit_default,
        is_environment_default=is_env_default,
        is_exposure_default=is_exp_default,
        existing_controls=existing_controls,
        available_controls=available_controls,
        inherent_risk_score=risk.inherent_risk_score,
        inherent_risk_level=risk.inherent_risk_level,
        residual_risk_score=risk.residual_risk_score,
        residual_risk_level=risk.residual_risk_level,
    )


def format_analysis_response(db_record: AIRiskAnalysis, result: Optional[AIAnalysisResult] = None) -> Dict[str, Any]:
    """Format an AIRiskAnalysis database record into a JSON-serializable dictionary."""
    return {
        "id": db_record.id,
        "risk_id": db_record.risk_id,
        "priority": db_record.priority,
        "simple_explanation": db_record.simple_explanation,
        "why_it_matters": db_record.why_it_matters,
        "severity_explanation": db_record.severity_explanation,
        "risk_factors": json.loads(db_record.risk_factors) if db_record.risk_factors else [],
        "potential_business_impact": json.loads(db_record.potential_business_impact) if db_record.potential_business_impact else [],
        "recommendation": json.loads(db_record.recommendation) if db_record.recommendation else [],
        "remediation": json.loads(db_record.remediation_steps) if db_record.remediation_steps else {
            "immediate_mitigation": [],
            "permanent_remediation": [],
            "validation": [],
        },
        "recommended_controls": json.loads(db_record.recommended_controls) if db_record.recommended_controls else [],
        "confidence": db_record.confidence,
        "human_review_required": db_record.human_review_required,
        "human_review_reasons": json.loads(db_record.human_review_reasons) if db_record.human_review_reasons else [],
        "model_name": db_record.model_name,
        "created_at": db_record.created_at.isoformat() if db_record.created_at else None,
    }


def analyze_risk(
    risk_id: int,
    db: Session,
    provider: Optional[AIProvider] = None,
) -> Dict[str, Any]:
    """Execute AI analysis for a given risk and persist the auditable record.

    CRITICAL ARCHITECTURAL RULE:
    Official rule-based risk scores (inherent_risk_score, residual_risk_score,
    likelihood, impact, residual_likelihood, residual_impact, status, treatment)
    are NEVER modified or overwritten by AI analysis.
    """
    risk = db.query(Risk).filter(Risk.id == risk_id).first()
    if not risk:
        raise ValueError(f"Risk with id {risk_id} not found")

    # Snapshot official scores before AI analysis to verify strict immutability
    official_inherent_score = risk.inherent_risk_score
    official_inherent_level = risk.inherent_risk_level
    official_residual_score = risk.residual_risk_score
    official_residual_level = risk.residual_risk_level
    official_likelihood = risk.likelihood
    official_impact = risk.impact
    official_residual_likelihood = risk.residual_likelihood
    official_residual_impact = risk.residual_impact
    official_status = risk.status
    official_treatment = risk.treatment

    # 1. Load associated Asset
    asset = db.query(Asset).filter(Asset.id == risk.asset_id).first() if risk.asset_id else None

    # 2. Find matching vulnerability on this asset if exists
    vuln = None
    if risk.asset_id:
        vulns = db.query(Vulnerability).filter(Vulnerability.asset_id == risk.asset_id).all()
        for v in vulns:
            if v.title and risk.title and (v.title.lower() in risk.title.lower() or risk.title.lower() in v.title.lower()):
                vuln = v
                break
            if v.service and risk.title and v.service.lower() in risk.title.lower():
                vuln = v
                break
        if not vuln and vulns:
            if len(vulns) == 1:
                vuln = vulns[0]

    # 3. Load available controls from platform catalog
    all_controls = db.query(Control).all()
    available_control_names = [c.name for c in all_controls] if all_controls else [
        "Network Segmentation",
        "Firewall Protection",
        "Access Control (RBAC)",
        "Patch Management",
        "Multi-Factor Authentication (MFA)",
        "Logging and Monitoring",
        "Endpoint Protection",
        "Data Encryption",
        "Vulnerability Management",
    ]

    # 4. Build sanitized normalized security context
    context = build_security_context(
        risk=risk,
        asset=asset,
        vuln=vuln,
        available_controls=available_control_names,
    )

    # 5. Invoke AI provider
    if provider is None:
        provider = get_ai_provider()

    result: AIAnalysisResult = provider.analyze_finding(context)

    # 6. Verify that the official risk scores were NOT modified
    if (
        risk.inherent_risk_score != official_inherent_score
        or risk.inherent_risk_level != official_inherent_level
        or risk.residual_risk_score != official_residual_score
        or risk.residual_risk_level != official_residual_level
        or risk.likelihood != official_likelihood
        or risk.impact != official_impact
        or risk.residual_likelihood != official_residual_likelihood
        or risk.residual_impact != official_residual_impact
        or risk.status != official_status
        or risk.treatment != official_treatment
    ):
        raise RuntimeError("CRITICAL INVARIANT VIOLATION: AI analysis modified official risk engine scores!")

    # 7. Persist auditable record in ai_risk_analyses table
    db_analysis = AIRiskAnalysis(
        risk_id=risk.id,
        priority=result.priority,
        simple_explanation=result.simple_explanation,
        why_it_matters=result.why_it_matters,
        severity_explanation=result.severity_explanation,
        risk_factors=json.dumps(result.risk_factors),
        potential_business_impact=json.dumps(result.potential_business_impact),
        recommendation=json.dumps(result.recommendation),
        remediation_steps=json.dumps(result.remediation.model_dump() if hasattr(result.remediation, "model_dump") else result.remediation.dict()),
        recommended_controls=json.dumps([rc.model_dump() if hasattr(rc, "model_dump") else rc.dict() for rc in result.recommended_controls]),
        confidence=result.confidence,
        human_review_required=result.human_review_required,
        human_review_reasons=json.dumps(result.human_review_reasons),
        model_name=result.model_name,
    )
    db.add(db_analysis)
    db.commit()
    db.refresh(db_analysis)

    return format_analysis_response(db_analysis, result)


def get_latest_risk_analysis(risk_id: int, db: Session) -> Optional[Dict[str, Any]]:
    """Retrieve the most recent auditable AI analysis for a given risk."""
    record = (
        db.query(AIRiskAnalysis)
        .filter(AIRiskAnalysis.risk_id == risk_id)
        .order_by(AIRiskAnalysis.created_at.desc(), AIRiskAnalysis.id.desc())
        .first()
    )
    if not record:
        return None
    return format_analysis_response(record)


def analyze_vulnerability_finding(
    vuln: Vulnerability,
    asset: Optional[Asset] = None,
    available_controls: Optional[List[str]] = None,
    provider: Optional[AIProvider] = None,
) -> AIAnalysisResult:
    """Analyze a vulnerability or security finding directly without requiring a risk record.
    
    Enables direct vulnerability/finding intelligence for future ad-hoc scans.
    """
    if available_controls is None:
        available_controls = [
            "Network Segmentation",
            "Firewall Protection",
            "Access Control (RBAC)",
            "Patch Management",
            "Multi-Factor Authentication (MFA)",
            "Logging and Monitoring",
            "Endpoint Protection",
            "Data Encryption",
            "Vulnerability Management",
        ]

    # Map severity to estimated initial likelihood/impact for context
    sev = (vuln.severity or "Medium").capitalize()
    score_map = {"Critical": (5, 5, 25), "High": (4, 4, 16), "Medium": (3, 3, 9), "Low": (2, 2, 4)}
    lik, imp, sc = score_map.get(sev, (3, 3, 9))

    context = NormalizedSecurityContext(
        risk_title=sanitize_text(vuln.title) or f"Vulnerability: {vuln.service or 'Service'}",
        risk_description=sanitize_text(vuln.description),
        service=vuln.service,
        port=vuln.port,
        product=vuln.product,
        version=vuln.version,
        cve=vuln.cve,
        cvss_score=vuln.cvss_score,
        cvss_version=vuln.cvss_version,
        cve_confidence=vuln.cve_confidence,
        asset_criticality=asset.criticality if (asset and asset.criticality) else "Medium",
        asset_environment=asset.environment if (asset and asset.environment) else "Production",
        asset_exposure=asset.exposure if (asset and asset.exposure) else "Internal",
        asset_business_function=asset.business_function if asset else None,
        is_criticality_default=not bool(asset and asset.criticality),
        is_environment_default=not bool(asset and asset.environment),
        is_exposure_default=not bool(asset and asset.exposure),
        existing_controls=[],
        available_controls=available_controls,
        inherent_risk_score=sc,
        inherent_risk_level=sev,
        residual_risk_score=sc,
        residual_risk_level=sev,
    )

    if provider is None:
        provider = get_ai_provider()

    return provider.analyze_finding(context)

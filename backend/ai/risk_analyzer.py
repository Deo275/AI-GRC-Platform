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

import hashlib
from datetime import datetime, timedelta

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
API_KEY_PATTERNS = re.compile(
    r"\b(sk-[a-zA-Z0-9_-]{8,}|gsk_[a-zA-Z0-9_-]{8,}|AIza[a-zA-Z0-9_-]{15,})\b"
)
PRIVATE_IPV4_PATTERN = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|"
    r"192\.168\.\d{1,3}\.\d{1,3}|"
    r"127\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"169\.254\.\d{1,3}\.\d{1,3})\b"
)

# Bounded in-memory context fingerprint cache for analysis freshness reuse
_context_fingerprint_cache: Dict[int, str] = {}
_MAX_FINGERPRINT_CACHE_ENTRIES = 2000


def redact_internal_ips(text: Optional[str]) -> Optional[str]:
    """Replace internal/private IPv4 addresses with [INTERNAL_ASSET] placeholder.

    Applied only to external AI prompts/context, preserving authoritative database records.
    """
    if not text:
        return text
    return PRIVATE_IPV4_PATTERN.sub("[INTERNAL_ASSET]", str(text))


def sanitize_text(text: Optional[str]) -> Optional[str]:
    """Sanitize free text of potential passwords, tokens, API keys, or credentials."""
    if not text:
        return text
    sanitized = CREDENTIAL_KEY_VAL.sub(r"\1=[REDACTED]", str(text))
    sanitized = DATABASE_URI_PATTERN.sub(r"\1\2:[REDACTED]@\4", sanitized)
    sanitized = PRIVATE_KEY_PATTERN.sub("[REDACTED PRIVATE KEY]", sanitized)
    sanitized = API_KEY_PATTERNS.sub("[REDACTED KEY]", sanitized)
    return sanitized


def _clamp_str(val: Optional[str], max_len: int) -> str:
    """Defensively clamp a string value to database column limits."""
    if not val:
        return ""
    s = str(val).strip()
    if len(s) > max_len:
        return s[:max(0, max_len - 3)] + "..."
    return s


def _clamp_json_list(items: Optional[List[Any]], max_len: int) -> str:
    """Serialize a list to JSON, trimming items if necessary to fit within max_len."""
    if not items:
        return "[]"
    clean_items = list(items)
    serialized = json.dumps(clean_items)
    if len(serialized) <= max_len:
        return serialized
    while clean_items and len(json.dumps(clean_items)) > max_len:
        clean_items.pop()
    if not clean_items and items:
        first_item = str(items[0])
        clamped_str = first_item[:max(0, max_len - 10)] + "..."
        return json.dumps([clamped_str])
    return json.dumps(clean_items)


def _clamp_json_dict(data: Optional[Dict[str, Any]], max_len: int) -> str:
    """Serialize a dictionary to JSON, trimming values if necessary to fit within max_len."""
    if not data:
        return "{}"
    serialized = json.dumps(data)
    if len(serialized) <= max_len:
        return serialized
    trimmed = {}
    for k, v in data.items():
        if isinstance(v, list):
            trimmed[k] = [str(x)[:200] for x in v[:5]]
        elif isinstance(v, str):
            trimmed[k] = v[:300]
        else:
            trimmed[k] = v
    serialized = json.dumps(trimmed)
    if len(serialized) <= max_len:
        return serialized
    for k in list(trimmed.keys()):
        if isinstance(trimmed[k], list) and len(trimmed[k]) > 1:
            trimmed[k] = trimmed[k][:1]
    serialized = json.dumps(trimmed)
    if len(serialized) <= max_len:
        return serialized
    return json.dumps({k: [] if isinstance(v, list) else "" for k, v in data.items()})


def compute_context_fingerprint(
    risk: Risk,
    asset: Optional[Asset] = None,
    vuln: Optional[Vulnerability] = None,
    available_controls: Optional[List[str]] = None,
) -> str:
    """Compute a deterministic SHA-256 fingerprint representing relevant security context."""
    ctrl_ids = sorted(c.id for c in risk.controls) if risk.controls else []
    payload = {
        "title": (risk.title or "").strip()[:200],
        "description": (risk.description or "").strip()[:500],
        "likelihood": risk.likelihood,
        "impact": risk.impact,
        "inh_score": risk.inherent_risk_score,
        "res_score": risk.residual_risk_score,
        "treatment": risk.treatment,
        "status": risk.status,
        "asset_crit": asset.criticality if asset else None,
        "asset_env": asset.environment if asset else None,
        "asset_exp": asset.exposure if asset else None,
        "asset_biz": asset.business_function if asset else None,
        "vuln_cve": vuln.cve if vuln else None,
        "vuln_cvss": vuln.cvss_score if vuln else None,
        "vuln_port": vuln.port if vuln else None,
        "vuln_service": vuln.service if vuln else None,
        "control_ids": ctrl_ids,
    }
    encoded = json.dumps(payload, sort_keys=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def build_security_context(
    risk: Risk,
    asset: Optional[Asset] = None,
    vuln: Optional[Vulnerability] = None,
    available_controls: Optional[List[str]] = None,
) -> NormalizedSecurityContext:
    """Construct a normalized, sanitized security context for AI analysis."""
    # Active controls mapped to this risk (bounded)
    existing_controls = []
    if risk.controls:
        for c in risk.controls[:10]:
            existing_controls.append({
                "name": str(c.name)[:100],
                "category": str(c.category)[:50] if c.category else None,
                "effectiveness": str(c.effectiveness)[:50] if c.effectiveness else None,
                "status": str(c.status)[:50] if c.status else None,
            })

    # Available platform controls catalog (bounded to 20)
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
    bounded_available_controls = [str(name)[:100] for name in available_controls[:20]]

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

    # Sanitize, redact internal IPs, and apply conservative length bounds
    raw_title = sanitize_text(risk.title) or "Security Risk"
    bounded_title = raw_title[:200]

    raw_desc = redact_internal_ips(sanitize_text(risk.description))
    bounded_desc = raw_desc[:500] if raw_desc else None

    raw_biz = sanitize_text(asset.business_function) if asset and asset.business_function else None
    bounded_biz = raw_biz[:200] if raw_biz else None

    return NormalizedSecurityContext(
        risk_title=bounded_title,
        risk_description=bounded_desc,
        service=str(service)[:100] if service else None,
        port=port,
        product=str(product)[:100] if product else None,
        version=str(version)[:100] if version else None,
        cve=str(cve)[:50] if cve else None,
        cvss_score=cvss_score,
        cvss_version=str(cvss_version)[:20] if cvss_version else None,
        cve_confidence=str(cve_confidence)[:50] if cve_confidence else None,
        asset_criticality=crit,
        asset_environment=env,
        asset_exposure=exp,
        asset_business_function=bounded_biz,
        is_criticality_default=is_crit_default,
        is_environment_default=is_env_default,
        is_exposure_default=is_exp_default,
        existing_controls=existing_controls,
        available_controls=bounded_available_controls,
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
    force_refresh: bool = False,
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

    # 3. Load available controls from platform catalog (bounded to 20)
    all_controls = db.query(Control).limit(20).all()
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

    # 4. Check for freshness reuse if not force_refresh
    current_fingerprint = compute_context_fingerprint(
        risk=risk,
        asset=asset,
        vuln=vuln,
        available_controls=available_control_names,
    )

    if not force_refresh:
        latest_analysis = (
            db.query(AIRiskAnalysis)
            .filter(AIRiskAnalysis.risk_id == risk_id)
            .order_by(AIRiskAnalysis.created_at.desc(), AIRiskAnalysis.id.desc())
            .first()
        )
        if latest_analysis and latest_analysis.created_at:
            now = datetime.utcnow()
            is_fresh = (now - latest_analysis.created_at) <= timedelta(minutes=60)
            if is_fresh:
                # Check if context is unchanged
                if latest_analysis.id in _context_fingerprint_cache:
                    context_unchanged = (_context_fingerprint_cache[latest_analysis.id] == current_fingerprint)
                else:
                    # In absence of cached fingerprint (e.g. process restart),
                    # verify risk was not modified after analysis creation
                    risk_not_modified = (
                        latest_analysis.created_at is not None
                        and (risk.updated_at is None or risk.updated_at <= latest_analysis.created_at)
                    )
                    context_unchanged = risk_not_modified
                    if context_unchanged:
                        _context_fingerprint_cache[latest_analysis.id] = current_fingerprint

                if context_unchanged:
                    logger.info(
                        f"Freshness reuse: Reusing AI analysis #{latest_analysis.id} for risk #{risk_id} "
                        f"(context unchanged, age <= 60m)."
                    )
                    resp = format_analysis_response(latest_analysis)
                    resp["is_reused"] = True
                    return resp

    # 5. Build sanitized normalized security context (bounded)
    context = build_security_context(
        risk=risk,
        asset=asset,
        vuln=vuln,
        available_controls=available_control_names,
    )

    # 6. Invoke AI provider
    if provider is None:
        provider = get_ai_provider()

    result: AIAnalysisResult = provider.analyze_finding(context)

    # 7. Verify that the official risk scores were NOT modified
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

    # 8. Defensively clamp strings and JSON serializations to database column limits
    remediation_dict = (
        result.remediation.model_dump()
        if hasattr(result.remediation, "model_dump")
        else result.remediation.dict()
    )
    rec_controls_list = [
        rc.model_dump() if hasattr(rc, "model_dump") else rc.dict()
        for rc in result.recommended_controls
    ]

    db_analysis = AIRiskAnalysis(
        risk_id=risk.id,
        priority=result.priority,
        simple_explanation=_clamp_str(result.simple_explanation, 2000),
        why_it_matters=_clamp_str(result.why_it_matters, 2000),
        severity_explanation=_clamp_str(result.severity_explanation, 2000),
        risk_factors=_clamp_json_list(result.risk_factors, 2000),
        potential_business_impact=_clamp_json_list(result.potential_business_impact, 2000),
        recommendation=_clamp_json_list(result.recommendation, 2000),
        remediation_steps=_clamp_json_dict(remediation_dict, 3000),
        recommended_controls=_clamp_json_list(rec_controls_list, 2000),
        confidence=result.confidence,
        human_review_required=result.human_review_required,
        human_review_reasons=_clamp_json_list(result.human_review_reasons, 1000),
        model_name=_clamp_str(result.model_name, 255),
    )
    db.add(db_analysis)
    db.commit()
    db.refresh(db_analysis)

    # Record fingerprint in bounded in-memory cache
    if len(_context_fingerprint_cache) > _MAX_FINGERPRINT_CACHE_ENTRIES:
        _context_fingerprint_cache.clear()
    _context_fingerprint_cache[db_analysis.id] = current_fingerprint

    resp = format_analysis_response(db_analysis, result)
    resp["is_reused"] = False
    return resp


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

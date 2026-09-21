"""Pydantic schemas for Phase 4 AI-Assisted Security & Risk Intelligence."""

from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any


class RemediationSteps(BaseModel):
    """Structured 3-tier remediation guidance."""
    immediate_mitigation: List[str] = Field(
        default_factory=list,
        description="Actions to reduce exposure immediately"
    )
    permanent_remediation: List[str] = Field(
        default_factory=list,
        description="Actions to resolve the underlying security root cause"
    )
    validation: List[str] = Field(
        default_factory=list,
        description="Verification steps such as re-scanning to confirm resolution"
    )


class RecommendedControl(BaseModel):
    """Recommended defensive safeguard from the platform's control catalog."""
    name: str = Field(..., description="Name of the security control in catalog")
    reason: str = Field(..., description="Explanation of why this control is relevant")


class AIAnalysisResult(BaseModel):
    """Structured, auditable AI security intelligence analysis."""
    priority: str = Field(
        ...,
        description="Contextual AI prioritization: Critical, High, Medium, or Low"
    )
    simple_explanation: str = Field(
        ...,
        description="Plain-language explanation understandable by non-technical GRC/business users"
    )
    why_it_matters: str = Field(
        ...,
        description="Why this finding is a security concern based on available evidence"
    )
    severity_explanation: str = Field(
        ...,
        description="Interpretation of technical severity and CVSS score in practical terms"
    )
    risk_factors: List[str] = Field(
        default_factory=list,
        description="Key factors contributing to risk (criticality, exposure, CVSS, controls)"
    )
    potential_business_impact: List[str] = Field(
        default_factory=list,
        description="Potential business consequences, strictly distinguishing inferred potential from verified facts"
    )
    recommendation: List[str] = Field(
        default_factory=list,
        description="Practical recommendations on what the organization should consider doing"
    )
    remediation: RemediationSteps = Field(
        ...,
        description="Concrete, tiered remediation guidance (Immediate, Permanent, Validation)"
    )
    recommended_controls: List[RecommendedControl] = Field(
        default_factory=list,
        description="Recommended controls from the platform catalog with rationales"
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confidence score (0.0 to 1.0) reflecting data completeness and certainty"
    )
    human_review_required: bool = Field(
        True,
        description="Flag indicating if human validation is recommended before making important decisions"
    )
    human_review_reasons: List[str] = Field(
        default_factory=list,
        description="Specific factors that warrant human verification (e.g. high severity, missing CVSS, prod env)"
    )
    model_name: str = Field(
        ...,
        description="Identifier of the AI model or analyzer provider used"
    )


class NormalizedSecurityContext(BaseModel):
    """Sanitized, normalized security context passed to the AI provider."""
    risk_title: str
    risk_description: Optional[str] = None
    service: Optional[str] = None
    port: Optional[int] = None
    product: Optional[str] = None
    version: Optional[str] = None
    cve: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_version: Optional[str] = None
    cve_confidence: Optional[str] = None
    asset_criticality: str = "Medium"
    asset_environment: str = "Production"
    asset_exposure: str = "Internal"
    asset_business_function: Optional[str] = None
    is_criticality_default: bool = False
    is_environment_default: bool = False
    is_exposure_default: bool = False
    existing_controls: List[Dict[str, Any]] = Field(default_factory=list)
    available_controls: List[str] = Field(default_factory=list)
    inherent_risk_score: int
    inherent_risk_level: str
    residual_risk_score: int
    residual_risk_level: str

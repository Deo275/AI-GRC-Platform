"""GRC Risk Engine for Phase 2.

Provides transparent and explainable risk calculation functions:
- Inherent Risk: Likelihood (1-4) x Impact (1-4) = Score (1-16)
- Impact derived from Asset Criticality
- Likelihood derived from Vulnerability Severity / CVSS + Asset Exposure
- Residual Risk: Mitigating security controls reduce likelihood (floor 1)
"""

CRITICALITY_TO_IMPACT = {
    "Low": 1,
    "Medium": 2,
    "High": 3,
    "Critical": 4
}

SEVERITY_TO_SCORE = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4
}

CONTROL_EFFECTIVENESS_REDUCTION = {
    "high": 2,
    "medium": 1,
    "low": 0
}


def calculate_risk_level(score: int) -> str:
    """Map a numerical risk score (1-16) to a descriptive risk level.

    1-3   -> Low
    4-6   -> Medium
    7-11  -> High
    12-16 -> Critical
    """
    if score >= 12:
        return "Critical"
    elif score >= 7:
        return "High"
    elif score >= 4:
        return "Medium"
    else:
        return "Low"


def criticality_to_impact(criticality: str | None) -> int:
    """Map asset business criticality to an impact score (1-4).

    Low      -> 1
    Medium   -> 2 (default)
    High     -> 3
    Critical -> 4
    """
    if not criticality:
        return 2
    return CRITICALITY_TO_IMPACT.get(criticality.strip().capitalize(), 2)


def calculate_likelihood(
    severity_str: str | None = None,
    cvss_score: float | None = None,
    exposure: str | None = "Internal",
    fallback_likelihood: str | None = "Medium"
) -> int:
    """Calculate likelihood score (1-4) based on technical findings and exposure.

    Preserves CVE confidence behavior:
    - CVSS score available -> CVSS-based likelihood.
    - CVSS unavailable -> severity string based likelihood.
    - Both unavailable -> fallback baseline likelihood.

    Exposure modifier:
    - External: +1 (increased discovery/exploit probability)
    - Internal: -1 (segmented/internal network)
    - DMZ / other: 0

    Result is strictly clamped between 1 and 4.
    """
    # 1. Determine base likelihood
    if cvss_score is not None:
        try:
            score = float(cvss_score)
            if score >= 9.0:
                base = 4
            elif score >= 7.0:
                base = 3
            elif score >= 4.0:
                base = 2
            else:
                base = 1
        except (ValueError, TypeError):
            base = 2
    elif severity_str:
        base = SEVERITY_TO_SCORE.get(severity_str.strip().lower(), 2)
    elif fallback_likelihood:
        base = SEVERITY_TO_SCORE.get(fallback_likelihood.strip().lower(), 2)
    else:
        base = 2

    # 2. Apply asset exposure modifier
    exp = (exposure or "Internal").strip().lower()
    if exp == "external":
        modifier = 1
    elif exp == "internal":
        modifier = -1
    else:
        modifier = 0

    return max(1, min(4, base + modifier))


def calculate_inherent_risk(likelihood: int, impact: int) -> dict:
    """Calculate inherent risk from likelihood (1-4) and impact (1-4).

    Inherent Risk Score = Likelihood x Impact (1-16)
    """
    score = likelihood * impact
    level = calculate_risk_level(score)
    return {
        "likelihood_score": likelihood,
        "impact_score": impact,
        "inherent_risk_score": score,
        "inherent_risk_level": level
    }


def calculate_residual_risk(
    inherent_likelihood: int,
    inherent_impact: int,
    controls: list | None = None
) -> dict:
    """Calculate residual risk after applying security controls.

    In Phase 2, security controls reduce likelihood only.
    Impact remains unchanged (residual_impact = inherent_impact).

    Controls reduction per implemented control:
    - High effectiveness: -2 likelihood points
    - Medium effectiveness: -1 likelihood point
    - Low effectiveness: 0 points

    Residual likelihood has a strict floor of 1.
    Residual score = residual_likelihood x residual_impact.
    """
    total_reduction = 0

    if controls:
        for ctrl in controls:
            # Handle both Control ORM models and dicts
            status = getattr(ctrl, "status", None) if not isinstance(ctrl, dict) else ctrl.get("status")
            eff = getattr(ctrl, "effectiveness", None) if not isinstance(ctrl, dict) else ctrl.get("effectiveness")

            # Only implemented controls provide mitigation
            if status and status.strip().lower() == "implemented":
                eff_key = (eff or "medium").strip().lower()
                total_reduction += CONTROL_EFFECTIVENESS_REDUCTION.get(eff_key, 1)

    residual_likelihood = max(1, inherent_likelihood - total_reduction)
    residual_impact = inherent_impact
    residual_score = residual_likelihood * residual_impact
    residual_level = calculate_risk_level(residual_score)

    return {
        "residual_likelihood": residual_likelihood,
        "residual_impact": residual_impact,
        "residual_risk_score": residual_score,
        "residual_risk_level": residual_level
    }

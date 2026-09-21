"""AI-Assisted Security & Risk Intelligence Package (Phase 4).

Provides an AI provider abstraction, normalized security context generation,
structured AI response validation, and risk analysis services.
"""

from .schemas import (
    NormalizedSecurityContext,
    RemediationSteps,
    RecommendedControl,
    AIAnalysisResult,
)
from .provider import (
    AIProvider,
    AIProviderError,
    get_ai_provider,
    GeminiAIProvider,
    RuleAssistedAIProvider,
    ExternalLLMProvider,
)
from .risk_analyzer import (
    analyze_risk,
    get_latest_risk_analysis,
    build_security_context,
    analyze_vulnerability_finding,
)

__all__ = [
    "NormalizedSecurityContext",
    "RemediationSteps",
    "RecommendedControl",
    "AIAnalysisResult",
    "AIProvider",
    "AIProviderError",
    "GeminiAIProvider",
    "RuleAssistedAIProvider",
    "ExternalLLMProvider",
    "get_ai_provider",
    "analyze_risk",
    "get_latest_risk_analysis",
    "build_security_context",
    "analyze_vulnerability_finding",
]

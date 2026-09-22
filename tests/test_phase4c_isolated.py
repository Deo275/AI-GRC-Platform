"""Phase 4C Isolated Automated Test Suite: Multi-LLM Provider Failover Architecture.

Runs 20 isolated test scenarios using Python unittest and in-memory SQLite:
1.  test_chain_gemini_success_no_failover
2.  test_chain_gemini_failure_no_internal_fallback
3.  test_chain_gemini_fails_openai_succeeds
4.  test_chain_gemini_openai_fail_groq_succeeds
5.  test_chain_all_llm_fail_rule_assisted
6.  test_chain_preserves_grc_immutability
7.  test_chain_human_review_on_failover
8.  test_chain_attempts_log_structure
9.  test_openai_provider_valid_response
10. test_openai_provider_timeout
11. test_openai_provider_missing_key
12. test_openai_provider_semantic_validation
13. test_groq_provider_valid_response
14. test_groq_provider_default_model
15. test_groq_provider_rate_limit_429
16. test_factory_chain_mode_is_default
17. test_factory_ai_provider_openai_returns_legacy
18. test_factory_ai_provider_openai_native
19. test_factory_chain_always_appends_rule_assisted
20. test_chain_no_credential_leakage_in_attempts

This test suite DOES NOT require real API keys and DOES NOT connect to external networks.
"""

import os
import sys
import json
import unittest
from unittest.mock import patch, MagicMock
from pathlib import Path
from datetime import datetime

# Setup sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(BASE_DIR / "backend"))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import models
from ai.schemas import (
    NormalizedSecurityContext,
    AIAnalysisResult,
    RemediationSteps,
    RecommendedControl,
)
from ai.provider import (
    AIProvider,
    AIProviderError,
    AIProviderTransientError,
    AIProviderFatalError,
    ProviderAttempt,
    GeminiAIProvider,
    OpenAIProvider,
    GroqProvider,
    ExternalLLMProvider,
    RuleAssistedAIProvider,
    ProviderChain,
    get_ai_provider,
    validate_and_sanitize_result,
    _sanitize_compact,
)
from ai.risk_analyzer import (
    build_security_context,
    analyze_risk,
)


def sample_context() -> NormalizedSecurityContext:
    return NormalizedSecurityContext(
        risk_title="PostgreSQL Database Accessible Over Network",
        risk_description="Port 5432 is open and exposed",
        service="postgresql",
        port=5432,
        product="PostgreSQL",
        version="14.2",
        cve="CVE-2022-1552",
        cvss_score=8.8,
        cvss_version="3.1",
        cve_confidence="Confirmed",
        asset_criticality="High",
        asset_environment="Production",
        asset_exposure="Internal",
        inherent_risk_score=15,
        inherent_risk_level="High",
        residual_risk_score=9,
        residual_risk_level="Medium",
        is_criticality_default=False,
        is_exposure_default=False,
    )


def sample_analysis_dict(priority="High", model_name="test-model"):
    return {
        "priority": priority,
        "simple_explanation": "A database is accessible over the network on port 5432.",
        "why_it_matters": "Databases hold business data and exposing ports expands the attack surface.",
        "severity_explanation": "CVSS score of 8.8 indicates high severity.",
        "risk_factors": ["Asset is High criticality", "Production environment"],
        "potential_business_impact": ["Data leakage", "Compliance penalty"],
        "recommendation": ["Restrict network access", "Require MFA"],
        "remediation": {
            "immediate_mitigation": ["Apply firewall rule"],
            "permanent_remediation": ["Migrate to private subnet"],
            "validation": ["Verify port 5432 is not reachable externally"]
        },
        "recommended_controls": [
            {"name": "Firewall Protection", "reason": "Restricts network ingress"}
        ],
        "confidence": 0.85,
        "human_review_required": True,
        "human_review_reasons": ["High severity finding warrants human review"],
        "model_name": model_name
    }


class MockFailingProvider(AIProvider):
    def __init__(self, name="MockFailingProvider", model="mock-model", error=None):
        self._name = name
        self.provider_name = name
        self.model_name = model
        self.error = error or AIProviderTransientError(f"{name} simulated failure")

    def analyze_finding(self, context: NormalizedSecurityContext) -> AIAnalysisResult:
        raise self.error


class MockSucceedingProvider(AIProvider):
    def __init__(self, name="MockSucceedingProvider", model="mock-model"):
        self._name = name
        self.provider_name = name
        self.model_name = model

    def analyze_finding(self, context: NormalizedSecurityContext) -> AIAnalysisResult:
        data = sample_analysis_dict(model_name=self.model_name)
        return AIAnalysisResult(**data)


class TestPhase4CProviderChain(unittest.TestCase):
    """Test suite for Phase 4C Multi-LLM Provider Failover Architecture."""

    def setUp(self):
        self.context = sample_context()

    def test_chain_gemini_success_no_failover(self):
        """Test 1: Gemini succeeds first; no failover annotation in model_name; attempts shows 1 success."""
        gemini_mock = MockSucceedingProvider(name="GeminiAIProvider", model="gemini-3.8-flash")
        rule_mock = RuleAssistedAIProvider()

        chain = ProviderChain([gemini_mock, rule_mock])
        result = chain.analyze_finding(self.context)

        self.assertEqual(result.model_name, "gemini-3.8-flash")
        self.assertNotIn("chain-failover:", result.model_name)
        self.assertEqual(len(chain.attempts), 1)
        self.assertTrue(chain.attempts[0].succeeded)
        self.assertEqual(chain.attempts[0].provider_name, "GeminiAIProvider")
        self.assertEqual(chain.attempts[0].model_name, "gemini-3.8-flash")
        self.assertIsNone(chain.attempts[0].error_type)

    def test_chain_gemini_failure_no_internal_fallback(self):
        """Test 2: Gemini with fallback_enabled=False raises AIProviderError and does NOT fall back."""
        mock_client = MagicMock()
        mock_client.models.generate_content.side_effect = Exception("503 Service Unavailable")

        provider = GeminiAIProvider(
            api_key="test_key",
            fallback_enabled=False,
            client=mock_client
        )
        with self.assertRaises(AIProviderError) as ctx:
            provider.analyze_finding(self.context)
        self.assertIn("Gemini AI provider failed", str(ctx.exception))

    def test_chain_gemini_fails_openai_succeeds(self):
        """Test 3: Gemini fails -> OpenAI succeeds; failover annotated in model_name and human_review_reasons."""
        gemini_mock = MockFailingProvider(name="GeminiAIProvider", model="gemini-3.8-flash")
        openai_mock = MockSucceedingProvider(name="OpenAIProvider", model="gpt-4o-mini")
        rule_mock = RuleAssistedAIProvider()

        chain = ProviderChain([gemini_mock, openai_mock, rule_mock])
        result = chain.analyze_finding(self.context)

        self.assertIn("gpt-4o-mini (chain-failover: GeminiAIProvider)", result.model_name)
        self.assertTrue(result.human_review_required)
        self.assertTrue(any("Chain failover: GeminiAIProvider unavailable" in r for r in result.human_review_reasons))
        self.assertEqual(len(chain.attempts), 2)
        self.assertFalse(chain.attempts[0].succeeded)
        self.assertEqual(chain.attempts[0].provider_name, "GeminiAIProvider")
        self.assertTrue(chain.attempts[1].succeeded)
        self.assertEqual(chain.attempts[1].provider_name, "OpenAIProvider")

    def test_chain_gemini_openai_fail_groq_succeeds(self):
        """Test 4: Gemini + OpenAI fail -> Groq succeeds; model_name contains groq and failover trail."""
        gemini_mock = MockFailingProvider(name="GeminiAIProvider", model="gemini-3.8-flash")
        openai_mock = MockFailingProvider(name="OpenAIProvider", model="gpt-4o-mini")
        groq_mock = MockSucceedingProvider(name="GroqProvider", model="openai/gpt-oss-120b (via groq)")
        rule_mock = RuleAssistedAIProvider()

        chain = ProviderChain([gemini_mock, openai_mock, groq_mock, rule_mock])
        result = chain.analyze_finding(self.context)

        self.assertIn("openai/gpt-oss-120b (via groq) (chain-failover: GeminiAIProvider, OpenAIProvider)", result.model_name)
        self.assertTrue(result.human_review_required)
        self.assertEqual(len(chain.attempts), 3)
        self.assertFalse(chain.attempts[0].succeeded)
        self.assertFalse(chain.attempts[1].succeeded)
        self.assertTrue(chain.attempts[2].succeeded)

    def test_chain_all_llm_fail_rule_assisted(self):
        """Test 5: All LLMs fail -> RuleAssistedAIProvider returns with full failover audit trail."""
        gemini_mock = MockFailingProvider(name="GeminiAIProvider", model="gemini-3.8-flash")
        openai_mock = MockFailingProvider(name="OpenAIProvider", model="gpt-4o-mini")
        groq_mock = MockFailingProvider(name="GroqProvider", model="openai/gpt-oss-120b (via groq)")
        rule_provider = RuleAssistedAIProvider()

        chain = ProviderChain([gemini_mock, openai_mock, groq_mock, rule_provider])
        result = chain.analyze_finding(self.context)

        expected_model = "rule-assisted-grc-v1 (chain-failover: GeminiAIProvider, OpenAIProvider, GroqProvider)"
        self.assertEqual(result.model_name, expected_model)
        self.assertTrue(result.human_review_required)
        self.assertEqual(len(chain.attempts), 4)
        self.assertTrue(chain.attempts[3].succeeded)

    def test_chain_preserves_grc_immutability(self):
        """Test 6: Full chain run through analyze_risk() preserves all official risk score fields."""
        engine = create_engine("sqlite:///:memory:")
        models.Base.metadata.create_all(bind=engine)
        Session = sessionmaker(bind=engine)
        db = Session()

        asset = models.Asset(
            hostname="db-server-01",
            ip_address="10.0.1.50",
            criticality="High",
            environment="Production",
            exposure="Internal",
        )
        db.add(asset)
        db.commit()
        db.refresh(asset)

        risk = models.Risk(
            title="Database Exposure",
            description="Exposed database port",
            asset_id=asset.id,
            likelihood="Medium",
            impact="High",
            inherent_risk_score=15,
            inherent_risk_level="High",
            likelihood_score=3,
            impact_score=4,
            residual_risk_score=9,
            residual_risk_level="Medium",
            residual_likelihood=2,
            residual_impact=3,
            treatment="Mitigate",
            status="Open",
            risk_owner="Security Lead",
        )
        db.add(risk)
        db.commit()
        db.refresh(risk)

        original_fields = {
            "likelihood": risk.likelihood,
            "impact": risk.impact,
            "inherent_risk_score": risk.inherent_risk_score,
            "inherent_risk_level": risk.inherent_risk_level,
            "likelihood_score": risk.likelihood_score,
            "impact_score": risk.impact_score,
            "residual_risk_score": risk.residual_risk_score,
            "residual_risk_level": risk.residual_risk_level,
            "residual_likelihood": risk.residual_likelihood,
            "residual_impact": risk.residual_impact,
            "treatment": risk.treatment,
            "status": risk.status,
            "risk_owner": risk.risk_owner,
        }

        # Run analyze_risk with a failing gemini mock and working rule provider
        gemini_mock = MockFailingProvider(name="GeminiAIProvider", model="gemini-3.8-flash")
        chain = ProviderChain([gemini_mock, RuleAssistedAIProvider()])

        analysis = analyze_risk(risk_id=risk.id, db=db, provider=chain)
        self.assertIsNotNone(analysis)

        db.expire_all()
        refreshed_risk = db.query(models.Risk).filter(models.Risk.id == risk.id).first()
        for field, value in original_fields.items():
            self.assertEqual(getattr(refreshed_risk, field), value, f"Field '{field}' was mutated by AI analysis!")

    def test_chain_human_review_on_failover(self):
        """Test 7: After any failover, human_review_required is True and failover reason is added."""
        provider_a = MockFailingProvider(name="ProviderA", model="model-a")
        provider_b = MockSucceedingProvider(name="ProviderB", model="model-b")

        chain = ProviderChain([provider_a, provider_b])
        result = chain.analyze_finding(self.context)

        self.assertTrue(result.human_review_required)
        self.assertTrue(any("Chain failover: ProviderA unavailable" in reason for reason in result.human_review_reasons))

    def test_chain_attempts_log_structure(self):
        """Test 8: chain.attempts property returns structured ProviderAttempt instances."""
        provider_a = MockFailingProvider(name="MockProviderA", model="model-a")
        provider_b = MockSucceedingProvider(name="MockProviderB", model="model-b")

        chain = ProviderChain([provider_a, provider_b])
        chain.analyze_finding(self.context)

        attempts = chain.attempts
        self.assertEqual(len(attempts), 2)
        self.assertIsInstance(attempts[0], ProviderAttempt)
        self.assertEqual(attempts[0].provider_name, "MockProviderA")
        self.assertEqual(attempts[0].model_name, "model-a")
        self.assertFalse(attempts[0].succeeded)
        self.assertEqual(attempts[0].error_type, "AIProviderTransientError")
        self.assertIsNotNone(attempts[0].error_message)

        self.assertIsInstance(attempts[1], ProviderAttempt)
        self.assertEqual(attempts[1].provider_name, "MockProviderB")
        self.assertEqual(attempts[1].model_name, "model-b")
        self.assertTrue(attempts[1].succeeded)
        self.assertIsNone(attempts[1].error_type)
        self.assertIsNone(attempts[1].error_message)

        chain = ProviderChain([provider_a, provider_b])
        chain.analyze_finding(self.context)

        attempts = chain.attempts
        self.assertEqual(len(attempts), 2)
        self.assertIsInstance(attempts[0], ProviderAttempt)
        self.assertEqual(attempts[0].provider_name, "MockProviderA")
        self.assertEqual(attempts[0].model_name, "model-a")
        self.assertFalse(attempts[0].succeeded)
        self.assertEqual(attempts[0].error_type, "AIProviderTransientError")
        self.assertIsNotNone(attempts[0].error_message)

        self.assertIsInstance(attempts[1], ProviderAttempt)
        self.assertEqual(attempts[1].provider_name, "MockProviderB")
        self.assertEqual(attempts[1].model_name, "model-b")
        self.assertTrue(attempts[1].succeeded)
        self.assertIsNone(attempts[1].error_type)
        self.assertIsNone(attempts[1].error_message)

    @patch("requests.post")
    def test_openai_provider_valid_response(self, mock_post):
        """Test 9: OpenAIProvider returns valid AIAnalysisResult from HTTP 200 response."""
        sample_dict = sample_analysis_dict()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [{"message": {"content": json.dumps(sample_dict)}}]
        }
        mock_post.return_value = mock_response

        provider = OpenAIProvider(api_key="sk-test-key", model_name="gpt-4o-mini")
        result = provider.analyze_finding(self.context)

        self.assertEqual(result.model_name, "gpt-4o-mini")
        self.assertEqual(result.priority, "High")
        self.assertIsInstance(result.remediation, RemediationSteps)

    @patch("requests.post")
    def test_openai_provider_timeout(self, mock_post):
        """Test 10: requests.Timeout raises AIProviderTransientError in OpenAIProvider."""
        import requests
        mock_post.side_effect = requests.Timeout("Connection timed out after 7s")

        provider = OpenAIProvider(api_key="sk-test-key")
        with self.assertRaises(AIProviderTransientError) as ctx:
            provider.analyze_finding(self.context)
        self.assertIn("timed out", str(ctx.exception))

    def test_openai_provider_missing_key(self):
        """Test 11: Empty API key raises AIProviderFatalError in OpenAIProvider."""
        with patch.dict(os.environ, {"OPENAI_API_KEY": ""}):
            provider = OpenAIProvider(api_key="")
            with self.assertRaises(AIProviderFatalError) as ctx:
                provider.analyze_finding(self.context)
            self.assertIn("not configured", str(ctx.exception))

    @patch("requests.post")
    def test_openai_provider_semantic_validation(self, mock_post):
        """Test 12: OpenAI response with priority='CATASTROPHIC' is normalized to 'Medium'."""
        sample_dict = sample_analysis_dict()
        sample_dict["priority"] = "CATASTROPHIC"
        sample_dict["confidence"] = 0.98

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [{"message": {"content": json.dumps(sample_dict)}}]
        }
        mock_post.return_value = mock_response

        # Context without CVSS to trigger confidence clamping
        ctx = self.context.model_copy() if hasattr(self.context, "model_copy") else self.context.copy()
        ctx.cvss_score = None

        provider = OpenAIProvider(api_key="sk-test-key")
        result = provider.analyze_finding(ctx)

        self.assertEqual(result.priority, "Medium")
        self.assertEqual(result.confidence, 0.70)
        self.assertTrue(result.human_review_required)

    @patch("requests.post")
    def test_groq_provider_valid_response(self, mock_post):
        """Test 13: GroqProvider returns valid AIAnalysisResult with model_name formatted '(via groq)'."""
        sample_dict = sample_analysis_dict()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [{"message": {"content": json.dumps(sample_dict)}}]
        }
        mock_post.return_value = mock_response

        provider = GroqProvider(api_key="gsk-test-key")
        result = provider.analyze_finding(self.context)

        self.assertEqual(result.model_name, "openai/gpt-oss-120b (via groq)")
        self.assertEqual(result.priority, "High")

    def test_groq_provider_default_model(self):
        """Test 14: GroqProvider uses default model 'openai/gpt-oss-120b'."""
        with patch.dict(os.environ, {"GROQ_MODEL": ""}):
            provider = GroqProvider(api_key="gsk-test")
            self.assertEqual(provider.DEFAULT_MODEL, "openai/gpt-oss-120b")
            self.assertEqual(provider.model_name, "openai/gpt-oss-120b (via groq)")

    @patch("requests.post")
    def test_groq_provider_rate_limit_429(self, mock_post):
        """Test 15: Mock HTTP 429 raises AIProviderTransientError in GroqProvider."""
        mock_response = MagicMock()
        mock_response.status_code = 429
        mock_response.text = "Rate limit reached for RPM"
        mock_post.return_value = mock_response

        provider = GroqProvider(api_key="gsk-test-key")
        with self.assertRaises(AIProviderTransientError) as ctx:
            provider.analyze_finding(self.context)
        self.assertIn("429", str(ctx.exception))

    @patch("ai.provider.ensure_env_loaded")
    def test_factory_chain_mode_is_default(self, mock_ensure):
        """Test 16: With AI_PROVIDER unset or empty, get_ai_provider() returns ProviderChain."""
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("AI_PROVIDER", None)
            provider = get_ai_provider()
            self.assertIsInstance(provider, ProviderChain)

    def test_factory_ai_provider_openai_returns_legacy(self):
        """Test 17: AI_PROVIDER=openai returns legacy ExternalLLMProvider for backward compatibility."""
        with patch.dict(os.environ, {"AI_PROVIDER": "openai"}):
            provider = get_ai_provider()
            self.assertIsInstance(provider, ExternalLLMProvider)
            self.assertNotIsInstance(provider, OpenAIProvider)

    def test_factory_ai_provider_openai_native(self):
        """Test 18: AI_PROVIDER=openai-native returns production OpenAIProvider."""
        with patch.dict(os.environ, {"AI_PROVIDER": "openai-native"}):
            provider = get_ai_provider()
            self.assertIsInstance(provider, OpenAIProvider)

    def test_factory_chain_always_appends_rule_assisted(self):
        """Test 19: AI_PROVIDER_CHAIN=gemini,openai,groq guarantees RuleAssistedAIProvider as final item."""
        with patch.dict(os.environ, {"AI_PROVIDER": "chain", "AI_PROVIDER_CHAIN": "gemini,openai,groq"}):
            chain = get_ai_provider()
            self.assertIsInstance(chain, ProviderChain)
            self.assertIsInstance(chain._providers[-1], RuleAssistedAIProvider)

    def test_chain_no_credential_leakage_in_attempts(self):
        """Test 20: Raw API keys and credentials are scrubbed from ProviderAttempt.error_message."""
        raw_key = "sk-proj-998877665544332211aabbccddeeff"
        raw_pwd = "password=SuperSecretPassword123"
        failing_msg = f"Failed to authenticate with key {raw_key} and {raw_pwd}"

        leaky_provider = MockFailingProvider(
            name="LeakyProvider",
            model="leak-model",
            error=AIProviderTransientError(failing_msg)
        )
        leaky_provider.__class__.__name__ = "LeakyProvider"

        chain = ProviderChain([leaky_provider, RuleAssistedAIProvider()])
        chain.analyze_finding(self.context)

        self.assertEqual(len(chain.attempts), 2)
        recorded_err = chain.attempts[0].error_message

        self.assertNotIn(raw_key, recorded_err)
        self.assertNotIn("SuperSecretPassword123", recorded_err)
        self.assertIn("[REDACTED", recorded_err)


if __name__ == "__main__":
    unittest.main()

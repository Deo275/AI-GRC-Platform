"""Phase 4 Isolated Automated Test Suite: Google Gemini AI & Risk Intelligence.

Runs isolated test scenarios using Python unittest and in-memory SQLite database:
1. Gemini provider initialization (model config, defaults)
2. Gemini structured output configuration (response_schema, JSON mime-type)
3. Valid Gemini response handling and Pydantic validation
4. Malformed Gemini response handling
5. Gemini API failure handling (HTTP 500, network error)
6. Gemini timeout handling
7. Missing API key handling
8. Local provider fallback behavior (RuleAssistedAIProvider)
9. Risk score immutability guarantee (CRITICAL GRC INVARIANT)
10. Human-review flag behavior and explicit reasons
11. Credential and secret sanitization
12. Remediation safety and uncertainty (no OS/iptables assumptions, fallback marking)

This test suite DOES NOT require a real Gemini API key and DOES NOT touch PostgreSQL.
"""

import os
import sys
import json
import unittest
from pathlib import Path
from datetime import datetime

# Setup sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(BASE_DIR / "backend"))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from pydantic import ValidationError

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
    GeminiAIProvider,
    RuleAssistedAIProvider,
    ProviderChain,
    get_ai_provider,
)
from ai.risk_analyzer import (
    build_security_context,
    analyze_risk,
    get_latest_risk_analysis,
    analyze_vulnerability_finding,
    sanitize_text,
)


class MockGeminiModels:
    """Mock for client.models in Google GenAI SDK."""
    def __init__(self, response_text=None, side_effect=None):
        self.response_text = response_text
        self.side_effect = side_effect
        self.last_call = None

    def generate_content(self, model, contents, config):
        self.last_call = {"model": model, "contents": contents, "config": config}
        if self.side_effect:
            raise self.side_effect
        return type("MockResponse", (), {"text": self.response_text})()


class MockGeminiClient:
    """Mock for genai.Client."""
    def __init__(self, response_text=None, side_effect=None):
        self.models = MockGeminiModels(response_text=response_text, side_effect=side_effect)


def create_sample_gemini_json():
    """Generate valid JSON string representing Gemini structured output."""
    return json.dumps({
        "priority": "High",
        "simple_explanation": "A database service (PostgreSQL) is accessible over the network on port 5432. If access is unneeded, an attacker could attempt unauthorized queries.",
        "why_it_matters": "Databases hold business data. Unrestricted network exposure expands the attack surface and bypasses application boundary controls.",
        "severity_explanation": "The finding carries an official CVSS 3.1 score of 8.8, indicating high technical severity.",
        "risk_factors": [
            "Asset Business Criticality is rated High.",
            "Operating Environment is designated as Production.",
            "Network Exposure is classified as Internal."
        ],
        "potential_business_impact": [
            "Potential unauthorized data inspection if authentication is breached (Inferred: actual sensitivity unverified).",
            "Potential service disruption if subjected to connection flooding."
        ],
        "recommendation": [
            "Review whether external network access to port 5432 is necessary.",
            "Restrict access using network security controls."
        ],
        "remediation": {
            "immediate_mitigation": [
                "Restrict access to TCP/5432 using the organization's approved network security controls."
            ],
            "permanent_remediation": [
                "Configure PostgreSQL to bind only to authorized interfaces and apply vendor security updates."
            ],
            "validation": [
                "Re-scan the host using the scanner to verify port 5432 is no longer accessible from untrusted zones."
            ]
        },
        "recommended_controls": [
            {
                "name": "Firewall",
                "reason": "Restricts network packet flow to authorized client IP ranges."
            },
            {
                "name": "Network Segmentation",
                "reason": "Isolates database instances in a dedicated management VLAN."
            }
        ],
        "confidence": 0.88,
        "human_review_required": True,
        "human_review_reasons": [
            "High priority finding on Production asset warrants human validation."
        ],
        "model_name": "gemini-3.8-flash"
    })


class TestPhase4GeminiIsolated(unittest.TestCase):
    """Test Phase 4 Gemini AI Provider and Security Intelligence in isolation."""

    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")
        models.Base.metadata.create_all(bind=self.engine)
        self.Session = sessionmaker(bind=self.engine)
        self.db = self.Session()
        self.local_provider = RuleAssistedAIProvider()

    def tearDown(self):
        self.db.close()
        models.Base.metadata.drop_all(bind=self.engine)

    # 1. Gemini Provider Initialization
    def test_gemini_provider_initialization(self):
        """Verify Gemini provider initializes with configurable model and defaults."""
        provider = GeminiAIProvider(api_key="test-api-key", model_name="gemini-3.8-flash")
        self.assertEqual(provider.model_name, "gemini-3.8-flash")
        self.assertEqual(provider.api_key, "test-api-key")
        self.assertTrue(provider.fallback_enabled)

        # Factory returns GeminiAIProvider by default
        old_env = os.environ.get("AI_PROVIDER")
        try:
            os.environ.pop("AI_PROVIDER", None)
            default_p = get_ai_provider()
            self.assertIsInstance(default_p, (GeminiAIProvider, ProviderChain))
            self.assertEqual(default_p.model_name, "gemini-3.8-flash")
        finally:
            if old_env is not None:
                os.environ["AI_PROVIDER"] = old_env

    # 2. Gemini Structured Output Configuration
    def test_gemini_structured_output_configuration(self):
        """Verify that Gemini requests specify response_schema=AIAnalysisResult and application/json."""
        mock_client = MockGeminiClient(response_text=create_sample_gemini_json())
        provider = GeminiAIProvider(api_key="mock-key", client=mock_client)

        context = NormalizedSecurityContext(
            risk_title="PostgreSQL exposed on port 5432",
            service="postgresql",
            port=5432,
            inherent_risk_score=8,
            inherent_risk_level="High",
            residual_risk_score=4,
            residual_risk_level="Medium"
        )
        provider.analyze_finding(context)

        # Verify Google GenAI client call arguments
        last_call = mock_client.models.last_call
        self.assertIsNotNone(last_call)
        self.assertEqual(last_call["model"], "gemini-3.8-flash")
        cfg = last_call["config"]
        self.assertEqual(cfg.response_mime_type, "application/json")
        self.assertEqual(cfg.response_schema, AIAnalysisResult)

    # 3. Valid Gemini Response
    def test_valid_gemini_response(self):
        """Verify that valid Gemini structured output is parsed and validated."""
        mock_client = MockGeminiClient(response_text=create_sample_gemini_json())
        provider = GeminiAIProvider(api_key="mock-key", client=mock_client)

        context = NormalizedSecurityContext(
            risk_title="PostgreSQL exposed on port 5432",
            service="postgresql",
            port=5432,
            cvss_score=8.8,
            asset_environment="Production",
            inherent_risk_score=12,
            inherent_risk_level="High",
            residual_risk_score=8,
            residual_risk_level="High"
        )
        result = provider.analyze_finding(context)

        self.assertIsInstance(result, AIAnalysisResult)
        self.assertEqual(result.priority, "High")
        self.assertEqual(result.model_name, "gemini-3.8-flash")
        self.assertIn("database", result.simple_explanation.lower())
        self.assertIn("attack surface", result.why_it_matters.lower())
        self.assertTrue(result.human_review_required)
        self.assertEqual(len(result.remediation.immediate_mitigation), 1)
        self.assertEqual(len(result.recommended_controls), 2)

    # 4. Malformed Gemini Response Handling
    def test_malformed_gemini_response(self):
        """Verify that invalid/malformed JSON raises AIProviderError when fallback disabled, or falls back."""
        # 1. Fallback disabled: raises AIProviderError
        bad_client = MockGeminiClient(response_text="{invalid json...")
        strict_provider = GeminiAIProvider(api_key="mock-key", fallback_enabled=False, client=bad_client)

        context = NormalizedSecurityContext(
            risk_title="Test Risk",
            inherent_risk_score=4,
            inherent_risk_level="Low",
            residual_risk_score=4,
            residual_risk_level="Low"
        )
        with self.assertRaises(AIProviderError):
            strict_provider.analyze_finding(context)

        # 2. Fallback enabled: engages RuleAssistedAIProvider
        resilient_provider = GeminiAIProvider(api_key="mock-key", fallback_enabled=True, client=bad_client)
        fallback_res = resilient_provider.analyze_finding(context)
        self.assertIsInstance(fallback_res, AIAnalysisResult)
        self.assertTrue(fallback_res.human_review_required)
        self.assertTrue(any("fallback" in r.lower() for r in fallback_res.human_review_reasons))

    # 5. Gemini API Failure Handling
    def test_gemini_api_failure(self):
        """Verify HTTP/API errors from Gemini trigger controlled failure or fallback."""
        err_client = MockGeminiClient(side_effect=RuntimeError("Google GenAI 503 Service Unavailable"))
        strict_provider = GeminiAIProvider(api_key="mock-key", fallback_enabled=False, client=err_client)

        context = NormalizedSecurityContext(
            risk_title="Test Risk",
            inherent_risk_score=6,
            inherent_risk_level="Medium",
            residual_risk_score=6,
            residual_risk_level="Medium"
        )
        with self.assertRaises(AIProviderError):
            strict_provider.analyze_finding(context)

        # With fallback enabled
        fallback_provider = GeminiAIProvider(api_key="mock-key", fallback_enabled=True, client=err_client)
        res = fallback_provider.analyze_finding(context)
        self.assertIsInstance(res, AIAnalysisResult)
        self.assertIn("fallback", res.model_name.lower())

    # 6. Gemini Timeout Handling
    def test_gemini_timeout(self):
        """Verify client timeout exception is handled safely."""
        timeout_client = MockGeminiClient(side_effect=TimeoutError("Request to Gemini API timed out after 10s"))
        strict_p = GeminiAIProvider(api_key="mock-key", fallback_enabled=False, client=timeout_client)

        context = NormalizedSecurityContext(
            risk_title="Test Risk",
            inherent_risk_score=4,
            inherent_risk_level="Low",
            residual_risk_score=4,
            residual_risk_level="Low"
        )
        with self.assertRaises(AIProviderError):
            strict_p.analyze_finding(context)

        fallback_p = GeminiAIProvider(api_key="mock-key", fallback_enabled=True, client=timeout_client)
        res = fallback_p.analyze_finding(context)
        self.assertTrue(res.human_review_required)

    # 7. Missing API Key Handling
    def test_missing_api_key(self):
        """Verify missing GEMINI_API_KEY raises error when fallback disabled, or engages fallback."""
        # Force empty key
        strict_p = GeminiAIProvider(api_key="", fallback_enabled=False)
        context = NormalizedSecurityContext(
            risk_title="Test Risk",
            inherent_risk_score=4,
            inherent_risk_level="Low",
            residual_risk_score=4,
            residual_risk_level="Low"
        )
        with self.assertRaises(AIProviderError):
            strict_p.analyze_finding(context)

        # Fallback enabled
        resilient_p = GeminiAIProvider(api_key="", fallback_enabled=True)
        res = resilient_p.analyze_finding(context)
        self.assertIsInstance(res, AIAnalysisResult)
        self.assertTrue(res.human_review_required)

    # 8. Local Provider Fallback
    def test_local_provider_fallback(self):
        """Verify AI_PROVIDER=local returns RuleAssistedAIProvider operating completely offline."""
        old_val = os.environ.get("AI_PROVIDER")
        try:
            os.environ["AI_PROVIDER"] = "local"
            provider = get_ai_provider()
            self.assertIsInstance(provider, RuleAssistedAIProvider)

            context = NormalizedSecurityContext(
                risk_title="Database finding",
                service="postgresql",
                port=5432,
                inherent_risk_score=8,
                inherent_risk_level="High",
                residual_risk_score=4,
                residual_risk_level="Medium"
            )
            res = provider.analyze_finding(context)
            self.assertEqual(res.model_name, "rule-assisted-grc-v1")
            self.assertIn("database", res.simple_explanation.lower())
        finally:
            if old_val is not None:
                os.environ["AI_PROVIDER"] = old_val
            else:
                os.environ.pop("AI_PROVIDER", None)

    # 9. Risk Score Immutability (CRITICAL GRC INVARIANT)
    def test_risk_score_immutability(self):
        """CRITICAL: Verify AI analysis NEVER alters official rule-based risk scores."""
        asset = models.Asset(
            hostname="Production Database",
            ip_address="10.1.1.5",
            criticality="High",
            environment="Production",
            exposure="Internal"
        )
        self.db.add(asset)
        self.db.commit()

        risk = models.Risk(
            asset_id=asset.id,
            title="PostgreSQL Listening Port",
            inherent_risk_score=12,
            inherent_risk_level="High",
            residual_risk_score=6,
            residual_risk_level="Medium",
            likelihood="Medium",
            impact="High",
            likelihood_score=3,
            impact_score=4,
            residual_likelihood=2,
            residual_impact=3,
            status="Open",
            treatment="Mitigate"
        )
        self.db.add(risk)
        self.db.commit()

        # Run AI analysis using mocked Gemini provider
        mock_client = MockGeminiClient(response_text=create_sample_gemini_json())
        gemini_p = GeminiAIProvider(api_key="mock-key", client=mock_client)

        analysis = analyze_risk(risk_id=risk.id, db=self.db, provider=gemini_p)
        self.assertIsNotNone(analysis)

        # Re-fetch risk from database
        self.db.expire_all()
        refreshed_risk = self.db.query(models.Risk).filter(models.Risk.id == risk.id).first()

        # Verify EVERY official rule-based score is untouched
        self.assertEqual(refreshed_risk.inherent_risk_score, 12)
        self.assertEqual(refreshed_risk.inherent_risk_level, "High")
        self.assertEqual(refreshed_risk.residual_risk_score, 6)
        self.assertEqual(refreshed_risk.residual_risk_level, "Medium")
        self.assertEqual(refreshed_risk.likelihood, "Medium")
        self.assertEqual(refreshed_risk.impact, "High")
        self.assertEqual(refreshed_risk.likelihood_score, 3)
        self.assertEqual(refreshed_risk.impact_score, 4)
        self.assertEqual(refreshed_risk.residual_likelihood, 2)
        self.assertEqual(refreshed_risk.residual_impact, 3)
        self.assertEqual(refreshed_risk.status, "Open")
        self.assertEqual(refreshed_risk.treatment, "Mitigate")

    # 10. Human-Review Flag Behavior
    def test_human_review_flag(self):
        """Verify human_review_required triggers on elevated risk, missing CVSS, or fallback assumptions."""
        mock_client = MockGeminiClient(response_text=create_sample_gemini_json())
        provider = GeminiAIProvider(api_key="mock-key", client=mock_client)

        # Context with missing CVSS and default exposure
        context = NormalizedSecurityContext(
            risk_title="Heuristic Finding",
            service="http",
            port=80,
            cvss_score=None,
            is_exposure_default=True,
            inherent_risk_score=12,
            inherent_risk_level="High",
            residual_risk_score=6,
            residual_risk_level="Medium"
        )
        res = provider.analyze_finding(context)
        self.assertTrue(res.human_review_required)
        self.assertGreater(len(res.human_review_reasons), 0)

    # 11. Credential Sanitization
    def test_credential_sanitization(self):
        """Verify passwords, database URIs, API keys, and private keys are scrubbed."""
        raw_text = "Connect with postgres://user:SuperSecretPassword123@db.local:5432/main and api_key=sk-abc12345"
        sanitized = sanitize_text(raw_text)
        self.assertNotIn("SuperSecretPassword123", sanitized)
        self.assertNotIn("sk-abc12345", sanitized)

        key_block = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"
        sanitized_key = sanitize_text(key_block)
        self.assertNotIn("MIIEowIBAAKCAQEA", sanitized_key)
        self.assertIn("[REDACTED PRIVATE KEY]", sanitized_key)

    # 12. Remediation Safety & Fallback Data Marking
    def test_remediation_uncertainty_and_safety(self):
        """Verify remediation avoids OS/iptables assumptions and marks fallback assumptions."""
        context = NormalizedSecurityContext(
            risk_title="PostgreSQL exposed on port 5432",
            service="postgresql",
            port=5432,
            is_criticality_default=True,
            is_exposure_default=True,
            inherent_risk_score=8,
            inherent_risk_level="High",
            residual_risk_score=4,
            residual_risk_level="Medium"
        )
        res = self.local_provider.analyze_finding(context)

        # Check remediation text does NOT make iptables assumptions
        all_remediation = " ".join(
            res.remediation.immediate_mitigation +
            res.remediation.permanent_remediation +
            res.remediation.validation
        )
        self.assertNotIn("iptables", all_remediation)
        self.assertIn("approved network security controls", all_remediation)

        # Check that default fallback asset values are explicitly noted in risk factors
        rf_text = " ".join(res.risk_factors).lower()
        self.assertTrue("by default" in rf_text or "unverified" in rf_text or "baseline" in rf_text)
        self.assertTrue(res.human_review_required)

    # 13. Gemini Timeout and Retry SDK Options Configuration
    def test_gemini_timeout_and_retry_options(self):
        """Verify Gemini provider builds HttpOptions with short timeout and single attempt (no retries)."""
        provider = GeminiAIProvider(
            api_key="mock-key",
            timeout_seconds=10,
            max_retries=1,
        )
        self.assertEqual(provider.timeout_seconds, 10)
        self.assertEqual(provider.max_retries, 1)

        http_opts = provider._build_http_options()
        self.assertIsNotNone(http_opts)
        self.assertGreaterEqual(http_opts.timeout, 10000)
        self.assertEqual(http_opts.client_args.get("timeout"), 10.0)
        self.assertIsNotNone(http_opts.retry_options)
        self.assertEqual(http_opts.retry_options.attempts, 1)

    # 14. Gemini 503 Immediate Local Fallback
    def test_gemini_503_immediate_local_fallback(self):
        """Verify 503 UNAVAILABLE triggers prompt local fallback to RuleAssistedAIProvider."""
        err_503 = RuntimeError("503 UNAVAILABLE: Model is experiencing high demand.")
        mock_client = MockGeminiClient(side_effect=err_503)
        provider = GeminiAIProvider(
            api_key="mock-key",
            fallback_enabled=True,
            client=mock_client,
        )

        context = NormalizedSecurityContext(
            risk_title="PostgreSQL exposed on port 5432",
            service="postgresql",
            port=5432,
            inherent_risk_score=12,
            inherent_risk_level="High",
            residual_risk_score=8,
            residual_risk_level="High",
        )

        result = provider.analyze_finding(context)
        self.assertIsInstance(result, AIAnalysisResult)
        self.assertTrue(result.human_review_required)
        self.assertTrue(any("fallback" in r.lower() or "unavailable" in r.lower() for r in result.human_review_reasons))
        self.assertIn("fallback", result.model_name.lower())
        self.assertIn("database", result.simple_explanation.lower())


if __name__ == "__main__":
    unittest.main()

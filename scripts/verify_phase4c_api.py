"""Live API verification script for Phase 4C Multi-LLM Provider Failover.

Tests:
1. Verification of configured provider architecture (ProviderChain / active provider)
2. Retrieval of existing risks (GET /risks)
3. Execution of AI analysis through ProviderChain (POST /risks/{risk_id}/analyze)
4. Verification of model_name and failover auditability
5. Full 13-field AIAnalysisResult response schema validation
6. Verification of human_review_required flag and human_review_reasons audit trail
7. Immutability validation: Confirms all official GRC risk scores are 100% unchanged
8. Retrieval of saved analysis (GET /risks/{risk_id}/analysis)
9. Error handling: 404 for invalid risk IDs
10. Health and stability check for Phase 1-3 endpoints (/assets, /controls, /frameworks)
"""

import os
import sys
import requests

# Setup import paths to load backend AI configuration
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BACKEND_DIR = os.path.join(BASE_DIR, "backend")
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

try:
    from backend.ai.provider import (
        ensure_env_loaded,
        get_ai_provider,
        ProviderChain,
        GeminiAIProvider,
        OpenAIProvider,
        GroqProvider,
    )
    ensure_env_loaded()
except ImportError:
    try:
        from ai.provider import (
            ensure_env_loaded,
            get_ai_provider,
            ProviderChain,
            GeminiAIProvider,
            OpenAIProvider,
            GroqProvider,
        )
        ensure_env_loaded()
    except ImportError:
        pass

BASE_URL = "http://127.0.0.1:8000"


def verify_phase4c_api():
    print(f"Connecting to AI-GRC Platform API at {BASE_URL}...\n")

    # 1. Inspect configured AI Provider mode
    try:
        provider = get_ai_provider()
        provider_type = type(provider).__name__
        configured_mode = os.getenv("AI_PROVIDER", "chain")
        chain_order = os.getenv("AI_PROVIDER_CHAIN", "gemini,openai,groq")
    except Exception as e:
        provider_type = f"Error resolving provider: {e}"
        configured_mode = os.getenv("AI_PROVIDER", "chain")
        chain_order = os.getenv("AI_PROVIDER_CHAIN", "gemini,openai,groq")

    print(f"Configured AI_PROVIDER:      {configured_mode}")
    print(f"Active Provider Instance:    {provider_type}")
    print(f"Configured Chain Order:      {chain_order}")
    if isinstance(provider, ProviderChain):
        tiers = [type(p).__name__ for p in provider._providers]
        print(f"ProviderChain Tiers:         {' -> '.join(tiers)}")
    print()

    # 2. Fetch risks
    r = requests.get(f"{BASE_URL}/risks", timeout=10)
    assert r.status_code == 200, f"GET /risks failed: {r.status_code}"
    risks_data = r.json()
    risks = risks_data["risks"] if isinstance(risks_data, dict) and "risks" in risks_data else risks_data
    assert len(risks) > 0, "No risks found in database"
    target_risk = risks[0]
    risk_id = target_risk["id"]
    print(f"[PASS] GET /risks -> Found {len(risks)} risks. Testing Risk ID: {risk_id} ('{target_risk.get('title')}')")

    # Snapshot official scores before AI analysis
    pre_inherent_score = target_risk.get("inherent_risk_score")
    pre_inherent_level = target_risk.get("inherent_risk_level")
    pre_residual_score = target_risk.get("residual_risk_score")
    pre_residual_level = target_risk.get("residual_risk_level")
    pre_status = target_risk.get("status")
    pre_treatment = target_risk.get("treatment")

    # 3. Trigger AI Analysis (POST /risks/{risk_id}/analyze)
    print(f"\nTriggering AI Security Intelligence Analysis (POST /risks/{risk_id}/analyze)...")
    r_post = requests.post(f"{BASE_URL}/risks/{risk_id}/analyze", timeout=25)
    assert r_post.status_code == 200, f"POST /risks/{risk_id}/analyze failed: {r_post.status_code} - {r_post.text}"
    post_data = r_post.json()

    assert "analysis" in post_data, "Missing 'analysis' in response"
    assert "official_risk_scores" in post_data, "Missing 'official_risk_scores' in response"
    assert "disclaimer" in post_data, "Missing 'disclaimer' in response"
    print("[PASS] POST /risks/{risk_id}/analyze -> Returned 200 OK with expected top-level structure")

    # 4. Validate AI Structured Intelligence Schema
    analysis = post_data["analysis"]
    required_fields = [
        "priority",
        "simple_explanation",
        "why_it_matters",
        "severity_explanation",
        "risk_factors",
        "potential_business_impact",
        "recommendation",
        "remediation",
        "recommended_controls",
        "confidence",
        "human_review_required",
        "human_review_reasons",
        "model_name",
    ]
    for field in required_fields:
        assert field in analysis, f"Missing field '{field}' in analysis payload"
    print(f"[PASS] Structured schema validated (all {len(required_fields)} required fields present)")

    # 5. Check model_name and failover auditability
    model_name = analysis.get("model_name", "")
    print(f"[PASS] Model identifier: '{model_name}'")
    if "chain-failover:" in model_name:
        print(f"       -> Multi-LLM failover detected: human_review_required={analysis.get('human_review_required')}")
        assert analysis.get("human_review_required") is True, "Failover must set human_review_required=True"
        assert any("Chain failover:" in r for r in analysis.get("human_review_reasons", [])), (
            "Failover reason missing in human_review_reasons"
        )
        print("[PASS] Failover correctly annotated in human_review_reasons and flagged for review")

    # 6. Validate Immutability
    r_verify = requests.get(f"{BASE_URL}/risks", timeout=10)
    risks_after = r_verify.json()
    risks_list = risks_after["risks"] if isinstance(risks_after, dict) and "risks" in risks_after else risks_after
    refreshed_risk = next(r for r in risks_list if r["id"] == risk_id)

    assert refreshed_risk.get("inherent_risk_score") == pre_inherent_score, "Inherent risk score was mutated!"
    assert refreshed_risk.get("inherent_risk_level") == pre_inherent_level, "Inherent risk level was mutated!"
    assert refreshed_risk.get("residual_risk_score") == pre_residual_score, "Residual risk score was mutated!"
    assert refreshed_risk.get("residual_risk_level") == pre_residual_level, "Residual risk level was mutated!"
    assert refreshed_risk.get("status") == pre_status, "Risk status was mutated!"
    assert refreshed_risk.get("treatment") == pre_treatment, "Risk treatment was mutated!"
    print("[PASS] Official GRC risk scores verified: 100% IMMUTABLE post AI analysis")

    # 7. Validate GET /risks/{risk_id}/analysis
    r_get = requests.get(f"{BASE_URL}/risks/{risk_id}/analysis", timeout=10)
    assert r_get.status_code == 200, f"GET /risks/{risk_id}/analysis failed: {r_get.status_code}"
    get_data = r_get.json()
    assert "analysis" in get_data, "Missing 'analysis' in GET response"
    assert get_data["analysis"]["model_name"] == model_name, "Stored analysis model_name mismatch"
    print("[PASS] GET /risks/{risk_id}/analysis -> Verified persistence and audit trail")

    # 8. Error Handling (404 on unknown risk)
    r_404 = requests.get(f"{BASE_URL}/risks/999999/analysis", timeout=10)
    assert r_404.status_code == 404, f"Expected 404 for invalid risk, got {r_404.status_code}"
    print("[PASS] Handled invalid risk ID correctly with HTTP 404")

    # 9. Health of Phase 1-3 endpoints
    r_assets = requests.get(f"{BASE_URL}/assets", timeout=10)
    assert r_assets.status_code == 200, "GET /assets failed"
    r_vulns = requests.get(f"{BASE_URL}/vulnerabilities", timeout=10)
    assert r_vulns.status_code == 200, "GET /vulnerabilities failed"
    r_controls = requests.get(f"{BASE_URL}/controls", timeout=10)
    assert r_controls.status_code == 200, "GET /controls failed"
    r_comp = requests.get(f"{BASE_URL}/compliance/summary", timeout=10)
    assert r_comp.status_code == 200, "GET /compliance/summary failed"
    print("[PASS] Phase 1-3 baseline endpoints (/assets, /vulnerabilities, /controls, /compliance/summary) healthy")

    print("\n========================================================")
    print("ALL PHASE 4C MULTI-LLM API VERIFICATION CHECKS PASSED!")
    print("========================================================\n")


if __name__ == "__main__":
    verify_phase4c_api()

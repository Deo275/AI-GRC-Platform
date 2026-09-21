"""Live API verification script for Phase 4 AI-Assisted Security Intelligence.

Tests:
1. Retrieval of existing risks (GET /risks)
2. Execution of AI analysis (POST /risks/{risk_id}/analyze)
3. Schema validation of structured AI intelligence response
4. Dual-audience explanations (simple vs technical)
5. 3-tier remediation validation (immediate, permanent, validation)
6. Recommended controls validation with justification
7. Confidence score and human-review flag behavior
8. Stored audit analysis retrieval (GET /risks/{risk_id}/analysis)
9. Strict immutability: Verifying official rule-based risk scores NEVER change
10. Controlled error handling (404 for invalid risk IDs)
11. Preservation and health of Phase 1-3 endpoints
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
    from backend.ai.provider import ensure_env_loaded, get_ai_provider, GeminiAIProvider
    ensure_env_loaded()
except ImportError:
    try:
        from ai.provider import ensure_env_loaded, get_ai_provider, GeminiAIProvider
        ensure_env_loaded()
    except ImportError:
        pass

BASE_URL = "http://127.0.0.1:8000"


def verify_phase4_api():
    print(f"Connecting to AI-GRC Platform API at {BASE_URL}...\n")

    # Check Gemini configuration status reflecting the application's actual provider
    try:
        provider = get_ai_provider()
        ai_provider = os.getenv("AI_PROVIDER", "gemini")
        if isinstance(provider, GeminiAIProvider):
            gemini_configured = bool(provider.api_key and len(provider.api_key) > 5)
            gemini_model = provider.model_name
        else:
            gemini_key = os.getenv("GEMINI_API_KEY", "").strip()
            gemini_configured = bool(gemini_key and len(gemini_key) > 5)
            gemini_model = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")
    except Exception:
        gemini_key = os.getenv("GEMINI_API_KEY", "").strip()
        gemini_configured = bool(gemini_key and len(gemini_key) > 5)
        ai_provider = os.getenv("AI_PROVIDER", "gemini")
        gemini_model = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")

    print(f"Configured AI Provider:     {ai_provider}")
    print(f"Gemini API Key Configured:  {gemini_configured} {'(Live Gemini LLM active)' if gemini_configured else '(Running in local fallback mode)'}")
    print(f"Configured Gemini Model:    {gemini_model}\n")

    # 1. Fetch risks
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

    # 2. Trigger AI Analysis (POST /risks/{risk_id}/analyze)
    print(f"\nTriggering AI Security Intelligence Analysis (POST /risks/{risk_id}/analyze)...")
    r_post = requests.post(f"{BASE_URL}/risks/{risk_id}/analyze", timeout=15)
    assert r_post.status_code == 200, f"POST /risks/{risk_id}/analyze failed: {r_post.status_code} - {r_post.text}"
    post_data = r_post.json()

    assert "analysis" in post_data, "Missing 'analysis' in response"
    assert "official_risk_scores" in post_data, "Missing 'official_risk_scores' in response"
    assert "disclaimer" in post_data, "Missing 'disclaimer' in response"
    print("[PASS] POST /risks/{risk_id}/analyze -> Returned 200 OK with expected top-level structure")

    # 3. Validate AI Structured Intelligence Schema
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
        assert field in analysis, f"Missing required analysis field: {field}"
    print("[PASS] AI output schema verified: all 13 required intelligence fields present")

    # 4. Dual-Audience Intelligence Verification
    print("\n--- AI Security Intelligence Output ---")
    print(f"AI Priority:           {analysis['priority']}")
    print(f"Confidence:            {analysis['confidence']:.2f}")
    print(f"Human Review Required: {analysis['human_review_required']}")
    print(f"Human Review Reasons:  {analysis['human_review_reasons']}")
    print(f"Model Identifier:      {analysis['model_name']}")
    print(f"\nSimple Explanation (Non-Technical GRC User):\n  \"{analysis['simple_explanation']}\"")
    print(f"\nWhy It Matters (Technical SecOps / GRC):\n  \"{analysis['why_it_matters']}\"")
    print(f"\nSeverity Interpretation:\n  \"{analysis['severity_explanation']}\"")

    # 5. 3-Tier Remediation Verification
    remediation = analysis["remediation"]
    assert "immediate_mitigation" in remediation, "Missing immediate_mitigation"
    assert "permanent_remediation" in remediation, "Missing permanent_remediation"
    assert "validation" in remediation, "Missing validation"
    print("\n3-Tier Remediation Guidance:")
    print(f"  Immediate Mitigation:  {remediation['immediate_mitigation']}")
    print(f"  Permanent Remediation: {remediation['permanent_remediation']}")
    print(f"  Validation/Retesting:  {remediation['validation']}")
    print("[PASS] 3-tier remediation structure verified")

    # 6. Recommended Controls Verification
    print(f"\nRecommended Platform Controls ({len(analysis['recommended_controls'])}):")
    for rc in analysis["recommended_controls"]:
        print(f"  - Control: {rc['name']} | Reason: {rc['reason']}")
    assert len(analysis["recommended_controls"]) > 0, "Expected at least one recommended control"
    print("[PASS] Recommended controls verified with justifications")

    # 7. Auditable Analysis Retrieval (GET /risks/{risk_id}/analysis)
    print(f"\nVerifying Stored Audit Record (GET /risks/{risk_id}/analysis)...")
    r_get = requests.get(f"{BASE_URL}/risks/{risk_id}/analysis", timeout=10)
    assert r_get.status_code == 200, f"GET /risks/{risk_id}/analysis failed: {r_get.status_code}"
    get_data = r_get.json()
    assert get_data["risk_id"] == risk_id
    assert get_data["analysis"]["priority"] == analysis["priority"]
    assert get_data["analysis"]["confidence"] == analysis["confidence"]
    print("[PASS] GET /risks/{risk_id}/analysis -> Successfully retrieved persisted auditable analysis record")

    # 8. Strict Immutability Verification: Official Rule-Based Risk Scores MUST NOT CHANGE
    print("\nVerifying Strict Risk Engine Score Immutability...")
    r_check = requests.get(f"{BASE_URL}/risks/{risk_id}", timeout=10)
    assert r_check.status_code == 200
    post_check_risk = r_check.json()

    assert post_check_risk.get("inherent_risk_score") == pre_inherent_score, "Inherent risk score altered!"
    assert post_check_risk.get("inherent_risk_level") == pre_inherent_level, "Inherent risk level altered!"
    assert post_check_risk.get("residual_risk_score") == pre_residual_score, "Residual risk score altered!"
    assert post_check_risk.get("residual_risk_level") == pre_residual_level, "Residual risk level altered!"
    assert post_check_risk.get("status") == pre_status, "Risk status altered!"
    assert post_check_risk.get("treatment") == pre_treatment, "Risk treatment altered!"

    print(f"[PASS] CRITICAL INVARIANT VERIFIED: Official risk scores remain 100% immutable:")
    print(f"       Inherent Risk Score: {post_check_risk.get('inherent_risk_score')} (Unchanged)")
    print(f"       Residual Risk Score: {post_check_risk.get('residual_risk_score')} (Unchanged)")
    print(f"       Status:              {post_check_risk.get('status')} (Unchanged)")
    print(f"       Treatment:           {post_check_risk.get('treatment')} (Unchanged)")

    # 9. Error Handling
    print("\nVerifying Controlled Error Handling (404 on non-existent risk)...")
    r_404_post = requests.post(f"{BASE_URL}/risks/999999/analyze", timeout=10)
    assert r_404_post.status_code == 404, f"Expected 404, got {r_404_post.status_code}"
    r_404_get = requests.get(f"{BASE_URL}/risks/999999/analysis", timeout=10)
    assert r_404_get.status_code == 404, f"Expected 404, got {r_404_get.status_code}"
    print("[PASS] Error handling: 404 returned cleanly for non-existent risk IDs")

    # 10. Health check on Phase 1-3 endpoints
    print("\nVerifying Health of Phase 1-3 Endpoints...")
    assert requests.get(f"{BASE_URL}/assets", timeout=5).status_code == 200
    assert requests.get(f"{BASE_URL}/vulnerabilities", timeout=5).status_code == 200
    assert requests.get(f"{BASE_URL}/controls", timeout=5).status_code == 200
    assert requests.get(f"{BASE_URL}/compliance/summary", timeout=5).status_code == 200
    print("[PASS] Phase 1-3 endpoints (Assets, Vulnerabilities, Controls, Compliance) healthy and intact")

    print("\n========================================================")
    print("  PHASE 4A LIVE API VERIFICATION SUCCESSFUL (ALL PASS)  ")
    print("========================================================")


if __name__ == "__main__":
    verify_phase4_api()

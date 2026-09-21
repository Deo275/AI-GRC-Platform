"""Live API verification script for Phase 2 GRC endpoints.

Tests:
1. GET /assets and GET /assets/1
2. GET /risks and GET /risks/1
3. GET /controls
4. POST /controls (create temporary test control)
5. POST /risks/1/controls/{id} (assign and verify residual risk mitigation)
6. DELETE /risks/1/controls/{id} (detach and verify residual risk restoration)
7. DELETE /controls/{id} (cleanup temporary control)
8. GET /vulnerabilities
"""

import requests
import json

BASE_URL = "http://127.0.0.1:8000"


def test_api():
    print(f"Connecting to {BASE_URL}...")
    # 1. Health check
    r = requests.get(f"{BASE_URL}/")
    assert r.status_code == 200, f"Root endpoint failed: {r.status_code}"
    print("[PASS] GET / -> Server healthy")

    # 2. Assets
    r = requests.get(f"{BASE_URL}/assets")
    assert r.status_code == 200, f"GET /assets failed: {r.status_code}"
    assets_data = r.json()
    assert "assets" in assets_data
    assets = assets_data["assets"]
    print(f"[PASS] GET /assets -> Found {len(assets)} assets")
    for a in assets:
        assert "criticality" in a, "Asset missing criticality"
        assert "environment" in a, "Asset missing environment"
        assert "exposure" in a, "Asset missing exposure"
        print(f"       Asset {a['id']} ({a['ip_address']}): Crit={a['criticality']}, Env={a['environment']}, Exp={a['exposure']}, Owner={a['owner']}")

    # 3. Individual Asset
    if assets:
        a_id = assets[0]["id"]
        r = requests.get(f"{BASE_URL}/assets/{a_id}")
        assert r.status_code == 200, f"GET /assets/{a_id} failed"
        print(f"[PASS] GET /assets/{a_id} -> OK")

    # 4. Risks
    r = requests.get(f"{BASE_URL}/risks")
    assert r.status_code == 200, f"GET /risks failed: {r.status_code}"
    risks_data = r.json()
    assert "risks" in risks_data
    risks = risks_data["risks"]
    print(f"[PASS] GET /risks -> Found {len(risks)} risks")
    for rsk in risks[:2]:
        assert "inherent_risk_score" in rsk, "Risk missing inherent_risk_score"
        assert "residual_risk_score" in rsk, "Risk missing residual_risk_score"
        assert "residual_impact" in rsk, "Risk missing residual_impact"
        assert "controls" in rsk, "Risk missing controls"
        print(f"       Risk {rsk['id']}: Inherent={rsk['inherent_risk_score']} ({rsk['inherent_risk_level']}), Residual={rsk['residual_risk_score']} ({rsk['residual_risk_level']}), Controls={len(rsk['controls'])}")

    # 5. Controls
    r = requests.get(f"{BASE_URL}/controls")
    assert r.status_code == 200, f"GET /controls failed: {r.status_code}"
    controls_data = r.json()
    assert "controls" in controls_data
    ctrls = controls_data["controls"]
    print(f"[PASS] GET /controls -> Found {len(ctrls)} controls in catalog")

    # 6. Create temporary control
    test_ctrl_payload = {
        "name": "TEST_ISOLATED_CONTROL_XYZ",
        "description": "Temporary control for API testing",
        "category": "Preventive",
        "framework": "NIST CSF (TEST)",
        "effectiveness": "High",
        "status": "Implemented"
    }
    r = requests.post(f"{BASE_URL}/controls", json=test_ctrl_payload)
    assert r.status_code == 200, f"POST /controls failed: {r.text}"
    test_ctrl = r.json()["control"]
    test_ctrl_id = test_ctrl["id"]
    print(f"[PASS] POST /controls -> Created temporary test control ID {test_ctrl_id}")

    # 7. Assign control to Risk 1 and check mitigation
    target_risk_id = risks[0]["id"]
    orig_res_score = risks[0]["residual_risk_score"]
    orig_res_lik = risks[0]["residual_likelihood"]
    orig_res_imp = risks[0]["residual_impact"]

    r = requests.post(f"{BASE_URL}/risks/{target_risk_id}/controls/{test_ctrl_id}")
    assert r.status_code == 200, f"Assign control failed: {r.text}"
    updated_risk = r.json()["risk"]
    new_res_lik = updated_risk["residual_likelihood"]
    new_res_imp = updated_risk["residual_impact"]
    new_res_score = updated_risk["residual_risk_score"]

    print(f"[PASS] POST /risks/{target_risk_id}/controls/{test_ctrl_id} -> Assigned control")
    print(f"       Before: Likelihood={orig_res_lik}, Impact={orig_res_imp}, Score={orig_res_score}")
    print(f"       After:  Likelihood={new_res_lik}, Impact={new_res_imp}, Score={new_res_score}")
    # Verify impact remained unchanged
    assert new_res_imp == orig_res_imp, f"Impact changed unexpectedly! {new_res_imp} != {orig_res_imp}"
    # Verify likelihood reduced or reached floor of 1
    assert new_res_lik <= orig_res_lik, f"Likelihood did not reduce: {new_res_lik} > {orig_res_lik}"

    # 8. Detach control from Risk 1
    r = requests.delete(f"{BASE_URL}/risks/{target_risk_id}/controls/{test_ctrl_id}")
    assert r.status_code == 200, f"Detach control failed: {r.text}"
    restored_risk = r.json()["risk"]
    print(f"[PASS] DELETE /risks/{target_risk_id}/controls/{test_ctrl_id} -> Detached control")
    assert restored_risk["residual_risk_score"] == orig_res_score, "Score did not restore after detach"

    # 9. Clean up temporary control
    r = requests.delete(f"{BASE_URL}/controls/{test_ctrl_id}")
    assert r.status_code == 200, f"DELETE /controls/{test_ctrl_id} failed: {r.text}"
    print(f"[PASS] DELETE /controls/{test_ctrl_id} -> Cleaned up temporary control")

    # 10. Vulnerabilities check
    r = requests.get(f"{BASE_URL}/vulnerabilities")
    assert r.status_code == 200, f"GET /vulnerabilities failed: {r.status_code}"
    vulns_data = r.json()
    assert "vulnerabilities" in vulns_data
    print(f"[PASS] GET /vulnerabilities -> Found {len(vulns_data['vulnerabilities'])} vulnerabilities")

    print("\nALL LIVE API VERIFICATION TESTS PASSED SUCCESSFULLY!")


if __name__ == "__main__":
    test_api()

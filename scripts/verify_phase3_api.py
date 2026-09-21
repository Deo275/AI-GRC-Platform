"""Live API verification script for Phase 3 Compliance Mapping endpoints.

Tests:
1. GET /compliance/frameworks
2. GET /compliance/requirements (unfiltered & filtered)
3. GET /compliance/mappings
4. GET /compliance/summary (metrics & coverage calculation)
5. PATCH /compliance/requirements/{id} (status update & restoration)
6. Preservation of Phase 1 and 2 endpoints (assets, risks, vulnerabilities, controls)
"""

import requests

BASE_URL = "http://127.0.0.1:8000"


def test_api():
    print(f"Connecting to {BASE_URL}...")

    # 1. Frameworks
    r = requests.get(f"{BASE_URL}/compliance/frameworks")
    assert r.status_code == 200, f"GET /compliance/frameworks failed: {r.status_code}"
    fw_data = r.json()
    assert fw_data["count"] == 2, f"Expected 2 frameworks, got {fw_data['count']}"
    print(f"[PASS] GET /compliance/frameworks -> Found {fw_data['count']} frameworks")
    for fw in fw_data["frameworks"]:
        print(f"       - {fw['name']} v{fw['version']}: {fw['requirement_count']} requirements")

    # 2. Requirements (Unfiltered)
    r = requests.get(f"{BASE_URL}/compliance/requirements")
    assert r.status_code == 200, f"GET /compliance/requirements failed: {r.status_code}"
    req_data = r.json()
    assert req_data["count"] == 34, f"Expected 34 requirements, got {req_data['count']}"
    print(f"[PASS] GET /compliance/requirements -> Found {req_data['count']} requirements total")

    # Filtered by framework "NIST CSF"
    r_nist = requests.get(f"{BASE_URL}/compliance/requirements?framework=NIST%20CSF")
    assert r_nist.status_code == 200
    nist_reqs = r_nist.json()["requirements"]
    assert len(nist_reqs) == 18, f"Expected 18 NIST requirements, got {len(nist_reqs)}"
    print(f"[PASS] GET /compliance/requirements?framework=NIST CSF -> {len(nist_reqs)} requirements")

    # Filtered by framework "ISO/IEC 27001"
    r_iso = requests.get(f"{BASE_URL}/compliance/requirements?framework=ISO/IEC%2027001")
    assert r_iso.status_code == 200
    iso_reqs = r_iso.json()["requirements"]
    assert len(iso_reqs) == 16, f"Expected 16 ISO requirements, got {len(iso_reqs)}"
    print(f"[PASS] GET /compliance/requirements?framework=ISO/IEC 27001 -> {len(iso_reqs)} requirements")

    # Filtered by status
    r_stat = requests.get(f"{BASE_URL}/compliance/requirements?status=Not%20Assessed")
    assert r_stat.status_code == 200
    print(f"[PASS] GET /compliance/requirements?status=Not Assessed -> {len(r_stat.json()['requirements'])} matching")

    # Check mapped controls in a requirement
    req_with_mappings = next((r for r in req_data["requirements"] if len(r["mapped_controls"]) > 0), None)
    assert req_with_mappings is not None, "No requirements found with mapped controls"
    print(f"[PASS] Requirement {req_with_mappings['requirement_id']} ({req_with_mappings['title']}) has {len(req_with_mappings['mapped_controls'])} mapped control(s):")
    for mc in req_with_mappings["mapped_controls"]:
        print(f"       Control '{mc['name']}' ({mc['mapping_strength']})")

    # 3. Mappings
    r = requests.get(f"{BASE_URL}/compliance/mappings")
    assert r.status_code == 200, f"GET /compliance/mappings failed: {r.status_code}"
    map_data = r.json()
    assert map_data["count"] == 30, f"Expected 30 mappings, got {map_data['count']}"
    print(f"[PASS] GET /compliance/mappings -> Found {map_data['count']} control-requirement mappings")

    # 4. Summary & Coverage
    r = requests.get(f"{BASE_URL}/compliance/summary")
    assert r.status_code == 200, f"GET /compliance/summary failed: {r.status_code}"
    sum_data = r.json()
    assert "summary" in sum_data
    assert "note" in sum_data
    print(f"[PASS] GET /compliance/summary -> Received summary report:")
    for s in sum_data["summary"]:
        print(f"       {s['framework_name']} v{s['framework_version']}: Total={s['total_requirements']}, Implemented={s['implemented']}, Coverage={s['implementation_coverage']}% ({s['metric_label']})")

    # 5. Update requirement status & notes, then restore
    target_req_id = req_data["requirements"][0]["id"]
    orig_status = req_data["requirements"][0]["status"]
    orig_notes = req_data["requirements"][0]["notes"]

    update_payload = {
        "status": "Partially Implemented",
        "notes": "Audited via live API verification script."
    }
    r_patch = requests.patch(f"{BASE_URL}/compliance/requirements/{target_req_id}", json=update_payload)
    assert r_patch.status_code == 200, f"PATCH requirement failed: {r_patch.text}"
    updated = r_patch.json()["requirement"]
    assert updated["status"] == "Partially Implemented"
    assert updated["notes"] == "Audited via live API verification script."
    print(f"[PASS] PATCH /compliance/requirements/{target_req_id} -> Status updated to 'Partially Implemented'")

    # Verify summary reflects partial implementation
    r_sum2 = requests.get(f"{BASE_URL}/compliance/summary")
    sum2_fw1 = r_sum2.json()["summary"][0]
    assert sum2_fw1["partially_implemented"] >= 1, "Summary did not reflect partially implemented requirement"
    print(f"       Summary updated coverage: {sum2_fw1['implementation_coverage']}%")

    # Restore original status
    restore_payload = {
        "status": orig_status or "Not Assessed",
        "notes": orig_notes
    }
    r_restore = requests.patch(f"{BASE_URL}/compliance/requirements/{target_req_id}", json=restore_payload)
    assert r_restore.status_code == 200
    print(f"[PASS] Restored requirement {target_req_id} status back to '{orig_status}'")

    # 6. Verify Phase 1 & 2 endpoints remain intact
    r_assets = requests.get(f"{BASE_URL}/assets")
    assert r_assets.status_code == 200 and r_assets.json()["count"] == 2
    r_risks = requests.get(f"{BASE_URL}/risks")
    assert r_risks.status_code == 200 and r_risks.json()["count"] == 6
    r_vulns = requests.get(f"{BASE_URL}/vulnerabilities")
    assert r_vulns.status_code == 200 and r_vulns.json()["count"] == 6
    r_ctrls = requests.get(f"{BASE_URL}/controls")
    assert r_ctrls.status_code == 200 and r_ctrls.json()["count"] == 9
    print("[PASS] Phase 1 & Phase 2 endpoints verified: 2 Assets, 6 Risks, 6 Vulns, 9 Controls intact.")

    print("\nALL PHASE 3 LIVE API VERIFICATION TESTS PASSED SUCCESSFULLY!")


if __name__ == "__main__":
    test_api()

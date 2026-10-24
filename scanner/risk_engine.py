"""Security Risk Calculation Engine.

Calculates quantitative risk score (0-100), categorical risk level,
assessment status, and contributing risk factors from observed port exposure,
CVSS vulnerability findings, asset criticality, and network exposure.
"""

from typing import List, Dict, Any, Optional


def calculate_risk(
    open_ports: Optional[List[Dict[str, Any]]] = None,
    vulnerabilities: Optional[List[Dict[str, Any]]] = None,
    asset_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Calculate asset risk score, risk level, assessment status, and findings.

    Backward compatible with calculate_risk(open_ports).
    Distinguishes confirmed CVEs from potential matches and hardening advisories.
    Does not inflate risk scores for standard internal services (SMB, RPC, NetBIOS).
    """
    # Check for unassessed or failed scan states
    if open_ports is None:
        failed = bool(asset_context and (asset_context.get("scan_failed") or asset_context.get("failure_reason")))
        partial = bool(asset_context and (asset_context.get("scan_partial") or asset_context.get("partial")))
        status = "Assessment failed/partial" if failed else ("Assessment incomplete" if partial else "Not assessed")
        return {
            "risk_score": 0,
            "risk_level": "Unknown",
            "findings": [],
            "assessment_status": status,
            "risk_factors": ["Asset has not completed port and vulnerability assessment"],
        }

    score = 0
    findings = []
    seen_findings = set()
    risk_factors = []
    evaluated_ports = set()

    # 1. Base Port Exposure Risk (Calibrated for internal LAN)
    for item in open_ports or []:
        try:
            port = int(item.get("port") or 0)
        except (ValueError, TypeError):
            continue

        evaluated_ports.add(port)
        service = item.get("service") or "unknown"
        product = str(item.get("product") or "").lower()

        if port == 445:
            score += 5
            finding = "SMB service exposed on port 445"
            if finding not in seen_findings:
                seen_findings.add(finding)
                findings.append(finding)
                risk_factors.append("Internal SMB file sharing service exposed (Port 445)")

        elif port == 139:
            score += 3
            finding = "NetBIOS service exposed on port 139"
            if finding not in seen_findings:
                seen_findings.add(finding)
                findings.append(finding)
                risk_factors.append("Internal NetBIOS session service exposed (Port 139)")

        elif port == 135:
            score += 2
            finding = "Microsoft RPC exposed on port 135"
            if finding not in seen_findings:
                seen_findings.add(finding)
                findings.append(finding)
                risk_factors.append("Internal Microsoft RPC endpoint exposed (Port 135)")

        elif port == 5432:
            score += 10
            finding = "PostgreSQL database exposed on port 5432"
            if finding not in seen_findings:
                seen_findings.add(finding)
                findings.append(finding)
                risk_factors.append("Exposed PostgreSQL database listener (Port 5432)")

        elif port in [902, 912]:
            score += 5
            finding = f"VMware service exposed on port {port}"
            if finding not in seen_findings:
                seen_findings.add(finding)
                findings.append(finding)
                risk_factors.append(f"VMware management daemon exposed (Port {port})")

        elif port == 23 or service == "telnet":
            score += 25
            finding = "Cleartext Telnet service exposed on port 23"
            if finding not in seen_findings:
                seen_findings.add(finding)
                findings.append(finding)
                risk_factors.append("Unencrypted Telnet remote management protocol")

        elif port == 21 or service == "ftp":
            score += 10
            finding = "Cleartext FTP service exposed on port 21"
            if finding not in seen_findings:
                seen_findings.add(finding)
                findings.append(finding)
                risk_factors.append("Unencrypted FTP service exposed (Port 21)")

        elif port == 1900 or "upnp" in service:
            score += 10
            finding = "UPnP SSDP service exposed on port 1900"
            if finding not in seen_findings:
                seen_findings.add(finding)
                findings.append(finding)
                risk_factors.append("Exposed UPnP service on local network (Port 1900)")

        elif port == 80 and ("admin" in product or "tp-link" in product or "router" in product):
            score += 10
            finding = "Unencrypted router HTTP admin on port 80"
            if finding not in seen_findings:
                seen_findings.add(finding)
                findings.append(finding)
                risk_factors.append("Unencrypted router HTTP management portal (Port 80)")

    # 2. Vulnerability CVSS & Verification Status Integration
    has_cve = False
    has_advisory = False

    if vulnerabilities:
        for v in vulnerabilities:
            v_title = v.get("title") or "Unknown Vulnerability"
            v_sev = (v.get("severity") or "Medium").capitalize()
            cve = v.get("cve")
            status = v.get("verification_status") or ("Confirmed" if cve else "Advisory")
            v_port = v.get("port")

            # Avoid duplicate findings text
            if v_title not in seen_findings:
                seen_findings.add(v_title)
                findings.append(v_title)

            if cve:
                has_cve = True
                if status == "Confirmed":
                    # Full impact for verified/confirmed CVEs
                    if v_sev == "Critical":
                        score += 25
                        risk_factors.append(f"Confirmed Critical Finding: {v_title} ({cve})")
                    elif v_sev == "High":
                        score += 15
                        risk_factors.append(f"Confirmed High Finding: {v_title} ({cve})")
                    elif v_sev == "Medium":
                        score += 8
                        risk_factors.append(f"Confirmed Medium Finding: {v_title} ({cve})")
                    else:
                        score += 3
                        risk_factors.append(f"Confirmed Low Finding: {v_title} ({cve})")
                else:
                    # Potential / Version match without active exploit proof
                    if v_sev == "Critical":
                        score += 15
                        risk_factors.append(f"Potential Critical Finding: {v_title} ({cve})")
                    elif v_sev == "High":
                        score += 10
                        risk_factors.append(f"Potential High Finding: {v_title} ({cve})")
                    elif v_sev == "Medium":
                        score += 5
                        risk_factors.append(f"Potential Medium Finding: {v_title} ({cve})")
                    else:
                        score += 2
                        risk_factors.append(f"Potential Low Finding: {v_title} ({cve})")
            else:
                has_advisory = True
                # General hardening advisory or exposed service (no CVE)
                # Only add slight increment if the port was not already scored
                if v_port and int(v_port) in evaluated_ports:
                    pass  # Already scored under base port exposure
                else:
                    if v_sev == "High":
                        score += 5
                        risk_factors.append(f"High Hardening Advisory: {v_title}")
                    elif v_sev == "Medium":
                        score += 3
                        risk_factors.append(f"Medium Hardening Advisory: {v_title}")
                    else:
                        score += 1

    # 3. Asset Context Adjustment (Criticality & Exposure)
    if asset_context and isinstance(asset_context, dict):
        crit = (asset_context.get("criticality") or "").strip().lower()
        expo = (asset_context.get("exposure") or "").strip().lower()

        multiplier = 1.0
        if crit == "critical":
            multiplier *= 1.3
            risk_factors.append("High Impact Asset: Critical infrastructure classification")
        elif crit == "high":
            multiplier *= 1.15
        elif crit == "low":
            multiplier *= 0.85

        if expo == "external":
            multiplier *= 1.4
            risk_factors.append("High Exposure: External perimeter reachability")
        elif expo == "dmz":
            multiplier *= 1.2

        score = int(round(score * multiplier))

    # Clamp score to 0 - 100
    score = max(0, min(100, score))

    # 4. Categorical Risk Level
    if score >= 70:
        risk_level = "Critical"
    elif score >= 40:
        risk_level = "High"
    elif score >= 20:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    # 5. Truthful Assessment Status & Limitations
    if asset_context and asset_context.get("scan_failed"):
        assessment_status = "Assessment failed"
        risk_factors.append(
            f"Assessment failed: {asset_context.get('scan_failure_reason') or 'Port scan encountered timeouts or network errors'}"
        )
    elif asset_context and asset_context.get("scan_partial"):
        assessment_status = "Assessment failed/partial"
        risk_factors.append("Assessment partial: Some target ports or service probes timed out")
    elif has_cve:
        assessment_status = "Findings detected"
    elif has_advisory or len(findings) > 0:
        assessment_status = "Completed — hardening advisories only"
    elif len(open_ports or []) == 0:
        assessment_status = "Completed — no findings detected"
        risk_factors.append(
            "Limitation Note: No open listening ports detected on host (host firewall or device isolation may restrict inbound service exposure; does not prove host is free of vulnerabilities)"
        )
    else:
        # Port scan finished and no vulnerabilities/risky ports detected
        assessment_status = "Completed — no findings detected"
        risk_factors.append(
            "Limitation Note: No known vulnerability signatures detected on tested services (does not prove host is immune or free of unpatched flaws)"
        )

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "findings": findings,
        "assessment_status": assessment_status,
        "risk_factors": risk_factors,
    }


if __name__ == "__main__":
    test_ports = [
        {"port": "135", "service": "msrpc"},
        {"port": "139", "service": "netbios-ssn"},
        {"port": "445", "service": "microsoft-ds"},
        {"port": "5432", "service": "postgresql"},
    ]

    result = calculate_risk(test_ports)

    print("Risk Score:", result["risk_score"])
    print("Risk Level:", result["risk_level"])
    print("Assessment Status:", result["assessment_status"])

    print("\nFindings:")
    for finding in result["findings"]:
        print("-", finding)
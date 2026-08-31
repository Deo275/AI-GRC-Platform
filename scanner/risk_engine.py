def calculate_risk(open_ports):

    score = 0
    findings = []

    for item in open_ports:

        port = int(item["port"])
        service = item["service"]

        if port == 445:
            score += 25
            findings.append("SMB service exposed on port 445")

        elif port == 139:
            score += 20
            findings.append("NetBIOS service exposed on port 139")

        elif port == 5432:
            score += 20
            findings.append("PostgreSQL database exposed on port 5432")

        elif port == 135:
            score += 10
            findings.append("Microsoft RPC exposed on port 135")

        elif port in [902, 912]:
            score += 10
            findings.append(
                f"VMware service exposed on port {port}"
            )

    if score >= 70:
        risk_level = "Critical"

    elif score >= 40:
        risk_level = "High"

    elif score >= 20:
        risk_level = "Medium"

    else:
        risk_level = "Low"

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "findings": findings
    }

if __name__ == "__main__":

    test_ports = [
        {"port": "135", "service": "msrpc"},
        {"port": "139", "service": "netbios-ssn"},
        {"port": "445", "service": "microsoft-ds"},
        {"port": "5432", "service": "postgresql"}
    ]

    result = calculate_risk(test_ports)

    print("Risk Score:", result["risk_score"])
    print("Risk Level:", result["risk_level"])

    print("\nFindings:")

    for finding in result["findings"]:
        print("-", finding)
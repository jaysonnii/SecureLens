def analyze_log(log_text: str) -> dict:
    text = log_text.lower()

    failed_login_count = text.count("failed login")
    powershell_count = text.count("powershell")
    administrator_count = text.count("administrator")
    successful_login_count = text.count("successful login")

    findings = []
    risk_score = 0

    if failed_login_count > 0:
        findings.append(
            {
                "type": "Failed Login Attempts",
                "count": failed_login_count,
                "severity": "Medium",
                "mitre_attack": "T1110 - Brute Force",
                "recommendation": (
                    "Review the source IP and consider account lockout policies."
                ),
            }
        )
        risk_score += min(failed_login_count * 10, 40)

    if powershell_count > 0:
        findings.append(
            {
                "type": "PowerShell Activity",
                "count": powershell_count,
                "severity": "Medium",
                "mitre_attack": "T1059.001 - PowerShell",
                "recommendation": (
                    "Review the PowerShell command and the parent process."
                ),
            }
        )
        risk_score += 25

    if administrator_count > 0:
        findings.append(
            {
                "type": "Administrator Account Activity",
                "count": administrator_count,
                "severity": "Low",
                "recommendation": (
                    "Confirm that administrator account activity was authorized."
                ),
            }
        )
        risk_score += 10

    if successful_login_count > 0 and failed_login_count >= 3:
        findings.append(
            {
                "type": "Login After Multiple Failures",
                "severity": "High",
                "mitre_attack": "T1110 - Brute Force",
                "recommendation": (
                    "Investigate whether the account was compromised."
                ),
            }
        )
        risk_score += 30

    risk_score = min(risk_score, 100)

    if risk_score >= 70:
        risk_level = "High"
    elif risk_score >= 30:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "total_findings": len(findings),
        "findings": findings,
    }
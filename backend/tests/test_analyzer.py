from app.services.analyzer import analyze_log


def get_finding(result: dict, finding_type: str) -> dict:
    return next(
        finding
        for finding in result["findings"]
        if finding["type"] == finding_type
    )


def test_benign_log_returns_low_risk():
    result = analyze_log(
        """
        Service started successfully
        Scheduled backup completed
        System health check passed
        """
    )

    assert result == {
        "risk_score": 0,
        "risk_level": "Low",
        "total_findings": 0,
        "findings": [],
    }


def test_windows_failed_logons_followed_by_success():
    result = analyze_log(
        """
        2026-07-30 10:01:00 Event ID: 4625 Source IP: 10.0.0.10
        2026-07-30 10:01:05 Event ID: 4625 Source IP: 10.0.0.10
        2026-07-30 10:01:10 Event ID: 4625 Source IP: 10.0.0.10
        2026-07-30 10:01:15 Event ID: 4624 Source IP: 10.0.0.10
        """
    )

    assert result["risk_score"] == 60
    assert result["risk_level"] == "Medium"
    assert result["total_findings"] == 2

    failed_logins = get_finding(
        result,
        "Failed Login Attempts",
    )

    assert failed_logins["count"] == 3
    assert failed_logins["severity"] == "Medium"
    assert len(failed_logins["evidence"]) == 3

    get_finding(
        result,
        "Login After Multiple Failures",
    )

def test_success_before_failures_does_not_trigger_sequence():
    result = analyze_log(
        """
        Event ID: 4624 Source IP: 10.0.0.10
        Event ID: 4625 Source IP: 10.0.0.10
        Event ID: 4625 Source IP: 10.0.0.10
        Event ID: 4625 Source IP: 10.0.0.10
        """
    )

    finding_types = {
        finding["type"]
        for finding in result["findings"]
    }

    assert result["risk_score"] == 30
    assert result["total_findings"] == 1
    assert "Failed Login Attempts" in finding_types
    assert "Login After Multiple Failures" not in finding_types


def test_suspicious_powershell_activity():
    log_line = (
        "Event ID: 4104 ScriptBlockText: "
        "powershell.exe -EncodedCommand AAAA"
    )

    result = analyze_log(log_line)

    assert result["risk_score"] == 40
    assert result["risk_level"] == "Medium"
    assert result["total_findings"] == 1

    finding = get_finding(
        result,
        "Suspicious PowerShell Activity",
    )

    assert finding["severity"] == "High"
    assert finding["count"] == 1
    assert finding["mitre_attack"] == (
        "T1059.001 - PowerShell"
    )
    assert finding["evidence"] == [log_line]


def test_windows_security_log_cleared():
    log_line = (
        "Event ID: 1102 The audit log was cleared"
    )

    result = analyze_log(log_line)

    assert result["risk_score"] == 40
    assert result["risk_level"] == "Medium"
    assert result["total_findings"] == 1

    finding = get_finding(
        result,
        "Windows Security Log Cleared",
    )

    assert finding["severity"] == "High"
    assert finding["count"] == 1
    assert finding["mitre_attack"] == (
        "T1685.005 - Clear Windows Event Logs"
    )
    assert finding["evidence"] == [log_line]


def test_evidence_is_unique_and_limited_to_three_lines():
    result = analyze_log(
        """
        Failed login from 10.0.0.1
        Failed login from 10.0.0.1
        Failed login from 10.0.0.2
        Failed login from 10.0.0.3
        Failed login from 10.0.0.4
        """
    )

    finding = get_finding(
        result,
        "Failed Login Attempts",
    )

    assert finding["count"] == 5
    assert finding["severity"] == "High"
    assert finding["evidence"] == [
        "Failed login from 10.0.0.1",
        "Failed login from 10.0.0.2",
        "Failed login from 10.0.0.3",
    ]
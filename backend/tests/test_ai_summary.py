import json

from app.services.ai_summary import (
    _build_ai_input,
    generate_ai_summary,
)


def test_disabled_ai_returns_local_summary():
    analysis = {
        "risk_score": 0,
        "risk_level": "Low",
        "total_findings": 0,
        "findings": [],
    }

    result = generate_ai_summary(analysis)

    assert result == {
        "status": "disabled",
        "provider": "local",
        "model": None,
        "summary": (
            "No suspicious security indicators were detected "
            "by the current SecureLens analysis rules."
        ),
        "priority_actions": [],
    }


def test_local_summary_includes_priority_actions():
    analysis = {
        "risk_score": 85,
        "risk_level": "High",
        "total_findings": 4,
        "findings": [
            {
                "type": "Suspicious PowerShell Activity",
                "severity": "High",
                "recommendation": "Review the PowerShell command.",
            },
            {
                "type": "Failed Login Attempts",
                "severity": "Medium",
                "recommendation": "Review the source IP address.",
            },
            {
                "type": "Windows Security Log Cleared",
                "severity": "High",
                "recommendation": "Investigate who cleared the log.",
            },
            {
                "type": "Repeated Recommendation",
                "severity": "Low",
                "recommendation": "Review the source IP address.",
            },
        ],
    }

    result = generate_ai_summary(analysis)

    assert result["status"] == "disabled"
    assert result["provider"] == "local"
    assert result["model"] is None
    assert "4 security finding(s)" in result["summary"]
    assert "High risk level" in result["summary"]

    assert result["priority_actions"] == [
        "Review the PowerShell command.",
        "Review the source IP address.",
        "Investigate who cleared the log.",
    ]


def test_ai_input_excludes_evidence_and_raw_log_content():
    analysis = {
        "risk_score": 40,
        "risk_level": "Medium",
        "total_findings": 1,
        "findings": [
            {
                "type": "Suspicious PowerShell Activity",
                "severity": "High",
                "count": 1,
                "mitre_attack": "T1059.001 - PowerShell",
                "recommendation": "Review the command.",
                "evidence": [
                    "powershell.exe -EncodedCommand SECRETDATA"
                ],
            }
        ],
    }

    payload = json.loads(_build_ai_input(analysis))

    finding = payload["findings"][0]

    assert payload["risk_score"] == 40
    assert finding["type"] == "Suspicious PowerShell Activity"
    assert finding["recommendation"] == "Review the command."
    assert "evidence" not in finding
    assert "SECRETDATA" not in json.dumps(payload)
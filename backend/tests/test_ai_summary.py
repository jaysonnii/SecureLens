import asyncio
import json
from types import SimpleNamespace

import app.services.ai_summary as ai_summary_service
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

    result = asyncio.run(
        generate_ai_summary(analysis)
    )

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

    result = asyncio.run(
        generate_ai_summary(analysis)
    )

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

def test_enabled_ai_without_key_returns_local_summary(
    monkeypatch,
):
    monkeypatch.setattr(
        ai_summary_service.config,
        "AI_SUMMARY_ENABLED",
        True,
    )
    monkeypatch.setattr(
        ai_summary_service.config,
        "OPENAI_API_KEY",
        "",
    )

    analysis = {
        "risk_score": 0,
        "risk_level": "Low",
        "total_findings": 0,
        "findings": [],
    }

    result = asyncio.run(
        generate_ai_summary(analysis)
    )

    assert result["status"] == "missing_api_key"
    assert result["provider"] == "local"
    assert result["model"] is None


def test_enabled_ai_returns_generated_summary(
    monkeypatch,
):
    captured = {}

    monkeypatch.setattr(
        ai_summary_service.config,
        "AI_SUMMARY_ENABLED",
        True,
    )
    monkeypatch.setattr(
        ai_summary_service.config,
        "OPENAI_API_KEY",
        "test-key",
    )
    monkeypatch.setattr(
        ai_summary_service.config,
        "OPENAI_MODEL",
        "gpt-5-mini",
    )

    class FakeResponses:
        async def create(self, **kwargs):
            captured.update(kwargs)

            return SimpleNamespace(
                output_text=(
                    "The activity indicates a high-risk "
                    "security incident requiring review."
                )
            )

    class FakeClient:
        def __init__(self, api_key):
            captured["api_key"] = api_key
            self.responses = FakeResponses()

    monkeypatch.setattr(
        ai_summary_service,
        "AsyncOpenAI",
        FakeClient,
    )

    analysis = {
        "risk_score": 90,
        "risk_level": "High",
        "total_findings": 1,
        "findings": [
            {
                "type": "Suspicious PowerShell Activity",
                "severity": "High",
                "count": 1,
                "mitre_attack": "T1059.001 - PowerShell",
                "recommendation": (
                    "Review the PowerShell command."
                ),
            }
        ],
    }

    result = asyncio.run(
        generate_ai_summary(analysis)
    )

    assert result["status"] == "generated"
    assert result["provider"] == "openai"
    assert result["model"] == "gpt-5-mini"
    assert "high-risk" in result["summary"]

    assert result["priority_actions"] == [
        "Review the PowerShell command."
    ]

    assert captured["api_key"] == "test-key"
    assert captured["model"] == "gpt-5-mini"
    assert captured["store"] is False


def test_openai_failure_returns_local_fallback(
    monkeypatch,
):
    monkeypatch.setattr(
        ai_summary_service.config,
        "AI_SUMMARY_ENABLED",
        True,
    )
    monkeypatch.setattr(
        ai_summary_service.config,
        "OPENAI_API_KEY",
        "test-key",
    )

    class FailingResponses:
        async def create(self, **kwargs):
            raise RuntimeError("Simulated API failure")

    class FailingClient:
        def __init__(self, api_key):
            self.responses = FailingResponses()

    monkeypatch.setattr(
        ai_summary_service,
        "AsyncOpenAI",
        FailingClient,
    )

    analysis = {
        "risk_score": 40,
        "risk_level": "Medium",
        "total_findings": 1,
        "findings": [
            {
                "type": "Failed Login Attempts",
                "severity": "Medium",
                "recommendation": (
                    "Review the source IP address."
                ),
            }
        ],
    }

    result = asyncio.run(
        generate_ai_summary(analysis)
    )

    assert result["status"] == "fallback"
    assert result["provider"] == "local"
    assert result["model"] is None

    assert result["priority_actions"] == [
        "Review the source IP address."
    ]

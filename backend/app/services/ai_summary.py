import json

from openai import AsyncOpenAI

import app.config as config


MAX_PRIORITY_ACTIONS = 3

SEVERITY_ORDER = {
    "Low": 1,
    "Medium": 2,
    "High": 3,
}


def _build_priority_actions(
    findings: list[dict],
) -> list[str]:
    actions = []
    seen = set()

    for finding in findings:
        recommendation = str(
            finding.get("recommendation", "")
        ).strip()

        if not recommendation:
            continue

        if recommendation in seen:
            continue

        seen.add(recommendation)
        actions.append(recommendation)

        if len(actions) == MAX_PRIORITY_ACTIONS:
            break

    return actions


def _build_local_summary(
    analysis: dict,
    status: str = "disabled",
) -> dict:
    findings = analysis.get("findings", [])

    if not findings:
        summary = (
            "No suspicious security indicators were detected "
            "by the current SecureLens analysis rules."
        )
    else:
        highest_severity = max(
            (
                finding.get("severity", "Low")
                for finding in findings
            ),
            key=lambda severity: SEVERITY_ORDER.get(
                severity,
                0,
            ),
        )

        finding_names = [
            finding.get("type", "Unknown finding")
            for finding in findings
        ]

        summary = (
            f"SecureLens detected {len(findings)} security "
            f"finding(s) with an overall "
            f"{analysis.get('risk_level', 'Unknown')} risk level "
            f"and a score of "
            f"{analysis.get('risk_score', 0)}/100. "
            f"The highest finding severity was "
            f"{highest_severity}. "
            f"Detected activity included: "
            f"{', '.join(finding_names)}."
        )

    return {
        "status": status,
        "provider": "local",
        "model": None,
        "summary": summary,
        "priority_actions": _build_priority_actions(
            findings
        ),
    }


def _build_ai_input(analysis: dict) -> str:
    safe_findings = []

    for finding in analysis.get("findings", []):
        safe_findings.append(
            {
                "type": finding.get("type"),
                "severity": finding.get("severity"),
                "count": finding.get("count"),
                "mitre_attack": finding.get(
                    "mitre_attack"
                ),
                "recommendation": finding.get(
                    "recommendation"
                ),
            }
        )

    payload = {
        "risk_score": analysis.get("risk_score", 0),
        "risk_level": analysis.get(
            "risk_level",
            "Unknown",
        ),
        "total_findings": analysis.get(
            "total_findings",
            len(safe_findings),
        ),
        "findings": safe_findings,
    }

    return json.dumps(payload, indent=2)


async def generate_ai_summary(analysis: dict) -> dict:
    fallback = _build_local_summary(analysis)

    if not config.AI_SUMMARY_ENABLED:
        return fallback

    if not config.OPENAI_API_KEY:
        return _build_local_summary(
            analysis,
            status="missing_api_key",
        )

    try:
        client = AsyncOpenAI(
            api_key=config.OPENAI_API_KEY
        )

        response = await client.responses.create(
            model=config.OPENAI_MODEL,
            instructions=(
                "You are a security operations center analyst. "
                "Summarize only the supplied deterministic "
                "security findings. Do not invent events, "
                "accounts, IP addresses, malware, causes, or "
                "evidence. Write one concise paragraph with "
                "three to five sentences."
            ),
            input=_build_ai_input(analysis),
            max_output_tokens=600,
            store=False,
        )

        summary = response.output_text.strip()

        if not summary:
            return _build_local_summary(
                analysis,
                status="fallback",
            )

        return {
            "status": "generated",
            "provider": "openai",
            "model": config.OPENAI_MODEL,
            "summary": summary,
            "priority_actions": (
                fallback["priority_actions"]
            ),
        }

    except Exception:
        return _build_local_summary(
            analysis,
            status="fallback",
        )

import re


MAX_EVIDENCE_LINES = 3
MAX_EVIDENCE_LENGTH = 240


FAILED_LOGIN_TERMS = (
    "failed login",
    "failed logon",
    "an account failed to log on",
    "authentication failure",
)

SUCCESSFUL_LOGIN_TERMS = (
    "successful login",
    "successful logon",
    "an account was successfully logged on",
)

POWERSHELL_TERMS = (
    "powershell",
    "powershell.exe",
    "pwsh",
    "pwsh.exe",
)

SUSPICIOUS_POWERSHELL_TERMS = (
    "-enc ",
    "-encodedcommand",
    "encodedcommand",
    "invoke-expression",
    "iex(",
    "downloadstring",
    "frombase64string",
    "executionpolicy bypass",
    "-w hidden",
    "windowstyle hidden",
    "invoke-webrequest",
    "start-bitstransfer",
    "clear-eventlog",
    "remove-eventlog",
)

ADMINISTRATOR_TERMS = (
    "administrator",
    "admin account",
    "privileged account",
)

CLEARED_LOG_TERMS = (
    "audit log was cleared",
    "security log was cleared",
    "cleared the security log",
    "wevtutil cl security",
    "clear-eventlog",
    "remove-eventlog",
)


EVENT_ID_PATTERNS = {
    event_id: re.compile(
        (
            rf"(?:\bevent\s*id\b|\beventid\b)"
            rf"\s*[:=]?\s*{event_id}\b"
            rf"|<eventid>\s*{event_id}\s*</eventid>"
        ),
        re.IGNORECASE,
    )
    for event_id in (1102, 4104, 4624, 4625)
}


def _line_matches(
    line: str,
    terms: tuple[str, ...] = (),
    event_ids: tuple[int, ...] = (),
) -> bool:
    lowercase_line = line.lower()

    if any(term in lowercase_line for term in terms):
        return True

    return any(
        EVENT_ID_PATTERNS[event_id].search(line)
        for event_id in event_ids
    )


def _find_matches(
    lines: list[str],
    terms: tuple[str, ...] = (),
    event_ids: tuple[int, ...] = (),
) -> list[tuple[int, str]]:
    matches = []

    for index, line in enumerate(lines):
        cleaned_line = " ".join(line.split())

        if not cleaned_line:
            continue

        if _line_matches(cleaned_line, terms, event_ids):
            matches.append((index, cleaned_line))

    return matches


def _create_evidence(
    matches: list[tuple[int, str]],
) -> list[str]:
    evidence = []
    seen = set()

    for _, line in matches:
        comparison_value = line.lower()

        if comparison_value in seen:
            continue

        seen.add(comparison_value)
        evidence.append(line[:MAX_EVIDENCE_LENGTH])

        if len(evidence) == MAX_EVIDENCE_LINES:
            break

    return evidence


def _has_success_after_failures(
    failed_matches: list[tuple[int, str]],
    successful_matches: list[tuple[int, str]],
) -> bool:
    if len(failed_matches) < 3:
        return False

    third_failure_index = failed_matches[2][0]

    return any(
        success_index > third_failure_index
        for success_index, _ in successful_matches
    )


def analyze_log(log_text: str) -> dict:
    lines = log_text.splitlines()

    failed_matches = _find_matches(
        lines,
        terms=FAILED_LOGIN_TERMS,
        event_ids=(4625,),
    )

    successful_matches = _find_matches(
        lines,
        terms=SUCCESSFUL_LOGIN_TERMS,
        event_ids=(4624,),
    )

    powershell_matches = _find_matches(
        lines,
        terms=POWERSHELL_TERMS,
        event_ids=(4104,),
    )

    suspicious_powershell_matches = [
        match
        for match in powershell_matches
        if _line_matches(
            match[1],
            terms=SUSPICIOUS_POWERSHELL_TERMS,
        )
    ]

    administrator_matches = _find_matches(
        lines,
        terms=ADMINISTRATOR_TERMS,
    )

    cleared_log_matches = _find_matches(
        lines,
        terms=CLEARED_LOG_TERMS,
        event_ids=(1102,),
    )

    findings = []
    risk_score = 0
    score_breakdown = []

    failed_login_count = len(failed_matches)

    if failed_login_count > 0:
        failed_login_severity = (
            "High" if failed_login_count >= 5 else "Medium"
        )

        findings.append(
            {
                "type": "Failed Login Attempts",
                "count": failed_login_count,
                "severity": failed_login_severity,
                "mitre_attack": "T1110 - Brute Force",
                "recommendation": (
                    "Review the source IP address, affected account, "
                    "logon type, and account lockout policies."
                ),
                "evidence": _create_evidence(failed_matches),
            }
        )

        failed_login_points = min(
            failed_login_count * 10,
            40,
        )
        risk_score += failed_login_points
        score_breakdown.append(
            {
                "finding_type": "Failed Login Attempts",
                "points": failed_login_points,
                "reason": (
                    f"{failed_login_count} failed login attempt(s) "
                    "at 10 points each, capped at 40."
                ),
            }
        )

    if powershell_matches:
        if suspicious_powershell_matches:
            findings.append(
                {
                    "type": "Suspicious PowerShell Activity",
                    "count": len(suspicious_powershell_matches),
                    "severity": "High",
                    "mitre_attack": "T1059.001 - PowerShell",
                    "recommendation": (
                        "Review the complete command, decoded arguments, "
                        "parent process, user account, and network activity."
                    ),
                    "evidence": _create_evidence(
                        suspicious_powershell_matches
                    ),
                }
            )

            risk_score += 40
            score_breakdown.append(
                {
                    "finding_type": (
                        "Suspicious PowerShell Activity"
                    ),
                    "points": 40,
                    "reason": (
                        "Suspicious PowerShell indicators were "
                        "detected."
                    ),
                }
            )
        else:
            findings.append(
                {
                    "type": "PowerShell Activity",
                    "count": len(powershell_matches),
                    "severity": "Medium",
                    "mitre_attack": "T1059.001 - PowerShell",
                    "recommendation": (
                        "Review the PowerShell command, parent process, "
                        "executing user, and execution context."
                    ),
                    "evidence": _create_evidence(
                        powershell_matches
                    ),
                }
            )

            risk_score += 25
            score_breakdown.append(
                {
                    "finding_type": "PowerShell Activity",
                    "points": 25,
                    "reason": (
                        "PowerShell execution was detected without "
                        "a known high-risk command indicator."
                    ),
                }
            )

    if administrator_matches:
        findings.append(
            {
                "type": "Administrator Account Activity",
                "count": len(administrator_matches),
                "severity": "Low",
                "recommendation": (
                    "Confirm that the administrator or privileged "
                    "account activity was expected and authorized."
                ),
                "evidence": _create_evidence(
                    administrator_matches
                ),
            }
        )

        risk_score += 10
        score_breakdown.append(
            {
                "finding_type": (
                    "Administrator Account Activity"
                ),
                "points": 10,
                "reason": (
                    "Administrator or privileged account activity "
                    "was detected."
                ),
            }
        )

    if _has_success_after_failures(
        failed_matches,
        successful_matches,
    ):
        combined_matches = (
            failed_matches[-3:] + successful_matches[:1]
        )

        findings.append(
            {
                "type": "Login After Multiple Failures",
                "severity": "High",
                "mitre_attack": "T1110 - Brute Force",
                "recommendation": (
                    "Investigate whether the account was compromised "
                    "and correlate the source address with other events."
                ),
                "evidence": _create_evidence(combined_matches),
            }
        )

        risk_score += 30
        score_breakdown.append(
            {
                "finding_type": (
                    "Login After Multiple Failures"
                ),
                "points": 30,
                "reason": (
                    "A successful login occurred after at least "
                    "three failed attempts."
                ),
            }
        )

    if cleared_log_matches:
        findings.append(
            {
                "type": "Windows Security Log Cleared",
                "count": len(cleared_log_matches),
                "severity": "High",
                "mitre_attack": (
                    "T1685.005 - Clear Windows Event Logs"
                ),
                "recommendation": (
                    "Identify the account and process that cleared the "
                    "log, preserve related evidence, and investigate "
                    "possible defense evasion."
                ),
                "evidence": _create_evidence(
                    cleared_log_matches
                ),
            }
        )

        risk_score += 40
        score_breakdown.append(
            {
                "finding_type": (
                    "Windows Security Log Cleared"
                ),
                "points": 40,
                "reason": (
                    "Windows security or audit log clearing "
                    "activity was detected."
                ),
            }
        )

    score_before_cap = risk_score
    risk_score = min(score_before_cap, 100)

    if risk_score >= 70:
        risk_level = "High"
    elif risk_score >= 30:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return {
        "risk_score": risk_score,
        "score_before_cap": score_before_cap,
        "score_cap": 100,
        "score_breakdown": score_breakdown,
        "risk_level": risk_level,
        "total_findings": len(findings),
        "findings": findings,
    }
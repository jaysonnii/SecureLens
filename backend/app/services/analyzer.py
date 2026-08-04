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

# Keep these terms specific enough to avoid treating a group named
# "Administrators" as generic administrator-account activity.
ADMINISTRATOR_TERMS = (
    "administrator account",
    "for administrator",
    "admin account",
    "privileged account",
    "account name: administrator",
    "account name=administrator",
)

CLEARED_LOG_TERMS = (
    "audit log was cleared",
    "security log was cleared",
    "cleared the security log",
    "wevtutil cl security",
    "clear-eventlog",
    "remove-eventlog",
)

PRIVILEGED_GROUP_TERMS = (
    "administrators",
    "domain admins",
    "enterprise admins",
    "schema admins",
    "account operators",
    "backup operators",
    "server operators",
)

BUILTIN_PRIVILEGED_ACCOUNTS = (
    "system",
    "local service",
    "network service",
    "anonymous logon",
)

MSHTA_TERMS = (
    "mshta.exe",
    "\\mshta",
    " mshta ",
)

CERTUTIL_TERMS = (
    "certutil.exe",
    "\\certutil",
    " certutil ",
)

SUSPICIOUS_CERTUTIL_TERMS = (
    "-urlcache",
    "-decode",
    "-decodehex",
    "-encode",
    "http://",
    "https://",
)

WMIC_TERMS = (
    "wmic.exe",
    "\\wmic",
    " wmic ",
)

SUSPICIOUS_WMIC_TERMS = (
    "process call create",
    "process get brief",
    "/node:",
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
    for event_id in (
        1102,
        4104,
        4624,
        4625,
        4672,
        4688,
        4720,
        4728,
        4732,
        4740,
    )
}


USER_PATTERNS = (
    re.compile(
        r"\bfor\s+user\s+([^\s,;]+)",
        re.IGNORECASE,
    ),
    re.compile(
        (
            r"\b(?:user(?:name)?|account\s+name)"
            r"\s*[:=]\s*([^\s,;]+)"
        ),
        re.IGNORECASE,
    ),
)

SOURCE_IP_PATTERN = re.compile(
    (
        r"\b(?:source\s+network\s+address|"
        r"source\s+ip|src(?:_ip)?|ip\s+address)"
        r"\s*[:=]\s*"
        r"((?:\d{1,3}\.){3}\d{1,3})\b"
    ),
    re.IGNORECASE,
)


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


def _build_event_blocks(
    lines: list[str],
) -> list[tuple[int, str]]:
    blocks = []
    current_index = None
    current_parts = []

    for index, line in enumerate(lines):
        cleaned_line = " ".join(line.split())

        if not cleaned_line:
            continue

        starts_event = any(
            pattern.search(cleaned_line)
            for pattern in EVENT_ID_PATTERNS.values()
        )

        if starts_event:
            if current_parts and current_index is not None:
                blocks.append(
                    (current_index, " ".join(current_parts))
                )

            current_index = index
            current_parts = [cleaned_line]
            continue

        if current_parts:
            current_parts.append(cleaned_line)

    if current_parts and current_index is not None:
        blocks.append(
            (current_index, " ".join(current_parts))
        )

    return blocks


def _find_event_blocks(
    event_blocks: list[tuple[int, str]],
    event_ids: tuple[int, ...],
) -> list[tuple[int, str]]:
    return [
        block
        for block in event_blocks
        if any(
            EVENT_ID_PATTERNS[event_id].search(block[1])
            for event_id in event_ids
        )
    ]


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


def _extract_event_identity(
    line: str,
) -> tuple[str | None, str | None]:
    username_candidates = []

    for pattern in USER_PATTERNS:
        for username_match in pattern.finditer(line):
            candidate = (
                username_match.group(1)
                .strip()
                .lower()
            )

            if candidate not in {
                "-",
                "n/a",
                "none",
                "unknown",
            }:
                username_candidates.append(candidate)

    username = (
        username_candidates[-1]
        if username_candidates
        else None
    )

    source_ip_match = SOURCE_IP_PATTERN.search(line)
    source_ip = (
        source_ip_match.group(1)
        if source_ip_match
        else None
    )

    return username, source_ip


def _is_builtin_privileged_account(line: str) -> bool:
    lowercase_line = line.lower()

    return any(
        (
            f"account name: {account}" in lowercase_line
            or f"account name={account}" in lowercase_line
        )
        for account in BUILTIN_PRIVILEGED_ACCOUNTS
    )


def _events_correlate(
    failure_line: str,
    success_line: str,
) -> bool:
    failure_user, failure_ip = (
        _extract_event_identity(failure_line)
    )
    success_user, success_ip = (
        _extract_event_identity(success_line)
    )

    matched_identifier = False

    if failure_user and success_user:
        if failure_user != success_user:
            return False

        matched_identifier = True

    if failure_ip and success_ip:
        if failure_ip != success_ip:
            return False

        matched_identifier = True

    if matched_identifier:
        return True

    identifiers = (
        failure_user,
        failure_ip,
        success_user,
        success_ip,
    )

    return not any(identifiers)


def _find_login_sequence(
    failed_matches: list[tuple[int, str]],
    successful_matches: list[tuple[int, str]],
) -> (
    tuple[
        list[tuple[int, str]],
        tuple[int, str],
    ]
    | None
):
    for success_match in successful_matches:
        success_index, success_line = success_match

        matching_failures = [
            failure_match
            for failure_match in failed_matches
            if (
                failure_match[0] < success_index
                and _events_correlate(
                    failure_match[1],
                    success_line,
                )
            )
        ]

        if len(matching_failures) >= 3:
            return matching_failures[-3:], success_match

    return None


def analyze_log(log_text: str) -> dict:
    lines = log_text.splitlines()
    event_blocks = _build_event_blocks(lines)

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

    account_lockout_matches = _find_event_blocks(
        event_blocks,
        (4740,),
    )

    account_created_matches = _find_event_blocks(
        event_blocks,
        (4720,),
    )

    group_membership_matches = _find_event_blocks(
        event_blocks,
        (4728, 4732),
    )
    privileged_group_matches = [
        match
        for match in group_membership_matches
        if _line_matches(
            match[1],
            terms=PRIVILEGED_GROUP_TERMS,
        )
    ]

    special_privilege_matches = [
        match
        for match in _find_event_blocks(
            event_blocks,
            (4672,),
        )
        if not _is_builtin_privileged_account(match[1])
    ]

    process_creation_matches = _find_event_blocks(
        event_blocks,
        (4688,),
    )

    mshta_matches = [
        match
        for match in process_creation_matches
        if _line_matches(match[1], terms=MSHTA_TERMS)
    ]

    certutil_matches = [
        match
        for match in process_creation_matches
        if (
            _line_matches(match[1], terms=CERTUTIL_TERMS)
            and _line_matches(
                match[1],
                terms=SUSPICIOUS_CERTUTIL_TERMS,
            )
        )
    ]

    wmic_matches = [
        match
        for match in process_creation_matches
        if (
            _line_matches(match[1], terms=WMIC_TERMS)
            and _line_matches(
                match[1],
                terms=SUSPICIOUS_WMIC_TERMS,
            )
        )
    ]

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

    login_sequence = _find_login_sequence(
        failed_matches,
        successful_matches,
    )

    if login_sequence:
        sequence_failures, sequence_success = (
            login_sequence
        )

        combined_matches = (
            sequence_failures[-2:]
            + [sequence_success]
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

    if account_lockout_matches:
        findings.append(
            {
                "type": "Account Lockout",
                "count": len(account_lockout_matches),
                "severity": "Medium",
                "mitre_attack": "T1110 - Brute Force",
                "recommendation": (
                    "Review preceding failed logons, the caller "
                    "computer, source addresses, and whether the "
                    "lockout was expected."
                ),
                "evidence": _create_evidence(
                    account_lockout_matches
                ),
            }
        )

        risk_score += 30
        score_breakdown.append(
            {
                "finding_type": "Account Lockout",
                "points": 30,
                "reason": (
                    "A Windows account lockout event was detected."
                ),
            }
        )

    if account_created_matches:
        findings.append(
            {
                "type": "User Account Created",
                "count": len(account_created_matches),
                "severity": "Medium",
                "mitre_attack": "T1136 - Create Account",
                "recommendation": (
                    "Verify who created the account, confirm the "
                    "business justification, and review its group "
                    "memberships and subsequent activity."
                ),
                "evidence": _create_evidence(
                    account_created_matches
                ),
            }
        )

        risk_score += 30
        score_breakdown.append(
            {
                "finding_type": "User Account Created",
                "points": 30,
                "reason": (
                    "A Windows user account creation event was "
                    "detected."
                ),
            }
        )

    if privileged_group_matches:
        findings.append(
            {
                "type": (
                    "Privileged Group Membership Change"
                ),
                "count": len(privileged_group_matches),
                "severity": "High",
                "mitre_attack": (
                    "T1098.007 - Additional Local or Domain Groups"
                ),
                "recommendation": (
                    "Confirm the membership change was authorized, "
                    "identify the actor and added member, and review "
                    "the account's activity before and after the change."
                ),
                "evidence": _create_evidence(
                    privileged_group_matches
                ),
            }
        )

        risk_score += 40
        score_breakdown.append(
            {
                "finding_type": (
                    "Privileged Group Membership Change"
                ),
                "points": 40,
                "reason": (
                    "A member was added to a recognized privileged "
                    "Windows group."
                ),
            }
        )

    if special_privilege_matches:
        findings.append(
            {
                "type": "Special Privileges Assigned",
                "count": len(special_privilege_matches),
                "severity": "Low",
                "mitre_attack": "T1078 - Valid Accounts",
                "recommendation": (
                    "Confirm the privileged logon was expected and "
                    "review the account, logon type, source system, "
                    "and activity that followed."
                ),
                "evidence": _create_evidence(
                    special_privilege_matches
                ),
            }
        )

        risk_score += 10
        score_breakdown.append(
            {
                "finding_type": (
                    "Special Privileges Assigned"
                ),
                "points": 10,
                "reason": (
                    "Special privileges were assigned to a "
                    "non-system account logon."
                ),
            }
        )

    if mshta_matches:
        findings.append(
            {
                "type": "Suspicious Mshta Execution",
                "count": len(mshta_matches),
                "severity": "High",
                "mitre_attack": "T1218.005 - Mshta",
                "recommendation": (
                    "Review the full command line, parent process, "
                    "referenced HTA or URL, user account, and related "
                    "network or child-process activity."
                ),
                "evidence": _create_evidence(mshta_matches),
            }
        )

        risk_score += 40
        score_breakdown.append(
            {
                "finding_type": (
                    "Suspicious Mshta Execution"
                ),
                "points": 40,
                "reason": (
                    "Mshta execution was detected in a Windows "
                    "process-creation event."
                ),
            }
        )

    if certutil_matches:
        findings.append(
            {
                "type": "Suspicious Certutil Activity",
                "count": len(certutil_matches),
                "severity": "High",
                "mitre_attack": (
                    "T1105 - Ingress Tool Transfer"
                ),
                "recommendation": (
                    "Review the full command line, downloaded or "
                    "decoded file, destination path, parent process, "
                    "user account, and network connections."
                ),
                "evidence": _create_evidence(
                    certutil_matches
                ),
            }
        )

        risk_score += 40
        score_breakdown.append(
            {
                "finding_type": (
                    "Suspicious Certutil Activity"
                ),
                "points": 40,
                "reason": (
                    "Certutil was used with download, encoding, "
                    "or decoding indicators."
                ),
            }
        )

    if wmic_matches:
        findings.append(
            {
                "type": (
                    "Suspicious WMI Process Creation"
                ),
                "count": len(wmic_matches),
                "severity": "High",
                "mitre_attack": (
                    "T1047 - Windows Management Instrumentation"
                ),
                "recommendation": (
                    "Review the WMIC command, target host, created "
                    "process, parent process, user account, and any "
                    "related remote execution activity."
                ),
                "evidence": _create_evidence(wmic_matches),
            }
        )

        risk_score += 35
        score_breakdown.append(
            {
                "finding_type": (
                    "Suspicious WMI Process Creation"
                ),
                "points": 35,
                "reason": (
                    "WMIC process creation or remote execution "
                    "indicators were detected."
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

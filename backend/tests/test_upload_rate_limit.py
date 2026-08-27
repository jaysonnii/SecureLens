import pytest
from fastapi.testclient import TestClient

import app.routers.uploads as uploads
from app.main import create_app


LOG_CONTENT = b"Failed login for administrator\n"


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(uploads, "RATE_LIMIT_ENABLED", True)
    monkeypatch.setattr(uploads, "RATE_LIMIT_MAX_REQUESTS", 2)
    monkeypatch.setattr(uploads, "RATE_LIMIT_WINDOW_SECONDS", 60)
    monkeypatch.setattr(uploads, "TRUST_PROXY_HEADERS", False)
    uploads.reset_rate_limiter()
    yield TestClient(create_app())
    uploads.reset_rate_limiter()


def _upload(client, **kwargs):
    return client.post(
        "/upload",
        files={"file": ("security.log", LOG_CONTENT, "text/plain")},
        **kwargs,
    )


def test_requests_within_the_limit_are_allowed(client):
    assert _upload(client).status_code == 200
    assert _upload(client).status_code == 200


def test_request_past_the_limit_is_rejected_with_429(client):
    _upload(client)
    _upload(client)

    response = _upload(client)

    assert response.status_code == 429
    assert "Retry-After" in response.headers
    assert "seconds" in response.json()["detail"]


def test_health_endpoint_is_not_rate_limited(client):
    _upload(client)
    _upload(client)
    _upload(client)

    assert client.get("/health").status_code == 200


def test_disabling_the_limit_allows_unlimited_requests(client, monkeypatch):
    monkeypatch.setattr(uploads, "RATE_LIMIT_ENABLED", False)
    uploads.reset_rate_limiter()

    for _ in range(5):
        assert _upload(client).status_code == 200


def test_trusted_proxy_uses_x_real_ip_for_separate_buckets(client, monkeypatch):
    monkeypatch.setattr(uploads, "TRUST_PROXY_HEADERS", True)
    uploads.reset_rate_limiter()

    assert _upload(client, headers={"X-Real-IP": "10.0.0.1"}).status_code == 200
    assert _upload(client, headers={"X-Real-IP": "10.0.0.1"}).status_code == 200
    assert _upload(client, headers={"X-Real-IP": "10.0.0.2"}).status_code == 200

    blocked = _upload(client, headers={"X-Real-IP": "10.0.0.1"})
    assert blocked.status_code == 429


def test_client_supplied_forwarded_for_is_ignored_without_x_real_ip(client, monkeypatch):
    monkeypatch.setattr(uploads, "TRUST_PROXY_HEADERS", True)
    uploads.reset_rate_limiter()

    for spoofed in ("1.1.1.1", "2.2.2.2", "3.3.3.3"):
        _upload(client, headers={"X-Forwarded-For": spoofed})

    blocked = _upload(client, headers={"X-Forwarded-For": "4.4.4.4"})
    assert blocked.status_code == 429

from fastapi.testclient import TestClient

import app.config as config
import app.main as main_module


def test_boolean_environment_parser(monkeypatch):
    monkeypatch.setenv(
        "SECURELENS_TEST_FLAG",
        "yes",
    )

    assert config._get_bool_env(
        "SECURELENS_TEST_FLAG"
    ) is True

    monkeypatch.setenv(
        "SECURELENS_TEST_FLAG",
        "false",
    )

    assert config._get_bool_env(
        "SECURELENS_TEST_FLAG",
        default=True,
    ) is False


def test_integer_environment_parser(monkeypatch):
    monkeypatch.setenv(
        "SECURELENS_TEST_INTEGER",
        "50",
    )

    assert config._get_int_env(
        "SECURELENS_TEST_INTEGER",
        default=25,
        minimum=1,
        maximum=100,
    ) == 50

    monkeypatch.setenv(
        "SECURELENS_TEST_INTEGER",
        "not-a-number",
    )

    assert config._get_int_env(
        "SECURELENS_TEST_INTEGER",
        default=25,
        minimum=1,
        maximum=100,
    ) == 25

    monkeypatch.setenv(
        "SECURELENS_TEST_INTEGER",
        "500",
    )

    assert config._get_int_env(
        "SECURELENS_TEST_INTEGER",
        default=25,
        minimum=1,
        maximum=100,
    ) == 100


def test_csv_environment_parser(monkeypatch):
    monkeypatch.setenv(
        "SECURELENS_TEST_LIST",
        " first.example,second.example ,, ",
    )

    assert config._get_csv_env(
        "SECURELENS_TEST_LIST"
    ) == [
        "first.example",
        "second.example",
    ]


def test_cors_allows_configured_origin(monkeypatch):
    allowed_origin = "https://securelens.example"

    monkeypatch.setattr(
        main_module,
        "CORS_ORIGINS",
        [allowed_origin],
    )

    client = TestClient(
        main_module.create_app()
    )

    response = client.options(
        "/upload",
        headers={
            "Origin": allowed_origin,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": (
                "content-type"
            ),
        },
    )

    assert response.status_code == 200

    assert response.headers[
        "access-control-allow-origin"
    ] == allowed_origin


def test_cors_rejects_unconfigured_origin(
    monkeypatch,
):
    monkeypatch.setattr(
        main_module,
        "CORS_ORIGINS",
        ["https://securelens.example"],
    )

    client = TestClient(
        main_module.create_app()
    )

    response = client.options(
        "/upload",
        headers={
            "Origin": "https://untrusted.example",
            "Access-Control-Request-Method": "POST",
        },
    )

    assert (
        response.headers.get(
            "access-control-allow-origin"
        )
        is None
    )


def test_api_documentation_can_be_disabled(
    monkeypatch,
):
    monkeypatch.setattr(
        main_module,
        "API_DOCS_ENABLED",
        False,
    )

    client = TestClient(
        main_module.create_app()
    )

    assert client.get("/docs").status_code == 404

    assert (
        client.get("/openapi.json").status_code
        == 404
    )

    assert client.get("/health").status_code == 200

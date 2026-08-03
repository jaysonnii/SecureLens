import os
from pathlib import Path

from dotenv import load_dotenv


BACKEND_DIR = Path(__file__).resolve().parents[1]

load_dotenv(BACKEND_DIR / ".env")


TRUE_VALUES = {
    "1",
    "true",
    "yes",
    "on",
}

DEFAULT_DEVELOPMENT_CORS_ORIGINS = (
    "http://localhost:5173",
    "http://127.0.0.1:5173",
)


def _get_bool_env(
    name: str,
    default: bool = False,
) -> bool:
    raw_value = os.getenv(name)

    if raw_value is None:
        return default

    return raw_value.strip().lower() in TRUE_VALUES


def _get_int_env(
    name: str,
    default: int,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    raw_value = os.getenv(name)

    if raw_value is None or not raw_value.strip():
        value = default
    else:
        try:
            value = int(raw_value)
        except ValueError:
            value = default

    if minimum is not None:
        value = max(value, minimum)

    if maximum is not None:
        value = min(value, maximum)

    return value


def _get_csv_env(
    name: str,
    default: tuple[str, ...] = (),
) -> list[str]:
    raw_value = os.getenv(name)

    if raw_value is None or not raw_value.strip():
        return list(default)

    return [
        value.strip()
        for value in raw_value.split(",")
        if value.strip()
    ]


APP_NAME = "SecureLens API"
APP_DESCRIPTION = "Backend API for analyzing security logs."
APP_VERSION = "0.3.0"

APP_ENV = os.getenv(
    "APP_ENV",
    "development",
).strip().lower()

IS_PRODUCTION = APP_ENV == "production"

API_DOCS_ENABLED = _get_bool_env(
    "API_DOCS_ENABLED",
    default=not IS_PRODUCTION,
)

CORS_ORIGINS = [
    origin.rstrip("/")
    for origin in _get_csv_env(
        "CORS_ORIGINS",
        default=(
            ()
            if IS_PRODUCTION
            else DEFAULT_DEVELOPMENT_CORS_ORIGINS
        ),
    )
]

MAX_FILE_SIZE_MB = _get_int_env(
    "MAX_FILE_SIZE_MB",
    default=25,
    minimum=1,
    maximum=100,
)

MAX_FILE_SIZE = MAX_FILE_SIZE_MB * 1024 * 1024

ALLOWED_EXTENSIONS = {
    ".txt",
    ".log",
    ".csv",
    ".json",
}

OPENAI_API_KEY = os.getenv(
    "OPENAI_API_KEY",
    "",
).strip()

OPENAI_MODEL = os.getenv(
    "OPENAI_MODEL",
    "gpt-5-mini",
).strip()

AI_SUMMARY_ENABLED = _get_bool_env(
    "AI_SUMMARY_ENABLED",
    default=False,
)

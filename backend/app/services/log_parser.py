from __future__ import annotations

import csv
import io
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


WINDOWS_DATE_PATTERN = re.compile(
    r"^/Date\((?P<milliseconds>-?\d+)(?:[+-]\d{4})?\)/$"
)

TIME_KEYS = {
    "timecreated",
    "timestamp",
    "eventtime",
    "datetime",
    "time",
    "date",
}

EVENT_ID_KEYS = {
    "id",
    "eventid",
    "eventcode",
}

MESSAGE_KEYS = {
    "message",
    "rendereddescription",
    "description",
}

PROVIDER_KEYS = {
    "providername",
    "provider",
    "source",
}

LEVEL_KEYS = {
    "leveldisplayname",
    "level",
    "severity",
}


class LogParseError(ValueError):
    """Raised when a structured log cannot be parsed safely."""


@dataclass(frozen=True)
class ParsedLog:
    analysis_text: str
    input_format: str
    record_count: int


def _normalized_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def _find_item(
    record: dict[str, Any],
    aliases: set[str],
) -> tuple[str, Any] | None:
    for key, value in record.items():
        if _normalized_key(str(key)) in aliases:
            return str(key), value

    return None


def _clean_value(value: Any) -> str:
    if value is None:
        return ""

    if isinstance(value, (dict, list)):
        text = json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
        )
    else:
        text = str(value)

    return " ".join(text.split())


def _humanize_key(value: str) -> str:
    separated = re.sub(
        r"(?<=[a-z0-9])(?=[A-Z])",
        " ",
        value,
    )
    separated = re.sub(r"[_-]+", " ", separated)
    return " ".join(separated.split())


def _parse_timestamp(value: Any) -> datetime | None:
    if value is None:
        return None

    if isinstance(value, (int, float)):
        seconds = (
            value / 1000
            if abs(value) >= 100_000_000_000
            else value
        )

        try:
            return datetime.fromtimestamp(
                seconds,
                tz=timezone.utc,
            )
        except (OSError, OverflowError, ValueError):
            return None

    text = str(value).strip()

    windows_match = WINDOWS_DATE_PATTERN.fullmatch(text)

    if windows_match:
        milliseconds = int(
            windows_match.group("milliseconds")
        )

        try:
            return datetime.fromtimestamp(
                milliseconds / 1000,
                tz=timezone.utc,
            )
        except (OSError, OverflowError, ValueError):
            return None

    try:
        parsed = datetime.fromisoformat(
            text.replace("Z", "+00:00")
        )
    except ValueError:
        return None

    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def _record_timestamp(
    record: dict[str, Any],
) -> datetime | None:
    item = _find_item(record, TIME_KEYS)

    if item is None:
        return None

    return _parse_timestamp(item[1])


def _sort_records(
    records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    timestamps = [
        _record_timestamp(record)
        for record in records
    ]

    if not records or any(
        timestamp is None
        for timestamp in timestamps
    ):
        return records

    indexed_records = list(enumerate(records))

    indexed_records.sort(
        key=lambda item: (
            timestamps[item[0]],
            item[0],
        )
    )

    return [
        record
        for _, record in indexed_records
    ]


def _record_to_line(
    record: dict[str, Any],
) -> str:
    parts: list[str] = []
    consumed_keys: set[str] = set()

    field_specs = (
        (TIME_KEYS, None),
        (EVENT_ID_KEYS, "Event ID"),
        (PROVIDER_KEYS, "Provider"),
        (LEVEL_KEYS, "Level"),
    )

    for aliases, output_label in field_specs:
        item = _find_item(record, aliases)

        if item is None:
            continue

        key, value = item
        cleaned_value = _clean_value(value)

        if not cleaned_value:
            continue

        consumed_keys.add(key)

        if output_label is None:
            parts.append(cleaned_value)
        else:
            parts.append(
                f"{output_label}: {cleaned_value}"
            )

    message_item = _find_item(record, MESSAGE_KEYS)

    if message_item is not None:
        consumed_keys.add(message_item[0])

    for key, value in record.items():
        key_text = str(key)

        if key_text in consumed_keys:
            continue

        cleaned_value = _clean_value(value)

        if cleaned_value:
            parts.append(
                f"{_humanize_key(key_text)}: "
                f"{cleaned_value}"
            )

    if message_item is not None:
        message = _clean_value(message_item[1])

        if message:
            parts.append(message)

    return " ".join(parts)


def _validate_records(
    records: list[Any],
    source_name: str,
) -> list[dict[str, Any]]:
    if not records:
        raise LogParseError(
            f"The {source_name} file does not contain any records."
        )

    if not all(
        isinstance(record, dict)
        for record in records
    ):
        raise LogParseError(
            f"Each {source_name} record must be an object "
            "with named fields."
        )

    return records


def _records_from_json_payload(
    payload: Any,
) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return _validate_records(payload, "JSON")

    if isinstance(payload, dict):
        for key in ("events", "records", "items", "value"):
            candidate = payload.get(key)

            if isinstance(candidate, list):
                return _validate_records(
                    candidate,
                    "JSON",
                )

        return [payload]

    raise LogParseError(
        "The JSON file must contain an object, "
        "an array of objects, or JSON Lines."
    )


def _parse_json_records(
    text: str,
) -> list[dict[str, Any]]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        records: list[Any] = []

        for line_number, line in enumerate(
            text.splitlines(),
            start=1,
        ):
            stripped_line = line.strip()

            if not stripped_line:
                continue

            try:
                records.append(
                    json.loads(stripped_line)
                )
            except json.JSONDecodeError as error:
                raise LogParseError(
                    "The JSON file is invalid near "
                    f"line {line_number}."
                ) from error

        return _validate_records(records, "JSON")

    return _records_from_json_payload(payload)


def _parse_csv_records(
    text: str,
) -> list[dict[str, Any]]:
    try:
        reader = csv.DictReader(io.StringIO(text))
        fieldnames = reader.fieldnames
        records = [
            {
                str(key): value
                for key, value in row.items()
                if key is not None
            }
            for row in reader
        ]
    except csv.Error as error:
        raise LogParseError(
            "The CSV file could not be parsed."
        ) from error

    if not fieldnames:
        raise LogParseError(
            "The CSV file must include a header row."
        )

    return _validate_records(records, "CSV")


def parse_log_content(
    text: str,
    extension: str,
) -> ParsedLog:
    cleaned_text = text.lstrip("\ufeff")
    normalized_extension = extension.lower()

    if normalized_extension == ".json":
        records = _parse_json_records(cleaned_text)
        input_format = "json"
    elif normalized_extension == ".csv":
        records = _parse_csv_records(cleaned_text)
        input_format = "csv"
    else:
        nonempty_lines = [
            line
            for line in cleaned_text.splitlines()
            if line.strip()
        ]

        return ParsedLog(
            analysis_text=cleaned_text,
            input_format="text",
            record_count=len(nonempty_lines),
        )

    sorted_records = _sort_records(records)
    normalized_lines = [
        _record_to_line(record)
        for record in sorted_records
    ]
    normalized_lines = [
        line
        for line in normalized_lines
        if line
    ]

    if not normalized_lines:
        raise LogParseError(
            "The structured log does not contain "
            "analyzable fields."
        )

    return ParsedLog(
        analysis_text="\n".join(normalized_lines),
        input_format=input_format,
        record_count=len(normalized_lines),
    )

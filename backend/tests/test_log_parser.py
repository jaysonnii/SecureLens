import json

import pytest

from app.services.log_parser import (
    LogParseError,
    parse_log_content,
)


def test_windows_json_array_is_sorted_and_normalized():
    records = [
        {
            "TimeCreated": "/Date(2000)/",
            "Id": 4624,
            "ProviderName": (
                "Microsoft-Windows-Security-Auditing"
            ),
            "Message": (
                "An account was successfully logged on. "
                "Account Name: alice "
                "Source Network Address: 10.0.0.10"
            ),
        },
        {
            "TimeCreated": "/Date(1000)/",
            "Id": 4625,
            "ProviderName": (
                "Microsoft-Windows-Security-Auditing"
            ),
            "Message": (
                "An account failed to log on. "
                "Account Name: alice "
                "Source Network Address: 10.0.0.10"
            ),
        },
    ]

    parsed = parse_log_content(
        "\ufeff" + json.dumps(records),
        ".json",
    )

    lines = parsed.analysis_text.splitlines()

    assert parsed.input_format == "json"
    assert parsed.record_count == 2
    assert "Event ID: 4625" in lines[0]
    assert "Event ID: 4624" in lines[1]
    assert "Source Network Address: 10.0.0.10" in lines[0]


def test_json_lines_are_supported():
    text = "\n".join(
        [
            json.dumps(
                {
                    "timestamp": "2026-08-02T10:00:00Z",
                    "event_id": 4625,
                    "message": "Failed login for user alice",
                }
            ),
            json.dumps(
                {
                    "timestamp": "2026-08-02T10:01:00Z",
                    "event_id": 4624,
                    "message": "Successful login for user alice",
                }
            ),
        ]
    )

    parsed = parse_log_content(text, ".json")

    assert parsed.record_count == 2
    assert "Event ID: 4625" in parsed.analysis_text
    assert "Event ID: 4624" in parsed.analysis_text


def test_nested_json_records_are_supported():
    parsed = parse_log_content(
        json.dumps(
            {
                "events": [
                    {
                        "EventId": 4104,
                        "Message": (
                            "PowerShell.exe "
                            "-EncodedCommand AAAA"
                        ),
                    }
                ]
            }
        ),
        ".json",
    )

    assert parsed.record_count == 1
    assert "Event ID: 4104" in parsed.analysis_text
    assert "-EncodedCommand" in parsed.analysis_text


def test_csv_records_are_normalized():
    text = (
        "TimeCreated,EventId,SourceIp,Message\n"
        "2026-08-02T10:00:00Z,4625,10.0.0.10,"
        "\"Failed login for user alice\"\n"
    )

    parsed = parse_log_content(text, ".csv")

    assert parsed.input_format == "csv"
    assert parsed.record_count == 1
    assert "Event ID: 4625" in parsed.analysis_text
    assert "Source Ip: 10.0.0.10" in parsed.analysis_text


def test_plain_text_preserves_content_and_counts_lines():
    parsed = parse_log_content(
        "first event\n\nsecond event\n",
        ".log",
    )

    assert parsed.input_format == "text"
    assert parsed.record_count == 2
    assert parsed.analysis_text == (
        "first event\n\nsecond event\n"
    )


def test_invalid_json_raises_safe_error():
    with pytest.raises(
        LogParseError,
        match="invalid near line",
    ):
        parse_log_content(
            '{"Id": 4625\nnot-json',
            ".json",
        )


def test_json_array_requires_object_records():
    with pytest.raises(
        LogParseError,
        match="must be an object",
    ):
        parse_log_content(
            json.dumps([4625, 4624]),
            ".json",
        )

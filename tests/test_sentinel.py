import csv
import gzip
import io
import json
from unittest.mock import patch, MagicMock
import pytest

from sentinel.loader import parse_cloudtrail_bytes, load_from_local, load_from_s3
from sentinel.rules import (
    detect_root_usage,
    detect_console_login_without_mfa,
    detect_brute_force,
    detect_logging_tampering,
    run_all_rules,
)
from sentinel.reporter import export_json, export_csv
from sentinel.cli import main


# --- Loader Tests ---

def test_parse_valid_records_dict():
    raw = json.dumps({"Records": [{"eventName": "ListBuckets"}]}).encode("utf-8")
    events = parse_cloudtrail_bytes(raw)
    assert len(events) == 1
    assert events[0]["eventName"] == "ListBuckets"


def test_parse_valid_records_list():
    raw = json.dumps([{"eventName": "GetObject"}]).encode("utf-8")
    events = parse_cloudtrail_bytes(raw)
    assert len(events) == 1


def test_parse_gzipped_logs():
    raw = gzip.compress(json.dumps({"Records": [{"eventName": "PutObject"}]}).encode("utf-8"))
    events = parse_cloudtrail_bytes(raw, is_gzipped=True)
    assert len(events) == 1
    assert events[0]["eventName"] == "PutObject"


def test_parse_invalid_format_raises():
    raw = json.dumps({"UnexpectedKey": []}).encode("utf-8")
    with pytest.raises(ValueError, match="Invalid CloudTrail log format"):
        parse_cloudtrail_bytes(raw)


def test_load_from_local_sample():
    events = load_from_local("tests/sample_logs.json")
    assert len(events) == 7


def test_load_from_local_missing_file():
    with pytest.raises(FileNotFoundError):
        load_from_local("tests/nonexistent_file.json")


@patch("sentinel.loader.boto3.client")
def test_load_from_s3_success(mock_boto_client):
    mock_s3 = MagicMock()
    mock_boto_client.return_value = mock_s3

    mock_paginator = MagicMock()
    mock_s3.get_paginator.return_value = mock_paginator
    mock_paginator.paginate.return_value = [
        {
            "Contents": [
                {"Key": "AWSLogs/123456789012/CloudTrail/log1.json"},
                {"Key": "AWSLogs/123456789012/CloudTrail/log2.json.gz"},
                {"Key": "AWSLogs/123456789012/CloudTrail/ignore.txt"},
            ]
        }
    ]

    plain_payload = json.dumps({"Records": [{"eventName": "ConsoleLogin"}]}).encode("utf-8")
    gz_payload = gzip.compress(json.dumps({"Records": [{"eventName": "StopLogging"}]}).encode("utf-8"))

    mock_s3.get_object.side_effect = [
        {"Body": io.BytesIO(plain_payload)},
        {"Body": io.BytesIO(gz_payload)},
    ]

    events = load_from_s3("my-security-bucket", prefix="AWSLogs/")
    assert len(events) == 2
    assert events[0]["eventName"] == "ConsoleLogin"
    assert events[1]["eventName"] == "StopLogging"


# --- Detection Rule Tests ---

def test_detect_root_usage_triggers():
    events = [{"userIdentity": {"type": "Root", "arn": "arn:aws:iam::111:root"}, "eventName": "CreateUser", "eventType": "AwsApiCall"}]
    findings = detect_root_usage(events)
    assert len(findings) == 1
    assert findings[0].rule_id == "CT-001"
    assert findings[0].severity == "CRITICAL"


def test_detect_root_usage_ignores_aws_service_event():
    events = [{"userIdentity": {"type": "Root"}, "eventName": "Decrypt", "eventType": "AwsServiceEvent"}]
    assert detect_root_usage(events) == []


def test_detect_login_without_mfa_triggers():
    events = [{
        "eventName": "ConsoleLogin",
        "userIdentity": {"userName": "alice"},
        "responseElements": {"ConsoleLogin": "Success"},
        "additionalEventData": {"MFAUsed": "No"},
    }]
    findings = detect_console_login_without_mfa(events)
    assert len(findings) == 1
    assert findings[0].rule_id == "CT-002"
    assert findings[0].actor == "alice"


def test_detect_login_with_mfa_ignored():
    events = [{
        "eventName": "ConsoleLogin",
        "userIdentity": {"userName": "alice"},
        "responseElements": {"ConsoleLogin": "Success"},
        "additionalEventData": {"MFAUsed": "Yes"},
    }]
    assert detect_console_login_without_mfa(events) == []


def test_detect_brute_force_triggers_at_threshold():
    events = [
        {"eventName": "ConsoleLogin", "sourceIPAddress": "1.2.3.4", "responseElements": {"ConsoleLogin": "Failure"}},
        {"eventName": "ConsoleLogin", "sourceIPAddress": "1.2.3.4", "responseElements": {"ConsoleLogin": "Failure"}},
        {"errorCode": "AccessDenied", "sourceIPAddress": "1.2.3.4"},
    ]
    findings = detect_brute_force(events, threshold=3)
    assert len(findings) == 1
    assert findings[0].rule_id == "CT-003"
    assert findings[0].source_ip == "1.2.3.4"


def test_detect_brute_force_below_threshold():
    events = [
        {"eventName": "ConsoleLogin", "sourceIPAddress": "1.2.3.4", "responseElements": {"ConsoleLogin": "Failure"}},
        {"eventName": "ConsoleLogin", "sourceIPAddress": "1.2.3.4", "responseElements": {"ConsoleLogin": "Failure"}},
    ]
    assert detect_brute_force(events, threshold=3) == []


@pytest.mark.parametrize("action", ["StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors"])
def test_detect_logging_tampering_all_actions(action):
    events = [{"eventName": action, "userIdentity": {"userName": "mallory"}, "requestParameters": {"name": "prod-trail"}}]
    findings = detect_logging_tampering(events)
    assert len(findings) == 1
    assert findings[0].rule_id == "CT-004"
    assert findings[0].severity == "CRITICAL"


def test_run_all_rules_sorts_by_severity():
    events = load_from_local("tests/sample_logs.json")
    findings = run_all_rules(events)
    assert len(findings) == 4
    assert findings[0].severity == "CRITICAL"
    assert findings[1].severity == "CRITICAL"
    assert findings[2].severity == "HIGH"
    assert findings[3].severity == "HIGH"


# --- Reporter & CLI Tests ---

def test_export_json_and_csv(tmp_path):
    events = load_from_local("tests/sample_logs.json")
    findings = run_all_rules(events)

    json_file = tmp_path / "out.json"
    export_json(findings, str(json_file))
    loaded_json = json.loads(json_file.read_text(encoding="utf-8"))
    assert len(loaded_json) == 4

    csv_file = tmp_path / "out.csv"
    export_csv(findings, str(csv_file))
    with open(csv_file, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == 4


def test_cli_table_execution(capsys):
    exit_code = main(["--file", "tests/sample_logs.json", "--format", "table"])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "CT-001" in captured.out
    assert "CT-004" in captured.out


def test_cli_missing_file_returns_error(capsys):
    exit_code = main(["--file", "does_not_exist.json"])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Error loading logs" in captured.err

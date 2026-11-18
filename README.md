# CloudTrail Sentinel

**CloudTrail Sentinel** is a lightweight, modular Python CLI threat detection engine built to ingest and analyze AWS CloudTrail logs for high-risk security events, privilege misuse, and logging tampering.

## Key Features

* **Flexible Log Ingestion (`boto3` & Local):** Parses plain `.json` and compressed `.json.gz` CloudTrail logs from local file paths or directly from AWS S3 buckets using paginated `boto3` streams.
* **Rule-Based Threat Detection Engine:** Evaluates CloudTrail API activity against modular security rules with severity scoring (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) and actionable remediation steps:
  * **CT-001 (CRITICAL):** Root Account Activity Detection
  * **CT-002 (HIGH):** AWS Management Console Login Without MFA
  * **CT-003 (HIGH):** Potential Brute-Force or API Enumeration Spikes
  * **CT-004 (CRITICAL):** CloudTrail Logging Tampering (`StopLogging`, `DeleteTrail`, `UpdateTrail`, `PutEventSelectors`)
* **Multi-Format Reporting:** Outputs color-coded terminal tables via `rich`, or exports structured `JSON` and `CSV` reports for SIEM ingestion and incident response workflows.
* **Automated Test Suite:** Includes 21 unit and integration tests built with `pytest` and `unittest.mock` covering log parsing, rule accuracy, CLI flags, and mocked S3 bucket ingestion.

## Project Architecture

```text
cloudtrail-sentinel/
├── sentinel/
│   ├── __init__.py
│   ├── cli.py           # CLI argument parsing and workflow orchestration
│   ├── loader.py        # Local and AWS S3 (boto3) log ingestion
│   ├── rules.py         # Threat detection rules, severity ranking, and remediation
│   └── reporter.py      # Rich CLI table, JSON, and CSV report exporters
├── tests/
│   ├── sample_logs.json # Sample AWS CloudTrail dataset
│   └── test_sentinel.py # Automated pytest suite (21 tests)
├── pyproject.toml
├── requirements.txt
└── README.md
```

## Quick Start

### 1. Clone and Set Up Environment
```bash
git clone https://github.com<your-username>/cloudtrail-sentinel.git
cd cloudtrail-sentinel
python -m venv venv
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Run a Security Scan
Scan a local CloudTrail log file and display a terminal report:
```bash
python -m sentinel.cli --file tests/sample_logs.json
```

Export findings to JSON or CSV:
```bash
python -m sentinel.cli --file tests/sample_logs.json --format json --output findings.json
python -m sentinel.cli --file tests/sample_logs.json --format csv --output findings.csv
```

Scan logs directly from an AWS S3 bucket (requires configured AWS credentials):
```bash
python -m sentinel.cli --s3-bucket my-cloudtrail-logs-bucket --s3-prefix AWSLogs/
```

### 3. Run the Test Suite
```bash
pytest -v
```

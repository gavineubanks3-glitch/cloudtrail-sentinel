import gzip
import json
from pathlib import Path
from typing import List, Dict, Any
import boto3


def parse_cloudtrail_bytes(raw_bytes: bytes, is_gzipped: bool = False) -> List[Dict[str, Any]]:
    if is_gzipped:
        raw_bytes = gzip.decompress(raw_bytes)
    payload = json.loads(raw_bytes.decode("utf-8"))
    if isinstance(payload, dict) and "Records" in payload:
        return payload["Records"]
    if isinstance(payload, list):
        return payload
    raise ValueError("Invalid CloudTrail log format: expected 'Records' key or list of events.")


def load_from_local(file_path: str) -> List[Dict[str, Any]]:
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {file_path}")
    is_gzipped = path.suffix == ".gz"
    return parse_cloudtrail_bytes(path.read_bytes(), is_gzipped=is_gzipped)


def load_from_s3(bucket: str, prefix: str = "") -> List[Dict[str, Any]]:
    s3_client = boto3.client("s3")
    paginator = s3_client.get_paginator("list_objects_v2")
    events: List[Dict[str, Any]] = []

    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            if key.endswith(".json") or key.endswith(".json.gz"):
                response = s3_client.get_object(Bucket=bucket, Key=key)
                raw_bytes = response["Body"].read()
                events.extend(parse_cloudtrail_bytes(raw_bytes, is_gzipped=key.endswith(".gz")))

    return events

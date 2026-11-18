import argparse
import sys
from sentinel.loader import load_from_local, load_from_s3
from sentinel.rules import run_all_rules
from sentinel.reporter import print_table_report, export_json, export_csv


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="cloudtrail-sentinel",
        description="Analyze AWS CloudTrail logs for security threats.",
    )
    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument("--file", help="Path to a local CloudTrail .json or .json.gz file")
    source_group.add_argument("--s3-bucket", help="AWS S3 bucket name containing CloudTrail logs")

    parser.add_argument("--s3-prefix", default="", help="Optional S3 key prefix (folder path)")
    parser.add_argument("--format", choices=["table", "json", "csv"], default="table", help="Output format")
    parser.add_argument("--output", help="Output file path when using json or csv format")
    parser.add_argument("--threshold", type=int, default=3, help="Failed attempts threshold for brute-force rule")

    args = parser.parse_args(argv)

    try:
        if args.file:
            events = load_from_local(args.file)
        else:
            events = load_from_s3(args.s3_bucket, args.s3_prefix)
    except Exception as exc:
        print(f"Error loading logs: {exc}", file=sys.stderr)
        return 1

    findings = run_all_rules(events, brute_force_threshold=args.threshold)

    if args.format == "table":
        print_table_report(findings)
    elif args.format == "json":
        out_file = args.output or "findings.json"
        export_json(findings, out_file)
        print(f"Exported {len(findings)} findings to {out_file}")
    elif args.format == "csv":
        out_file = args.output or "findings.csv"
        export_csv(findings, out_file)
        print(f"Exported {len(findings)} findings to {out_file}")

    return 0


if __name__ == "__main__":
    sys.exit(main())

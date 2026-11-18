import csv
import json
from pathlib import Path
from typing import List
from rich.console import Console
from rich.table import Table
from sentinel.rules import Finding


def print_table_report(findings: List[Finding]) -> None:
    console = Console()
    if not findings:
        console.print("[bold green]No suspicious CloudTrail activity detected.[/bold green]")
        return

    table = Table(title="CloudTrail Sentinel - Security Findings", show_lines=True)
    table.add_column("Rule ID", style="cyan", no_wrap=True)
    table.add_column("Severity", style="bold")
    table.add_column("Title", style="white")
    table.add_column("Actor", style="magenta")
    table.add_column("Source IP", style="yellow")
    table.add_column("Details & Remediation", style="white")

    severity_colors = {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "blue",
    }

    for f in findings:
        sev_style = severity_colors.get(f.severity, "white")
        combined_info = f"{f.details}\n[dim]Fix: {f.remediation}[/dim]"
        table.add_row(
            f.rule_id,
            f"[{sev_style}]{f.severity}[/{sev_style}]",
            f.title,
            f.actor,
            f.source_ip,
            combined_info,
        )

    console.print(table)


def export_json(findings: List[Finding], output_path: str) -> None:
    data = [f.to_dict() for f in findings]
    Path(output_path).write_text(json.dumps(data, indent=2), encoding="utf-8")


def export_csv(findings: List[Finding], output_path: str) -> None:
    fieldnames = ["rule_id", "title", "severity", "event_time", "actor", "source_ip", "details", "remediation"]
    with open(output_path, mode="w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        for f in findings:
            writer.writerow(f.to_dict())

from dataclasses import dataclass, asdict
from typing import List, Dict, Any
from collections import defaultdict


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    event_time: str
    actor: str
    source_ip: str
    details: str
    remediation: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def detect_root_usage(events: List[Dict[str, Any]]) -> List[Finding]:
    findings = []
    for event in events:
        identity = event.get("userIdentity", {})
        if identity.get("type") == "Root" and event.get("eventType") != "AwsServiceEvent":
            findings.append(
                Finding(
                    rule_id="CT-001",
                    title="Root Account Activity Detected",
                    severity="CRITICAL",
                    event_time=event.get("eventTime", "Unknown"),
                    actor=identity.get("arn", "Root"),
                    source_ip=event.get("sourceIPAddress", "Unknown"),
                    details=f"Root user executed '{event.get('eventName')}' in {event.get('awsRegion', 'unknown region')}.",
                    remediation="Enforce hardware MFA on the root account, lock away credentials, and use least-privilege IAM roles for daily operations.",
                )
            )
    return findings


def detect_console_login_without_mfa(events: List[Dict[str, Any]]) -> List[Finding]:
    findings = []
    for event in events:
        if event.get("eventName") == "ConsoleLogin":
            response_elements = event.get("responseElements", {})
            additional_data = event.get("additionalEventData", {})
            login_status = response_elements.get("ConsoleLogin")
            mfa_used = additional_data.get("MFAUsed")

            if login_status == "Success" and mfa_used == "No":
                identity = event.get("userIdentity", {})
                actor = identity.get("userName") or identity.get("arn", "Unknown")
                findings.append(
                    Finding(
                        rule_id="CT-002",
                        title="AWS Console Login Without MFA",
                        severity="HIGH",
                        event_time=event.get("eventTime", "Unknown"),
                        actor=actor,
                        source_ip=event.get("sourceIPAddress", "Unknown"),
                        details="User successfully authenticated to the AWS Management Console without Multi-Factor Authentication.",
                        remediation="Enable virtual or hardware MFA for the IAM user and enforce an IAM policy denying actions when aws:MultiFactorAuthPresent is false.",
                    )
                )
    return findings


def detect_brute_force(events: List[Dict[str, Any]], threshold: int = 3) -> List[Finding]:
    findings = []
    failed_attempts_by_ip = defaultdict(list)

    for event in events:
        is_failed_login = (
            event.get("eventName") == "ConsoleLogin"
            and event.get("responseElements", {}).get("ConsoleLogin") == "Failure"
        )
        is_access_denied = event.get("errorCode") in {"AccessDenied", "UnauthorizedOperation", "Client.UnauthorizedOperation"}

        if is_failed_login or is_access_denied:
            ip = event.get("sourceIPAddress", "Unknown")
            failed_attempts_by_ip[ip].append(event)

    for ip, failed_events in failed_attempts_by_ip.items():
        if len(failed_events) >= threshold:
            first_event = failed_events[0]
            identity = first_event.get("userIdentity", {})
            actor = identity.get("userName") or identity.get("arn", "Unknown")
            findings.append(
                Finding(
                    rule_id="CT-003",
                    title="Potential Brute-Force or Enumeration Spike",
                    severity="HIGH",
                    event_time=first_event.get("eventTime", "Unknown"),
                    actor=actor,
                    source_ip=ip,
                    details=f"Detected {len(failed_events)} failed login or unauthorized API calls from IP {ip}.",
                    remediation="Investigate the source IP, block malicious traffic via AWS WAF or Network ACLs, and rotate compromised IAM credentials.",
                )
            )
    return findings


def detect_logging_tampering(events: List[Dict[str, Any]]) -> List[Finding]:
    tamper_actions = {"StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors"}
    findings = []

    for event in events:
        event_name = event.get("eventName")
        if event_name in tamper_actions:
            identity = event.get("userIdentity", {})
            actor = identity.get("userName") or identity.get("arn", "Unknown")
            trail_name = event.get("requestParameters", {}).get("name", "Unknown Trail")
            findings.append(
                Finding(
                    rule_id="CT-004",
                    title="CloudTrail Logging Tampering Detected",
                    severity="CRITICAL",
                    event_time=event.get("eventTime", "Unknown"),
                    actor=actor,
                    source_ip=event.get("sourceIPAddress", "Unknown"),
                    details=f"Action '{event_name}' was executed against trail '{trail_name}'.",
                    remediation="Immediately re-enable CloudTrail logging, enable log file integrity validation, and restrict trail modification via Service Control Policies (SCPs).",
                )
            )
    return findings


def run_all_rules(events: List[Dict[str, Any]], brute_force_threshold: int = 3) -> List[Finding]:
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    all_findings: List[Finding] = []

    all_findings.extend(detect_root_usage(events))
    all_findings.extend(detect_console_login_without_mfa(events))
    all_findings.extend(detect_brute_force(events, threshold=brute_force_threshold))
    all_findings.extend(detect_logging_tampering(events))

    all_findings.sort(key=lambda f: severity_order.get(f.severity, 99))
    return all_findings

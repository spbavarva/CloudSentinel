from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from scan_parser import ParsedScan, parse_scan_file


PRIMARY_SERVICES = {"ec2", "s3", "iam", "vpc"}
FINDING_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
FINDING_STATUSES = {"TRUE", "NEEDS_REVIEW"}
CHAIN_EVIDENCE_STATUSES = {"CONFIRMED", "INFERRED"}
FINDING_CATEGORIES = {
    "network_exposure",
    "access_control",
    "encryption",
    "logging_monitoring",
    "data_exposure",
    "credential_risk",
    "resource_hygiene",
    "backup_recovery",
    "compliance",
    "cost",
}
OVERALL_HEALTH_VALUES = {"AT_RISK", "SECURE", "SCAN_INCOMPLETE"}
SUMMARY_SEVERITY_KEYS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NEEDS_REVIEW")
FINDING_ID_RE = re.compile(r"^[A-Z0-9_]+-\d+$")
ATTACK_PATH_ID_RE = re.compile(r"^AP-\d+$")
RESOURCE_ID_RE = re.compile(
    r"\b(?:i|sg|subnet|vpc|vol|snap|ami|eipalloc|eni|rtb|acl|igw|nat|vpce|pcx|fl|tgw-attach)-[0-9a-f]+\b",
    re.IGNORECASE,
)
ARN_RE = re.compile(r"^arn:[A-Za-z0-9:_/\-*.]+$")
TARGET_STRING_KEYS = {
    "id",
    "name",
    "arn",
    "bucket",
    "bucketname",
    "functionname",
    "rolename",
    "username",
    "groupname",
    "policyname",
    "resourceid",
    "instanceid",
    "securitygroupid",
    "subnetid",
    "vpcid",
    "volumeid",
    "snapshotid",
    "imageid",
    "keyname",
    "allocationid",
    "associationid",
    "internetgatewayid",
    "routetableid",
    "networkaclid",
    "natgatewayid",
    "vpcendpointid",
    "vpcpeeringconnectionid",
    "flowlogid",
    "transitgatewayattachmentid",
    "dbinstanceidentifier",
    "loadbalancername",
    "secretid",
    "secretarn",
    "secretname",
}


@dataclass(slots=True)
class ValidationIssue:
    path: str
    message: str
    severity: str

    def to_dict(self) -> dict[str, str]:
        return {
            "path": self.path,
            "message": self.message,
            "severity": self.severity,
        }


@dataclass(slots=True)
class ValidationResult:
    errors: list[ValidationIssue]
    warnings: list[ValidationIssue]

    @property
    def ok(self) -> bool:
        return not self.errors

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "errors": [issue.to_dict() for issue in self.errors],
            "warnings": [issue.to_dict() for issue in self.warnings],
        }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate a CloudSentinel AI analysis JSON file."
    )
    parser.add_argument(
        "--analysis-file",
        required=True,
        help="Path to the LLM analysis JSON file.",
    )
    parser.add_argument(
        "--scan-file",
        help="Optional scanner output text file for cross-checking analysis against evidence.",
    )
    parser.add_argument(
        "--output-file",
        help="Optional path to write the validation report JSON.",
    )
    return parser.parse_args()


def add_issue(
    issues: list[ValidationIssue],
    *,
    path: str,
    message: str,
    severity: str,
) -> None:
    issues.append(ValidationIssue(path=path, message=message, severity=severity))


def read_json_file(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def is_non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def collect_evidence_strings(value: Any, *, parent_key: str | None = None) -> set[str]:
    strings: set[str] = set()
    key = parent_key.lower() if parent_key else None

    if isinstance(value, dict):
        for child_key, child_value in value.items():
            strings.update(collect_evidence_strings(child_value, parent_key=str(child_key)))
        return strings

    if isinstance(value, list):
        for item in value:
            strings.update(collect_evidence_strings(item, parent_key=parent_key))
        return strings

    if not isinstance(value, str):
        return strings

    trimmed = value.strip()
    if not trimmed:
        return strings

    if key and (key in TARGET_STRING_KEYS or key.endswith("id") or key.endswith("name") or key.endswith("arn")):
        strings.add(trimmed)
    if RESOURCE_ID_RE.search(trimmed) or ARN_RE.match(trimmed):
        strings.add(trimmed)
    return strings


def extract_scan_evidence(parsed_scan: ParsedScan) -> set[str]:
    evidence: set[str] = set()
    for section in parsed_scan.sections:
        for command in section.commands:
            evidence.add(command.label)
            if command.payload is not None:
                evidence.update(collect_evidence_strings(command.payload))
    return evidence


def validate_account_summary(
    account_summary: Any,
    *,
    findings: list[dict[str, Any]],
    attack_paths: list[dict[str, Any]],
    errors: list[ValidationIssue],
    warnings: list[ValidationIssue],
    path: str = "$.account_summary",
) -> None:
    if not isinstance(account_summary, dict):
        add_issue(errors, path=path, message="account_summary must be an object.", severity="error")
        return

    for key in ("total_resources_scanned", "total_findings", "total_attack_paths", "severity_breakdown", "overall_health"):
        if key not in account_summary:
            add_issue(errors, path=f"{path}.{key}", message="Missing required account_summary field.", severity="error")

    total_findings = account_summary.get("total_findings")
    if not isinstance(total_findings, int) or total_findings < 0:
        add_issue(errors, path=f"{path}.total_findings", message="total_findings must be a non-negative integer.", severity="error")
    elif total_findings != len(findings):
        add_issue(errors, path=f"{path}.total_findings", message="total_findings does not match findings length.", severity="error")

    total_attack_paths = account_summary.get("total_attack_paths")
    if not isinstance(total_attack_paths, int) or total_attack_paths < 0:
        add_issue(errors, path=f"{path}.total_attack_paths", message="total_attack_paths must be a non-negative integer.", severity="error")
    elif total_attack_paths != len(attack_paths):
        add_issue(errors, path=f"{path}.total_attack_paths", message="total_attack_paths does not match attack_paths length.", severity="error")

    total_resources_scanned = account_summary.get("total_resources_scanned")
    if not isinstance(total_resources_scanned, int) or total_resources_scanned < 0:
        add_issue(errors, path=f"{path}.total_resources_scanned", message="total_resources_scanned must be a non-negative integer.", severity="error")

    severity_breakdown = account_summary.get("severity_breakdown")
    if not isinstance(severity_breakdown, dict):
        add_issue(errors, path=f"{path}.severity_breakdown", message="severity_breakdown must be an object.", severity="error")
    else:
        calculated = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "NEEDS_REVIEW": 0,
        }
        for finding in findings:
            severity = finding.get("severity")
            status = finding.get("status")
            if severity in FINDING_SEVERITIES:
                calculated[severity] += 1
            if status == "NEEDS_REVIEW":
                calculated["NEEDS_REVIEW"] += 1
        for key in SUMMARY_SEVERITY_KEYS:
            value = severity_breakdown.get(key)
            if not isinstance(value, int) or value < 0:
                add_issue(errors, path=f"{path}.severity_breakdown.{key}", message="severity_breakdown values must be non-negative integers.", severity="error")
                continue
            if value != calculated[key]:
                add_issue(
                    warnings,
                    path=f"{path}.severity_breakdown.{key}",
                    message=f"severity_breakdown.{key} does not match calculated finding counts ({calculated[key]}).",
                    severity="warning",
                )

    overall_health = account_summary.get("overall_health")
    if overall_health not in OVERALL_HEALTH_VALUES:
        add_issue(errors, path=f"{path}.overall_health", message="overall_health must be one of AT_RISK, SECURE, or SCAN_INCOMPLETE.", severity="error")


def validate_findings(
    findings: Any,
    *,
    service: str,
    attack_path_ids: set[str],
    evidence_strings: set[str] | None,
    errors: list[ValidationIssue],
    warnings: list[ValidationIssue],
) -> list[dict[str, Any]]:
    if not isinstance(findings, list):
        add_issue(errors, path="$.findings", message="findings must be an array.", severity="error")
        return []

    validated: list[dict[str, Any]] = []
    expected_prefix = service.upper() + "-"

    for index, finding in enumerate(findings):
        path = f"$.findings[{index}]"
        if not isinstance(finding, dict):
            add_issue(errors, path=path, message="Each finding must be an object.", severity="error")
            continue
        validated.append(finding)

        finding_id = finding.get("id")
        if not is_non_empty_string(finding_id):
            add_issue(errors, path=f"{path}.id", message="Finding id must be a non-empty string.", severity="error")
        elif not FINDING_ID_RE.match(finding_id) or not str(finding_id).startswith(expected_prefix):
            add_issue(errors, path=f"{path}.id", message=f"Finding id must match the primary service prefix {expected_prefix}.", severity="error")

        for key in ("resource_name", "resource_id", "severity", "status", "fix_command", "category"):
            if key not in finding:
                add_issue(errors, path=f"{path}.{key}", message="Missing required finding field.", severity="error")

        resource_name = finding.get("resource_name")
        resource_id = finding.get("resource_id")
        if not is_non_empty_string(resource_name):
            add_issue(errors, path=f"{path}.resource_name", message="resource_name must be a non-empty string.", severity="error")
        if not is_non_empty_string(resource_id):
            add_issue(errors, path=f"{path}.resource_id", message="resource_id must be a non-empty string.", severity="error")

        severity = finding.get("severity")
        if severity not in FINDING_SEVERITIES:
            add_issue(errors, path=f"{path}.severity", message="severity must be one of CRITICAL, HIGH, MEDIUM, LOW.", severity="error")

        status = finding.get("status")
        if status not in FINDING_STATUSES:
            add_issue(errors, path=f"{path}.status", message="status must be TRUE or NEEDS_REVIEW.", severity="error")

        category = finding.get("category")
        if category not in FINDING_CATEGORIES:
            add_issue(errors, path=f"{path}.category", message="category is not a valid CloudSentinel category.", severity="error")

        fix_command = finding.get("fix_command")
        if not is_non_empty_string(fix_command):
            add_issue(errors, path=f"{path}.fix_command", message="fix_command must be a non-empty string.", severity="error")
        elif "aws " not in str(fix_command) and "cannot be fixed" not in str(fix_command).lower():
            add_issue(
                warnings,
                path=f"{path}.fix_command",
                message="fix_command does not look like an AWS CLI command or an explicit manual-action note.",
                severity="warning",
            )

        linked_attack_path_ids = finding.get("attack_path_ids")
        if linked_attack_path_ids is not None:
            if not isinstance(linked_attack_path_ids, list) or not all(is_non_empty_string(item) for item in linked_attack_path_ids):
                add_issue(errors, path=f"{path}.attack_path_ids", message="attack_path_ids must be an array of non-empty strings.", severity="error")
            else:
                for attack_path_id in linked_attack_path_ids:
                    if attack_path_id not in attack_path_ids:
                        add_issue(errors, path=f"{path}.attack_path_ids", message=f"Unknown attack path reference: {attack_path_id}.", severity="error")

        if evidence_strings:
            name_in_evidence = isinstance(resource_name, str) and resource_name in evidence_strings
            id_in_evidence = isinstance(resource_id, str) and resource_id in evidence_strings
            if not name_in_evidence and not id_in_evidence:
                add_issue(
                    warnings,
                    path=path,
                    message="Neither resource_name nor resource_id was found in parsed scan evidence.",
                    severity="warning",
                )

    return validated


def validate_attack_paths(
    attack_paths: Any,
    *,
    errors: list[ValidationIssue],
    warnings: list[ValidationIssue],
) -> list[dict[str, Any]]:
    if not isinstance(attack_paths, list):
        add_issue(errors, path="$.attack_paths", message="attack_paths must be an array.", severity="error")
        return []

    validated: list[dict[str, Any]] = []
    for index, attack_path in enumerate(attack_paths):
        path = f"$.attack_paths[{index}]"
        if not isinstance(attack_path, dict):
            add_issue(errors, path=path, message="Each attack path must be an object.", severity="error")
            continue
        validated.append(attack_path)

        attack_path_id = attack_path.get("id")
        if not is_non_empty_string(attack_path_id):
            add_issue(errors, path=f"{path}.id", message="Attack path id must be a non-empty string.", severity="error")
        elif not ATTACK_PATH_ID_RE.match(str(attack_path_id)):
            add_issue(errors, path=f"{path}.id", message="Attack path id must match AP-{NUMBER}.", severity="error")

        severity = attack_path.get("severity")
        if severity not in FINDING_SEVERITIES:
            add_issue(errors, path=f"{path}.severity", message="Attack path severity must be one of CRITICAL, HIGH, MEDIUM, LOW.", severity="error")

        for key in ("chain", "full_path_summary", "impact", "remediation_priority"):
            if key not in attack_path:
                add_issue(errors, path=f"{path}.{key}", message="Missing required attack path field.", severity="error")

        chain = attack_path.get("chain")
        if not isinstance(chain, list) or not chain:
            add_issue(errors, path=f"{path}.chain", message="chain must be a non-empty array.", severity="error")
            continue

        confirmed_hops = 0
        inferred_hops = 0
        for hop_index, hop in enumerate(chain):
            hop_path = f"{path}.chain[{hop_index}]"
            if not isinstance(hop, dict):
                add_issue(errors, path=hop_path, message="Each chain hop must be an object.", severity="error")
                continue
            evidence_status = hop.get("evidence_status")
            if evidence_status not in CHAIN_EVIDENCE_STATUSES:
                add_issue(errors, path=f"{hop_path}.evidence_status", message="evidence_status must be CONFIRMED or INFERRED.", severity="error")
                continue
            if evidence_status == "CONFIRMED":
                confirmed_hops += 1
            else:
                inferred_hops += 1

        if confirmed_hops < 2:
            add_issue(errors, path=f"{path}.chain", message="Attack paths must contain at least 2 CONFIRMED hops.", severity="error")
        if inferred_hops > 1:
            add_issue(errors, path=f"{path}.chain", message="Attack paths may not contain more than 1 inferred hop.", severity="error")

        full_path_summary = attack_path.get("full_path_summary")
        if not is_non_empty_string(full_path_summary):
            add_issue(errors, path=f"{path}.full_path_summary", message="full_path_summary must be a non-empty string.", severity="error")
        elif "→" not in str(full_path_summary) and "->" not in str(full_path_summary):
            add_issue(
                warnings,
                path=f"{path}.full_path_summary",
                message="full_path_summary does not appear to use arrow notation.",
                severity="warning",
            )

        for key in ("impact", "remediation_priority"):
            value = attack_path.get(key)
            if not is_non_empty_string(value):
                add_issue(errors, path=f"{path}.{key}", message=f"{key} must be a non-empty string.", severity="error")

    return validated


def validate_quick_wins(
    quick_wins: Any,
    *,
    finding_ids: set[str],
    errors: list[ValidationIssue],
) -> None:
    if not isinstance(quick_wins, list):
        add_issue(errors, path="$.quick_wins", message="quick_wins must be an array.", severity="error")
        return

    for index, quick_win in enumerate(quick_wins):
        path = f"$.quick_wins[{index}]"
        if not isinstance(quick_win, dict):
            add_issue(errors, path=path, message="Each quick_wins entry must be an object.", severity="error")
            continue
        for key in ("finding_id", "action", "effort", "impact"):
            if not is_non_empty_string(quick_win.get(key)):
                add_issue(errors, path=f"{path}.{key}", message=f"{key} must be a non-empty string.", severity="error")
        finding_id = quick_win.get("finding_id")
        if isinstance(finding_id, str) and finding_id not in finding_ids:
            add_issue(errors, path=f"{path}.finding_id", message=f"Unknown finding reference: {finding_id}.", severity="error")


def validate_narrative(
    narrative: Any,
    *,
    errors: list[ValidationIssue],
    warnings: list[ValidationIssue],
) -> None:
    if not is_non_empty_string(narrative):
        add_issue(errors, path="$.narrative", message="narrative must be a non-empty string.", severity="error")
        return
    paragraphs = [paragraph.strip() for paragraph in str(narrative).split("\n\n") if paragraph.strip()]
    if len(paragraphs) != 2:
        add_issue(
            warnings,
            path="$.narrative",
            message="narrative should contain exactly 2 paragraphs.",
            severity="warning",
        )


def validate_analysis_document(
    analysis: Any,
    *,
    parsed_scan: ParsedScan | None = None,
) -> ValidationResult:
    errors: list[ValidationIssue] = []
    warnings: list[ValidationIssue] = []

    if not isinstance(analysis, dict):
        add_issue(errors, path="$", message="Top-level analysis must be a JSON object.", severity="error")
        return ValidationResult(errors=errors, warnings=warnings)

    for key in ("service", "scan_timestamp", "account_summary", "findings", "attack_paths", "narrative", "quick_wins"):
        if key not in analysis:
            add_issue(errors, path=f"$.{key}", message="Missing required top-level field.", severity="error")

    service = analysis.get("service")
    if not is_non_empty_string(service):
        add_issue(errors, path="$.service", message="service must be a non-empty string.", severity="error")
        service_value = ""
    else:
        service_value = str(service).lower()
        if service_value not in PRIMARY_SERVICES:
            add_issue(errors, path="$.service", message="service must be one of ec2, s3, iam, vpc.", severity="error")
        if parsed_scan and service_value != parsed_scan.primary_service:
            add_issue(errors, path="$.service", message="service does not match the parsed scan primary service.", severity="error")

    if not is_non_empty_string(analysis.get("scan_timestamp")):
        add_issue(errors, path="$.scan_timestamp", message="scan_timestamp must be a non-empty string.", severity="error")
    elif parsed_scan and parsed_scan.scan_timestamp and analysis.get("scan_timestamp") != parsed_scan.scan_timestamp:
        add_issue(
            warnings,
            path="$.scan_timestamp",
            message="scan_timestamp does not match the earliest parsed scan timestamp.",
            severity="warning",
        )

    raw_attack_paths = analysis.get("attack_paths")
    attack_paths = validate_attack_paths(raw_attack_paths, errors=errors, warnings=warnings)
    attack_path_ids = {
        attack_path["id"]
        for attack_path in attack_paths
        if isinstance(attack_path.get("id"), str)
    }

    evidence_strings = extract_scan_evidence(parsed_scan) if parsed_scan else None
    raw_findings = analysis.get("findings")
    findings = validate_findings(
        raw_findings,
        service=service_value,
        attack_path_ids=attack_path_ids,
        evidence_strings=evidence_strings,
        errors=errors,
        warnings=warnings,
    )
    finding_ids = {
        finding["id"]
        for finding in findings
        if isinstance(finding.get("id"), str)
    }

    validate_account_summary(
        analysis.get("account_summary"),
        findings=findings,
        attack_paths=attack_paths,
        errors=errors,
        warnings=warnings,
    )
    validate_narrative(analysis.get("narrative"), errors=errors, warnings=warnings)
    validate_quick_wins(
        analysis.get("quick_wins"),
        finding_ids=finding_ids,
        errors=errors,
    )

    if parsed_scan:
        if parsed_scan.total_error_commands and analysis.get("account_summary", {}).get("overall_health") == "SECURE":
            add_issue(
                warnings,
                path="$.account_summary.overall_health",
                message="Scan contains failed commands; SECURE may be too strong if coverage was incomplete.",
                severity="warning",
            )
        if not findings and not attack_paths and not parsed_scan.total_error_commands:
            overall_health = analysis.get("account_summary", {}).get("overall_health")
            if overall_health != "SECURE":
                add_issue(
                    warnings,
                    path="$.account_summary.overall_health",
                    message="No findings were returned for a complete scan; overall_health is usually SECURE in this case.",
                    severity="warning",
                )

    return ValidationResult(errors=errors, warnings=warnings)


def write_output(payload: dict[str, Any], output_file: str | None) -> None:
    rendered = json.dumps(payload, indent=2, sort_keys=True)
    if output_file:
        Path(output_file).write_text(rendered + "\n", encoding="utf-8")
        return
    print(rendered)


def main() -> int:
    args = parse_args()
    analysis = read_json_file(args.analysis_file)
    parsed_scan = parse_scan_file(args.scan_file) if args.scan_file else None
    result = validate_analysis_document(analysis, parsed_scan=parsed_scan)
    payload = result.to_dict()
    if parsed_scan:
        payload["scan_summary"] = parsed_scan.to_dict()
    write_output(payload, args.output_file)
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
